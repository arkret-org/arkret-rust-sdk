//! Realm membership management.
//!
//! Wire-shaped types are reused from `arkret-core`:
//! [`MembershipPayloadState`] (spec vocabulary `invite/join/knock/leave/ban`),
//! [`Invite`] (mirrors `invite.schema.json`) and [`ThirdPartyInvite`]
//! (3PID carrier — the plaintext address MUST NEVER appear on the wire).
//! Manager-only bookkeeping (granted role per invite, change log) stays in
//! [`MembershipManager`] private fields.

use std::collections::BTreeMap;

pub use arkret_core::{
    INVITE_SCHEMA, Invite, InviteState, MembershipPayloadState, ThirdPartyInvite,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{DeliveryStatus, MembershipPayload, OP_MEMBER_STATE};
use crate::{BlobRef, Did, Error, InviteId, Operation, OperationId, RealmId, Result};

/// Generate a new UUIDv7-based wire ID with the given Arkret typed prefix
/// (e.g. `ak:invite:`, `ak:operation:`). RFC 9562 §5.7 / `conformance/encoding.md` §4.
fn generate_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Default invite TTL used by [`MembershipManager::send_invite`].
///
/// `invite.schema.json` requires every invite to carry a hard `expires_at`;
/// callers that need a different window use
/// [`MembershipManager::send_invite_with_expiry`].
const DEFAULT_INVITE_TTL_DAYS: i64 = 7;

/// Validate a membership transition against the authoritative `ak.member.state`
/// FSM (`event-kind-registry.json` → `ak.member.state.parameters`).
///
/// The FSM uses `initial_state = leave`, so `from = None` ("no prior
/// membership") is treated as `leave`. The `allowed_transitions` are:
///
/// - `leave → {invite, knock, join, ban}`
/// - `invite → {join, leave, ban}`
/// - `knock → {invite, join, leave, ban}`
/// - `join → {leave, ban}`
/// - `ban → {leave, invite}`
///
/// Same-state writes (e.g. `Join → Join`) are allowed as idempotent
/// no-ops; reducers may still emit a profile/role change without flipping
/// state. Anything else returns `false` and the reducer MUST reject the
/// event with `state_mismatch`.
pub fn is_legal_membership_transition(
    from: Option<MembershipPayloadState>,
    to: MembershipPayloadState,
) -> bool {
    use MembershipPayloadState::*;
    // Spec initial state is `leave`; the "no prior membership" sentinel maps
    // onto it (there is no distinct `none` wire value).
    let from = from.unwrap_or(Leave);
    if to == from {
        return true;
    }
    matches!(
        (from, to),
        (Leave, Invite)
            | (Leave, Knock)
            | (Leave, Join)
            | (Leave, Ban)
            | (Invite, Join)
            | (Invite, Leave)
            | (Invite, Ban)
            | (Knock, Invite)
            | (Knock, Join)
            | (Knock, Leave)
            | (Knock, Ban)
            | (Join, Leave)
            | (Join, Ban)
            | (Ban, Leave)
            | (Ban, Invite)
    )
}

/// Role used for coarse permission checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// Read-only participant.
    Viewer,
    /// Regular participant.
    Member,
    /// Realm moderator.
    Moderator,
    /// Realm administrator.
    Admin,
    /// Realm owner.
    Owner,
}

impl MemberRole {
    /// Numeric power level compatible with Matrix-style comparisons.
    pub fn power_level(self) -> u8 {
        match self {
            Self::Viewer => 10,
            Self::Member => 50,
            Self::Moderator => 75,
            Self::Admin => 90,
            Self::Owner => 100,
        }
    }
}

/// Member profile cached by the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberProfile {
    /// Display name.
    pub display_name: Option<String>,
    /// Canonical Arkret avatar Blob reference.
    pub avatar_blob_ref: Option<BlobRef>,
}

/// Membership entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Member actor DID.
    pub actor_id: Did,
    /// Current membership state.
    pub state: MembershipPayloadState,
    /// Role in the Realm.
    pub role: MemberRole,
    /// Cached profile.
    pub profile: Option<MemberProfile>,
    /// Last membership update time.
    pub updated_at: DateTime<Utc>,
}

/// Notification emitted when a member changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberChange {
    /// Changed actor.
    pub actor_id: Did,
    /// Previous state if known.
    pub previous: Option<MembershipPayloadState>,
    /// New state.
    pub current: MembershipPayloadState,
}

/// Whether an invite is still pending (not accepted, rejected, revoked,
/// expired or otherwise terminal).
pub fn invite_is_pending(invite: &Invite) -> bool {
    invite.state == InviteState::Pending
}

/// Whether an invite's hard expiry has passed.
pub fn invite_is_expired(invite: &Invite) -> bool {
    Utc::now() >= invite.expires_at
}

/// In-memory membership manager.
#[derive(Clone, Debug)]
pub struct MembershipManager {
    realm_id: RealmId,
    current_user: Did,
    members: BTreeMap<Did, Member>,
    invites: BTreeMap<InviteId, Invite>,
    /// Manager-only bookkeeping: role granted when an invite is accepted.
    /// The wire [`Invite`] carries capability grant refs instead of a role.
    invite_roles: BTreeMap<InviteId, MemberRole>,
    changes: Vec<MemberChange>,
}

impl MembershipManager {
    /// Create a membership manager for one Realm.
    pub fn new(realm_id: RealmId, current_user: Did) -> Self {
        Self {
            realm_id,
            current_user,
            members: BTreeMap::new(),
            invites: BTreeMap::new(),
            invite_roles: BTreeMap::new(),
            changes: Vec::new(),
        }
    }

    /// Insert or update a member.
    pub fn upsert_member(
        &mut self,
        actor_id: Did,
        state: MembershipPayloadState,
        role: MemberRole,
        profile: Option<MemberProfile>,
    ) {
        let previous = self.members.get(&actor_id).map(|member| member.state);
        self.members.insert(
            actor_id.clone(),
            Member {
                actor_id: actor_id.clone(),
                state,
                role,
                profile,
                updated_at: Utc::now(),
            },
        );
        if previous != Some(state) {
            self.changes.push(MemberChange {
                actor_id,
                previous,
                current: state,
            });
        }
    }

    /// Accept an invitation or initial join through the canonical transition table.
    pub fn join(&mut self, actor_id: &Did) -> Result<()> {
        self.apply_transition(actor_id, MembershipPayloadState::Join)
    }

    /// Leave a joined Realm.
    pub fn leave(&mut self, actor_id: &Did) -> Result<()> {
        match self.members.get(actor_id).map(|member| member.state) {
            Some(MembershipPayloadState::Join) => {
                let member = self.members.get(actor_id).cloned().expect("member exists");
                self.upsert_member(
                    actor_id.clone(),
                    MembershipPayloadState::Leave,
                    member.role,
                    member.profile,
                );
                Ok(())
            }
            _ => Err(Error::Protocol("only joined members can leave".to_owned())),
        }
    }

    /// Ban a member.
    pub fn ban(&mut self, actor_id: &Did) -> Result<()> {
        self.apply_transition(actor_id, MembershipPayloadState::Ban)
    }

    /// Unban a member, leaving them in `Leave` state.
    pub fn unban(&mut self, actor_id: &Did) -> Result<()> {
        match self.members.get(actor_id).map(|member| member.state) {
            Some(MembershipPayloadState::Ban) => {
                let member = self.members.get(actor_id).cloned().expect("member exists");
                self.upsert_member(
                    actor_id.clone(),
                    MembershipPayloadState::Leave,
                    member.role,
                    member.profile,
                );
                Ok(())
            }
            _ => Err(Error::Protocol(
                "only banned members can be unbanned".to_owned(),
            )),
        }
    }

    /// Record a `knock` request — `none → Knock` or `Leave → Knock`.
    pub fn knock(&mut self, actor_id: &Did) -> Result<()> {
        self.apply_transition(actor_id, MembershipPayloadState::Knock)
    }

    /// Apply a state transition, rejecting it via `state_mismatch` when the
    /// transition is illegal per `event-auth-state-resolution.md` §5.
    ///
    /// Convenience writers such as [`Self::join`] / [`Self::leave`] /
    /// [`Self::ban`] all route through this same canonical transition table.
    pub fn apply_transition(&mut self, actor_id: &Did, to: MembershipPayloadState) -> Result<()> {
        let from = self.members.get(actor_id).map(|m| m.state);
        if !is_legal_membership_transition(from, to) {
            return Err(Error::Protocol(format!(
                "illegal membership transition {from:?} -> {to:?}"
            )));
        }
        let role = self
            .members
            .get(actor_id)
            .map(|m| m.role)
            .unwrap_or(MemberRole::Member);
        let profile = self.members.get(actor_id).and_then(|m| m.profile.clone());
        self.upsert_member(actor_id.clone(), to, role, profile);
        Ok(())
    }

    /// Current user role.
    pub fn current_user_role(&self) -> Option<MemberRole> {
        self.members
            .get(&self.current_user)
            .map(|member| member.role)
    }

    /// Check the current user has at least `required` role level.
    pub fn current_user_can(&self, required: MemberRole) -> bool {
        self.current_user_role()
            .map(|role| role.power_level() >= required.power_level())
            .unwrap_or(false)
    }

    /// Query a named capability using coarse role mapping.
    pub fn has_capability(&self, capability: &str) -> bool {
        let required = match capability {
            "ak.invite.create" | "ak.invite.cancel" => MemberRole::Moderator,
            "ak.invite.revoke" | "ak.realm.policy" => MemberRole::Admin,
            "ak.realm.destroy" => MemberRole::Owner,
            "ak.event.read" => MemberRole::Viewer,
            "ak.message.create" => MemberRole::Member,
            _ => return false,
        };
        self.current_user_can(required)
    }

    /// List all members.
    pub fn members(&self) -> Vec<&Member> {
        self.members.values().collect()
    }

    /// Get one member.
    pub fn member(&self, actor_id: &Did) -> Option<&Member> {
        self.members.get(actor_id)
    }

    /// Drain member change notifications.
    pub fn drain_changes(&mut self) -> Vec<MemberChange> {
        self.changes.drain(..).collect()
    }

    /// Update cached member profile.
    pub fn update_profile(&mut self, actor_id: &Did, profile: MemberProfile) -> Result<()> {
        let member = self
            .members
            .get_mut(actor_id)
            .ok_or_else(|| Error::Protocol("member not found".to_owned()))?;
        member.profile = Some(profile);
        member.updated_at = Utc::now();
        Ok(())
    }

    fn new_invite(
        &self,
        invitee: Option<Did>,
        third_party: Option<&ThirdPartyInvite>,
        inviter: Did,
        expires_at: DateTime<Utc>,
    ) -> Result<Invite> {
        Ok(Invite {
            id: InviteId::new(generate_id("ak:invite:"))?,
            schema: INVITE_SCHEMA.to_owned(),
            realm_id: self.realm_id.clone(),
            inviter,
            invitee,
            invite_delivery_target: None,
            introduction_evidence_digest: None,
            third_party_id: third_party.map(serde_json::to_value).transpose()?,
            // The in-memory manager does not track the Realm join-rule
            // cell; callers building durable wire invites should snapshot
            // the effective join rule here.
            join_rule_snapshot: BTreeMap::new(),
            capability_grant_refs: Vec::new(),
            state: InviteState::Pending,
            expires_at,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        })
    }

    /// Send a DID invite using the default TTL
    /// ([`DEFAULT_INVITE_TTL_DAYS`] — `invite.schema.json` requires a
    /// hard expiry on every invite).
    pub fn send_invite(
        &mut self,
        actor_id: Did,
        invited_by: Did,
        role: MemberRole,
    ) -> Result<Invite> {
        self.send_invite_with_expiry(
            actor_id,
            invited_by,
            role,
            Utc::now() + Duration::days(DEFAULT_INVITE_TTL_DAYS),
        )
    }

    /// Send a DID invite with an explicit expiration time.
    pub fn send_invite_with_expiry(
        &mut self,
        actor_id: Did,
        invited_by: Did,
        role: MemberRole,
        expires_at: DateTime<Utc>,
    ) -> Result<Invite> {
        let invite = self.new_invite(Some(actor_id.clone()), None, invited_by, expires_at)?;
        self.upsert_member(actor_id, MembershipPayloadState::Invite, role, None);
        self.invite_roles.insert(invite.id.clone(), role);
        self.invites.insert(invite.id.clone(), invite.clone());
        Ok(invite)
    }

    /// Send a 3PID invite.
    pub fn send_third_party_invite(
        &mut self,
        third_party: ThirdPartyInvite,
        invited_by: Did,
        role: MemberRole,
    ) -> Result<Invite> {
        let invite = self.new_invite(
            None,
            Some(&third_party),
            invited_by,
            Utc::now() + Duration::days(DEFAULT_INVITE_TTL_DAYS),
        )?;
        self.invite_roles.insert(invite.id.clone(), role);
        self.invites.insert(invite.id.clone(), invite.clone());
        Ok(invite)
    }

    /// Revoke a pending invite.
    pub fn revoke_invite(&mut self, invite_id: &InviteId) -> Result<()> {
        let invite = self
            .invites
            .get(invite_id)
            .ok_or_else(|| Error::Protocol("invite not found".to_owned()))?;
        match invite.state {
            InviteState::Accepted => {
                return Err(Error::Protocol(
                    "accepted invite cannot be revoked".to_owned(),
                ));
            }
            InviteState::Revoked => {
                return Err(Error::Protocol("invite is already revoked".to_owned()));
            }
            _ => {}
        }
        let invitee = invite.invitee.clone();
        let role = self.invite_role(invite_id);
        let invite = self.invites.get_mut(invite_id).expect("invite exists");
        invite.state = InviteState::Revoked;
        invite.updated_at = Some(Utc::now());
        if let Some(invitee) = invitee {
            self.upsert_member(invitee, MembershipPayloadState::Leave, role, None);
        }
        Ok(())
    }

    /// Expire all pending invites whose expiration time has passed,
    /// moving them to the `expired` state.
    ///
    /// Returns the number of invites that were expired.
    pub fn expire_invites(&mut self) -> usize {
        let now = Utc::now();
        // Collect the IDs and invitee info of invites to expire to avoid borrow conflict.
        let to_expire: Vec<(InviteId, Option<Did>)> = self
            .invites
            .iter()
            .filter(|(_, invite)| invite.state == InviteState::Pending && now >= invite.expires_at)
            .map(|(id, invite)| (id.clone(), invite.invitee.clone()))
            .collect();

        let count = to_expire.len();
        for (invite_id, invitee) in to_expire {
            let role = self.invite_role(&invite_id);
            if let Some(invite) = self.invites.get_mut(&invite_id) {
                invite.state = InviteState::Expired;
                invite.updated_at = Some(now);
            }
            if let Some(invitee) = invitee {
                self.upsert_member(invitee, MembershipPayloadState::Leave, role, None);
            }
        }
        count
    }

    /// List all pending invites.
    pub fn pending_invites(&self) -> Vec<&Invite> {
        self.invites
            .values()
            .filter(|invite| invite_is_pending(invite))
            .collect()
    }

    /// Get an invite by ID.
    pub fn invite(&self, invite_id: &InviteId) -> Option<&Invite> {
        self.invites.get(invite_id)
    }

    /// Role granted on acceptance of an invite (manager-side bookkeeping).
    pub fn invite_role(&self, invite_id: &InviteId) -> MemberRole {
        self.invite_roles
            .get(invite_id)
            .copied()
            .unwrap_or(MemberRole::Member)
    }

    /// Accept an invite for a DID.
    pub fn accept_invite(&mut self, invite_id: &InviteId, actor_id: Did) -> Result<()> {
        let role = self.invite_role(invite_id);
        {
            let invite = self
                .invites
                .get_mut(invite_id)
                .ok_or_else(|| Error::Protocol("invite not found".to_owned()))?;
            match invite.state {
                InviteState::Rejected => {
                    return Err(Error::Protocol(
                        "rejected invite cannot be accepted".to_owned(),
                    ));
                }
                InviteState::Revoked => {
                    return Err(Error::Protocol(
                        "revoked invite cannot be accepted".to_owned(),
                    ));
                }
                InviteState::Expired => {
                    return Err(Error::Protocol(
                        "expired invite cannot be accepted".to_owned(),
                    ));
                }
                _ => {}
            }
            if invite_is_expired(invite) {
                return Err(Error::Protocol(
                    "expired invite cannot be accepted".to_owned(),
                ));
            }
            invite.state = InviteState::Accepted;
            invite.invitee = Some(actor_id.clone());
            invite.updated_at = Some(Utc::now());
        }
        self.upsert_member(actor_id, MembershipPayloadState::Join, role, None);
        Ok(())
    }

    /// Reject an invite.
    pub fn reject_invite(&mut self, invite_id: &InviteId) -> Result<()> {
        let role = self.invite_role(invite_id);
        let invitee = {
            let invite = self
                .invites
                .get_mut(invite_id)
                .ok_or_else(|| Error::Protocol("invite not found".to_owned()))?;
            match invite.state {
                InviteState::Accepted => {
                    return Err(Error::Protocol(
                        "accepted invite cannot be rejected".to_owned(),
                    ));
                }
                InviteState::Revoked => {
                    return Err(Error::Protocol(
                        "revoked invite cannot be rejected".to_owned(),
                    ));
                }
                _ => {}
            }
            invite.state = InviteState::Rejected;
            invite.updated_at = Some(Utc::now());
            invite.invitee.clone()
        };
        if let Some(invitee) = invitee {
            self.upsert_member(invitee, MembershipPayloadState::Leave, role, None);
        }
        Ok(())
    }

    /// Build a `ak.member.state` operation for submission.
    ///
    /// The wire payload follows `event-payload.schema.json#/$defs/membership_payload`
    /// (`membership` state + `actor_id` cell subject). The acting principal is
    /// carried by the Event envelope's `created_by`, not the payload, so the
    /// `actor_id` argument does not appear in the payload body; the membership
    /// cell subject is `target_did`.
    pub fn membership_operation(
        &self,
        actor_id: Did,
        target_did: Did,
        state: MembershipPayloadState,
    ) -> Result<Operation> {
        // The acting principal is authenticated at the envelope layer; it is
        // intentionally not echoed into the membership payload.
        let _ = actor_id;
        let realm_id = RealmId::new(self.realm_id.to_string())?;
        let mut payload = if state == MembershipPayloadState::Join {
            // `membership=join` requires realm_id + delivery_status per schema;
            // this thin helper produces an `unroutable` join (no concrete
            // delivery binding). Callers needing a routable join use
            // `Realm::create_join_with_binding`.
            MembershipPayload::join(
                realm_id.clone(),
                target_did,
                DeliveryStatus::Unroutable,
                String::new(),
            )
        } else {
            MembershipPayload::transition(state, target_did, String::new())
        };
        payload.reason = None;
        Ok(Operation::create(
            OperationId::new(generate_id("ak:operation:"))?,
            realm_id,
            OP_MEMBER_STATE,
            payload.to_value()?,
        ))
    }
}

// Track-scoped membership (`ak.strand.track.member` and
// `StrandTrackMembership` / `StrandTrackMembershipManager`) was REMOVED in
// arkret-spec revision `0a5ab85`. Track no longer carries independent
// membership; access semantics inherit from the Strand's Realm. Use
// `ak.member.state` at the Realm or child Realm level instead.
//
// See `arkret-spec/spec/v1/artifacts/registry/removed-event-kinds.json`.

#[cfg(test)]
mod tests {
    use arkret_core::ThirdPartyInviteOobKind;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn third_party_invite() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::Lookup,
            token_commitment: None,
            token_salt_id: None,
            token_entropy_bits: None,
            lookup_table_ref: "lookup-table-1".to_owned().into(),
            pepper_id: "pepper-1".to_owned().into(),
            max_claims: 3,
            verification_service_id: did("verifier"),
            verification_public_key: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned(),
        }
    }

    #[test]
    fn membership_transitions_cover_invite_join_leave_and_ban() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        manager.upsert_member(
            alice.clone(),
            MembershipPayloadState::Invite,
            MemberRole::Member,
            None,
        );
        manager.join(&alice).unwrap();
        assert_eq!(
            manager.member(&alice).unwrap().state,
            MembershipPayloadState::Join
        );

        manager.leave(&alice).unwrap();
        assert_eq!(
            manager.member(&alice).unwrap().state,
            MembershipPayloadState::Leave
        );

        // `leave → join` is a legal transition per `ak.member.state`
        // (initial state is `leave`), so re-joining after leaving succeeds
        // directly without a fresh invite.
        manager.join(&alice).unwrap();
        manager.ban(&alice).unwrap();
        // `ban → join` is not allowed; a banned member must be unbanned
        // (→ `leave`) before re-admission.
        assert!(manager.join(&alice).is_err());
        manager.unban(&alice).unwrap();
        assert_eq!(
            manager.member(&alice).unwrap().state,
            MembershipPayloadState::Leave
        );
    }

    #[test]
    fn membership_checks_role_capabilities() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = MembershipManager::new(realm_id, alice.clone());
        manager.upsert_member(alice, MembershipPayloadState::Join, MemberRole::Admin, None);

        assert!(manager.current_user_can(MemberRole::Moderator));
        assert!(manager.has_capability("ak.realm.policy"));
        assert!(!manager.has_capability("ak.realm.destroy"));
    }

    #[test]
    fn membership_manages_member_list_profiles_and_changes() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice);

        manager.upsert_member(
            bob.clone(),
            MembershipPayloadState::Join,
            MemberRole::Member,
            None,
        );
        manager
            .update_profile(
                &bob,
                MemberProfile {
                    display_name: Some("Bob".to_owned()),
                    avatar_blob_ref: None,
                },
            )
            .unwrap();

        assert_eq!(manager.members().len(), 1);
        assert_eq!(
            manager
                .member(&bob)
                .unwrap()
                .profile
                .as_ref()
                .unwrap()
                .display_name,
            Some("Bob".to_owned())
        );
        assert_eq!(manager.drain_changes().len(), 1);
        assert!(manager.drain_changes().is_empty());
    }

    #[test]
    fn membership_handles_did_and_third_party_invites() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        let invite = manager
            .send_invite(bob.clone(), alice.clone(), MemberRole::Member)
            .unwrap();
        assert_eq!(invite.schema, INVITE_SCHEMA);
        manager.accept_invite(&invite.id, bob.clone()).unwrap();
        assert_eq!(
            manager.member(&bob).unwrap().state,
            MembershipPayloadState::Join
        );

        let third_party = manager
            .send_third_party_invite(third_party_invite(), alice, MemberRole::Viewer)
            .unwrap();
        assert!(third_party.third_party_id.is_some());
        manager.reject_invite(&third_party.id).unwrap();
        assert_eq!(
            manager.invite(&third_party.id).unwrap().state,
            InviteState::Rejected
        );
    }

    #[test]
    fn invite_revocation_blocks_acceptance() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        let invite = manager
            .send_invite(bob.clone(), alice, MemberRole::Member)
            .unwrap();
        manager.revoke_invite(&invite.id).unwrap();

        let stored = manager.invite(&invite.id).unwrap();
        assert_eq!(stored.state, InviteState::Revoked);
        assert!(!invite_is_pending(stored));

        // Trying to accept a revoked invite should fail.
        assert!(manager.accept_invite(&invite.id, bob).is_err());
    }

    #[test]
    fn invite_cannot_revoke_accepted() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        let invite = manager
            .send_invite(bob.clone(), alice, MemberRole::Member)
            .unwrap();
        manager.accept_invite(&invite.id, bob).unwrap();
        assert!(manager.revoke_invite(&invite.id).is_err());
    }

    #[test]
    fn invite_expiration_marks_expired() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        // Invite that already expired
        let past = "2020-01-01T00:00:00Z".parse().unwrap();
        let invite = manager
            .send_invite_with_expiry(bob, alice, MemberRole::Member, past)
            .unwrap();

        assert!(invite_is_expired(&invite));
        assert!(invite_is_pending(&invite)); // Not yet processed

        let expired_count = manager.expire_invites();
        assert_eq!(expired_count, 1);

        let stored = manager.invite(&invite.id).unwrap();
        assert_eq!(stored.state, InviteState::Expired);
        assert!(!invite_is_pending(stored));
    }

    #[test]
    fn invite_pending_invites_excludes_expired_and_revoked() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        // Pending invite
        let invite1 = manager
            .send_invite(bob, alice.clone(), MemberRole::Member)
            .unwrap();
        // Expired invite
        let past = "2020-01-01T00:00:00Z".parse().unwrap();
        let _invite2 = manager
            .send_invite_with_expiry(carol, alice, MemberRole::Member, past)
            .unwrap();

        assert_eq!(manager.pending_invites().len(), 2); // Both still pending until expire runs
        manager.expire_invites();
        assert_eq!(manager.pending_invites().len(), 1);
        assert_eq!(manager.pending_invites()[0].id, invite1.id);
    }
}
