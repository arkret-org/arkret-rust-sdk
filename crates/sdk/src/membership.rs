//! Realm membership management.
//!
//! Wire-shaped types are reused from `cokret-core`:
//! [`MembershipState`] (spec vocabulary `invite/join/knock/leave/ban`),
//! [`Invite`] (mirrors `invite.schema.json`) and [`ThirdPartyInvite`]
//! (3PID carrier — the plaintext address MUST NEVER appear on the wire).
//! Manager-only bookkeeping (granted role per invite, change log) stays in
//! [`MembershipManager`] private fields.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
pub use cokret_core::events::MembershipState;
pub use cokret_core::{INVITE_SCHEMA, Invite, InviteState, ThirdPartyInvite};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Did, Error, InviteId, Operation, OperationId, RealmId, Result};

/// Generate a new UUIDv7-based wire ID with the given Cokret typed prefix
/// (e.g. `ck:invite:`, `ck:operation:`). RFC 9562 §5.7 / `conformance/encoding.md` §4.
fn generate_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Default invite TTL used by [`MembershipManager::send_invite`].
///
/// `invite.schema.json` requires every invite to carry a hard `expires_at`;
/// callers that need a different window use
/// [`MembershipManager::send_invite_with_expiry`].
const DEFAULT_INVITE_TTL_DAYS: i64 = 7;

/// Validate a membership transition per `event-auth-state-resolution.md` §5.
///
/// `from = None` represents the "no prior membership" state (the spec calls
/// this `none`). The legal transition table covers:
///
/// - `none → {join, invite, knock}`
/// - `invite → {join, leave}`
/// - `knock → {invite, leave}`
/// - `join → {leave, ban}`
/// - `leave → {invite, knock}` (re-enter via fresh invite or knock)
/// - `ban → leave` (only via unban; reducer MUST emit `Leave` then a fresh invite for re-admission)
///
/// Same-state writes (e.g. `Join → Join`) are allowed as idempotent
/// no-ops; reducers may still emit a profile/role change without flipping
/// state. Anything else returns `false` and the reducer MUST reject the
/// event with `state_mismatch`.
pub fn is_legal_membership_transition(from: Option<MembershipState>, to: MembershipState) -> bool {
    use MembershipState::*;
    if Some(to) == from {
        return true;
    }
    matches!(
        (from, to),
        (None, Join)
            | (None, Invite)
            | (None, Knock)
            | (Some(Invite), Join)
            | (Some(Invite), Leave)
            | (Some(Knock), Invite)
            | (Some(Knock), Leave)
            | (Some(Join), Leave)
            | (Some(Join), Ban)
            | (Some(Leave), Invite)
            | (Some(Leave), Knock)
            | (Some(Ban), Leave)
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
    /// Avatar URL or media reference.
    pub avatar_url: Option<String>,
}

/// Membership entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Member actor DID.
    pub actor_id: Did,
    /// Current membership state.
    pub state: MembershipState,
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
    pub previous: Option<MembershipState>,
    /// New state.
    pub current: MembershipState,
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
        state: MembershipState,
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
        self.apply_transition(actor_id, MembershipState::Join)
    }

    /// Leave a joined Realm.
    pub fn leave(&mut self, actor_id: &Did) -> Result<()> {
        match self.members.get(actor_id).map(|member| member.state) {
            Some(MembershipState::Join) => {
                let member = self.members.get(actor_id).cloned().expect("member exists");
                self.upsert_member(
                    actor_id.clone(),
                    MembershipState::Leave,
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
        self.apply_transition(actor_id, MembershipState::Ban)
    }

    /// Unban a member, leaving them in `Leave` state.
    pub fn unban(&mut self, actor_id: &Did) -> Result<()> {
        match self.members.get(actor_id).map(|member| member.state) {
            Some(MembershipState::Ban) => {
                let member = self.members.get(actor_id).cloned().expect("member exists");
                self.upsert_member(
                    actor_id.clone(),
                    MembershipState::Leave,
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
        self.apply_transition(actor_id, MembershipState::Knock)
    }

    /// Apply a state transition, rejecting it via `state_mismatch` when the
    /// transition is illegal per `event-auth-state-resolution.md` §5.
    ///
    /// Convenience writers such as [`Self::join`] / [`Self::leave`] /
    /// [`Self::ban`] all route through this same canonical transition table.
    pub fn apply_transition(&mut self, actor_id: &Did, to: MembershipState) -> Result<()> {
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
            "ck.invite.create" | "ck.invite.cancel" => MemberRole::Moderator,
            "ck.invite.revoke" | "ck.realm.policy" => MemberRole::Admin,
            "ck.realm.destroy" => MemberRole::Owner,
            "ck.event.read" => MemberRole::Viewer,
            "ck.message.create" => MemberRole::Member,
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
            id: InviteId::new(generate_id("ck:invite:"))?,
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
            join_rule_snapshot: json!({}),
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
        self.upsert_member(actor_id, MembershipState::Invite, role, None);
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
            self.upsert_member(invitee, MembershipState::Leave, role, None);
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
                self.upsert_member(invitee, MembershipState::Leave, role, None);
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
        self.upsert_member(actor_id, MembershipState::Join, role, None);
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
            self.upsert_member(invitee, MembershipState::Leave, role, None);
        }
        Ok(())
    }

    /// Build a membership operation payload for submission.
    pub fn membership_operation(
        &self,
        actor_id: Did,
        target_did: Did,
        state: MembershipState,
    ) -> Result<Operation> {
        Ok(Operation::create(
            OperationId::new(generate_id("ck:operation:"))?,
            RealmId::new(self.realm_id.to_string())?,
            "membership",
            json!({
                "actor_id": actor_id.as_str(),
                "target_did": target_did.as_str(),
                "membership": state,
            }),
        ))
    }
}

// Track-scoped membership (`ck.strand.track.member` and
// `StrandTrackMembership` / `StrandTrackMembershipManager`) was REMOVED in
// cokret-spec revision `0a5ab85`. Track no longer carries independent
// membership; access semantics inherit from the Strand's Realm. Use
// `ck.member.state` at the Realm or child Realm level instead.
//
// See `cokret-spec/spec/v1/artifacts/registry/removed-event-kinds.json`.

#[cfg(test)]
mod tests {
    use cokret_core::ThirdPartyInviteOobKind;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
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
            verification_service_did: did("verifier"),
            verification_public_key: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned(),
        }
    }

    #[test]
    fn membership_transitions_cover_invite_join_leave_and_ban() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        manager.upsert_member(
            alice.clone(),
            MembershipState::Invite,
            MemberRole::Member,
            None,
        );
        manager.join(&alice).unwrap();
        assert_eq!(manager.member(&alice).unwrap().state, MembershipState::Join);

        manager.leave(&alice).unwrap();
        assert_eq!(
            manager.member(&alice).unwrap().state,
            MembershipState::Leave
        );

        assert!(manager.join(&alice).is_err());
        manager
            .send_invite(alice.clone(), alice.clone(), MemberRole::Member)
            .unwrap();
        manager.join(&alice).unwrap();
        manager.ban(&alice).unwrap();
        assert!(manager.join(&alice).is_err());
        manager.unban(&alice).unwrap();
        assert_eq!(
            manager.member(&alice).unwrap().state,
            MembershipState::Leave
        );
    }

    #[test]
    fn membership_checks_role_capabilities() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = MembershipManager::new(realm_id, alice.clone());
        manager.upsert_member(alice, MembershipState::Join, MemberRole::Admin, None);

        assert!(manager.current_user_can(MemberRole::Moderator));
        assert!(manager.has_capability("ck.realm.policy"));
        assert!(!manager.has_capability("ck.realm.destroy"));
    }

    #[test]
    fn membership_manages_member_list_profiles_and_changes() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice);

        manager.upsert_member(bob.clone(), MembershipState::Join, MemberRole::Member, None);
        manager
            .update_profile(
                &bob,
                MemberProfile {
                    display_name: Some("Bob".to_owned()),
                    avatar_url: None,
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
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(realm_id, alice.clone());

        let invite = manager
            .send_invite(bob.clone(), alice.clone(), MemberRole::Member)
            .unwrap();
        assert_eq!(invite.schema, INVITE_SCHEMA);
        manager.accept_invite(&invite.id, bob.clone()).unwrap();
        assert_eq!(manager.member(&bob).unwrap().state, MembershipState::Join);

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
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
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
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
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
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
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
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
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
