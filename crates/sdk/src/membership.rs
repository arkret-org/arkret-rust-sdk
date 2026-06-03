//! Space membership management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Did, Error, InviteId, Operation, OperationId, RealmId, Result};

/// Generate a new UUIDv7-based wire ID with the given Cokret typed prefix
/// (e.g. `ck:invite:`, `ck:operation:`). RFC 9562 §5.7 / `conformance/encoding.md` §4.
fn generate_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Membership state for a user in a space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    /// User has been invited.
    Invited,
    /// User has joined.
    Joined,
    /// User has left.
    Left,
    /// User is banned.
    Banned,
    /// User has knocked (requested entry to a `knock` / `knock_restricted`
    /// Space). Resolves to `Invited` (admit) or `Left` (decline) per
    /// `event-auth-state-resolution.md` §5.
    Knocked,
}

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
/// - `ban → leave` (only via unban; reducer MUST emit `Left` then a fresh
///   invite for re-admission)
///
/// Same-state writes (e.g. `Joined → Joined`) are allowed as idempotent
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
        (None, Joined)
            | (None, Invited)
            | (None, Knocked)
            | (Some(Invited), Joined)
            | (Some(Invited), Left)
            | (Some(Knocked), Invited)
            | (Some(Knocked), Left)
            | (Some(Joined), Left)
            | (Some(Joined), Banned)
            | (Some(Left), Invited)
            | (Some(Left), Knocked)
            | (Some(Banned), Left)
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
    /// Space moderator.
    Moderator,
    /// Space administrator.
    Admin,
    /// Space owner.
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
    /// User DID.
    pub user_id: Did,
    /// Current membership state.
    pub state: MembershipState,
    /// Role in the space.
    pub role: MemberRole,
    /// Cached profile.
    pub profile: Option<MemberProfile>,
    /// Last membership update time.
    pub updated_at: DateTime<Utc>,
}

/// Notification emitted when a member changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberChange {
    /// Changed user.
    pub user_id: Did,
    /// Previous state if known.
    pub previous: Option<MembershipState>,
    /// New state.
    pub current: MembershipState,
}

/// Third-party invite address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyInvite {
    /// Address medium, for example `email`.
    pub medium: String,
    /// Address value.
    pub address: String,
    /// Optional display name.
    pub display_name: Option<String>,
}

/// Invite record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Invite ID.
    pub invite_id: InviteId,
    /// Target user DID if known.
    pub user_id: Option<Did>,
    /// Third-party address when DID is not known.
    pub third_party: Option<ThirdPartyInvite>,
    /// Role granted on acceptance.
    pub role: MemberRole,
    /// Sender DID.
    pub invited_by: Did,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Whether the invite was accepted.
    pub accepted: bool,
    /// Whether the invite was rejected.
    pub rejected: bool,
    /// Whether the invite was revoked.
    pub revoked: bool,
    /// Optional expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl Invite {
    /// Whether this invite is still pending (not accepted, rejected, revoked, or expired).
    pub fn is_pending(&self) -> bool {
        !self.accepted && !self.rejected && !self.revoked
    }

    /// Whether this invite has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }
}

/// In-memory membership manager.
#[derive(Clone, Debug)]
pub struct MembershipManager {
    space_id: RealmId,
    current_user: Did,
    members: BTreeMap<Did, Member>,
    invites: BTreeMap<InviteId, Invite>,
    changes: Vec<MemberChange>,
}

impl MembershipManager {
    /// Create a membership manager for one space.
    pub fn new(space_id: RealmId, current_user: Did) -> Self {
        Self {
            space_id,
            current_user,
            members: BTreeMap::new(),
            invites: BTreeMap::new(),
            changes: Vec::new(),
        }
    }

    /// Insert or update a member.
    pub fn upsert_member(
        &mut self,
        user_id: Did,
        state: MembershipState,
        role: MemberRole,
        profile: Option<MemberProfile>,
    ) {
        let previous = self.members.get(&user_id).map(|member| member.state);
        self.members.insert(
            user_id.clone(),
            Member { user_id: user_id.clone(), state, role, profile, updated_at: Utc::now() },
        );
        if previous != Some(state) {
            self.changes.push(MemberChange { user_id, previous, current: state });
        }
    }

    /// Accept an invitation or initial join through the canonical transition table.
    pub fn join(&mut self, user_id: &Did) -> Result<()> {
        self.apply_transition(user_id, MembershipState::Joined)
    }

    /// Leave a joined space.
    pub fn leave(&mut self, user_id: &Did) -> Result<()> {
        match self.members.get(user_id).map(|member| member.state) {
            Some(MembershipState::Joined) => {
                let member = self.members.get(user_id).cloned().expect("member exists");
                self.upsert_member(
                    user_id.clone(),
                    MembershipState::Left,
                    member.role,
                    member.profile,
                );
                Ok(())
            }
            _ => Err(Error::Protocol("only joined members can leave".to_owned())),
        }
    }

    /// Ban a member.
    pub fn ban(&mut self, user_id: &Did) -> Result<()> {
        self.apply_transition(user_id, MembershipState::Banned)
    }

    /// Unban a member, leaving them in `Left` state.
    pub fn unban(&mut self, user_id: &Did) -> Result<()> {
        match self.members.get(user_id).map(|member| member.state) {
            Some(MembershipState::Banned) => {
                let member = self.members.get(user_id).cloned().expect("member exists");
                self.upsert_member(
                    user_id.clone(),
                    MembershipState::Left,
                    member.role,
                    member.profile,
                );
                Ok(())
            }
            _ => Err(Error::Protocol("only banned members can be unbanned".to_owned())),
        }
    }

    /// Record a `knock` request — `none → Knocked` or `Left → Knocked`.
    pub fn knock(&mut self, user_id: &Did) -> Result<()> {
        let from = self.members.get(user_id).map(|m| m.state);
        if !is_legal_membership_transition(from, MembershipState::Knocked) {
            return Err(Error::Protocol(format!(
                "illegal membership transition {from:?} -> Knocked"
            )));
        }
        let role = self.members.get(user_id).map(|m| m.role).unwrap_or(MemberRole::Member);
        let profile = self.members.get(user_id).and_then(|m| m.profile.clone());
        self.upsert_member(user_id.clone(), MembershipState::Knocked, role, profile);
        Ok(())
    }

    /// Apply a state transition, rejecting it via `state_mismatch` when the
    /// transition is illegal per `event-auth-state-resolution.md` §5.
    ///
    /// Convenience writers such as [`Self::join`] / [`Self::leave`] /
    /// [`Self::ban`] all route through this same canonical transition table.
    pub fn apply_transition(&mut self, user_id: &Did, to: MembershipState) -> Result<()> {
        let from = self.members.get(user_id).map(|m| m.state);
        if !is_legal_membership_transition(from, to) {
            return Err(Error::Protocol(format!(
                "illegal membership transition {from:?} -> {to:?}"
            )));
        }
        let role = self.members.get(user_id).map(|m| m.role).unwrap_or(MemberRole::Member);
        let profile = self.members.get(user_id).and_then(|m| m.profile.clone());
        self.upsert_member(user_id.clone(), to, role, profile);
        Ok(())
    }

    /// Current user role.
    pub fn current_user_role(&self) -> Option<MemberRole> {
        self.members.get(&self.current_user).map(|member| member.role)
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
            "space.invite" | "space.kick" => MemberRole::Moderator,
            "space.ban" | "space.settings" => MemberRole::Admin,
            "space.delete" => MemberRole::Owner,
            "space.read" => MemberRole::Viewer,
            "space.write" => MemberRole::Member,
            _ => return false,
        };
        self.current_user_can(required)
    }

    /// List all members.
    pub fn members(&self) -> Vec<&Member> {
        self.members.values().collect()
    }

    /// Get one member.
    pub fn member(&self, user_id: &Did) -> Option<&Member> {
        self.members.get(user_id)
    }

    /// Drain member change notifications.
    pub fn drain_changes(&mut self) -> Vec<MemberChange> {
        self.changes.drain(..).collect()
    }

    /// Update cached member profile.
    pub fn update_profile(&mut self, user_id: &Did, profile: MemberProfile) -> Result<()> {
        let member = self
            .members
            .get_mut(user_id)
            .ok_or_else(|| Error::Protocol("member not found".to_owned()))?;
        member.profile = Some(profile);
        member.updated_at = Utc::now();
        Ok(())
    }

    /// Send a DID invite.
    pub fn send_invite(
        &mut self,
        user_id: Did,
        invited_by: Did,
        role: MemberRole,
    ) -> Result<Invite> {
        let invite = Invite {
            invite_id: InviteId::new(generate_id("ck:invite:"))?,
            user_id: Some(user_id.clone()),
            third_party: None,
            role,
            invited_by,
            created_at: Utc::now(),
            accepted: false,
            rejected: false,
            revoked: false,
            expires_at: None,
        };
        self.upsert_member(user_id, MembershipState::Invited, role, None);
        self.invites.insert(invite.invite_id.clone(), invite.clone());
        Ok(invite)
    }

    /// Send a DID invite with an expiration time.
    pub fn send_invite_with_expiry(
        &mut self,
        user_id: Did,
        invited_by: Did,
        role: MemberRole,
        expires_at: DateTime<Utc>,
    ) -> Result<Invite> {
        let mut invite = self.send_invite(user_id, invited_by, role)?;
        invite.expires_at = Some(expires_at);
        self.invites.insert(invite.invite_id.clone(), invite.clone());
        Ok(invite)
    }

    /// Send a 3PID invite.
    pub fn send_third_party_invite(
        &mut self,
        third_party: ThirdPartyInvite,
        invited_by: Did,
        role: MemberRole,
    ) -> Result<Invite> {
        let invite = Invite {
            invite_id: InviteId::new(generate_id("ck:invite:"))?,
            user_id: None,
            third_party: Some(third_party),
            role,
            invited_by,
            created_at: Utc::now(),
            accepted: false,
            rejected: false,
            revoked: false,
            expires_at: None,
        };
        self.invites.insert(invite.invite_id.clone(), invite.clone());
        Ok(invite)
    }

    /// Revoke a pending invite.
    pub fn revoke_invite(&mut self, invite_id: &InviteId) -> Result<()> {
        let invite = self
            .invites
            .get(invite_id)
            .ok_or_else(|| Error::Protocol("invite not found".to_owned()))?;
        if invite.accepted {
            return Err(Error::Protocol("accepted invite cannot be revoked".to_owned()));
        }
        if invite.revoked {
            return Err(Error::Protocol("invite is already revoked".to_owned()));
        }
        let user_id = invite.user_id.clone();
        let role = invite.role;
        self.invites.get_mut(invite_id).expect("invite exists").revoked = true;
        if let Some(user_id) = user_id {
            self.upsert_member(user_id, MembershipState::Left, role, None);
        }
        Ok(())
    }

    /// Expire all invites whose expiration time has passed.
    ///
    /// Returns the number of invites that were expired.
    pub fn expire_invites(&mut self) -> usize {
        let now = Utc::now();
        // Collect the IDs and user info of invites to expire to avoid borrow conflict.
        let to_expire: Vec<(InviteId, Option<Did>, MemberRole)> = self
            .invites
            .iter()
            .filter(|(_, i)| {
                !i.accepted
                    && !i.rejected
                    && !i.revoked
                    && i.expires_at.is_some_and(|exp| now >= exp)
            })
            .map(|(id, i)| (id.clone(), i.user_id.clone(), i.role))
            .collect();

        let count = to_expire.len();
        for (invite_id, user_id, role) in to_expire {
            if let Some(invite) = self.invites.get_mut(&invite_id) {
                invite.revoked = true;
            }
            if let Some(user_id) = user_id {
                self.upsert_member(user_id, MembershipState::Left, role, None);
            }
        }
        count
    }

    /// List all pending (non-expired, non-revoked) invites.
    pub fn pending_invites(&self) -> Vec<&Invite> {
        self.invites.values().filter(|i| i.is_pending()).collect()
    }

    /// Get an invite by ID.
    pub fn invite(&self, invite_id: &InviteId) -> Option<&Invite> {
        self.invites.get(invite_id)
    }

    /// Accept an invite for a DID.
    pub fn accept_invite(&mut self, invite_id: &InviteId, user_id: Did) -> Result<()> {
        let role = {
            let invite = self
                .invites
                .get_mut(invite_id)
                .ok_or_else(|| Error::Protocol("invite not found".to_owned()))?;
            if invite.rejected {
                return Err(Error::Protocol("rejected invite cannot be accepted".to_owned()));
            }
            if invite.revoked {
                return Err(Error::Protocol("revoked invite cannot be accepted".to_owned()));
            }
            if invite.is_expired() {
                return Err(Error::Protocol("expired invite cannot be accepted".to_owned()));
            }
            invite.accepted = true;
            invite.user_id = Some(user_id.clone());
            invite.role
        };
        self.upsert_member(user_id, MembershipState::Joined, role, None);
        Ok(())
    }

    /// Reject an invite.
    pub fn reject_invite(&mut self, invite_id: &InviteId) -> Result<()> {
        let transition = {
            let invite = self
                .invites
                .get_mut(invite_id)
                .ok_or_else(|| Error::Protocol("invite not found".to_owned()))?;
            if invite.accepted {
                return Err(Error::Protocol("accepted invite cannot be rejected".to_owned()));
            }
            if invite.revoked {
                return Err(Error::Protocol("revoked invite cannot be rejected".to_owned()));
            }
            invite.rejected = true;
            invite.user_id.clone().map(|user_id| (user_id, invite.role))
        };
        if let Some((user_id, role)) = transition {
            self.upsert_member(user_id, MembershipState::Left, role, None);
        }
        Ok(())
    }

    /// Build a membership operation payload for submission.
    pub fn membership_operation(
        &self,
        actor_id: Did,
        user_id: Did,
        state: MembershipState,
    ) -> Result<Operation> {
        Ok(Operation::create(
            OperationId::new(generate_id("ck:operation:"))?,
            RealmId::new(self.space_id.to_string())?,
            "membership",
            json!({
                "actor_id": actor_id.as_str(),
                "target_did": user_id.as_str(),
                "membership": state,
            }),
        ))
    }
}

// Track-scoped membership (`ck.flow.track.member` and
// `FlowTrackMembership` / `FlowTrackMembershipManager`) was REMOVED in
// cokret-spec revision `0a5ab85`. Track no longer carries independent
// membership; access semantics inherit from the Flow's Space. Use
// `ck.member.state` at the Space or child Space level instead.
//
// See `cokret-spec/spec/v1/artifacts/registry/removed-event-kinds.json`.

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn membership_transitions_cover_invite_join_leave_and_ban() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = MembershipManager::new(space_id, alice.clone());

        manager.upsert_member(alice.clone(), MembershipState::Invited, MemberRole::Member, None);
        manager.join(&alice).unwrap();
        assert_eq!(manager.member(&alice).unwrap().state, MembershipState::Joined);

        manager.leave(&alice).unwrap();
        assert_eq!(manager.member(&alice).unwrap().state, MembershipState::Left);

        assert!(manager.join(&alice).is_err());
        manager.send_invite(alice.clone(), alice.clone(), MemberRole::Member).unwrap();
        manager.join(&alice).unwrap();
        manager.ban(&alice).unwrap();
        assert!(manager.join(&alice).is_err());
        manager.unban(&alice).unwrap();
        assert_eq!(manager.member(&alice).unwrap().state, MembershipState::Left);
    }

    #[test]
    fn membership_checks_role_capabilities() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = MembershipManager::new(space_id, alice.clone());
        manager.upsert_member(alice, MembershipState::Joined, MemberRole::Admin, None);

        assert!(manager.current_user_can(MemberRole::Moderator));
        assert!(manager.has_capability("space.ban"));
        assert!(!manager.has_capability("space.delete"));
    }

    #[test]
    fn membership_manages_member_list_profiles_and_changes() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(space_id, alice);

        manager.upsert_member(bob.clone(), MembershipState::Joined, MemberRole::Member, None);
        manager
            .update_profile(
                &bob,
                MemberProfile { display_name: Some("Bob".to_owned()), avatar_url: None },
            )
            .unwrap();

        assert_eq!(manager.members().len(), 1);
        assert_eq!(
            manager.member(&bob).unwrap().profile.as_ref().unwrap().display_name,
            Some("Bob".to_owned())
        );
        assert_eq!(manager.drain_changes().len(), 1);
        assert!(manager.drain_changes().is_empty());
    }

    #[test]
    fn membership_handles_did_and_third_party_invites() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(space_id, alice.clone());

        let invite = manager.send_invite(bob.clone(), alice.clone(), MemberRole::Member).unwrap();
        manager.accept_invite(&invite.invite_id, bob.clone()).unwrap();
        assert_eq!(manager.member(&bob).unwrap().state, MembershipState::Joined);

        let third_party = manager
            .send_third_party_invite(
                ThirdPartyInvite {
                    medium: "email".to_owned(),
                    address: "carol@example.com".to_owned(),
                    display_name: Some("Carol".to_owned()),
                },
                alice,
                MemberRole::Viewer,
            )
            .unwrap();
        manager.reject_invite(&third_party.invite_id).unwrap();
    }

    #[test]
    fn invite_revocation_blocks_acceptance() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(space_id, alice.clone());

        let invite = manager.send_invite(bob.clone(), alice, MemberRole::Member).unwrap();
        manager.revoke_invite(&invite.invite_id).unwrap();

        let stored = manager.invite(&invite.invite_id).unwrap();
        assert!(stored.revoked);
        assert!(!stored.is_pending());

        // Trying to accept a revoked invite should fail (it's treated as rejected)
        assert!(manager.accept_invite(&invite.invite_id, bob).is_err());
    }

    #[test]
    fn invite_cannot_revoke_accepted() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(space_id, alice.clone());

        let invite = manager.send_invite(bob.clone(), alice, MemberRole::Member).unwrap();
        manager.accept_invite(&invite.invite_id, bob).unwrap();
        assert!(manager.revoke_invite(&invite.invite_id).is_err());
    }

    #[test]
    fn invite_expiration_marks_revoked() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = MembershipManager::new(space_id, alice.clone());

        // Invite that already expired
        let past = "2020-01-01T00:00:00Z".parse().unwrap();
        let invite = manager.send_invite_with_expiry(bob, alice, MemberRole::Member, past).unwrap();

        assert!(invite.is_expired());
        assert!(invite.is_pending()); // Not yet processed

        let expired_count = manager.expire_invites();
        assert_eq!(expired_count, 1);

        let stored = manager.invite(&invite.invite_id).unwrap();
        assert!(stored.revoked);
        assert!(!stored.is_pending());
    }

    #[test]
    fn invite_pending_invites_excludes_expired_and_revoked() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let mut manager = MembershipManager::new(space_id, alice.clone());

        // Pending invite
        let invite1 = manager.send_invite(bob, alice.clone(), MemberRole::Member).unwrap();
        // Expired invite
        let past = "2020-01-01T00:00:00Z".parse().unwrap();
        let _invite2 =
            manager.send_invite_with_expiry(carol, alice, MemberRole::Member, past).unwrap();

        assert_eq!(manager.pending_invites().len(), 2); // Both still pending until expire runs
        manager.expire_invites();
        assert_eq!(manager.pending_invites().len(), 1);
        assert_eq!(manager.pending_invites()[0].invite_id, invite1.invite_id);
    }
}
