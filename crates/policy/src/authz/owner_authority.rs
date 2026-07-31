//! The two capability-aggregate questions, kept apart on purpose.
//!
//! `capabilities.md` section 3.2 asks two different things of an aggregate
//! action and they have different namespaces:
//!
//! - **Operational coverage** — may the holder directly author this durable Event? Answered over
//!   `target_event_kinds`.
//! - **Grant authority** — may the holder sign a grant *for* this action? Answered over
//!   `grant_authority_actions`, by action id.
//!
//! Several actions map to one event kind (`ak.agent.sidecar.write` and
//! `ak.message.create` both target `ak.message.create`), so answering the
//! second question with the first one's data hands a profile-gated action to
//! anyone holding the core one. Both helpers live here, in the single SDK
//! implementation, so a service cannot grow its own divergent copy.

use arkret_wire::Hash;

use crate::{Error, Result};

/// The Realm-wide owner aggregate. Held either by the current controller of the
/// Realm authority-root cell or by an ordinary revocable co-owner grant.
pub const REALM_OWNER_ACTION: &str = "ak.realm.owner";

/// Resolve the registry basis an expansion is anchored to.
///
/// A grant or authority-root cell names the snapshot it was signed against.
/// Expanding under any other snapshot would silently re-interpret a historical
/// signature, so an unknown basis fails closed instead of falling back to the
/// receiver's own registry.
pub fn require_registry_basis(basis: Option<&Hash>) -> Result<()> {
    let Some(basis) = basis else {
        return Err(Error::Protocol(
            "capability_registry_basis_unavailable: aggregate expansion requires a registry basis"
                .to_owned(),
        ));
    };
    let current = super::current_capability_action_registry_digest()?;
    if basis != &current {
        return Err(Error::Protocol(
            "capability_registry_basis_unavailable: registry snapshot is unknown or unavailable"
                .to_owned(),
        ));
    }
    Ok(())
}

/// True when `holder_action` directly authorizes authoring every durable Event
/// kind that `child_action` targets.
///
/// Use for Event admission only. Never for "may this issuer sign a grant for
/// `child_action`".
pub fn action_covers_event_kinds(holder_action: &str, child_action: &str) -> Result<bool> {
    if holder_action == child_action {
        return Ok(true);
    }
    let holder = descriptor(holder_action)?;
    let child = descriptor(child_action)?;
    // An empty child coverage set is a subset of everything. Without this guard
    // every non-event action would be "covered" by every aggregate.
    if child.target_event_kinds.is_empty() {
        return Ok(false);
    }
    Ok(child
        .target_event_kinds
        .iter()
        .all(|kind| holder.target_event_kinds.contains(kind)))
}

/// True when `holder_action` authorizes signing a grant for `child_action`.
///
/// Matching is by action id against the rule-derived `grant_authority_actions`
/// set. Event-kind containment MUST NOT be substituted here.
pub fn action_grants_authority_for(holder_action: &str, child_action: &str) -> Result<bool> {
    if holder_action == child_action {
        return Ok(true);
    }
    let holder = descriptor(holder_action)?;
    Ok(holder
        .grant_authority_actions
        .iter()
        .any(|action| *action == child_action))
}

/// True when the Realm owner aggregate may sign a grant for `child_action`
/// under the given registry basis.
///
/// `active_profiles` supplies the profile ids the Realm has declared in its
/// `schema_refs`. A profile-gated action is owner-grantable exactly when its
/// profile is declared — the declaration is the whole condition, there is no
/// second per-action whitelist — and a grantable action still has to pass
/// that profile's own registration / constraint / evidence gates downstream.
pub fn owner_may_grant(
    child_action: &str,
    registry_basis: Option<&Hash>,
    active_profiles: &[String],
) -> Result<bool> {
    require_registry_basis(registry_basis)?;
    let child = descriptor(child_action)?;
    if child.root_control_only || child.subject_only || child.reducer_only {
        return Ok(false);
    }
    if let Some(profile) = child.profile {
        return Ok(active_profiles.iter().any(|active| active == profile));
    }
    action_grants_authority_for(REALM_OWNER_ACTION, child_action)
}

/// True when the Realm owner aggregate directly authorizes authoring
/// `event_kind` under the given registry basis.
pub fn owner_may_author_event_kind(
    event_kind: &str,
    registry_basis: Option<&Hash>,
) -> Result<bool> {
    require_registry_basis(registry_basis)?;
    Ok(descriptor(REALM_OWNER_ACTION)?
        .target_event_kinds
        .contains(&event_kind))
}

fn descriptor(action: &str) -> Result<&'static arkret_schema::CapabilityActionDescriptor> {
    arkret_schema::capability_action(action).ok_or_else(|| {
        Error::Protocol(format!(
            "schema_violation: capability action '{action}' is not registered"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> Hash {
        super::super::current_capability_action_registry_digest().unwrap()
    }

    #[test]
    fn owner_covers_strand_create_but_not_non_event_actions() {
        assert!(action_covers_event_kinds(REALM_OWNER_ACTION, "ak.strand.create").unwrap());
        // ak.audit.export is a non-event surface: an empty coverage set must
        // never be satisfied by an aggregate.
        assert!(!action_covers_event_kinds(REALM_OWNER_ACTION, "ak.audit.export").unwrap());
    }

    #[test]
    fn owner_may_grant_core_non_event_and_key_share() {
        let basis = basis();
        assert!(owner_may_grant("ak.audit.export", Some(&basis), &[]).unwrap());
        assert!(owner_may_grant("ak.realm_key.share", Some(&basis), &[]).unwrap());
        assert!(owner_may_grant("ak.strand.create", Some(&basis), &[]).unwrap());
        // Owner is self-grantable: that is how a co-owner is appointed.
        assert!(owner_may_grant(REALM_OWNER_ACTION, Some(&basis), &[]).unwrap());
    }

    #[test]
    fn owner_may_not_grant_root_control_or_reducer_only_actions() {
        let basis = basis();
        assert!(!owner_may_grant("ak.realm.destroy", Some(&basis), &[]).unwrap());
        assert!(!owner_may_grant("ak.realm.tombstone", Some(&basis), &[]).unwrap());
        assert!(!owner_may_grant("ak.capability.derived", Some(&basis), &[]).unwrap());
        // ...and they are outside operational coverage too.
        assert!(!action_covers_event_kinds(REALM_OWNER_ACTION, "ak.realm.destroy").unwrap());
    }

    #[test]
    fn profile_actions_need_their_profile_declared() {
        let basis = basis();
        assert!(!owner_may_grant("ak.agent.sidecar.write", Some(&basis), &[]).unwrap());
        let declared = vec!["ak.profile.agent_sidecar.v1".to_owned()];
        assert!(owner_may_grant("ak.agent.sidecar.write", Some(&basis), &declared).unwrap());
        // Declaring an unrelated profile grants nothing.
        let unrelated = vec!["ak.profile.calendar_event.v1".to_owned()];
        assert!(!owner_may_grant("ak.agent.sidecar.write", Some(&basis), &unrelated).unwrap());
    }

    #[test]
    fn same_target_event_kind_does_not_confer_grant_authority() {
        // Both map to ak.message.create, but only the core action is in the
        // owner grant-authority set.
        assert!(action_covers_event_kinds(REALM_OWNER_ACTION, "ak.agent.sidecar.write").unwrap());
        assert!(
            !action_grants_authority_for(REALM_OWNER_ACTION, "ak.agent.sidecar.write").unwrap()
        );
    }

    #[test]
    fn expansion_without_a_known_registry_basis_fails_closed() {
        assert!(owner_may_grant("ak.strand.create", None, &[]).is_err());
        let unknown = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert!(owner_may_grant("ak.strand.create", Some(&unknown), &[]).is_err());
    }

    #[test]
    fn realm_admin_still_cannot_reach_strand_create() {
        assert!(!action_covers_event_kinds("ak.realm.admin", "ak.strand.create").unwrap());
        assert!(!action_grants_authority_for("ak.realm.admin", "ak.strand.create").unwrap());
    }
}
