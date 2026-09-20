//! Capability aggregate queries for the compiled current profile.
//!
//! Runtime authorization is selected by the Realm profile. Registry JSON is a
//! build-time input only and never participates in a signed authority basis.

use arkret_wire::CapabilityActionId;

use crate::{Result, WireError};

/// True when `holder_action` directly authorizes authoring every durable Event
/// kind that `child_action` targets.
pub fn action_covers_event_kinds(holder_action: &str, child_action: &str) -> Result<bool> {
    if holder_action == child_action {
        return Ok(true);
    }
    let holder = descriptor(holder_action)?;
    let child = descriptor(child_action)?;
    if child.target_event_kinds.is_empty() {
        return Ok(false);
    }
    Ok(child
        .target_event_kinds
        .iter()
        .all(|kind| holder.target_event_kinds.contains(kind)))
}

/// True when `holder_action` authorizes signing a grant for `child_action`.
pub fn action_grants_authority_for(holder_action: &str, child_action: &str) -> Result<bool> {
    if holder_action == child_action {
        return Ok(true);
    }
    let holder = descriptor(holder_action)?;
    Ok(holder.grant_authority_actions.contains(&child_action))
}

/// True when the compiled Realm-owner role may sign a grant for `child_action`.
pub fn owner_may_grant(child_action: &str) -> Result<bool> {
    let child = descriptor(child_action)?;
    if owner_role_must_not_cover(child) {
        return Ok(false);
    }
    action_grants_authority_for(CapabilityActionId::REALM_OWNER, child_action)
}

/// True when the compiled Realm-owner role may author `event_kind`.
pub fn owner_may_author_event_kind(event_kind: &str) -> Result<bool> {
    let owner = descriptor(CapabilityActionId::REALM_OWNER)?;
    Ok(owner.target_event_kinds.contains(&event_kind))
}

/// True when the compiled Realm-owner role covers the durable Events represented
/// by `child_action`. Non-event surfaces are not accepted through this helper.
pub fn owner_may_author_action(child_action: &str) -> Result<bool> {
    let child = descriptor(child_action)?;
    if owner_role_must_not_cover(child) {
        return Ok(false);
    }
    action_covers_event_kinds(CapabilityActionId::REALM_OWNER, child_action)
}

/// Structural boundary: a Realm role can never cross into root or
/// subject/personal authority even if generated aggregate rows are
/// accidentally widened. This predicate is compiled into the profile code and
/// is evaluated before either direct Event coverage or grant-authority sets.
fn owner_role_must_not_cover(action: &arkret_schema::CapabilityActionDescriptor) -> bool {
    action.root_control_only
        || action.subject_only
        || action.category == "personal"
        || action.action.as_str().starts_with("ak.self.")
}

fn descriptor(action: &str) -> Result<&'static arkret_schema::CapabilityActionDescriptor> {
    arkret_schema::capability_action(action).ok_or_else(|| {
        WireError::Protocol(format!(
            "schema_violation: capability action '{action}' is not registered"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_covers_core_events_but_not_non_event_actions() {
        assert!(owner_may_author_action("ak.strand.create").unwrap());
        assert!(owner_may_author_event_kind("ak.message.create").unwrap());
        assert!(!owner_may_author_action("ak.audit.export").unwrap());
    }

    #[test]
    fn owner_grant_surface_uses_the_compiled_exact_action_set() {
        assert!(owner_may_grant("ak.audit.export").unwrap());
        assert!(owner_may_grant("ak.strand.create").unwrap());
        assert!(owner_may_grant(CapabilityActionId::REALM_OWNER).unwrap());
        assert!(!owner_may_grant("ak.realm.destroy").unwrap());
        assert!(!owner_may_grant("ak.realm.tombstone").unwrap());
        assert!(!owner_may_grant("ak.agent.sidecar.write").unwrap());
        assert!(owner_may_grant("ak.rsvp.set").unwrap());
    }

    #[test]
    fn owner_role_hard_denies_root_subject_personal_and_unknown_semantics() {
        for action in [
            "ak.realm.destroy",
            "ak.capability.relinquish",
            "ak.invite.accept",
            "ak.read_cursor.advance",
            "ak.self.committed_event.read.scan.v1",
        ] {
            assert!(!owner_may_author_action(action).unwrap(), "{action}");
            assert!(!owner_may_grant(action).unwrap(), "{action}");
        }

        assert!(owner_may_author_action("ak.unknown.future").is_err());
        assert!(owner_may_grant("ak.unknown.future").is_err());
    }

    #[test]
    fn event_coverage_does_not_confer_grant_authority() {
        assert!(
            action_covers_event_kinds(CapabilityActionId::REALM_OWNER, "ak.agent.sidecar.write")
                .unwrap()
        );
        assert!(
            !action_grants_authority_for(CapabilityActionId::REALM_OWNER, "ak.agent.sidecar.write")
                .unwrap()
        );
    }

    #[test]
    fn realm_admin_still_cannot_reach_strand_create() {
        assert!(!action_covers_event_kinds("ak.realm.admin", "ak.strand.create").unwrap());
        assert!(!action_grants_authority_for("ak.realm.admin", "ak.strand.create").unwrap());
    }
}
