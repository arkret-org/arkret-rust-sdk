//! Cross-registry referential integrity for the generated conformance-profile
//! requirement table.
//!
//! `arkret-spec/tools/artifact_lint/schemas.py` already checks these references
//! inside `conformance-profiles.json`. This test is the SDK-side counterpart:
//! the requirement table and the id registries come out of *different*
//! generators, so a partially-run or stale sync can leave the table pointing at
//! an operation / schema / event kind / capability action / profile that the
//! enum registries no longer declare. Every entry here must resolve, which is
//! what typing the table's `&'static str` payloads as registry constants would
//! have bought — without making one generator depend on another's identifier
//! naming rules.
//!
//! Not covered, deliberately: `required_features`, `required_fixtures`,
//! `required_cell_namespaces`, `required_cells` and `required_constraint_kinds`
//! have no closed registry to resolve against.

use arkret_wire::generated::profile_requirements::PROFILE_REQUIREMENTS;
use arkret_wire::{CapabilityActionId, EventKind, ProfileId, SchemaId, ServiceOperationId};

/// `schemas.py` exempts `wire_scope:` pseudo-kinds from the event-kind registry
/// check; they name a wire scope, not a registered `Event.kind`.
const WIRE_SCOPE_PREFIX: &str = "wire_scope:";

fn assert_event_kind(profile_id: &str, field: &str, kind: &str) {
    if kind.starts_with(WIRE_SCOPE_PREFIX) {
        return;
    }
    assert!(
        EventKind::try_new(kind).is_some(),
        "{profile_id}.{field} references unregistered event kind: {kind}"
    );
}

#[test]
fn every_profile_key_matches_its_entry_and_resolves_to_a_registered_profile_id() {
    for (key, requirements) in PROFILE_REQUIREMENTS.iter() {
        assert_eq!(
            *key, requirements.profile_id,
            "profile table key {key} disagrees with its entry's profile_id"
        );
        assert!(
            ProfileId::from_wire(key).is_some(),
            "profile table key is not a registered ProfileId: {key}"
        );
    }
}

#[test]
fn inherited_profiles_are_registered_and_present_in_the_table() {
    for (profile_id, requirements) in PROFILE_REQUIREMENTS.iter() {
        for inherited in requirements.inherits {
            assert!(
                ProfileId::from_wire(inherited).is_some(),
                "{profile_id}.inherits references unregistered profile: {inherited}"
            );
            assert!(
                PROFILE_REQUIREMENTS.contains_key(inherited),
                "{profile_id}.inherits references a profile with no requirement entry: {inherited}"
            );
        }
    }
}

#[test]
fn required_operations_resolve_to_registered_operation_ids() {
    for (profile_id, requirements) in PROFILE_REQUIREMENTS.iter() {
        for operation in requirements.required_operations {
            assert!(
                ServiceOperationId::from_wire(operation).is_some(),
                "{profile_id}.required_operations references unregistered operation: {operation}"
            );
        }
    }
}

#[test]
fn required_schemas_resolve_to_registered_schema_ids() {
    for (profile_id, requirements) in PROFILE_REQUIREMENTS.iter() {
        for schema in requirements.required_schemas {
            assert!(
                SchemaId::from_wire(schema).is_some(),
                "{profile_id}.required_schemas references unregistered schema: {schema}"
            );
        }
    }
}

#[test]
fn required_capability_actions_resolve_to_registered_actions() {
    for (profile_id, requirements) in PROFILE_REQUIREMENTS.iter() {
        for action in requirements.required_capability_actions {
            assert!(
                CapabilityActionId::from_wire(action).is_some(),
                "{profile_id}.required_capability_actions references unregistered action: {action}"
            );
        }
    }
}

#[test]
fn required_and_rejected_event_kinds_resolve_to_registered_kinds() {
    for (profile_id, requirements) in PROFILE_REQUIREMENTS.iter() {
        for kind in requirements.required_event_kinds {
            assert_event_kind(profile_id, "required_event_kinds", kind);
        }
        for kind in requirements.rejected_event_kinds {
            assert_event_kind(profile_id, "rejected_event_kinds", kind);
        }
    }
}

#[test]
fn non_event_grant_authority_rules_resolve_across_registries() {
    for (profile_id, requirements) in PROFILE_REQUIREMENTS.iter() {
        for rule in requirements.non_event_grant_authority_rules {
            assert!(
                CapabilityActionId::from_wire(rule.issuer_action).is_some(),
                "{profile_id} grant rule issuer_action is unregistered: {}",
                rule.issuer_action
            );
            assert!(
                CapabilityActionId::from_wire(rule.grantable_action).is_some(),
                "{profile_id} grant rule grantable_action is unregistered: {}",
                rule.grantable_action
            );
            assert_event_kind(
                profile_id,
                "non_event_grant_authority_rules.required_registration_event_kind",
                rule.required_registration_event_kind,
            );
            assert!(
                ProfileId::from_wire(rule.required_claimed_profile).is_some(),
                "{profile_id} grant rule required_claimed_profile is unregistered: {}",
                rule.required_claimed_profile
            );
        }
    }
}
