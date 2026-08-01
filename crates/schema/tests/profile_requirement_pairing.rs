//! Pins the status pairing in `ArtifactDriftReport::profile_requirement_issues`.
//!
//! The SDK generates the **active** registry surface, so comparing every profile
//! requirement against the generated constants reported one false positive:
//! `ak.profile.candidate.join_policy.v1` is a `candidate` profile requiring the
//! schema registry's only `candidate` row, and neither side is drifting.
//!
//! Relaxing a gate is the failure mode this drift report exists to prevent, so
//! the exemption is pinned here by injection: each case below builds a bundle
//! that differs from the exempt one in exactly one status, and asserts the gate
//! still fires. A bug that widened the exemption into "ignore anything the SDK
//! did not generate" fails these tests rather than passing quietly.
//!
//! The bundles are synthetic rather than loaded from `arkret-spec`, so the
//! matrix stays complete even for combinations the live spec does not currently
//! contain, and the test needs no co-checkout.

use arkret_schema::{REGISTERED_SCHEMA_IDS, SpecArtifactBundle};
use serde_json::json;

const CANDIDATE_SCHEMA: &str = "ak.schema.only_a_candidate.v1";

/// A schema id the SDK generates, i.e. one that is active in the live registry.
fn generated_schema_id() -> &'static str {
    REGISTERED_SCHEMA_IDS
        .first()
        .expect("REGISTERED_SCHEMA_IDS is empty; the generated descriptors collapsed")
        .schema_id
}

/// Build a bundle whose only interesting content is one profile requiring one
/// schema. `schema_status` of `None` leaves the schema out of the registry.
fn bundle(
    profile_status: &str,
    schema_id: &str,
    schema_status: Option<&str>,
) -> SpecArtifactBundle {
    let schemas = match schema_status {
        Some(status) => vec![json!({"schema_id": schema_id, "status": status})],
        None => Vec::new(),
    };
    SpecArtifactBundle {
        schema_registry: json!({"schemas": schemas}),
        event_kind_registry: json!({"event_kinds": []}),
        operation_registry: json!({"operations": []}),
        operation_clause_registry: json!({}),
        id_kind_registry: json!({"id_kinds": [], "special_forms": []}),
        capability_action_registry: json!({}),
        conformance_profiles: json!({
            "profile_requirements": {
                "ak.profile.test.v1": {
                    "status": profile_status,
                    "required_schemas": [schema_id],
                }
            }
        }),
        artifacts_dir: None,
    }
}

fn requirement_issues(
    profile_status: &str,
    schema_id: &str,
    schema_status: Option<&str>,
) -> Vec<String> {
    bundle(profile_status, schema_id, schema_status)
        .drift_report()
        .profile_requirement_issues
}

#[test]
fn candidate_profile_may_require_a_candidate_schema() {
    assert_eq!(
        requirement_issues("candidate", CANDIDATE_SCHEMA, Some("candidate")),
        Vec::<String>::new(),
        "a candidate profile requiring a candidate schema is the exempt pairing: the SDK \
         generates the active surface only, so the schema's absence from REGISTERED_SCHEMA_IDS \
         is correct"
    );
}

#[test]
fn active_profile_may_require_a_generated_schema() {
    assert_eq!(
        requirement_issues("active", generated_schema_id(), Some("active")),
        Vec::<String>::new(),
        "the ordinary case must stay silent, otherwise the assertions below would pass for the \
         wrong reason"
    );
}

#[test]
fn active_profile_requiring_a_candidate_schema_is_drift() {
    let found = requirement_issues("active", CANDIDATE_SCHEMA, Some("candidate"));
    assert_eq!(
        found.len(),
        1,
        "an active profile requiring a candidate schema is a spec-side status inversion and must \
         still be reported: {found:?}"
    );
    assert!(
        found[0].contains("active profile requires") && found[0].contains("candidate"),
        "the status inversion must be reported as such, not as an SDK generation gap: {found:?}"
    );
}

#[test]
fn candidate_profile_requiring_an_active_schema_the_sdk_skipped_is_drift() {
    let found = requirement_issues(
        "candidate",
        "ak.schema.active_but_ungenerated.v1",
        Some("active"),
    );
    assert_eq!(
        found.len(),
        1,
        "an active schema missing from REGISTERED_SCHEMA_IDS is a generation gap whatever the \
         requiring profile's status: {found:?}"
    );
    assert!(
        found[0].contains("is active in the spec registry"),
        "the generation gap must name the reason: {found:?}"
    );
}

#[test]
fn requiring_a_schema_no_registry_ships_is_drift_for_any_profile_status() {
    for profile_status in ["active", "candidate"] {
        let found = requirement_issues(profile_status, "ak.schema.nowhere.v1", None);
        assert_eq!(
            found.len(),
            1,
            "a dangling requirement must be reported for a {profile_status} profile: {found:?}"
        );
        assert!(
            found[0].contains("absent from the spec schemas registry"),
            "a dangling requirement must be distinguishable from a status mismatch: {found:?}"
        );
    }
}

/// A profile requirement without a `status` field is an ordinary active profile;
/// nothing may be exempted by omission.
#[test]
fn a_profile_without_a_status_field_is_treated_as_active() {
    let bundle = SpecArtifactBundle {
        conformance_profiles: json!({
            "profile_requirements": {
                "ak.profile.test.v1": {"required_schemas": [CANDIDATE_SCHEMA]}
            }
        }),
        ..bundle("active", CANDIDATE_SCHEMA, Some("candidate"))
    };
    let found = bundle.drift_report().profile_requirement_issues;
    assert_eq!(
        found.len(),
        1,
        "omitting `status` must not buy the exemption a `candidate` status would not: {found:?}"
    );
    assert!(found[0].contains("active profile requires"), "{found:?}");
}
