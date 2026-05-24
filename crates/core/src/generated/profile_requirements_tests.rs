//! Drift + behavioural tests for the generated `profile_requirements` module.
//!
//! The drift test re-reads the conformance-profiles artifact, recomputes the
//! per-profile (inheritance, operations, event_kinds, schemas, rejected kinds,
//! fixtures, features, capability actions, cells, constraint_kinds) requirement
//! tuple in memory, and compares it against the committed
//! `generated::profile_requirements::PROFILE_REQUIREMENTS` map. If the
//! generator was not re-run after a spec change, this test fails — same
//! contract as the existing `generated_profile_constants_match_artifact_profile_ids`
//! drift test that gates the profile-ID constants module.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::profile_requirements::{
    PROFILE_REQUIREMENTS, ProfileRequirementsError, known_profile_ids, profile_compliance_report,
    requirements_for, validate_profile_requirements,
};
use crate::schema::default_spec_artifacts_dir;

fn artifact_path() -> Option<std::path::PathBuf> {
    let artifacts_dir = default_spec_artifacts_dir()?;
    let path = artifacts_dir.join("profiles").join("conformance-profiles.json");
    path.exists().then_some(path)
}

fn collect_str_array(value: Option<&Value>) -> BTreeSet<String> {
    let Some(Value::Array(items)) = value else {
        return BTreeSet::new();
    };
    items.iter().filter_map(|v| v.as_str().map(|s| s.to_owned())).collect()
}

fn artifact_requirement_table() -> BTreeMap<String, ProfileRequirementSnapshot> {
    let Some(path) = artifact_path() else {
        return BTreeMap::new();
    };
    let raw = std::fs::read_to_string(&path).expect("read conformance-profiles.json");
    let json: Value = serde_json::from_str(&raw).expect("parse conformance-profiles.json");
    let Some(Value::Object(map)) = json.get("profile_requirements") else {
        panic!("conformance-profiles.json missing 'profile_requirements' object");
    };
    let mut out = BTreeMap::new();
    for (profile_id, entry) in map {
        let required_operations = collect_str_array(entry.get("required_endpoints"));
        let required_event_kinds = collect_str_array(entry.get("required_event_kinds"));
        let required_schemas = collect_str_array(entry.get("required_schemas"));
        let inherits = collect_str_array(entry.get("inherits"));
        let rejected_event_kinds = collect_str_array(entry.get("rejected_event_kinds"));
        let required_fixtures = collect_str_array(entry.get("required_fixtures"));
        let required_capability_actions =
            collect_str_array(entry.get("required_capability_actions"));
        let required_features = collect_str_array(entry.get("required_features"));
        let required_cell_namespaces = collect_str_array(entry.get("required_cell_namespaces"));
        let required_cells = collect_str_array(entry.get("required_cells"));
        let mut required_constraint_kinds = BTreeSet::new();
        required_constraint_kinds.extend(collect_str_array(entry.get("required_constraint_types")));
        required_constraint_kinds
            .extend(collect_str_array(entry.get("required_constraint_subtypes")));
        required_constraint_kinds.extend(collect_str_array(entry.get("required_constraint_kinds")));
        out.insert(
            profile_id.clone(),
            ProfileRequirementSnapshot {
                inherits,
                required_operations,
                required_event_kinds,
                required_schemas,
                rejected_event_kinds,
                required_fixtures,
                required_capability_actions,
                required_features,
                required_cell_namespaces,
                required_cells,
                required_constraint_kinds,
            },
        );
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
struct ProfileRequirementSnapshot {
    inherits: BTreeSet<String>,
    required_operations: BTreeSet<String>,
    required_event_kinds: BTreeSet<String>,
    required_schemas: BTreeSet<String>,
    rejected_event_kinds: BTreeSet<String>,
    required_fixtures: BTreeSet<String>,
    required_capability_actions: BTreeSet<String>,
    required_features: BTreeSet<String>,
    required_cell_namespaces: BTreeSet<String>,
    required_cells: BTreeSet<String>,
    required_constraint_kinds: BTreeSet<String>,
}

#[test]
fn generated_profile_requirements_match_artifact() {
    let artifact_table = artifact_requirement_table();
    if artifact_table.is_empty() {
        // No spec artifact resolvable (e.g. publish build outside the workspace).
        return;
    }

    let generated_ids: BTreeSet<&str> = PROFILE_REQUIREMENTS.keys().copied().collect();
    let artifact_ids: BTreeSet<&str> = artifact_table.keys().map(String::as_str).collect();
    assert_eq!(
        generated_ids, artifact_ids,
        "generated profile_requirements profile set drifted from artifact"
    );

    for (profile_id, snapshot) in &artifact_table {
        let generated = PROFILE_REQUIREMENTS
            .get(profile_id.as_str())
            .unwrap_or_else(|| panic!("missing generated entry for {profile_id}"));
        let generated_snapshot = ProfileRequirementSnapshot {
            inherits: generated.inherits.iter().map(|s| (*s).to_owned()).collect(),
            required_operations: generated
                .required_operations
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_event_kinds: generated
                .required_event_kinds
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_schemas: generated.required_schemas.iter().map(|s| (*s).to_owned()).collect(),
            rejected_event_kinds: generated
                .rejected_event_kinds
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_fixtures: generated
                .required_fixtures
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_capability_actions: generated
                .required_capability_actions
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_features: generated
                .required_features
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_cell_namespaces: generated
                .required_cell_namespaces
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            required_cells: generated.required_cells.iter().map(|s| (*s).to_owned()).collect(),
            required_constraint_kinds: generated
                .required_constraint_kinds
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        };
        assert_eq!(
            &generated_snapshot, snapshot,
            "generated requirements for {profile_id} drifted from artifact; \
             re-run tools/generate-sdk-profile-requirements.ps1"
        );
    }
}

#[test]
fn generated_profile_requirements_arrays_are_sorted_unique() {
    for (profile_id, req) in PROFILE_REQUIREMENTS.iter() {
        for (label, arr) in [
            ("inherits", req.inherits),
            ("required_operations", req.required_operations),
            ("required_event_kinds", req.required_event_kinds),
            ("required_schemas", req.required_schemas),
            ("rejected_event_kinds", req.rejected_event_kinds),
            ("required_fixtures", req.required_fixtures),
            ("required_capability_actions", req.required_capability_actions),
            ("required_features", req.required_features),
            ("required_cell_namespaces", req.required_cell_namespaces),
            ("required_cells", req.required_cells),
            ("required_constraint_kinds", req.required_constraint_kinds),
        ] {
            let mut sorted = arr.to_vec();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted.as_slice(),
                arr,
                "{profile_id} field {label} is not sorted-deduplicated"
            );
        }
        assert_eq!(
            req.profile_id, *profile_id,
            "profile_id field must match map key for {profile_id}"
        );
    }
}

#[test]
fn known_profile_ids_matches_static_map() {
    let from_helper: BTreeSet<&str> = known_profile_ids().into_iter().collect();
    let from_map: BTreeSet<&str> = PROFILE_REQUIREMENTS.keys().copied().collect();
    assert_eq!(from_helper, from_map);
}

#[test]
fn validate_profile_requirements_rejects_unknown_profile() {
    let err = validate_profile_requirements("cx.profile.does_not_exist.v1", &[], &[], &[])
        .expect_err("unknown profile must fail");
    assert!(matches!(
        err,
        ProfileRequirementsError::UnknownProfile { ref profile_id }
            if profile_id == "cx.profile.does_not_exist.v1"
    ));
}

#[test]
fn validate_profile_requirements_passes_when_caller_implements_everything() {
    let req = requirements_for("cx.profile.core_event_store.v1")
        .expect("core_event_store profile present");
    let ops: Vec<&str> = req.required_operations.to_vec();
    let kinds: Vec<&str> = req.required_event_kinds.to_vec();
    let schemas: Vec<&str> = req.required_schemas.to_vec();
    validate_profile_requirements(req.profile_id, &ops, &kinds, &schemas)
        .expect("complete implementation must validate");
}

#[test]
fn validate_profile_requirements_reports_structured_diff_when_incomplete() {
    let req = requirements_for("cx.profile.core_event_store.v1")
        .expect("core_event_store profile present");
    // Skip the first required op + first required event kind to force a diff.
    let ops: Vec<&str> = req.required_operations[1..].to_vec();
    let kinds: Vec<&str> = req.required_event_kinds[1..].to_vec();
    let schemas: Vec<&str> = req.required_schemas.to_vec();
    let err = validate_profile_requirements(req.profile_id, &ops, &kinds, &schemas)
        .expect_err("incomplete implementation must fail");
    match err {
        ProfileRequirementsError::MissingRequirements {
            profile_id,
            missing_operations,
            missing_event_kinds,
            missing_schemas,
        } => {
            assert_eq!(profile_id, req.profile_id);
            assert_eq!(missing_operations, vec![req.required_operations[0].to_owned()]);
            assert_eq!(missing_event_kinds, vec![req.required_event_kinds[0].to_owned()]);
            assert!(missing_schemas.is_empty(), "schemas should all be present");
        }
        other => panic!("expected MissingRequirements, got {other:?}"),
    }
}

#[test]
fn profile_compliance_report_partitions_satisfied_and_missing() {
    let req = requirements_for("cx.profile.chat_mvp.v1").expect("chat_mvp profile present");
    let ops: Vec<&str> = req.required_operations[1..].to_vec();
    let kinds: Vec<&str> = req.required_event_kinds.to_vec();
    let schemas: Vec<&str> = req.required_schemas.to_vec();
    let report = profile_compliance_report(req.profile_id, &ops, &kinds, &schemas)
        .expect("known profile must produce report");
    assert_eq!(report.profile_id, req.profile_id);
    assert_eq!(report.missing_operations, vec![req.required_operations[0].to_owned()]);
    assert_eq!(report.satisfied_operations.len(), req.required_operations.len() - 1);
    assert!(report.missing_event_kinds.is_empty());
    assert!(report.missing_schemas.is_empty());
    assert!(!report.is_compliant());
}

#[test]
fn profile_compliance_report_is_compliant_when_everything_implemented() {
    let req = requirements_for("cx.profile.core_event_store.v1")
        .expect("core_event_store profile present");
    let ops: Vec<&str> = req.required_operations.to_vec();
    let kinds: Vec<&str> = req.required_event_kinds.to_vec();
    let schemas: Vec<&str> = req.required_schemas.to_vec();
    let report = profile_compliance_report(req.profile_id, &ops, &kinds, &schemas)
        .expect("known profile must produce report");
    assert!(report.is_compliant());
    assert_eq!(report.satisfied_operations.len(), req.required_operations.len());
    assert_eq!(report.satisfied_event_kinds.len(), req.required_event_kinds.len());
    assert_eq!(report.satisfied_schemas.len(), req.required_schemas.len());
}
