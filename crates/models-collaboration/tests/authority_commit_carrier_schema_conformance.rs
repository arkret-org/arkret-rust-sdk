//! Authority Event ingress DTOs stay isomorphic to their canonical schema fragments.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingDependencyMissingProblem, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, SelfAuthoritySubmitRequest,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{ApprovalSignature, EventAdmissionSubmission};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn schema_value(file: &str) -> Value {
    let path = artifacts_dir().join("schemas").join(file);
    serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .expect("schema artifact must be valid JSON")
}

fn validate_fragment(file: &str, fragment: &str, value: &Value) {
    let mut registry: ProtocolSchemaRegistry =
        schema_registry_from_spec_artifacts(artifacts_dir()).unwrap();
    let schema = schema_value(file);
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let schema_id = format!("test:{file}{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap();
    registry
        .validate_value(&schema_id, value)
        .unwrap_or_else(|error| panic!("{file}{fragment} rejected value: {error}"));
}

fn schema_rejects(file: &str, fragment: &str, value: &Value) -> bool {
    let mut registry: ProtocolSchemaRegistry =
        schema_registry_from_spec_artifacts(artifacts_dir()).unwrap();
    let schema = schema_value(file);
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let schema_id = format!("test:{file}{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap();
    registry.validate_value(&schema_id, value).is_err()
}

fn assert_schema_and_serde<T>(file: &str, fragment: &str, value: Value)
where
    T: DeserializeOwned + serde::Serialize,
{
    validate_fragment(file, fragment, &value);
    let parsed: T = serde_json::from_value(value.clone()).expect("SDK must accept schema value");
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

fn approved_event_submission() -> Value {
    let fixture_path = artifacts_dir()
        .join("fixtures")
        .join("approval-signature-kat-fixture.json");
    let fixture: Value = serde_json::from_str(&fs::read_to_string(fixture_path).unwrap()).unwrap();
    fixture["event_id_invariance"]["submission_with_evidence"].clone()
}

#[test]
fn event_submission_sidecar_and_both_endpoint_unions_reuse_one_shape() {
    let submission = approved_event_submission();
    assert_schema_and_serde::<EventAdmissionSubmission>(
        "authority-commit-operations.schema.json",
        "#/$defs/committed_event_submission/properties/event_submission",
        submission.clone(),
    );
    assert_schema_and_serde::<SelfAuthoritySubmitRequest>(
        "authority-commit-operations.schema.json",
        "#/$defs/self_submit_request",
        submission.clone(),
    );
    assert_schema_and_serde::<PeerAuthoritySubmitRequest>(
        "authority-commit-operations.schema.json",
        "#/$defs/peer_submit_request",
        json!({"branch": "authority_forward", "event_submission": submission}),
    );

    let approval = approved_event_submission()["approval_signatures"][0].clone();
    assert_schema_and_serde::<ApprovalSignature>("approval-signature.schema.json", "#", approval);
}

#[test]
fn direct_conversation_dependency_problem_is_closed() {
    let problem = json!({
        "type": "https://arkret.org/problems/dependency_missing",
        "title": "Dependency missing",
        "status": 409,
        "detail": "exact founding dependency is not locally available",
        "details": {"missing_dependencies": [
            {"kind": "committed_event", "event_id": "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB"}
        ]}
    });
    assert_schema_and_serde::<DirectConversationFoundingDependencyMissingProblem>(
        "authority-commit-operations.schema.json",
        "#/$defs/direct_conversation_founding_dependency_missing_problem",
        problem,
    );
}

#[test]
fn peer_registered_unit_rejection_has_no_open_or_cross_branch_form() {
    let value = json!({
        "branch": "registered_atomic_unit",
        "outcome": {
            "unit_kind": "direct_conversation_founding",
            "status": "rejected",
            "reason_code": "dependency_missing",
            "details": {"missing_dependencies": [
                {"kind": "service_verification_method", "verification_method": "did:web:station.example#authority"}
            ]}
        }
    });
    assert_schema_and_serde::<PeerAuthoritySubmitOutcome>(
        "authority-commit-operations.schema.json",
        "#/$defs/peer_submit_outcome",
        value.clone(),
    );

    let mut mixed = value;
    mixed["outcome"]["commit"] = json!({});
    assert!(serde_json::from_value::<PeerAuthoritySubmitOutcome>(mixed).is_err());

    let cross_branch = json!({
        "branch": "committed_replication",
        "unit": {"unit_kind": "direct_conversation_founding"}
    });
    assert!(serde_json::from_value::<PeerAuthoritySubmitRequest>(cross_branch).is_err());
}

#[test]
fn empty_approval_sidecar_and_unknown_union_members_fail_closed() {
    let mut submission = approved_event_submission();
    submission["approval_signatures"] = json!([]);
    let parsed: EventAdmissionSubmission = serde_json::from_value(submission).unwrap();
    assert!(parsed.validate().is_err());

    let unknown = json!({"branch": "future_branch", "event_submission": {}});
    assert!(serde_json::from_value::<PeerAuthoritySubmitRequest>(unknown).is_err());
}

const PEER_SCHEMA: &str = "authority-commit-operations.schema.json";

fn source_commit_for(submission: &Value) -> Value {
    let event = &submission["event"];
    json!({
        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        "realm_id": event["realm_id"],
        "stream_ref": event["scope_ref"],
        "stream_position": 0,
        "previous_commit_ref": null,
        "event_ref": event["event_id"],
        "governance_generation": 0,
        "authority_ref": event["event_id"],
        "committed_at": "2026-09-20T00:00:00.000Z",
        "signature": {
            "context": "ak.realm_commit_signature.v1",
            "signature_algorithm": "Ed25519",
            "verification_method": "did:web:station.example#authority",
            "signed_digest": format!("sha256:{}", "4".repeat(64)),
            "created_at": "2026-09-20T00:00:00.000Z",
            "sig": "A".repeat(86)
        }
    })
}

fn replication_item() -> Value {
    let submission = approved_event_submission();
    let source_commit = source_commit_for(&submission);
    json!({"event_submission": submission, "source_commit": source_commit})
}

fn replication_request(count: usize) -> Value {
    json!({
        "branch": "committed_replication",
        "replications": (0..count).map(|_| replication_item()).collect::<Vec<_>>()
    })
}

/// A retired or malformed shape must be refused by the canonical schema and by
/// the SDK DTO independently; neither side may be the only guard.
fn assert_rejected_by_schema_and_dto<T: DeserializeOwned>(fragment: &str, value: &Value) {
    assert!(
        schema_rejects(PEER_SCHEMA, fragment, value),
        "schema {fragment} accepted retired shape: {value}"
    );
    assert!(
        serde_json::from_value::<T>(value.clone()).is_err(),
        "SDK DTO accepted retired shape for {fragment}: {value}"
    );
}

#[test]
fn committed_replication_carries_only_source_submission_and_commit() {
    let request = replication_request(2);
    assert_schema_and_serde::<PeerAuthoritySubmitRequest>(
        PEER_SCHEMA,
        "#/$defs/peer_submit_request",
        request.clone(),
    );
    let parsed: PeerAuthoritySubmitRequest = serde_json::from_value(request.clone()).unwrap();
    parsed.validate().unwrap();
    assert!(matches!(
        parsed,
        PeerAuthoritySubmitRequest::CommittedReplication(_)
    ));

    let mut wrong_event_ref = request.clone();
    wrong_event_ref["replications"][0]["source_commit"]["event_ref"] =
        json!("ak:event:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0");
    serde_json::from_value::<PeerAuthoritySubmitRequest>(wrong_event_ref)
        .unwrap()
        .validate()
        .unwrap_err();

    let fragment = "#/$defs/peer_submit_request";
    // Retired 09-20 request shape: processing mode + submissions[] of
    // {committed_event:{event_submission,source_commit}, recipient_witnesses}.
    let item = replication_item();
    let retired = json!({
        "branch": "committed_replication",
        "processing": "per_item",
        "submissions": [{
            "committed_event": item.clone(),
            "recipient_witnesses": [{
                "realm_id": item["source_commit"]["realm_id"],
                "member_id": "ak:actor:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB",
                "membership_event_ref": item["source_commit"]["event_ref"],
                "recipient_service_id": "ak:did_core:web:peer.example"
            }]
        }]
    });
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &retired);

    let mut stray_processing = request.clone();
    stray_processing["processing"] = json!("per_item");
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &stray_processing);

    let mut stray_witness = request.clone();
    stray_witness["replications"][0]["recipient_witnesses"] = json!([]);
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &stray_witness);

    let wrapped = json!({
        "branch": "committed_replication",
        "replications": [{"committed_event": replication_item()}]
    });
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &wrapped);

    let mut missing_commit = request.clone();
    missing_commit["replications"][0]
        .as_object_mut()
        .unwrap()
        .remove("source_commit");
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &missing_commit);

    let mut cross_branch = request;
    cross_branch["event_submission"] = approved_event_submission();
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &cross_branch);

    for count in [0, 101] {
        let value = replication_request(count);
        assert!(schema_rejects(PEER_SCHEMA, fragment, &value));
        serde_json::from_value::<PeerAuthoritySubmitRequest>(value)
            .unwrap()
            .validate()
            .unwrap_err();
    }
}

#[test]
fn committed_replication_outcomes_are_same_order_rows_without_echo() {
    let outcome = json!({
        "branch": "committed_replication",
        "replication_outcomes": [
            {"status": "stored"},
            {"status": "duplicate"},
            {"status": "rejected", "reason_code": "dependency_missing"}
        ]
    });
    assert_schema_and_serde::<PeerAuthoritySubmitOutcome>(
        PEER_SCHEMA,
        "#/$defs/peer_submit_outcome",
        outcome.clone(),
    );
    let parsed: PeerAuthoritySubmitOutcome = serde_json::from_value(outcome).unwrap();
    let three: PeerAuthoritySubmitRequest = serde_json::from_value(replication_request(3)).unwrap();
    parsed.validate_for_request(&three).unwrap();
    let two: PeerAuthoritySubmitRequest = serde_json::from_value(replication_request(2)).unwrap();
    parsed.validate_for_request(&two).unwrap_err();

    let fragment = "#/$defs/peer_submit_outcome";
    let committed_ref = json!({
        "event_id": "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB",
        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
    });
    let retired = json!({
        "branch": "committed_replication",
        "results": [{"status": "stored", "index": 0, "committed_ref": committed_ref}]
    });
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitOutcome>(fragment, &retired);
    for row in [
        json!({"status": "stored", "index": 0}),
        json!({"status": "duplicate", "committed_ref": committed_ref}),
        json!({"status": "rejected", "reason_code": "dependency_missing", "index": 0}),
        json!({"status": "rejected"}),
        json!({"status": "stored", "reason_code": "dependency_missing"}),
        json!({"status": "accepted"}),
    ] {
        let value = json!({"branch": "committed_replication", "replication_outcomes": [row]});
        assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitOutcome>(fragment, &value);
    }
    let empty = json!({"branch": "committed_replication", "replication_outcomes": []});
    assert!(schema_rejects(PEER_SCHEMA, fragment, &empty));
    serde_json::from_value::<PeerAuthoritySubmitOutcome>(empty)
        .unwrap()
        .validate()
        .unwrap_err();
}
