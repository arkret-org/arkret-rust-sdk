//! Authority Event ingress DTOs stay isomorphic to their canonical schema fragments.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingAcceptanceReceipt,
    DirectConversationFoundingDependencyMissingProblem, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, SelfAuthoritySubmitRequest,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{ApprovalSignature, EventCommitSubmission};
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
    assert_schema_and_serde::<EventCommitSubmission>(
        "service-operation-dtos.schema.json",
        "#/$defs/EventCommitSubmission",
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
fn direct_conversation_receipt_and_dependency_problem_are_closed() {
    let receipt = json!({
        "pair_key": format!("sha256:{}", "1".repeat(64)),
        "founder_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:webvh:z6mkfixturestationexample"
            }
        },
        "realm_id": "ak:realm:ATh7OWLLpUdTVYsKdp6rkClScUpjYJlF1Y3byjeyHS8J",
        "main_strand_id": "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0",
        "founding_unit_digest": format!("sha256:{}", "2".repeat(64)),
        "authorization_core": {
            "kind": "controller_agent",
            "agent_provision_ref": "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB",
            "controller_binding_digest": format!("sha256:{}", "3".repeat(64))
        },
        "issuer_id": "ak:did_core:web:station.example",
        "accepted_at": "2026-09-20T00:00:00.000Z",
        "proof": {
            "verification_method": "did:web:station.example#authority",
            "created_at": "2026-09-20T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
        }
    });
    assert_schema_and_serde::<DirectConversationFoundingAcceptanceReceipt>(
        "direct-conversation-operations.schema.json",
        "#/$defs/direct_conversation_founding_acceptance_receipt",
        receipt,
    );

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
    let parsed: EventCommitSubmission = serde_json::from_value(submission).unwrap();
    assert!(parsed.validate().is_err());

    let unknown = json!({"branch": "future_branch", "event_submission": {}});
    assert!(serde_json::from_value::<PeerAuthoritySubmitRequest>(unknown).is_err());
}
