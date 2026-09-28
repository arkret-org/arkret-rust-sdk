//! Authority Event ingress DTOs stay isomorphic to their canonical schema fragments.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, DirectConversationFoundingDependencyMissingProblem,
    PeerAuthorityForwardEventRequest, PeerAuthorityForwardMlsRequest, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, SelfAuthoritySubmitRequest,
};
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestation, DeviceProjectionAttestationCore,
    DeviceStatus,
};
use arkret_models_identity::{
    AccountDeviceSignerEvidence, AuthenticatedServiceResolution, DidDocument,
    ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    normalized_did_document_digest,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{
    AccountId, ApprovalSignature, DeviceId, Did, DidCoreId, DidKey, DidUrl, ErrorCode,
    EventAdmissionSubmission, EventId, MlsCommitSubmission, NonEmptyString, ProtocolSignature,
    WireError,
};
use chrono::{TimeZone as _, Utc};
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
        "service-operation-dtos.schema.json",
        "#/$defs/EventAdmissionSubmission",
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
    let mut submission = approved_event_submission();
    submission
        .as_object_mut()
        .unwrap()
        .remove("approval_signatures");
    let source_commit = source_commit_for(&submission);
    json!({"event_submission": submission, "source_commit": source_commit})
}

#[test]
fn committed_replication_keeps_event_and_commit_but_omits_private_approval() {
    let source = approved_event_submission();
    let submission: EventAdmissionSubmission = serde_json::from_value(source.clone()).unwrap();
    let commit = serde_json::from_value(source_commit_for(&source)).unwrap();
    let replica = CommittedEventSubmission::from_source_submission(&submission, commit, None);
    assert_eq!(
        serde_json::to_value(&replica.event_submission).unwrap(),
        json!({"event": source["event"]})
    );
    assert_eq!(
        serde_json::to_value(&replica.source_commit).unwrap(),
        source_commit_for(&source)
    );
    replica.validate().unwrap();
    validate_fragment(
        PEER_SCHEMA,
        "#/$defs/committed_event_submission",
        &serde_json::to_value(&replica).unwrap(),
    );

    let mut leaked = serde_json::to_value(&replica).unwrap();
    leaked["event_submission"]["approval_signatures"] = source["approval_signatures"].clone();
    assert!(schema_rejects(
        PEER_SCHEMA,
        "#/$defs/committed_event_submission",
        &leaked,
    ));
    let parsed: CommittedEventSubmission = serde_json::from_value(leaked.clone()).unwrap();
    assert!(matches!(
        parsed.validate(),
        Err(WireError::ProtocolCode {
            code: ErrorCode::SchemaViolation,
            ..
        })
    ));
    let peer: PeerAuthoritySubmitRequest = serde_json::from_value(json!({
        "branch": "committed_replication",
        "replications": [leaked]
    }))
    .unwrap();
    assert!(peer.validate().is_err());
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

const DEVICE_FRAGMENT: &str = "ak:device:0196419b-0000-7000-8000-000000000001";

fn producer_device_evidence() -> AccountDeviceSignerEvidence {
    let did = Did::new("did:web:station.example").unwrap();
    let document: DidDocument = serde_json::from_value(json!({
        "id": did,
        "verificationMethod": [],
        "service": [{
            "id": "did:web:station.example#service",
            "type": "ArkretService",
            "serviceKind": "station",
            "serviceEndpoint": "https://station.example/"
        }]
    }))
    .unwrap();
    let digest = normalized_did_document_digest(&document).unwrap();
    let version = format!(
        "synthetic-jcs-sha256:{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let at = Utc.with_ymd_and_hms(2026, 9, 24, 0, 0, 0).unwrap();
    AccountDeviceSignerEvidence {
        device_projection_attestation: DeviceProjectionAttestation {
            attestation: DeviceProjectionAttestationCore {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                    arkret_wire::project_did_to_core_id(&did).unwrap(),
                ),
                device_id: DeviceId::new(DEVICE_FRAGMENT).unwrap(),
                device_signing_key_did: DidKey::new(
                    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
                )
                .unwrap(),
                hpke_key: NonEmptyString::new("hpke-1").unwrap(),
                device_authorize_event_id: EventId::new(
                    "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                )
                .unwrap(),
                authorized_generation_ref: 1,
                device_status: DeviceStatus::Active,
                authorization_window: DeviceAuthorizationWindow {
                    not_before: at,
                    expires_at: None,
                },
                attested_at: at,
                expires_at: at + chrono::Duration::minutes(5),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new("did:web:station.example#signing-1").unwrap(),
                created_at: at,
                jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
            },
        },
        service_resolution: AuthenticatedServiceResolution {
            service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
            service_kind: "station".to_owned(),
            method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: digest.to_string(),
                    to_method_history_head: digest.to_string(),
                    from_version_id: version.clone(),
                    to_version_id: version,
                },
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "web".to_owned(),
                    document_digest: digest,
                    method_proofs: vec![],
                },
            },
            normalized_did_document: document,
        },
    }
}

/// The fixture Account submission re-signed (structurally) under `fragment`.
fn submission_signed_with(fragment: &str) -> Value {
    let mut submission = approved_event_submission();
    let method = submission["event"]["producer_proof"]["verification_method"]
        .as_str()
        .unwrap()
        .to_owned();
    let controller = method.split_once('#').unwrap().0;
    submission["event"]["producer_proof"]["verification_method"] =
        json!(format!("{controller}#{fragment}"));
    submission
}

fn forward(submission: &Value, evidence: Option<&Value>) -> Value {
    let mut value = json!({"branch": "authority_forward", "event_submission": submission});
    if let Some(evidence) = evidence {
        value["producer_device_evidence"] = evidence.clone();
    }
    value
}

/// Top-level members serialize in schema property order.
fn assert_member_order(text: &str, members: &[&str]) {
    let positions = members
        .iter()
        .map(|member| text.find(&format!("\"{member}\":")).unwrap())
        .collect::<Vec<_>>();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
}

fn presence_violation(value: Value) -> bool {
    serde_json::from_value::<PeerAuthoritySubmitRequest>(value)
        .unwrap()
        .validate()
        .unwrap_err()
        .error_code()
        == Some(ErrorCode::SchemaViolation)
}

#[test]
fn human_device_producer_requires_producer_device_evidence() {
    let evidence = serde_json::to_value(producer_device_evidence()).unwrap();
    let human = submission_signed_with(DEVICE_FRAGMENT);

    assert!(presence_violation(forward(&human, None)));

    let carried = forward(&human, Some(&evidence));
    validate_fragment(PEER_SCHEMA, "#/$defs/peer_submit_request", &carried);
    let parsed: PeerAuthoritySubmitRequest = serde_json::from_value(carried.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), carried);
    assert_member_order(
        &serde_json::to_string(&parsed).unwrap(),
        &["branch", "event_submission", "producer_device_evidence"],
    );
    let PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) = parsed else {
        panic!("authority_forward Event branch expected");
    };
    let producer = request.human_device_producer().unwrap().unwrap();
    assert_eq!(producer.device_id.as_str(), DEVICE_FRAGMENT);
    assert_eq!(
        serde_json::to_value(&producer.account_id).unwrap(),
        human["event"]["actor_id"]["account_id"]
    );

    let submission: EventAdmissionSubmission = serde_json::from_value(human).unwrap();
    assert_eq!(
        PeerAuthorityForwardEventRequest::new(submission.clone(), None, None)
            .unwrap_err()
            .error_code(),
        Some(ErrorCode::SchemaViolation)
    );
    PeerAuthorityForwardEventRequest::new(submission, None, Some(producer_device_evidence()))
        .unwrap();
}

#[test]
fn non_device_producer_forbids_producer_device_evidence() {
    let evidence = serde_json::to_value(producer_device_evidence()).unwrap();
    let account_key = approved_event_submission();
    serde_json::from_value::<PeerAuthoritySubmitRequest>(forward(&account_key, None))
        .unwrap()
        .validate()
        .unwrap();
    assert!(presence_violation(forward(&account_key, Some(&evidence))));

    // The actual signer is `executed_by`: a Service executor signing under an
    // `ak:device:`-shaped fragment is still not a human device producer.
    let mut delegated = submission_signed_with(DEVICE_FRAGMENT);
    delegated["event"]["executed_by"] =
        json!({"kind": "service", "service_id": "ak:did_core:web:station.example"});
    serde_json::from_value::<PeerAuthoritySubmitRequest>(forward(&delegated, None))
        .unwrap()
        .validate()
        .unwrap();
    assert!(presence_violation(forward(&delegated, Some(&evidence))));

    // Conversely an Account executor makes a Service-authored Event human.
    let mut executed = submission_signed_with(DEVICE_FRAGMENT);
    executed["event"]["executed_by"] = executed["event"]["actor_id"].clone();
    executed["event"]["actor_id"] =
        json!({"kind": "service", "service_id": "ak:did_core:web:station.example"});
    assert!(presence_violation(forward(&executed, None)));
    serde_json::from_value::<PeerAuthoritySubmitRequest>(forward(&executed, Some(&evidence)))
        .unwrap()
        .validate()
        .unwrap();

    // A device-shaped fragment that is not a canonical device id is malformed.
    let malformed = submission_signed_with("ak:device:not-a-uuid");
    assert!(presence_violation(forward(&malformed, None)));
    assert!(presence_violation(forward(&malformed, Some(&evidence))));
}

#[test]
fn mls_forward_presence_follows_the_commit_event_producer() {
    let evidence = producer_device_evidence();
    let submission_for = |submission: Value| -> MlsCommitSubmission {
        let mut commit_event = submission["event"].clone();
        commit_event["kind"] = json!("ak.mls.commit");
        serde_json::from_value(json!({
            "commit_event": commit_event,
            "welcomes": [],
            "idempotency_key": "0196419b-0000-7000-8000-000000000001"
        }))
        .unwrap()
    };
    let human = submission_for(submission_signed_with(DEVICE_FRAGMENT));
    let error: WireError = PeerAuthorityForwardMlsRequest::new(human.clone(), None).unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::SchemaViolation));
    let request = PeerAuthorityForwardMlsRequest::new(human, Some(evidence.clone())).unwrap();
    PeerAuthoritySubmitRequest::AuthorityForwardMls(request.clone())
        .validate()
        .unwrap();
    assert_member_order(
        &serde_json::to_string(&request).unwrap(),
        &["branch", "mls_submission", "producer_device_evidence"],
    );

    let account_key = submission_for(approved_event_submission());
    PeerAuthorityForwardMlsRequest::new(account_key.clone(), None).unwrap();
    assert_eq!(
        PeerAuthorityForwardMlsRequest::new(account_key, Some(evidence))
            .unwrap_err()
            .error_code(),
        Some(ErrorCode::SchemaViolation)
    );
}

#[test]
fn producer_device_evidence_exists_only_on_authority_forward() {
    let evidence = serde_json::to_value(producer_device_evidence()).unwrap();
    let fragment = "#/$defs/peer_submit_request";
    let mut replication = replication_request(1);
    replication["producer_device_evidence"] = evidence.clone();
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &replication);

    let unit = json!({
        "branch": "registered_atomic_unit",
        "unit": {"unit_kind": "direct_conversation_founding"},
        "producer_device_evidence": evidence
    });
    assert_rejected_by_schema_and_dto::<PeerAuthoritySubmitRequest>(fragment, &unit);
}

fn welcome_delivery() -> Value {
    let fixture_path = artifacts_dir()
        .join("fixtures")
        .join("keypackage-lifecycle-fixture.json");
    let fixture: Value = serde_json::from_str(&fs::read_to_string(fixture_path).unwrap()).unwrap();
    fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|case| {
            let instance = &case["instance"];
            instance.get("producer_proof").map(|_| instance.clone())
        })
        .unwrap()
}

#[test]
fn replicated_welcomes_are_refused_for_a_non_commit_event() {
    let mut request = replication_request(1);
    request["replications"][0]["welcomes"] = json!([welcome_delivery()]);
    assert!(schema_rejects(
        PEER_SCHEMA,
        "#/$defs/peer_submit_request",
        &request
    ));
    assert!(presence_violation(request));

    let mut empty = replication_request(1);
    empty["replications"][0]["welcomes"] = json!([]);
    assert!(schema_rejects(
        PEER_SCHEMA,
        "#/$defs/peer_submit_request",
        &empty
    ));
    assert!(presence_violation(empty));
}

#[test]
fn genesis_material_is_refused_for_a_non_genesis_event() {
    let mut value = forward(&approved_event_submission(), None);
    value["mls_genesis_material"] =
        json!({"group_info_bytes_b64": "AAEAAQ", "ratchet_tree_bytes_b64": "AQIDBA"});
    assert!(schema_rejects(
        PEER_SCHEMA,
        "#/$defs/peer_submit_request",
        &value
    ));
    assert!(presence_violation(value));
}

#[test]
fn genesis_material_is_canonical_bounded_base64url() {
    use arkret_models_collaboration::authority_commit::MlsGenesisMaterial;

    let material = MlsGenesisMaterial::from_bytes(&[0, 1, 0, 1], &[1, 2, 3, 4]);
    validate_fragment(
        PEER_SCHEMA,
        "#/$defs/mls_genesis_material",
        &serde_json::to_value(&material).unwrap(),
    );
    assert_eq!(
        material.decode().unwrap(),
        (vec![0, 1, 0, 1], vec![1, 2, 3, 4])
    );
    for bad in ["", "AAEAAQ==", "AAE+AQ"] {
        let candidate = MlsGenesisMaterial {
            group_info_bytes_b64: bad.to_owned(),
            ratchet_tree_bytes_b64: "AQIDBA".to_owned(),
        };
        assert_eq!(
            candidate.validate().unwrap_err().error_code(),
            Some(ErrorCode::SchemaViolation),
            "{bad}"
        );
    }
}

#[test]
fn genesis_material_members_bound_the_pair_to_the_group_state_material_response() {
    use arkret_models_collaboration::authority_commit::{
        MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES, MlsGenesisMaterial,
    };

    let largest = MlsGenesisMaterial::from_bytes(
        &vec![0; MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES],
        &vec![0; MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES],
    );
    assert_eq!(largest.group_info_bytes_b64.len(), 5_592_406);
    let (group_info, ratchet_tree) = largest.decode().unwrap();
    assert_eq!(group_info.len() + ratchet_tree.len(), 8_388_608);
    for (over_group_info, over_tree) in [(true, false), (false, true)] {
        let one_more = |over: bool| {
            let bytes = MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES + usize::from(over);
            arkret_wire::base64url::base64url_encode(&vec![0; bytes])
        };
        let candidate = MlsGenesisMaterial {
            group_info_bytes_b64: one_more(over_group_info),
            ratchet_tree_bytes_b64: one_more(over_tree),
        };
        assert_eq!(
            candidate.validate().unwrap_err().error_code(),
            Some(ErrorCode::SchemaViolation)
        );
    }
}
