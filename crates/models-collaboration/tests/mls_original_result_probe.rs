//! Carrier/response shape tests only, not RFC or authenticated G acceptance.
use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, ForwardedAuthorityResponseBody, MlsGroupStateMaterial,
    PeerAuthorityForwardMlsRequestBody, PeerAuthorityForwardResponseBody,
    PeerAuthoritySubmitRequestBody, PeerAuthoritySubmitResponseBody,
};
use arkret_wire::{AuthorityRejectionStatus, AuthoritySubmitResponseBody, MlsCommitSubmission};
use serde_json::json;

fn probe() -> PeerAuthorityForwardMlsRequestBody {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/mls-cross-station-welcome-replication-fixture.json",
    )
    .unwrap();
    let source = fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "mls_commit_item_with_welcomes_valid")
        .unwrap();
    let submission: MlsCommitSubmission = serde_json::from_value(json!({
        "commit_event":source["instance"]["event_submission"]["event"],
        "welcomes":[], "idempotency_key":"0196419b-0000-7000-8000-000000000077"
    }))
    .unwrap();
    PeerAuthorityForwardMlsRequestBody {
        branch: AuthorityForwardBranch::AuthorityForward,
        mls_submission: submission.for_origin_forward(None),
        mls_group_state_material: MlsGroupStateMaterial::from_bytes(&[0, 1], &[2, 3]),
        content_backup_sources: None,
        producer_device_evidence: None,
        producer_agent_evidence: None,
    }
}

#[test]
fn account_probe_shape_is_separate_from_first_admission_and_validates_original_response() {
    let probe = probe();
    assert!(probe.is_original_result_probe());
    probe.validate_replay_shape().unwrap();
    assert!(
        probe.validate().is_err(),
        "no producer proof cannot admit a new Account Event"
    );
    let request = PeerAuthoritySubmitRequestBody::AuthorityForwardMls(probe.clone());
    let outcome =
        PeerAuthoritySubmitResponseBody::AuthorityForward(PeerAuthorityForwardResponseBody {
            branch: AuthorityForwardBranch::AuthorityForward,
            response_body: ForwardedAuthorityResponseBody::Ordinary(
                AuthoritySubmitResponseBody::Rejected {
                    status: AuthorityRejectionStatus::Rejected,
                    reason_code: "governance_binding_mismatch".into(),
                },
            ),
        });
    outcome.validate_for_request(&request).unwrap();
    let exact = serde_json::to_value(&request).unwrap();
    assert!(exact.get("producer_device_evidence").is_none());
    assert!(exact.get("producer_agent_evidence").is_none());
    let mut malformed = probe;
    malformed.mls_group_state_material = MlsGroupStateMaterial::from_bytes(&[], &[2, 3]);
    assert!(malformed.validate_replay_shape().is_err());
    assert!(
        outcome
            .validate_for_request(&PeerAuthoritySubmitRequestBody::AuthorityForwardMls(
                malformed
            ))
            .is_err()
    );
}

#[test]
fn service_without_account_is_not_reclassified_as_a_result_probe() {
    let mut request = probe();
    request.mls_submission.commit_event.actor_id =
        arkret_wire::ActorId::service("ak:did_core:web:producer.example".parse().unwrap());
    assert!(!request.is_original_result_probe());
    request.validate().unwrap();
}

#[test]
fn original_probe_requires_true_absence_not_explicit_null_evidence() {
    let request = probe();
    let original = serde_json::to_value(&request).unwrap();
    let parsed: PeerAuthorityForwardMlsRequestBody =
        serde_json::from_value(original.clone()).unwrap();
    assert!(parsed.is_original_result_probe());
    for fields in [
        vec!["producer_device_evidence"],
        vec!["producer_agent_evidence"],
        vec!["producer_device_evidence", "producer_agent_evidence"],
    ] {
        let mut invalid = original.clone();
        for field in fields {
            invalid[field] = serde_json::Value::Null;
        }
        assert!(
            serde_json::from_value::<PeerAuthorityForwardMlsRequestBody>(invalid.clone()).is_err()
        );
        assert!(serde_json::from_value::<PeerAuthoritySubmitRequestBody>(invalid).is_err());
    }
    // The existing generic carrier already rejects an explicit null source.
    // Do not add a second owner or change that field to fix evidence parsing.
    let mut invalid = original;
    invalid["mls_submission"]["recovery_source"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<PeerAuthorityForwardMlsRequestBody>(invalid).is_err());
}
