//! First-admission usage gates do not restrict historical source decoding.

use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, CommittedEventSubmission, MlsGroupStateMaterial,
    PeerAuthorityForwardEventRequestBody, PeerAuthorityForwardMlsRequestBody,
    SelfAuthoritySubmitRequestBody,
};
use arkret_wire::{
    ActorId, AuthoritySubmitRequestBody, ErrorCode, EventAdmissionSubmission, EventKind,
    MlsCommitSubmission, WireError,
};
use serde_json::{Value, json};

fn original_source() -> Value {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/mls-cross-station-welcome-replication-fixture.json",
    )
    .unwrap();
    fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "mls_commit_item_with_welcomes_valid")
        .unwrap()["instance"]
        .clone()
}

fn complete(submission: &EventAdmissionSubmission) -> MlsCommitSubmission {
    serde_json::from_value(json!({
        "commit_event": submission.event,
        "welcomes": [],
        "idempotency_key": "0196419b-0000-7000-8000-000000000001"
    }))
    .unwrap()
}

fn requires_complete(error: WireError) {
    match error {
        WireError::ProtocolCode { code, message } => {
            assert_eq!(code, ErrorCode::SchemaViolation);
            assert_eq!(
                message,
                "first MLS admission requires the complete MlsCommitSubmission"
            );
        }
        other => panic!("unexpected first-admission error: {other}"),
    }
}

#[test]
fn every_actor_uses_complete_mls_and_original_history_remains_decodable() {
    let source = original_source();
    let original: EventAdmissionSubmission =
        serde_json::from_value(source["event_submission"].clone()).unwrap();
    // The fixture is a historical accepted source. Only structural usage is
    // exercised below; altered actors are never represented as authenticated.
    original.validate().unwrap();
    let actors: [ActorId; 3] = [
        original.event.actor_id.clone(),
        serde_json::from_value(json!({"kind":"service", "service_id":
            "ak:did_core:webvh:z6mkfixturestationexample"}))
        .unwrap(),
        serde_json::from_value(json!({"kind":"realm", "realm_actor_id": {
            "realm_id":original.event.realm_id,
            "principal_id":"ak:did_core:webvh:z6mkfixture"
        }}))
        .unwrap(),
    ];
    for actor in actors {
        let mut submission = original.clone();
        submission.event.actor_id = actor;
        requires_complete(
            AuthoritySubmitRequestBody::Event(submission.clone())
                .validate()
                .unwrap_err(),
        );
        requires_complete(
            SelfAuthoritySubmitRequestBody::Event(submission.clone())
                .validate()
                .unwrap_err(),
        );
        let peer = PeerAuthorityForwardEventRequestBody {
            branch: AuthorityForwardBranch::AuthorityForward,
            event_submission: submission.clone(),
            mls_group_state_material: None,
            content_backup_sources: None,
            producer_device_evidence: None,
            producer_agent_evidence: None,
            successor_device_evidence: None,
        };
        requires_complete(peer.validate().unwrap_err());
        AuthoritySubmitRequestBody::MlsCommit(complete(&submission))
            .validate()
            .unwrap();
        SelfAuthoritySubmitRequestBody::MlsCommit(complete(&submission))
            .validate()
            .unwrap();
        if matches!(submission.event.actor_id, ActorId::Service { .. }) {
            PeerAuthorityForwardMlsRequestBody::new(
                complete(&submission).for_origin_forward(None),
                MlsGroupStateMaterial::from_bytes(&[0, 1], &[2, 3]),
                None,
                None,
            )
            .unwrap()
            .validate()
            .unwrap();
            // Genesis remains a normal Event at all usage boundaries. Its
            // payload/RFC/authority checks remain separate from these gates.
            submission.event.kind = EventKind::MlsGenesis;
            AuthoritySubmitRequestBody::Event(submission.clone())
                .validate()
                .unwrap();
            SelfAuthoritySubmitRequestBody::Event(submission.clone())
                .validate()
                .unwrap();
            PeerAuthorityForwardEventRequestBody::new(
                submission,
                Some(MlsGroupStateMaterial::from_bytes(&[0, 1], &[2, 3])),
                None,
                None,
            )
            .unwrap()
            .validate()
            .unwrap();
        }
    }
    // First-admission refusal must not poison the shared Event DTO or accepted
    // replication carrier, which still decodes its exact original Commit.
    let accepted: CommittedEventSubmission = serde_json::from_value(source.clone()).unwrap();
    accepted.validate().unwrap();
    assert_eq!(serde_json::to_value(accepted).unwrap(), source);
    assert_eq!(
        serde_json::to_value(original).unwrap(),
        source["event_submission"]
    );
}
