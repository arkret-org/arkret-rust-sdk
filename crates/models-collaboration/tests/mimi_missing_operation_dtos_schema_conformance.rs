//! The MIMI facade's remaining current request/outcome DTOs must stay closed.

use std::fs;

use arkret_models_collaboration::mimi_operations::{
    MimiNotifyOutcome, MimiNotifyRequestBody, MimiReportAbuseRequestBody,
    MimiRequestConsentOutcome, MimiRoomUpdateOutcome, MimiRoomUpdateRequestBody,
    MimiUpdateConsentOutcome,
};
use arkret_models_crypto::{PeerKeyPackagesClaimQueryOutcome, PeerKeyPackagesClaimRequestBody};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const MLS_GROUP: &str = "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4";
const EVENT: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONSENT: &str = "ak:consent:0198ff00-0000-7000-8000-000000000001";

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    schema_accepts_from("mimi-operations.schema.json", fragment, value)
}

fn schema_accepts_from(document: &str, fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value =
        serde_json::from_slice(&fs::read(artifacts.join("schemas").join(document)).unwrap())
            .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            format!("test:mimi-{fragment}"),
            schema,
            format!("#/$defs/{fragment}"),
        )
        .unwrap();
    registry
        .validate_value(&format!("test:mimi-{fragment}"), value)
        .is_ok()
}

fn assert_closed_roundtrip<T: DeserializeOwned + Serialize>(fragment: &str, value: Value) {
    assert!(
        schema_accepts(fragment, &value),
        "schema rejected {fragment}"
    );
    let parsed: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    let mut extra = value;
    extra["legacy_status"] = json!("accepted");
    assert!(!schema_accepts(fragment, &extra));
    assert!(serde_json::from_value::<T>(extra).is_err());
}

#[test]
fn key_material_reuses_closed_native_claim_without_a_second_mimi_carrier() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/keypackage-lifecycle-fixture.json")).unwrap(),
    )
    .unwrap();
    let mut request = fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "local_and_remote_claim_share_closed_authorization_carrier")
        .unwrap()["instance"]
        .clone();
    request["required_capabilities"] = json!(["mimi.content.v1"]);
    let schema = "keypackage-operations.schema.json";
    let request_fragment = "keypackages_claim_request_body";
    assert!(schema_accepts_from(schema, request_fragment, &request));
    let parsed: PeerKeyPackagesClaimRequestBody = serde_json::from_value(request.clone()).unwrap();
    parsed.validate_shape().unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), request);
    for field in ["requester_id", "epoch", "proofs", "group_info"] {
        let mut legacy = request.clone();
        legacy[field] = json!("retired");
        assert!(!schema_accepts_from(schema, request_fragment, &legacy));
        assert!(serde_json::from_value::<PeerKeyPackagesClaimRequestBody>(legacy).is_err());
    }
    let pending =
        json!({"claim_request_id": parsed.claim_request_id, "state":"pending", "retry_after_ms":1});
    assert!(schema_accepts_from(
        schema,
        "peer_keypackages_claim_command_outcome",
        &pending
    ));
    serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(pending)
        .unwrap()
        .validate_command_shape()
        .unwrap();
    let unknown = json!({"claim_request_id": parsed.claim_request_id, "state":"unknown"});
    assert!(!schema_accepts_from(
        schema,
        "peer_keypackages_claim_command_outcome",
        &unknown
    ));
    assert!(
        serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(unknown)
            .unwrap()
            .validate_command_shape()
            .is_err()
    );
    for retired in [
        json!({"keypackages":[]}),
        json!({"group_info":{"mls_group_id":MLS_GROUP,"epoch":1,"group_info":"YQ"}}),
    ] {
        assert!(serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(retired).is_err());
    }
    let old: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/mimi-operations.schema.json")).unwrap(),
    )
    .unwrap();
    for retired in [
        "group_info",
        "keypackage",
        "mimi_key_material_request_body",
        "mimi_key_material_outcome",
    ] {
        assert!(old["$defs"].get(retired).is_none());
    }
}

#[test]
fn report_abuse_claim_and_full_commit_refs_are_closed() {
    use arkret_wire::{
        AccountId, ActorId, CommitStreamRef, CommittedEventRef, DidCoreId, EventId, RealmCommitId,
        RealmId, ScopeRef,
    };

    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:reporter.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let reference = |byte, position| CommittedEventRef {
        event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32]),
        commit_id: RealmCommitId::from_digest([byte; 32]),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: position,
    };
    let mut value = json!({
        "reporter_authority": {
            "actor_id": actor,
            "membership_ref": reference(0x11, 7),
            "room_binding_ref": reference(0x22, 8),
            "expires_at": "2026-09-23T13:40:00.000Z",
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:reporter.example#device-1",
                "payload_digest": format!("sha256:{}", "0".repeat(64)),
                "created_at": "2026-09-23T13:30:00.000Z",
                "domain": "ak.mimi_reporter_authority_proof.v1",
                "audience": "ak:did_core:web:facade.example",
                "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
            }
        },
        "report_claim": {
            "realm_id": realm_id,
            "scope_ref": ScopeRef::Realm { realm_id: realm_id.clone() },
            "target_ref": EVENT,
            "report_reason_code": "spam"
        }
    });
    assert_closed_roundtrip::<MimiReportAbuseRequestBody>(
        "mimi_report_abuse_request_body",
        value.clone(),
    );
    let mut request: MimiReportAbuseRequestBody = serde_json::from_value(value.clone()).unwrap();
    request.reporter_authority.proof.payload_digest = request.payload_digest().unwrap();
    request.validate().unwrap();
    let signed_bytes = request.reporter_authority_binding_bytes().unwrap();
    request.report_claim.target_ref =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x33; 32]).to_string();
    assert!(request.validate().is_err());
    assert!(request.reporter_authority_binding_bytes().is_err());
    request.reporter_authority.proof.payload_digest = request.payload_digest().unwrap();
    assert_ne!(
        signed_bytes,
        request.reporter_authority_binding_bytes().unwrap()
    );
    value["report_event"] = json!({});
    assert!(!schema_accepts("mimi_report_abuse_request_body", &value));
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(value.clone()).is_err());
    value.as_object_mut().unwrap().remove("report_event");
    value["reporter_authority"]["membership_ref"] = json!(EVENT);
    assert!(!schema_accepts("mimi_report_abuse_request_body", &value));
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(value).is_err());
}

#[test]
fn room_update_and_notify_are_closed() {
    assert_closed_roundtrip::<MimiRoomUpdateRequestBody>(
        "mimi_room_update_request_body",
        json!({
            "mls_group_id": MLS_GROUP,
            "update": {
                "kind": "receipt",
                "payload": {
                    "content_type": "application/octet-stream",
                    "payload_digest": format!("sha256:{}", "1".repeat(64))
                }
            }
        }),
    );
    assert_closed_roundtrip::<MimiRoomUpdateOutcome>(
        "mimi_room_update_outcome",
        json!({"accepted": true}),
    );
    let missing_binding_event: MimiRoomUpdateRequestBody = serde_json::from_value(json!({
        "mls_group_id": MLS_GROUP,
        "update": {
            "kind": "ak.mimi.room_binding",
            "payload": {
                "content_type": "application/octet-stream",
                "payload_digest": format!("sha256:{}", "1".repeat(64))
            }
        }
    }))
    .unwrap();
    assert!(missing_binding_event.validate().is_err());
    assert_closed_roundtrip::<MimiNotifyRequestBody>(
        "mimi_notify_request_body",
        json!({"notification": {"kind": "receipt"}}),
    );
    assert_closed_roundtrip::<MimiNotifyOutcome>("mimi_notify_outcome", json!({"accepted": true}));
}

#[test]
fn consent_outcomes_have_no_retired_status() {
    assert_closed_roundtrip::<MimiRequestConsentOutcome>(
        "mimi_request_consent_outcome",
        json!({"consent_id": CONSENT}),
    );
    assert_closed_roundtrip::<MimiUpdateConsentOutcome>(
        "mimi_update_consent_outcome",
        json!({
            "consent_id": CONSENT,
            "decision": "accept",
            "updated_at": "2026-09-21T00:00:00.000Z",
            "event_ref": EVENT
        }),
    );
}
