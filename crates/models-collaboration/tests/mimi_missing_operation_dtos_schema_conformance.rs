//! The MIMI facade's remaining current request/outcome DTOs must stay closed.

use std::fs;

use arkret_models_collaboration::mimi_operations::{
    MimiNotifyRequestBody, MimiNotifyResponseBody, MimiRequestConsentResponseBody,
    MimiRoomUpdateRequestBody, MimiRoomUpdateResponseBody, MimiUpdateConsentResponseBody,
};
use arkret_models_crypto::{KeyPackagesClaimRequestBody, PeerKeyPackagesClaimQueryResponseBody};
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
    let parsed: KeyPackagesClaimRequestBody = serde_json::from_value(request.clone()).unwrap();
    parsed.validate_shape().unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), request);
    for field in ["requester_id", "epoch", "proofs", "group_info"] {
        let mut legacy = request.clone();
        legacy[field] = json!("retired");
        assert!(!schema_accepts_from(schema, request_fragment, &legacy));
        assert!(serde_json::from_value::<KeyPackagesClaimRequestBody>(legacy).is_err());
    }
    let pending =
        json!({"claim_request_id": parsed.claim_request_id, "state":"pending", "retry_after_ms":1});
    assert!(schema_accepts_from(
        schema,
        "peer_keypackages_claim_command_response_body",
        &pending
    ));
    serde_json::from_value::<PeerKeyPackagesClaimQueryResponseBody>(pending)
        .unwrap()
        .validate_command_shape()
        .unwrap();
    let unknown = json!({"claim_request_id": parsed.claim_request_id, "state":"unknown"});
    assert!(!schema_accepts_from(
        schema,
        "peer_keypackages_claim_command_response_body",
        &unknown
    ));
    assert!(
        serde_json::from_value::<PeerKeyPackagesClaimQueryResponseBody>(unknown)
            .unwrap()
            .validate_command_shape()
            .is_err()
    );
    for retired in [
        json!({"keypackages":[]}),
        json!({"group_info":{"mls_group_id":MLS_GROUP,"epoch":"1","group_info":"YQ"}}),
    ] {
        assert!(serde_json::from_value::<PeerKeyPackagesClaimQueryResponseBody>(retired).is_err());
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
    assert_closed_roundtrip::<MimiRoomUpdateResponseBody>(
        "mimi_room_update_response_body",
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
    assert_closed_roundtrip::<MimiNotifyResponseBody>(
        "mimi_notify_response_body",
        json!({"accepted": true}),
    );
}

#[test]
fn consent_outcomes_have_no_retired_status() {
    assert_closed_roundtrip::<MimiRequestConsentResponseBody>(
        "mimi_request_consent_response_body",
        json!({"consent_id": CONSENT}),
    );
    assert_closed_roundtrip::<MimiUpdateConsentResponseBody>(
        "mimi_update_consent_response_body",
        json!({
            "consent_id": CONSENT,
            "decision": "accept",
            "updated_at": "2026-09-21T00:00:00.000Z",
            "event_ref": EVENT
        }),
    );
}
