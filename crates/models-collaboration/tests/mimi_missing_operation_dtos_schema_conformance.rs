//! The MIMI facade's remaining current request/outcome DTOs must stay closed.

use std::fs;

use arkret_models_collaboration::mimi_operations::{
    MimiKeyMaterialOutcome, MimiKeyMaterialRequestBody, MimiNotifyOutcome, MimiNotifyRequestBody,
    MimiRequestConsentOutcome, MimiRoomUpdateOutcome, MimiRoomUpdateRequestBody,
    MimiUpdateConsentOutcome,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const STRAND: &str = "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const DEVICE: &str = "ak:device:0198ff00-0000-7000-8000-000000000001";
const MLS_GROUP: &str = "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4";
const EVENT: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONSENT: &str = "ak:consent:0198ff00-0000-7000-8000-000000000001";

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/mimi-operations.schema.json")).unwrap(),
    )
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
fn key_material_request_and_outcome_are_closed() {
    assert_closed_roundtrip::<MimiKeyMaterialRequestBody>(
        "mimi_key_material_request_body",
        json!({
            "requester_id": "ak:did_core:web:provider.example",
            "strand_id": STRAND,
            "device_id": DEVICE
        }),
    );
    assert_closed_roundtrip::<MimiKeyMaterialOutcome>(
        "mimi_key_material_outcome",
        json!({"keypackages": []}),
    );
    assert!(
        serde_json::from_value::<MimiKeyMaterialOutcome>(json!({}))
            .unwrap()
            .validate()
            .is_err()
    );
    let empty_proofs = json!({
        "requester_id": "ak:did_core:web:provider.example",
        "strand_id": STRAND,
        "device_id": DEVICE,
        "proofs": []
    });
    assert!(!schema_accepts(
        "mimi_key_material_request_body",
        &empty_proofs
    ));
    assert!(serde_json::from_value::<MimiKeyMaterialRequestBody>(empty_proofs).is_err());
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
