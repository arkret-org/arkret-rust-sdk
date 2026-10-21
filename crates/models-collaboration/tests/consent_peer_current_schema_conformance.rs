//! Formal full-set Consent and immutable Direct confirmation shape vectors.
use std::fs;

use arkret_models_collaboration::call_invitation::{
    ConsentCurrentReadRequestBody, ConsentCurrentRow,
};
use arkret_models_collaboration::consent_operations::ConsentRequestRequestBody;
use arkret_models_collaboration::events_payloads::consent::ConsentReplacePayload;
use arkret_models_collaboration::events_payloads::direct_conversation::{
    DirectConversationBindingCurrentValue, DirectConversationBoundPayload,
};
use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantineEntry, HolderQuarantineInvalidation,
};
use arkret_models_collaboration::message_authoring::MessageAuthoringIntent;
use serde_json::Value;

#[test]
fn sdk_models_follow_the_formal_protocol_simplification_shape_vectors() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/protocol-simplification-fixture.json")).unwrap(),
    )
    .unwrap();
    for case in fixture["schema_validation_cases"].as_array().unwrap() {
        let instance = case["instance"].clone();
        let schema = case["schema_ref"].as_str().unwrap();
        let parsed = match schema {
            "schemas/event-payload.schema.json#/$defs/consent_replace_payload" => {
                serde_json::from_value::<ConsentReplacePayload>(instance)
                    .map_err(|e| e.to_string())
                    .and_then(|p| p.validate().map_err(|e| e.to_string()))
            }
            "schemas/typed-current-result.schema.json#/$defs/consent_result" => {
                serde_json::from_value::<ConsentCurrentRow>(instance)
                    .map_err(|e| e.to_string())
                    .and_then(|p| p.value.validate().map_err(|e| e.to_string()))
            }
            "schemas/consent-operations.schema.json#/$defs/consent_current_read_request_body" => {
                serde_json::from_value::<ConsentCurrentReadRequestBody>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            "schemas/consent-operations.schema.json#/$defs/consent_request_request_body" => {
                serde_json::from_value::<ConsentRequestRequestBody>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            "schemas/typed-current-result.schema.json#/$defs/direct_conversation_binding_value" => {
                serde_json::from_value::<DirectConversationBindingCurrentValue>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            "schemas/event-payload.schema.json#/$defs/direct_conversation_bound_payload" => {
                serde_json::from_value::<DirectConversationBoundPayload>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            "schemas/message-authoring.schema.json#/$defs/message_authoring_intent" => {
                serde_json::from_value::<MessageAuthoringIntent>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            "schemas/holder-quarantine.schema.json#/$defs/quarantine_entry" => {
                serde_json::from_value::<HolderQuarantineEntry>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            "schemas/holder-quarantine.schema.json#/$defs/consent_revoke_invalidation" => {
                serde_json::from_value::<HolderQuarantineInvalidation>(instance)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            _ => panic!("unmapped formal simplification schema: {schema}"),
        };
        assert_eq!(
            parsed.is_ok(),
            case["expect_valid"].as_bool().unwrap(),
            "{}: {parsed:?}",
            case["name"]
        );
    }
}

#[test]
fn replacement_preserves_explicit_empty_and_rejects_noncanonical_scope_order() {
    let value = serde_json::json!({"peer":{"kind":"actor","actor_id":{"kind":"service","service_id":"ak:did_core:web:peer.example"}},"expected_current":{"state":"never_written"},"permissions":[]});
    let mut payload: ConsentReplacePayload = serde_json::from_value(value.clone()).unwrap();
    payload.validate().unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), value);
    payload.permissions = serde_json::from_value(
        serde_json::json!([{"consent_scope":"presence"},{"consent_scope":"invite"}]),
    )
    .unwrap();
    assert!(payload.validate().is_err());
}

#[test]
fn consent_state_branches_reject_extra_members_and_explicit_nulls() {
    use arkret_models_collaboration::call_invitation::ConsentCurrentState;
    use arkret_models_collaboration::events_payloads::consent::ConsentExpectedCurrent;
    for value in [
        serde_json::json!({"state":"never_written","revision":{"commit_id":arkret_wire::RealmCommitId::from_digest([7;32]),"stream_position":1}}),
        serde_json::json!({"state":"never_written","revision":null}),
        serde_json::json!({"state":"never_written","extra":true}),
        serde_json::json!({"state":"present"}),
    ] {
        assert!(serde_json::from_value::<ConsentExpectedCurrent>(value).is_err());
    }
    for value in [
        serde_json::json!({"state":"never_written","result":{}}),
        serde_json::json!({"state":"never_written","result":null}),
        serde_json::json!({"state":"never_written","extra":true}),
        serde_json::json!({"state":"present"}),
    ] {
        assert!(serde_json::from_value::<ConsentCurrentState>(value).is_err());
    }
    assert!(
        serde_json::from_value::<ConsentExpectedCurrent>(
            serde_json::json!({"state":"never_written"})
        )
        .is_ok()
    );
    assert!(
        serde_json::from_value::<ConsentCurrentState>(serde_json::json!({"state":"never_written"}))
            .is_ok()
    );
}
