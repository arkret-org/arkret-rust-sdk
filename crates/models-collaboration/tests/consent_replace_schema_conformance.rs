//! Run every formal simplification shape through its schema and shared SDK type.

use std::fs;

use arkret_models_collaboration::consent_operations::{
    ConsentCurrentReadRequestBody, ConsentCurrentRow, ConsentRequestRequestBody,
};
use arkret_models_collaboration::events_payloads::consent::ConsentReplacePayload;
use arkret_models_collaboration::events_payloads::direct_conversation::{
    DirectConversationBindingCurrentValue, DirectConversationBoundPayload,
};
use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantineEntry, HolderQuarantineInvalidation,
};
use arkret_models_collaboration::message_authoring::MessageAuthoringIntent;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn typed<T: DeserializeOwned + Serialize>(value: &Value) -> Result<Value, String> {
    let parsed: T = serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    serde_json::to_value(parsed).map_err(|error| error.to_string())
}

fn sdk_value(definition: &str, value: &Value) -> Result<Value, String> {
    match definition {
        "consent_replace_payload" => {
            let parsed: ConsentReplacePayload =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            parsed.validate().map_err(|error| error.to_string())?;
            serde_json::to_value(parsed).map_err(|error| error.to_string())
        }
        "consent_result" => {
            let parsed: ConsentCurrentRow =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            parsed.value.validate().map_err(|error| error.to_string())?;
            serde_json::to_value(parsed).map_err(|error| error.to_string())
        }
        "consent_current_read_request_body" => typed::<ConsentCurrentReadRequestBody>(value),
        "consent_request_request_body" => typed::<ConsentRequestRequestBody>(value),
        "direct_conversation_binding_value" => {
            typed::<DirectConversationBindingCurrentValue>(value)
        }
        "direct_conversation_bound_payload" => typed::<DirectConversationBoundPayload>(value),
        "message_authoring_intent" => typed::<MessageAuthoringIntent>(value),
        "quarantine_entry" => typed::<HolderQuarantineEntry>(value),
        "consent_revoke_invalidation" => typed::<HolderQuarantineInvalidation>(value),
        other => panic!("formal case has no SDK executor: {other}"),
    }
}

#[test]
fn every_formal_case_has_matching_schema_and_sdk_decisions_without_losing_optional_fields() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/protocol-simplification-fixture.json")).unwrap(),
    )
    .unwrap();
    let cases = fixture["schema_validation_cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    let mut registry =
        arkret_schema_conformance::schema_registry_from_spec_artifacts(&artifacts).unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let reference = case["schema_ref"].as_str().unwrap();
        let (file, fragment) = reference.split_once('#').unwrap();
        let schema: Value =
            serde_json::from_slice(&fs::read(artifacts.join(file)).unwrap()).unwrap();
        registry
            .register_reference_document(schema.clone())
            .unwrap();
        let key = format!("test:simplification:{name}");
        registry
            .register_fragment(&key, schema, format!("#{fragment}"))
            .unwrap();
        let value = &case["instance"];
        let expected = case["expect_valid"].as_bool().unwrap();
        let schema_result = registry.validate_value(&key, value);
        assert_eq!(
            schema_result.is_ok(),
            expected,
            "formal schema case {name}: {schema_result:?}"
        );
        let sdk = sdk_value(fragment.strip_prefix("/$defs/").unwrap(), value);
        assert_eq!(sdk.is_ok(), expected, "SDK case {name}: {sdk:?}");
        if expected {
            assert_eq!(
                sdk.unwrap(),
                *value,
                "complete original fields changed in {name}"
            );
        }
    }
}

#[test]
fn consent_introduction_is_an_event_id_and_current_revision_is_not_its_wire_shape() {
    use arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence;
    use serde_json::json;
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry =
        arkret_schema_conformance::schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/invite-delivery-request.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let key = "test:consent-introduction";
    registry
        .register_fragment(key, schema, "#/$defs/introduction_evidence")
        .unwrap();
    let event_id = "ak:event:ARf0hBMoVkQqflOWgdkxNzM3DDLeIZcTJgfcuk16MrSh";
    let valid = json!({"kind":"consent_grant","consent_grant_ref":event_id});
    let invalid_ref = json!({"kind":"consent_grant","consent_grant_ref":{
        "event_id":event_id,
        "commit_id":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        "stream_ref":{"kind":"realm","realm_id":"ak:realm:AZocxLUuB-7lfxVbVJzNCcxSEn-aDa07Di6MnigFwGfd"},
        "stream_position":12
    }});
    let mut extra = valid.clone();
    extra["consent_id"] = json!("not-a-native-selector");
    for (value, expected) in [(valid, true), (invalid_ref, false), (extra, false)] {
        assert_eq!(registry.validate_value(key, &value).is_ok(), expected);
        let parsed = typed::<IntroductionEvidence>(&value);
        assert_eq!(parsed.is_ok(), expected, "SDK shape: {parsed:?}");
        if expected {
            assert_eq!(parsed.unwrap(), value);
        }
    }
}
