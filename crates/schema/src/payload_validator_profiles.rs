//! Executable validators for payload contracts selected outside the finite
//! event-payload JSON Schema family.

use arkret_wire::EventKind;
use serde_json::Value;

use crate::{Error, Result};

pub const JSON_SCHEMA_2020_12_DEFINITION_VALIDATOR_PROFILE: &str =
    "ak.validator.json_schema_2020_12_definition.v1";
pub const JSON_SCHEMA_2020_12_META_SCHEMA_URI: &str =
    "https://json-schema.org/draft/2020-12/schema";

#[must_use]
pub fn payload_validator_profile_id(event_kind: &EventKind) -> Option<&'static str> {
    match event_kind {
        EventKind::SchemaDefine => Some(JSON_SCHEMA_2020_12_DEFINITION_VALIDATOR_PROFILE),
        _ => None,
    }
}

fn profile_violation(message: impl Into<String>) -> Error {
    Error::Protocol(format!("schema_violation: {}", message.into()))
}

/// Run the external payload validator, when the Event kind has one registered.
///
/// Kind-bound payload JSON Schema validation must run before this function.
/// Unlisted Event kinds have no external validator and therefore return `Ok`.
pub fn validate_payload_validator_profile(event_kind: &EventKind, payload: &Value) -> Result<()> {
    let Some(profile_id) = payload_validator_profile_id(event_kind) else {
        return Ok(());
    };

    let payload = payload
        .as_object()
        .ok_or_else(|| profile_violation("ak.schema.define payload must be a JSON object"))?;
    let schema_id = payload
        .get("schema_id")
        .and_then(Value::as_str)
        .ok_or_else(|| profile_violation("ak.schema.define requires schema_id"))?;
    let document = payload
        .get("value")
        .and_then(Value::as_object)
        .ok_or_else(|| profile_violation("ak.schema.define requires an object value"))?;
    if document.get("$schema").and_then(Value::as_str) != Some(JSON_SCHEMA_2020_12_META_SCHEMA_URI)
    {
        return Err(profile_violation(format!(
            "{} requires the Draft 2020-12 meta-schema URI",
            profile_id
        )));
    }
    if document.get("$id").and_then(Value::as_str) != Some(schema_id) {
        return Err(profile_violation(
            "ak.schema.define schema_id must equal value.$id",
        ));
    }

    jsonschema::draft202012::meta::validate(&Value::Object(document.clone())).map_err(|error| {
        profile_violation(format!(
            "{} rejected the schema definition: {error}",
            profile_id
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn definition_profile_checks_meta_schema_without_resolving_instance_refs() {
        let payload = json!({
            "schema_id": "ak.schema.example.v1",
            "value": {
                "$schema": JSON_SCHEMA_2020_12_META_SCHEMA_URI,
                "$id": "ak.schema.example.v1",
                "$ref": "https://schemas.example.invalid/not-installed.json"
            }
        });
        validate_payload_validator_profile(&EventKind::SchemaDefine, &payload).unwrap();
    }

    #[test]
    fn definition_profile_rejects_invalid_keyword_shapes_and_subject_mismatch() {
        let invalid_keyword = json!({
            "schema_id": "ak.schema.example.v1",
            "value": {
                "$schema": JSON_SCHEMA_2020_12_META_SCHEMA_URI,
                "$id": "ak.schema.example.v1",
                "type": "not-a-json-schema-type"
            }
        });
        assert!(
            validate_payload_validator_profile(&EventKind::SchemaDefine, &invalid_keyword).is_err()
        );

        let mismatched_id = json!({
            "schema_id": "ak.schema.example.v1",
            "value": {
                "$schema": JSON_SCHEMA_2020_12_META_SCHEMA_URI,
                "$id": "ak.schema.other.v1",
                "type": "object"
            }
        });
        assert!(
            validate_payload_validator_profile(&EventKind::SchemaDefine, &mismatched_id).is_err()
        );
    }

    #[test]
    fn executable_dispatch_matches_the_embedded_profile_registry() {
        let registry = crate::artifacts::read_embedded_json_artifact(
            "registry/payload-validator-profile-registry.json",
        )
        .unwrap();
        let profiles = registry["profiles"].as_array().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["event_kind"], EventKind::SchemaDefine.as_str());
        assert_eq!(
            profiles[0]["validator_profile_id"],
            JSON_SCHEMA_2020_12_DEFINITION_VALIDATOR_PROFILE
        );
        assert_eq!(
            payload_validator_profile_id(&EventKind::SchemaDefine),
            Some(JSON_SCHEMA_2020_12_DEFINITION_VALIDATOR_PROFILE)
        );
    }
}
