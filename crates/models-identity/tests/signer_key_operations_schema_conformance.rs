//! The self signer-key DTOs remain byte-for-byte aligned with the published
//! closed request and outcome fragments.

use std::fs;
use std::path::PathBuf;

use arkret_models_identity::signer_key_operations::{
    SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn schema_value() -> Value {
    let path = artifacts_dir()
        .join("schemas")
        .join("signer-key-operations.schema.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("schema artifact must be valid JSON")
}

fn validate_fragment(fragment: &str, value: &Value) {
    let mut registry: ProtocolSchemaRegistry = schema_registry_from_spec_artifacts(artifacts_dir())
        .expect("the spec artifacts must produce a schema registry");
    let schema = schema_value();
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    let schema_id = format!("test:signer-key-operations{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap_or_else(|error| panic!("{fragment}: {error}"));
    registry
        .validate_value(&schema_id, value)
        .unwrap_or_else(|error| panic!("{fragment} rejected the document: {error}"));
}

fn assert_schema_and_serde<T>(fragment: &str, value: Value)
where
    T: DeserializeOwned + serde::Serialize,
{
    validate_fragment(fragment, &value);
    let parsed: T = serde_json::from_value(value.clone()).expect("SDK must accept schema value");
    assert_eq!(
        serde_json::to_value(parsed).expect("SDK value serializes"),
        value
    );
}

fn historical_selector() -> Value {
    json!({
        "verification_mode": "historical_event",
        "sender_kind": "agent",
        "actor": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:agent.example",
                "station_id": "ak:did_core:web:station.example"
            }
        },
        "verification_method": "did:web:agent.example#runtime-1",
        "committed_event_ref": {
            "event_id": "ak:event:ARTzU1T6HTPffn8VGBicK6XWx4KIC4PXvv0NX-EMSj4G",
            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
            },
            "stream_position": 12
        }
    })
}

#[test]
fn historical_request_and_station_response_match_the_published_schema() {
    let request = json!({
        "request_id": "ak:request:01904100-0000-7000-8000-000000000001",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
        "recipient_account_id": {
            "principal_id": "ak:did_core:web:recipient.example",
            "station_id": "ak:did_core:web:station.example"
        },
        "queries": [historical_selector()]
    });
    assert_schema_and_serde::<SignerKeysQueryRequestBody>("#/$defs/query_request_body", request);

    let outcome = json!({
        "request_id": "ak:request:01904100-0000-7000-8000-000000000001",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
        "recipient_account_id": {
            "principal_id": "ak:did_core:web:recipient.example",
            "station_id": "ak:did_core:web:station.example"
        },
        "results": [{
            "selector": historical_selector(),
            "status": "resolved",
            "key": {
                "public_key_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "authorization_ref": {
                    "event_id": "ak:event:Aao964Xuq1Q7PmnLt9I97ih00Qs2N6qMkBgKgYCvUFFe",
                    "commit_id": "ak:realm_commit:AdA0TA9zF1BPiudM7qe4WqKZLjMn0r7--gKAHqstAWDZ",
                    "stream_ref": {
                        "kind": "realm",
                        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
                    },
                    "stream_position": 7
                },
                "revision": {
                    "commit_id": "ak:realm_commit:AQPhm6Di_JMyu-JM932ww_EvyQU0dIIEO2ykFmYb9nD5",
                    "stream_position": 15
                },
                "governance_generation": 4
            },
            "accepted_at": "2026-09-20T00:00:00.000Z"
        }]
    });
    assert_schema_and_serde::<SignerKeysQueryOutcome>("#/$defs/query_outcome", outcome);
}

#[test]
fn human_current_privacy_fixture_matches_sdk_and_schema() {
    use arkret_models_identity::signer_key_operations::SignerKeyQueryOutcome;
    let fixture: Value = serde_json::from_str(
        &fs::read_to_string(
            artifacts_dir().join("fixtures/current-signer-contact-endpoint-fixture.json"),
        )
        .unwrap(),
    )
    .unwrap();
    for case in fixture["schema_validation_cases"].as_array().unwrap() {
        let schema = case["schema_ref"].as_str().unwrap();
        if !schema.starts_with("schemas/signer-key-operations.schema.json") {
            continue;
        }
        let instance = case["instance"].clone();
        let parsed = serde_json::from_value::<SignerKeyQueryOutcome>(instance.clone());
        if case["expect_valid"] == true {
            validate_fragment(
                &format!("#{}", schema.split_once('#').unwrap().1),
                &instance,
            );
            let parsed = parsed.unwrap();
            let realm = "ak:realm:AZocxLUuB-7lfxVbVJzNCcxSEn-aDa07Di6MnigFwGfd"
                .parse()
                .unwrap();
            parsed.validate(&realm).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), instance);
        } else {
            assert!(parsed.is_err(), "{}", case["name"]);
        }
    }
}
