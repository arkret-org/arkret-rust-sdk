//! Compare the client/server DTOs with the live closed protocol fragments.

use arkret_models_identity::{MediaServiceBindingRequestBody, MediaServiceBindingResponseBody};
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/media-service-binding-operations.schema.json"))
            .unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment("test:media_binding".to_owned(), schema, fragment)
        .unwrap();
    registry.validate_value("test:media_binding", value).is_ok()
}

#[test]
fn media_binding_uses_session_identity_and_exact_closed_response() {
    let query = json!({
        "request_id": "ak:request:0196419b-0000-7000-8000-000000000001",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
    });
    assert!(schema_accepts(
        "#/$defs/media_service_binding_request_body",
        &query
    ));
    let request: MediaServiceBindingRequestBody = serde_json::from_value(query.clone()).unwrap();
    request.validate().unwrap();
    assert_eq!(serde_json::to_value(&request).unwrap(), query);

    let did = arkret_wire::Did::new("did:web:media.example").unwrap();
    let service = arkret_wire::project_did_to_core_id(&did).unwrap();
    let value = json!({
        "request_id": request.request_id,
        "realm_id": request.realm_id,
        "route": {
            "service_id": service,
            "service_kind": "station",
            "did": did,
            "method_history_head": "current-document",
            "version_id": "current-document",
            "resolution_event_ref": format!("did-web-document-sha256:{}", "a".repeat(64)),
            "base_url": "https://media.example/"
        },
        "signing_keys": [{
            "verification_method": "did:web:media.example#issuer",
            "public_key_base64url": arkret_canonical::base64url_encode([1u8;32])
        }],
        "observed_at": "2026-10-15T00:00:00.000Z",
        "expires_at": "2026-10-15T00:05:00.000Z"
    });
    assert!(schema_accepts(
        "#/$defs/media_service_binding_response_body",
        &value
    ));
    let outcome: MediaServiceBindingResponseBody = serde_json::from_value(value.clone()).unwrap();
    outcome.validate_for_request(&request, &service).unwrap();
    assert_eq!(serde_json::to_value(&outcome).unwrap(), value);

    for field in ["account_id", "assignment_ref", "revision"] {
        let mut extra = value.clone();
        extra[field] = json!({});
        assert!(!schema_accepts(
            "#/$defs/media_service_binding_response_body",
            &extra
        ));
        assert!(serde_json::from_value::<MediaServiceBindingResponseBody>(extra).is_err());
    }
    let mut foreign_account = query;
    foreign_account["account_id"] = json!({});
    assert!(!schema_accepts(
        "#/$defs/media_service_binding_request_body",
        &foreign_account
    ));
    assert!(serde_json::from_value::<MediaServiceBindingRequestBody>(foreign_account).is_err());

    let mut wrong_role = outcome.clone();
    wrong_role.route.service_kind = "push_gateway".to_owned();
    assert!(wrong_role.validate_for_request(&request, &service).is_err());
    let mut wrong_key = outcome;
    wrong_key.signing_keys[0].verification_method =
        arkret_wire::DidUrl::new("did:web:other.example#issuer").unwrap();
    assert!(wrong_key.validate_for_request(&request, &service).is_err());
}
