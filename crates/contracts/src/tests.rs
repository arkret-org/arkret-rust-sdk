use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{Duration, Utc};
use cokret_core::{Did, FederationTransactionRequestBody, Hash};
use serde_json::json;

#[test]
fn builtin_operation_ids_are_unique() {
    let ids = cokret_core::BUILT_IN_OPERATION_KINDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), cokret_core::BUILT_IN_OPERATION_KINDS.len());
}

#[test]
fn core_registry_matches_spec_operation_registry_when_available() {
    let path = spec_operation_registry_path();

    let registry = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let registry: serde_json::Value = serde_json::from_str(&registry)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    let spec_ids = registry
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("{} has no operations array", path.display()))
        .iter()
        .map(|operation| {
            operation
                .get("operation_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("operation without operation_id in {}", path.display()))
        })
        .collect::<BTreeSet<_>>();
    let builtin_ids =
        cokret_core::BUILT_IN_OPERATION_KINDS.iter().copied().collect::<BTreeSet<_>>();

    let missing_from_core = spec_ids.difference(&builtin_ids).copied().collect::<Vec<_>>();
    let extra_in_core = builtin_ids.difference(&spec_ids).copied().collect::<Vec<_>>();

    assert!(
        missing_from_core.is_empty(),
        "core registry missing spec operations {missing_from_core:?}"
    );
    assert!(
        extra_in_core.is_empty(),
        "core registry has operations outside spec {extra_in_core:?}"
    );
}

#[test]
fn push_bridge_describe_serde_shape_is_stable() {
    let value = json!({
        "contract": "ck.push.bridge.v1",
        "version": "1.0.0",
        "api_base_path": "/_cokret/edge/push",
        "spec_version": crate::push::EXPECTED_SPEC_VERSION,
        "gateway": {
            "service_did": "did:web:push.example",
            "supported_profiles": ["fcm"],
            "supported_providers": ["fcm"],
            "auth_modes": ["http-message-signature"]
        },
        "notify": {
            "notify_path": "/_cokret/edge/push/notify",
            "operation_id": "ck.edge.push.notify",
            "request_id_header": "X-Cokret-Request-Id",
            "idempotency_key_header": "X-Cokret-Idempotency-Key",
            "origin_service_did_header": "X-Cokret-Origin-Service-Did",
            "destination_service_did_header": "X-Cokret-Destination-Service-Did",
            "max_request_size_bytes": 16384,
            "dedup_ttl_seconds": 300
        },
        "privacy": {
            "default_mode": "blind_wakeup",
            "plaintext_visibility_class": "service-visible",
            "active_reference_fields": ["event_id"]
        }
    });

    let response: crate::push::PushBridgeDescribeOutcome =
        serde_json::from_value(value).expect("push bridge shape decodes");
    assert!(response.warn_on_spec_version_mismatch());
    assert!(response.gateway.supports_auth_mode("HTTP-Message-Signature"));
    assert_eq!(response.notify.dedup_window(), Some(std::time::Duration::from_secs(300)));

    let encoded = serde_json::to_value(&response).expect("push bridge shape encodes");
    assert!(encoded.get("api_base_path").is_some());
    assert!(encoded.get("provider_capabilities").is_none());
    assert!(encoded["notify"].get("max_request_size_bytes").is_some());
}

#[test]
fn identity_resolve_keeps_did_document_wire_names() {
    let document = crate::identity::DidDocument::new(
        Did::new("did:web:alice.example").unwrap(),
        "did:web:alice.example#key-1",
        "z6Mkkey",
    );
    let response = crate::identity::resolve_response_from_document(document, None);
    let encoded = serde_json::to_value(response).expect("identity resolve encodes");

    assert_eq!(encoded["did_document"]["did"], "did:web:alice.example");
    assert!(encoded["did_document"]["document"].get("verificationMethod").is_some());
    assert!(encoded["did_document"]["document"].get("verification_methods").is_none());
    assert!(encoded.get("method_evidence").is_none());
}

#[test]
fn federation_envelope_serde_shape_uses_contract_hashes() {
    let origin = Did::new("did:web:a.example").unwrap();
    let destination = Did::new("did:web:b.example").unwrap();
    let payload = FederationTransactionRequestBody {
        origin: origin.clone(),
        destination: destination.clone(),
        service_binding_ref: "svc".to_owned(),
        operations: Vec::new(),
        receipts: Vec::new(),
        frontier: None,
    };

    let envelope = crate::federation::FederationTransactionEnvelope::new(
        "txn-1",
        origin,
        destination,
        Utc::now() + Duration::minutes(5),
        payload,
    )
    .expect("envelope builds");
    envelope.validate_digest().expect("content digest matches payload");

    let encoded = serde_json::to_value(&envelope).expect("federation envelope encodes");
    assert_eq!(encoded["transaction_id"], "txn-1");
    assert!(encoded.get("origin").is_some());
    assert!(encoded.get("destination").is_some());
    assert!(encoded["content_digest"].as_str().unwrap().starts_with("sha256:"));
    assert!(encoded.get("signature").is_none());

    let replay = crate::federation::FederationReplayRecord {
        transaction_id: "txn-1".to_owned(),
        content_digest: Hash::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        first_seen_at: Utc::now(),
    };
    let replay_shape = serde_json::to_value(replay).expect("replay record encodes");
    assert!(replay_shape["content_digest"].as_str().unwrap().starts_with("sha256:"));
}

#[cfg(feature = "salvo")]
#[test]
fn push_contracts_keep_salvo_schema_feature_gate() {
    fn assert_schema<T: salvo::oapi::ToSchema>() {}

    assert_schema::<crate::integration::IntegrationDescribeOutcome>();
    assert_schema::<crate::principal::PrincipalAuthBridgeDescribeOutcome>();
    assert_schema::<crate::push::PushBridgeDescribeOutcome>();
    assert_schema::<crate::push::ProviderCapabilityDescriptor>();
}

fn spec_operation_registry_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        manifest_dir
            .join("../../../cokret-spec/spec/v1/artifacts/registry/operation-registry.json"),
        PathBuf::from("../cokret-spec/spec/v1/artifacts/registry/operation-registry.json"),
    ]
    .into_iter()
    .find(|path| path.exists())
    .unwrap_or_else(|| {
        panic!(
            "spec operation registry artifact is required for drift tests; looked next to {}",
            manifest_dir.display()
        )
    })
}
