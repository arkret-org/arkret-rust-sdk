//! Receiver verification is independent of the directory's own key claims.
use arkret_http_client::mimi_directory::MimiDirectoryAuthority;
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use arkret_models_identity::DidDocument;
use arkret_wire::{Did, MimiUri};
use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000, 0).unwrap()
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[31; 32])
}
fn document() -> DidDocument {
    serde_json::from_value(json!({
        "id":"did:web:provider.example",
        "verificationMethod":[{"id":"did:web:provider.example#assertion", "type":"Multikey",
            "controller":"did:web:provider.example",
            "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key().verifying_key().to_bytes())}],
        "assertionMethod":["did:web:provider.example#assertion"]
    })).unwrap()
}
fn authority_with(document: DidDocument) -> MimiDirectoryAuthority {
    MimiDirectoryAuthority::new(
        arkret_wire::project_did_to_core_id(&Did::new("did:web:provider.example").unwrap())
            .unwrap(),
        document,
        "https://provider.example/_arkret/open/mimi"
            .parse()
            .unwrap(),
        chrono::Duration::minutes(5),
    )
    .unwrap()
}
fn authority() -> MimiDirectoryAuthority {
    authority_with(document())
}
fn sign(mut directory: ProviderDirectory) -> ProviderDirectory {
    directory.proof.0.payload_digest = directory.payload_digest().unwrap();
    directory.proof.0.jws = arkret_signatures::sign_ed25519_detached_jws(
        &key(),
        &directory.proof_binding_bytes().unwrap(),
    )
    .unwrap();
    directory
}
fn directory() -> ProviderDirectory {
    sign(serde_json::from_value(json!({
        "schema":"ak.schema.mimi_interop.v1","service_id":"ak:did_core:web:provider.example",
        "service_kind":"mimi_provider_facade","supported_profiles":["ak.profile.mimi_interop.v1"],
        "mimi":{
            "protocol_draft":"draft-ietf-mimi-protocol-06","content_draft":"draft-ietf-mimi-content-08",
            "room_policy_draft":"draft-ietf-mimi-room-policy-03","identifier_draft":"draft-kohbrok-mimi-identifiers-01",
            "base_url":"https://provider.example/_arkret/open/mimi","provider_id":"mimi://provider.example",
            "endpoints":[{"endpoint_id":"notify","relative_path":"/_arkret/open/mimi/strands/{strand_id}/notify"}],
            "features":["notify"],"mls_cipher_suites":["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "content_profiles":["application/mimi-content"],"room_policy_components":["membership"]
        },
        "proof":{"kind":"detached_jws","verification_method":"did:web:provider.example#assertion",
            "created_at":arkret_canonical::format_timestamp_canonical(now()),
            "payload_digest":format!("sha256:{}","0".repeat(64)),"jws":"eyJhbGciOiJFZDI1NTE5In0..AA"}
    })).unwrap())
}
fn accepts(value: ProviderDirectory) -> bool {
    authority()
        .verify(
            value,
            Some(&MimiUri::new("mimi://provider.example").unwrap()),
            &["notify".into()],
            now(),
        )
        .is_ok()
}

#[test]
fn full_binding_accepts_and_derives_only_registered_root_relative_urls() {
    let verified = authority().verify(directory(), None, &[], now()).unwrap();
    let url = verified.endpoint("notify").unwrap();
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://provider.example"
    );
    assert!(url.path().starts_with("/_arkret/open/mimi/strands/"));
    assert!(url.path().ends_with("/notify"));
    assert!(verified.endpoint("unregistered").is_none());
    let binding: serde_json::Value =
        serde_json::from_slice(&directory().proof_binding_bytes().unwrap()).unwrap();
    assert_eq!(binding["context"], "ak.mimi_provider_directory_proof.v1");
    assert_eq!(binding.as_object().unwrap().len(), 9);
    assert!(binding.get("proof").is_none());
}

#[test]
fn projection_digest_and_all_security_metadata_substitutions_fail() {
    let original = serde_json::to_value(directory()).unwrap();
    for (pointer, replacement) in [
        ("/mimi/endpoints/0/relative_path", json!("/different")),
        ("/mimi/mls_cipher_suites/0", json!("different")),
        (
            "/mimi/content_profiles/0",
            json!("text/plain;charset=utf-8"),
        ),
        ("/mimi/room_policy_components/0", json!("roles")),
        (
            "/proof/created_at",
            json!(arkret_canonical::format_timestamp_canonical(
                now() - chrono::Duration::seconds(1)
            )),
        ),
        (
            "/proof/verification_method",
            json!("did:web:other.example#assertion"),
        ),
        (
            "/proof/payload_digest",
            json!(format!("sha256:{}", "f".repeat(64))),
        ),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            !accepts(serde_json::from_value(value).unwrap()),
            "{pointer}"
        );
    }
}

#[test]
fn projection_only_and_adjacent_context_signatures_are_not_directory_proofs() {
    let mut value = directory();
    value.proof.0.jws = arkret_signatures::sign_ed25519_detached_jws(
        &key(),
        &value.unsigned_projection_bytes().unwrap(),
    )
    .unwrap();
    assert!(!accepts(value));
    let mut value = directory();
    let mut binding: serde_json::Value =
        serde_json::from_slice(&value.proof_binding_bytes().unwrap()).unwrap();
    binding["context"] = json!(arkret_wire::ProofContextId::EVENT_PROOF_V1);
    value.proof.0.jws = arkret_signatures::sign_ed25519_detached_jws(
        &key(),
        &arkret_canonical::canonical_json_bytes(&binding).unwrap(),
    )
    .unwrap();
    assert!(!accepts(value));
}

#[test]
fn current_assertion_authority_and_requested_bindings_are_independent() {
    let mut doc = document();
    doc.raw_properties
        .insert("assertionMethod".into(), json!([]));
    assert!(
        authority_with(doc)
            .verify(directory(), None, &[], now())
            .is_err()
    );
    let mut doc = document();
    let wrong_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
    );
    doc.verification_methods
        .values_mut()
        .for_each(|value| *value = wrong_key.clone());
    doc.raw_properties.get_mut("verificationMethod").unwrap()[0]["publicKeyMultibase"] =
        json!(wrong_key);
    assert!(
        authority_with(doc)
            .verify(directory(), None, &[], now())
            .is_err()
    );
    assert!(
        authority()
            .verify(
                directory(),
                Some(&MimiUri::new("mimi://other.example").unwrap()),
                &[],
                now()
            )
            .is_err()
    );
    assert!(
        authority()
            .verify(directory(), None, &["report_abuse".into()], now())
            .is_err()
    );
    let mut value = directory();
    value.service_id = "ak:did_core:web:other.example".parse().unwrap();
    assert!(!accepts(sign(value)));
    let mut value = directory();
    value.mimi.base_url = "https://other.example/_arkret/open/mimi".into();
    assert!(!accepts(sign(value)));
}

#[test]
fn fresh_signed_metadata_is_required_and_cannot_be_rewritten() {
    for seconds in [-301, 1] {
        let mut value = directory();
        value.proof.0.created_at = now() + chrono::Duration::seconds(seconds);
        assert!(!accepts(sign(value)));
    }
    let mut value = directory();
    value.proof.0.created_at = now() - chrono::Duration::seconds(300);
    assert!(accepts(sign(value)));
}

#[test]
fn closed_capabilities_required_members_and_unsafe_paths_fail_even_when_signed() {
    for path in [
        "https://evil.example/path",
        "//evil.example/path",
        "/a?b",
        "/a#b",
        "/a b",
        "/a\\b",
        "/a/../b",
        "/a/./b",
        "/a/%2e%2e/b",
        "/a/%2F/b",
        "/a/%5c/b",
        "/a/%zz",
    ] {
        let mut value = directory();
        value.mimi.endpoints[0].relative_path = path.into();
        assert!(!accepts(sign(value)), "{path}");
    }
    let original = serde_json::to_value(directory()).unwrap();
    for member in [
        "endpoints",
        "features",
        "mls_cipher_suites",
        "content_profiles",
        "room_policy_components",
    ] {
        let mut value = original.clone();
        value["mimi"][member] = json!([]);
        assert!(
            !accepts(sign(serde_json::from_value(value).unwrap())),
            "empty {member}"
        );
        let mut value = original.clone();
        value["mimi"].as_object_mut().unwrap().remove(member);
        assert!(
            serde_json::from_value::<ProviderDirectory>(value).is_err(),
            "missing {member}"
        );
    }
    let mut value = directory();
    value.mimi.features.push("notify".into());
    assert!(!accepts(sign(value)));
    let mut value = directory();
    value.mimi.features = vec!["notify".into(), "consent".into()];
    assert!(!accepts(sign(value)));
    let mut value = directory();
    value.mimi.endpoints.push(value.mimi.endpoints[0].clone());
    assert!(!accepts(sign(value)));
    let mut value = directory();
    value.mimi.protocol_draft = "unsupported".into();
    assert!(!accepts(sign(value)));
    let mut value = original;
    value["mimi"]["endpoints"][0]["base_url"] = json!("https://evil.example");
    assert!(serde_json::from_value::<ProviderDirectory>(value).is_err());
}

#[test]
fn unknown_extensions_neither_change_signature_nor_effective_routing() {
    let mut value = directory();
    value
        .extra
        .insert("base_url".into(), json!("https://evil.example"));
    value.mimi.extra.insert(
        "endpoint_override".into(),
        json!({"notify":"https://evil.example"}),
    );
    let verified = authority().verify(value, None, &[], now()).unwrap();
    assert!(verified.directory().extra.is_empty());
    assert!(verified.directory().mimi.extra.is_empty());
    assert_eq!(
        verified.endpoint("notify").unwrap().host_str(),
        Some("provider.example")
    );
}

#[test]
fn https_and_egress_are_independent_of_a_valid_directory_signature() {
    let service = directory().service_id;
    for base in [
        "http://provider.example/mimi",
        "https://user@provider.example/mimi",
        "https://provider.example/mimi?query",
        "https://provider.example/mimi#fragment",
    ] {
        assert!(
            MimiDirectoryAuthority::new(
                service.clone(),
                document(),
                base.parse().unwrap(),
                chrono::Duration::minutes(5)
            )
            .is_err()
        );
    }
    let mut value = directory();
    value.mimi.base_url = "https://127.0.0.1/mimi".into();
    let authority = MimiDirectoryAuthority::new(
        service,
        document(),
        value.mimi.base_url.parse().unwrap(),
        chrono::Duration::minutes(5),
    )
    .unwrap();
    assert!(authority.verify(sign(value), None, &[], now()).is_err());
    for (host, permitted) in [("10.0.0.10", true), ("169.254.169.254", false)] {
        let mut value = directory();
        value.mimi.base_url = format!("https://{host}/mimi");
        let authority = MimiDirectoryAuthority::new(
            value.service_id.clone(),
            document(),
            value.mimi.base_url.parse().unwrap(),
            chrono::Duration::minutes(5),
        )
        .unwrap()
        .with_egress_policy(arkret_egress_policy::OutboundPolicy::controlled_network(
            false,
        ));
        assert_eq!(
            authority.verify(sign(value), None, &[], now()).is_ok(),
            permitted,
            "{host}"
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn forbidden_directory_target_is_rejected_before_transport() {
    let client = arkret_http_client::Client::builder("https://127.0.0.1:9/".parse().unwrap())
        .build()
        .unwrap();
    let authority = MimiDirectoryAuthority::new(
        directory().service_id,
        document(),
        "https://127.0.0.1:9/_arkret/open/mimi".parse().unwrap(),
        chrono::Duration::minutes(5),
    )
    .unwrap();
    assert!(
        matches!(client.mimi_provider_directory(&authority,None,&[]).await,Err(arkret_http_client::Error::Protocol(message)) if message.contains("loopback"))
    );
}
