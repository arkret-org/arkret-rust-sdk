use arkret_wire::{
    AccountId, ActorId, Audience, CriticalExtension, DidCoreId, DidUrl, Hash, ProducerEventProof,
    ProofBindingRequirements, RealmId,
};
use chrono::Utc;
use serde_json::json;

fn test_realm_id() -> RealmId {
    RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
}

fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
    ))
}

fn valid_proof() -> ProducerEventProof {
    ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "header.payload.signature".to_owned(),
    }
}

#[test]
fn payload_proof_uses_the_same_compact_jws_syntax_as_event_proof() {
    let event = valid_proof();
    let mut proof = arkret_wire::PayloadProof {
        kind: event.kind,
        verification_method: event.verification_method,
        payload_digest: event.event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    for (jws, accepted) in [
        ("test-detached-jws", false),
        ("", false),
        ("header.signature", false),
        ("header..signature.extra", false),
        ("header..signature=", false),
        ("header..signature", true),
        ("header.payload.signature", true),
    ] {
        proof.jws = jws.to_owned();
        assert_eq!(proof.validate().is_ok(), accepted, "{jws}");
        assert_eq!(proof.validate_production().is_ok(), accepted, "{jws}");
    }
}

#[test]
fn proof_validate_rejects_empty_fields() {
    // `verification_method` is a `DidUrl`; an empty value is unrepresentable,
    // so the runtime emptiness check was removed with the migration. See
    // `proof_verification_method_rejects_non_did_url` below.
    let mut proof = valid_proof();
    proof.jws = "".to_owned();
    assert!(proof.validate().is_err());

    let mut proof = valid_proof();
    proof.kind = "".to_owned();
    assert!(proof.validate().is_err());
}

#[test]
fn proof_validate_accepts_valid_proof() {
    assert!(valid_proof().validate().is_ok());
}

#[test]
fn proof_validate_production_rejects_dev_kinds() {
    for kind in &["dev", "test", "mock", "stub", "dummy"] {
        let mut proof = valid_proof();
        proof.kind = kind.to_string();
        assert!(
            proof.validate_production().is_err(),
            "should reject kind: {kind}"
        );
    }
}

#[test]
fn proof_wrapper_rejects_duplicate_outer_algorithm_selector() {
    let mut value = serde_json::to_value(valid_proof()).unwrap();
    value["alg"] = json!("Ed25519");
    let error = serde_json::from_value::<ProducerEventProof>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field `alg`"));
}

#[test]
fn proof_validate_binding_matches_expected_fields() {
    let proof = valid_proof();
    let expected = proof.binding_payload(&actor());
    assert!(proof.validate_binding(&expected).is_ok());
}

#[test]
fn proof_validate_binding_rejects_mismatched_verification_method() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&actor());
    expected.verification_method = DidUrl::new("did:webvh:z6mkfixture:bob.example#key-1").unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_payload_digest() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&actor());
    expected.payload_digest =
        Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_domain() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&actor());
    expected.domain = Some("other.example".to_owned());
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_audience() {
    let mut proof = valid_proof();
    proof.audience = Some(Audience::Single("svc-a".to_owned()));
    let mut expected = proof.binding_payload(&actor());
    expected.audience = Some(Audience::Single("svc-b".to_owned()));
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_accepts_multi_audience_covering_required_context() {
    let mut proof = valid_proof();
    proof.audience = Some(Audience::Multiple(vec![
        "did:webvh:z6mkfixture:service-a.example".to_owned(),
        "did:webvh:z6mkfixture:service-b.example".to_owned(),
    ]));
    let mut expected = proof.binding_payload(&actor());
    expected.audience = Some(Audience::Single(
        "did:webvh:z6mkfixture:service-b.example".to_owned(),
    ));
    assert!(proof.validate_binding(&expected).is_ok());
}

#[test]
fn proof_validate_binding_ignores_domain_and_audience_when_context_is_local() {
    let mut proof = valid_proof();
    proof.domain = Some("ak:trust_domain:example.net".to_owned());
    proof.audience = Some(Audience::Single(
        "did:webvh:z6mkfixture:service.example".to_owned(),
    ));
    let mut expected = proof.binding_payload(&actor());
    expected.domain = None;
    expected.audience = None;
    assert!(proof.validate_binding(&expected).is_ok());
}

#[test]
fn proof_validate_rejects_empty_domain_or_audience() {
    let mut proof = valid_proof();
    proof.domain = Some(" ".to_owned());
    assert!(proof.validate().is_err());

    let mut proof = valid_proof();
    proof.audience = Some(Audience::Multiple(vec![]));
    assert!(proof.validate().is_err());

    let mut proof = valid_proof();
    proof.audience = Some(Audience::Multiple(vec![
        "svc-a".to_owned(),
        "svc-a".to_owned(),
    ]));
    assert!(proof.validate().is_err());
}

#[test]
fn proof_validate_binding_rejects_excessive_time_drift() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&actor());
    expected.created_at = "2026-04-26T01:00:00.000Z".parse().unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn event_validate_proof_bindings_checks_digest_match() {
    let event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: test_realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let event_digest = Hash::new(digest).unwrap();
    let jws = arkret_wire::test_support::structural_only_detached_jws(&event_digest);
    let proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws,
    };

    let mut signed_event = event;
    signed_event.producer_proof = Some(proof.into());
    assert!(
        signed_event
            .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256,)
            .is_ok()
    );
}

#[test]
fn event_validate_proof_bindings_rejects_mismatched_digest() {
    let event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: test_realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let event_digest =
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let jws = arkret_wire::test_support::structural_only_detached_jws(&event_digest);
    let bad_proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws,
    };

    let mut signed_event = event;
    signed_event.producer_proof = Some(bad_proof.into());
    assert!(
        signed_event
            .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256,)
            .is_err()
    );
}

#[test]
fn event_validate_proof_bindings_with_context_requires_cross_domain_binding() {
    let event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: test_realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let event_digest = Hash::new(digest).unwrap();
    let jws = arkret_wire::test_support::structural_only_detached_jws(&event_digest);
    let proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest,
        created_at: Utc::now(),
        domain: None,
        audience: Some(Audience::Single(
            "did:webvh:z6mkfixture:service.example".to_owned(),
        )),
        proof_purpose: None,
        jws,
    };
    let mut signed_event = event;
    signed_event.producer_proof = Some(proof.into());
    let error = signed_event
        .validate_proof_bindings_with_context_and_digest_suite(
            Some("ak:trust_domain:example.net".to_owned()),
            Some(Audience::Single(
                "did:webvh:z6mkfixture:service.example".to_owned(),
            )),
            ProofBindingRequirements::cross_domain(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("proof_binding_missing"),
        "{error}"
    );
    signed_event
        .producer_proof
        .as_mut()
        .expect("producer proof")
        .domain = Some("ak:trust_domain:example.net".to_owned());
    assert!(
        signed_event
            .validate_proof_bindings_with_context_and_digest_suite(
                Some("ak:trust_domain:example.net".to_owned()),
                Some(Audience::Single(
                    "did:webvh:z6mkfixture:service.example".to_owned()
                )),
                ProofBindingRequirements::cross_domain(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_ok()
    );
}

#[test]
fn critical_extension_uses_spec_extension_scope_field() {
    let extension: CriticalExtension = serde_json::from_value(json!({
        "id": "ak.feature.policy_gate.v1",
        "extension_scope": "payload",
        "schema_ref": "ak.schema.policy.v1",
        "profile_ref": "ak.profile.policy.v1",
        "parameters": {"mode": "strict"},
        "material_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "evidence_ref": "ak:event:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
        "fail_closed": true
    }))
    .unwrap();

    assert_eq!(extension.extension_scope, "payload");
    let value = serde_json::to_value(extension).unwrap();
    assert_eq!(value["extension_scope"], "payload");
    assert!(value.get("scope").is_none());

    let error = serde_json::from_value::<CriticalExtension>(json!({
        "id": "ak.feature.policy_gate.v1",
        "scope": "payload",
        "fail_closed": true
    }))
    .unwrap_err();
    assert!(error.to_string().contains("scope"), "{error}");
}

#[test]
fn proof_verification_method_rejects_non_did_url() {
    // `ProducerEventProof.verification_method: DidUrl` replaces the old
    // `String` + emptiness/`starts_with("did:")` checks.
    assert!(DidUrl::new("").is_err());
    assert!(DidUrl::new("not-a-did").is_err());
    // Bare DID (no `#fragment`) is not a verification method.
    assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example").is_err());
    assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").is_ok());
}
