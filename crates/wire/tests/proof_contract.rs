use arkret_wire::{
    Audience, CriticalExtension, DidCoreId, DidUrl, FeatureRef, Hash, Hlc, ProfileRef, Proof,
    ProofBindingRequirements, RealmId,
};
use chrono::Utc;
use serde_json::json;

fn test_realm_id() -> RealmId {
    RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
}

fn valid_proof() -> Proof {
    Proof {
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
    let error = serde_json::from_value::<Proof>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field `alg`"));
}

#[test]
fn proof_validate_binding_matches_expected_fields() {
    let proof = valid_proof();
    let expected = proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    assert!(proof.validate_binding(&expected).is_ok());
}

#[test]
fn proof_validate_binding_rejects_mismatched_verification_method() {
    let proof = valid_proof();
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    expected.verification_method = DidUrl::new("did:webvh:z6mkfixture:bob.example#key-1").unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_payload_digest() {
    let proof = valid_proof();
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    expected.payload_digest =
        Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_domain() {
    let proof = valid_proof();
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    expected.domain = Some("other.example".to_owned());
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_audience() {
    let mut proof = valid_proof();
    proof.audience = Some(Audience::Single("svc-a".to_owned()));
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
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
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
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
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    expected.domain = None;
    expected.audience = None;
    assert!(proof.validate_binding(&expected).is_ok());
}

#[test]
fn proof_validate_cross_domain_binding_requires_domain_and_audience() {
    let mut proof = valid_proof();
    proof.audience = Some(Audience::Single(
        "did:webvh:z6mkfixture:service.example".to_owned(),
    ));
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    expected.domain = Some("ak:trust_domain:example.net".to_owned());
    expected.audience = Some(Audience::Single(
        "did:webvh:z6mkfixture:service.example".to_owned(),
    ));
    let error = proof.validate_cross_domain_binding(&expected).unwrap_err();
    assert!(
        error.to_string().contains("proof_binding_missing"),
        "{error}"
    );

    proof.domain = Some("ak:trust_domain:example.net".to_owned());
    assert!(proof.validate_cross_domain_binding(&expected).is_ok());
}

#[test]
fn proof_validate_cross_domain_binding_requires_expected_context() {
    let mut proof = valid_proof();
    proof.domain = Some("ak:trust_domain:example.net".to_owned());
    proof.audience = Some(Audience::Single(
        "did:webvh:z6mkfixture:service.example".to_owned(),
    ));
    let expected =
        valid_proof().binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
    let error = proof.validate_cross_domain_binding(&expected).unwrap_err();
    assert!(
        error.to_string().contains("proof_binding_missing"),
        "{error}"
    );
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
    let mut expected =
        proof.binding_payload(&DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap());
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
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let digest = event.event_digest().unwrap();
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: Hash::new(digest).unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "sig".to_owned(),
    };

    let mut signed_event = event;
    signed_event.proofs = vec![proof.into()];
    assert!(signed_event.validate_proof_bindings().is_ok());
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
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let bad_proof = Proof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "sig".to_owned(),
    };

    let mut signed_event = event;
    signed_event.proofs = vec![bad_proof.into()];
    assert!(signed_event.validate_proof_bindings().is_err());
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
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let digest = event.event_digest().unwrap();
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: Hash::new(digest).unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: Some(Audience::Single(
            "did:webvh:z6mkfixture:service.example".to_owned(),
        )),
        proof_purpose: None,
        jws: "sig".to_owned(),
    };
    let mut signed_event = event;
    signed_event.proofs = vec![proof.into()];
    let error = signed_event
        .validate_proof_bindings_with_context(
            Some("ak:trust_domain:example.net".to_owned()),
            Some(Audience::Single(
                "did:webvh:z6mkfixture:service.example".to_owned(),
            )),
            ProofBindingRequirements::cross_domain(),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("proof_binding_missing"),
        "{error}"
    );
    signed_event.proofs[0].as_producer_mut().unwrap().domain =
        Some("ak:trust_domain:example.net".to_owned());
    assert!(
        signed_event
            .validate_proof_bindings_with_context(
                Some("ak:trust_domain:example.net".to_owned()),
                Some(Audience::Single(
                    "did:webvh:z6mkfixture:service.example".to_owned()
                )),
                ProofBindingRequirements::cross_domain(),
            )
            .is_ok()
    );
}

#[test]
fn event_digest_includes_schema_profiles_features_and_critical_extensions() {
    let mut event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: test_realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();
    let base_digest = event.event_digest().unwrap();

    event
        .requirements
        .schema_profile_refs
        .push(ProfileRef::new("ak.schema.core_event.v1").unwrap());
    event
        .requirements
        .required_features
        .push(FeatureRef::new("ak.feature.event_extensions.v1").unwrap());
    event
        .requirements
        .critical_extensions
        .push(CriticalExtension {
            id: "ak.feature.policy_gate.v1".to_owned(),
            extension_scope: "authz".to_owned(),
            schema_ref: Some("ak.schema.policy.v1".to_owned()),
            profile_ref: None,
            parameters: None,
            material_digest: None,
            evidence_ref: None,
            fail_closed: true,
        });

    assert_ne!(base_digest, event.event_digest().unwrap());
    let value = serde_json::to_value(&event).unwrap();
    assert!(value.get("schema_profile_refs").is_none());
    assert_eq!(
        value["requirements"]["schema"][0],
        "ak.schema.core_event.v1"
    );
    assert!(value["requirements"].get("reducer").is_none());
    assert_eq!(
        value["requirements"]["features"][0],
        "ak.feature.event_extensions.v1"
    );

    event.requirements.critical_extensions[0].fail_closed = false;
    assert!(event.validate_for_submit_structural().is_err());
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
    // `Proof.verification_method: DidUrl` replaces the old
    // `String` + emptiness/`starts_with("did:")` checks.
    assert!(DidUrl::new("").is_err());
    assert!(DidUrl::new("not-a-did").is_err());
    // Bare DID (no `#fragment`) is not a verification method.
    assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example").is_err());
    assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").is_ok());
}
