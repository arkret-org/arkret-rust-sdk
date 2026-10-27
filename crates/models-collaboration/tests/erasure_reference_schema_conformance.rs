//! Structural scope parity only; no native erasure authority is claimed.
use arkret_models_collaboration::governance::erasure::{
    ErasureScope, ErasureStorageBoundary, ErasureSubject, ErasureSubjectKind,
};
use serde_json::Value;

#[test]
fn receipt_and_stub_scopes_accept_the_same_canonical_principal_reference() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry =
        arkret_schema_conformance::schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/erasure-verification-stub.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment("test:erasure-scope", schema.clone(), "#/$defs/scope")
        .unwrap();
    registry
        .register_fragment("test:erasure-subject", schema, "#/$defs/subject")
        .unwrap();
    for principal in [
        "ak:did_core:web:alice.example",
        "ak:did_core:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey",
    ] {
        let scope = ErasureScope {
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            realm_id: None,
            target_refs: Some(vec![principal.into()]),
            retention_policy_id: None,
            service_scope: Some("scope-structure-component".into()),
        };
        let wire = serde_json::to_value(scope).unwrap();
        registry
            .validate_value("test:erasure-scope", &wire)
            .unwrap();
        let stub_scope: ErasureScope = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(stub_scope).unwrap(), wire);
        let mut invalid = wire.clone();
        invalid["target_refs"][0] = "arbitrary-private-string".into();
        assert!(
            registry
                .validate_value("test:erasure-scope", &invalid)
                .is_err()
        );
    }
    let event = arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]);
    for (kind, subject_ref) in [
        (
            ErasureSubjectKind::Principal,
            "ak:did_core:web:alice.example".to_owned(),
        ),
        (
            ErasureSubjectKind::Realm,
            arkret_wire::RealmId::from_event_id(&event).to_string(),
        ),
        (ErasureSubjectKind::Event, event.to_string()),
        (
            ErasureSubjectKind::Blob,
            arkret_wire::BlobRef::from_bytes(b"erasure schema component").to_string(),
        ),
        (
            ErasureSubjectKind::Device,
            "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
        ),
        (
            ErasureSubjectKind::AccountPrivateState,
            format!("sha256:{}", "07".repeat(32)),
        ),
        (
            ErasureSubjectKind::AccountPrivateState,
            format!("blake3:{}", "08".repeat(32)),
        ),
    ] {
        let scope = serde_json::json!({"storage_boundary":"service_defined", "service_scope":"structural-reference-test", "target_refs":[subject_ref]});
        registry
            .validate_value("test:erasure-scope", &scope)
            .unwrap();
        let scope: ErasureScope = serde_json::from_value(scope).unwrap();
        assert_eq!(scope.target_refs, Some(vec![subject_ref.clone()]));
        let wire = serde_json::to_value(ErasureSubject { kind, subject_ref }).unwrap();
        registry
            .validate_value("test:erasure-subject", &wire)
            .unwrap();
    }
    let retired = serde_json::json!({"kind":"space","subject_ref":"ak:space:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"});
    assert!(serde_json::from_value::<ErasureSubject>(retired.clone()).is_err());
    assert!(
        registry
            .validate_value("test:erasure-subject", &retired)
            .is_err()
    );
}

#[test]
fn stub_reference_is_closed_and_links_the_subject_without_claiming_acceptance() {
    use arkret_models_collaboration::events_payloads::event_wire::VerificationStub;
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let registry =
        arkret_schema_conformance::schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let event = arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9; 32]);
    let token = event.as_str().strip_prefix("ak:event:").unwrap();
    // Structural coordinates only; this test supplies no signature or native proof.
    let wire = serde_json::json!({
        "stub_schema":"ak.schema.erasure_verification_stub.v1",
        "subject":{"kind":"event","subject_ref":event},
        "scope":{"storage_boundary":"canonical_log_minimization"},
        "receipt_id":"ak:receipt:01964137-0000-7000-8000-000000000001",
        "trigger":{"kind":"event","event_id":event},
        "event_digest":event.event_digest(),
        "completed_at":"2026-10-26T00:00:00.000Z",
        "committed_event_ref":{
            "event_id":event,
            "commit_id":format!("ak:realm_commit:{token}"),
            "stream_ref":{"kind":"realm","realm_id":arkret_wire::RealmId::from_event_id(&event)},
            "stream_position":0
        }
    });
    let schema = "ak.schema.erasure_verification_stub.v1";
    registry.validate_value(schema, &wire).unwrap();
    let stub: VerificationStub = serde_json::from_value(wire.clone()).unwrap();
    stub.validate_linkage().unwrap();
    assert_eq!(serde_json::to_value(stub).unwrap(), wire);
    for retired in ["commit_inclusion", "commit_ref"] {
        let mut invalid = wire.clone();
        let reference = invalid
            .as_object_mut()
            .unwrap()
            .remove("committed_event_ref")
            .unwrap();
        invalid[retired] = reference;
        assert!(registry.validate_value(schema, &invalid).is_err());
        assert!(serde_json::from_value::<VerificationStub>(invalid).is_err());
    }
    for incomplete in [
        serde_json::json!({}),
        serde_json::json!({"commit_id":format!("ak:realm_commit:{token}")}),
    ] {
        let mut invalid = wire.clone();
        invalid["committed_event_ref"] = incomplete;
        assert!(registry.validate_value(schema, &invalid).is_err());
        assert!(serde_json::from_value::<VerificationStub>(invalid).is_err());
    }
    for member in [
        "event_digest",
        "retained_digests",
        "committed_event_ref",
        "redaction_authorization_ref",
    ] {
        let mut invalid = wire.clone();
        invalid[member] = Value::Null;
        assert!(
            registry.validate_value(schema, &invalid).is_err(),
            "{member}"
        );
        assert!(
            serde_json::from_value::<VerificationStub>(invalid).is_err(),
            "{member}"
        );
    }
    let mut mismatch = wire.clone();
    mismatch["committed_event_ref"]["event_id"] = serde_json::to_value(
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [8; 32]),
    )
    .unwrap();
    assert!(
        serde_json::from_value::<VerificationStub>(mismatch)
            .unwrap()
            .validate_linkage()
            .is_err()
    );
    let mut non_event = wire.clone();
    non_event["subject"] =
        serde_json::json!({"kind":"principal","subject_ref":"ak:did_core:web:alice.example"});
    assert!(registry.validate_value(schema, &non_event).is_err());
    assert!(
        serde_json::from_value::<VerificationStub>(non_event)
            .unwrap()
            .validate_linkage()
            .is_err()
    );
    let mut bad_digest = wire;
    bad_digest["event_digest"] = format!("sha256:{}", "00".repeat(32)).into();
    assert!(
        serde_json::from_value::<VerificationStub>(bad_digest)
            .unwrap()
            .validate_linkage()
            .is_err()
    );
}

#[test]
fn receipt_and_stub_preserve_signed_optional_presence_exactly() {
    use arkret_models_collaboration::events_payloads::event_wire::VerificationStub;
    use arkret_models_collaboration::governance::erasure::ErasureReceipt;
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let registry =
        arkret_schema_conformance::schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let event = arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9; 32]);
    // Shape and canonical-byte regressions only. No test object is signed or
    // asserted to be native evidence, an accepted Event, or a legal-hold proof.
    for targets_present in [false, true] {
        for hold in [
            None,
            Some(Value::Null),
            Some(serde_json::json!(
                "ak:policy:01964137-0000-7000-8000-000000000001"
            )),
            Some(serde_json::json!(format!("blake3:{}", "09".repeat(32)))),
        ] {
            for peers_present in [false, true] {
                let mut scope = serde_json::json!({"storage_boundary":"service_defined","service_scope":"canonical-presence-component"});
                if targets_present {
                    scope["target_refs"] = serde_json::json!([]);
                }
                let mut stub = serde_json::json!({
                    "stub_schema":"ak.schema.erasure_verification_stub.v1",
                    "subject":{"kind":"principal","subject_ref":"ak:did_core:web:alice.example"},
                    "scope":scope, "receipt_id":"ak:receipt:01964137-0000-7000-8000-000000000001",
                    "trigger":{"kind":"event","event_id":event}, "completed_at":"2026-10-26T00:00:00.000Z"
                });
                if let Some(value) = &hold {
                    stub["legal_hold_ref"] = value.clone();
                }
                let mut receipt = serde_json::json!({
                    "receipt_id":stub["receipt_id"],"trigger":stub["trigger"],
                    "schema":"ak.schema.erasure_receipt.v1","issuer_id":"ak:did_core:web:issuer.example",
                    "subject":stub["subject"],"scope":scope,"outcome":"partially_completed","erased_classes":[],
                    "retained_stub_digest":arkret_canonical::canonical_sha256(&stub).unwrap(),
                    "completed_at":stub["completed_at"],
                    "proofs":[{"verification_method":"did:web:issuer.example#notary-key", "payload_digest":format!("sha256:{}", "00".repeat(32)),"signature":"unsigned-structural-component"}]
                });
                if let Some(value) = &hold {
                    receipt["legal_hold_ref"] = value.clone();
                }
                if peers_present {
                    receipt["peer_receipts"] = serde_json::json!([]);
                }
                let typed: ErasureReceipt = serde_json::from_value(receipt.clone()).unwrap();
                receipt["proofs"][0]["payload_digest"] =
                    serde_json::to_value(typed.canonical_payload_digest().unwrap()).unwrap();
                registry
                    .validate_value("ak.schema.erasure_receipt.v1", &receipt)
                    .unwrap();
                registry
                    .validate_value("ak.schema.erasure_verification_stub.v1", &stub)
                    .unwrap();
                let typed: ErasureReceipt = serde_json::from_value(receipt.clone()).unwrap();
                let typed_stub: VerificationStub = serde_json::from_value(stub.clone()).unwrap();
                assert_eq!(serde_json::to_value(&typed).unwrap(), receipt);
                assert_eq!(serde_json::to_value(&typed_stub).unwrap(), stub);
                assert_eq!(
                    arkret_canonical::canonical_json_bytes(&typed).unwrap(),
                    arkret_canonical::canonical_json_bytes(&receipt).unwrap()
                );
                assert_eq!(
                    arkret_canonical::canonical_json_bytes(&typed_stub).unwrap(),
                    arkret_canonical::canonical_json_bytes(&stub).unwrap()
                );
                typed.validate_with_retained_stub(&typed_stub).unwrap();
                let mut other_stub = typed_stub.clone();
                other_stub.scope.target_refs = if targets_present { None } else { Some(vec![]) };
                let mut other_receipt = typed.clone();
                other_receipt.retained_stub_digest = arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(&other_stub).unwrap(),
                )
                .unwrap();
                assert!(
                    other_receipt
                        .validate_with_retained_stub(&other_stub)
                        .unwrap_err()
                        .to_string()
                        .contains("stub_binding_mismatch")
                );
                for member in [
                    "issued_at",
                    "fanout_status",
                    "peer_receipts",
                    "retained_stub",
                ] {
                    let mut invalid = receipt.clone();
                    invalid[member] = Value::Null;
                    assert!(
                        registry
                            .validate_value("ak.schema.erasure_receipt.v1", &invalid)
                            .is_err(),
                        "{member}"
                    );
                    assert!(
                        serde_json::from_value::<ErasureReceipt>(invalid).is_err(),
                        "{member}"
                    );
                }
                if hold.as_ref().is_none_or(Value::is_null) {
                    let mut blocked = receipt;
                    blocked["outcome"] = "blocked_by_legal_hold".into();
                    assert!(
                        registry
                            .validate_value("ak.schema.erasure_receipt.v1", &blocked)
                            .is_err()
                    );
                    assert!(
                        serde_json::from_value::<ErasureReceipt>(blocked)
                            .unwrap()
                            .validate_minimal()
                            .is_err()
                    );
                }
            }
        }
    }
}
