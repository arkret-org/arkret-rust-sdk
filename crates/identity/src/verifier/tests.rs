/// A protocol instant is millisecond-precision, and
/// `VerifiedDidBinding::new` floors its freshness window to it. A raw
/// `Utc::now()` here would leave a fixture holding sub-millisecond digits
/// the binding cannot carry, so window assertions would compare against a
/// value no store could return.
fn protocol_now() -> DateTime<Utc> {
    arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now())
}
use std::collections::BTreeMap;

use arkret_signatures::jws::sign_jws_ed25519;
use chrono::Duration;
use ed25519_dalek::SigningKey;

use super::*;
use crate::binding::{FreshnessProfile, VerifiedDidBindingDocumentInput};
use crate::binding_digest::{EvidenceReceipt, MethodEvidence};
use crate::binding_store::InMemoryVerifiedDidBindingStore;

fn hash(seed: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("valid hash")
}

fn trust_domain() -> TrustDomainId {
    TrustDomainId::new("ak:trust_domain:local".to_owned()).expect("valid trust domain")
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn published_fixture_signing_key() -> SigningKey {
    let fixture: serde_json::Value =
        serde_json::from_slice(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../arkret-spec/spec/v1/artifacts/fixtures/crypto-signature-fixture.json",
            ))
            .unwrap(),
        )
        .unwrap();
    let seed = arkret_canonical::base64url::base64url_decode(
        fixture["vectors"][0]["test_private_key_jwk"]["d"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    SigningKey::from_bytes(seed.as_slice().try_into().unwrap())
}

fn did() -> Did {
    Did::new("did:webvh:QmS1gUenXyfWpb5krKbJbiZ93L1yJ6wJFBrf8zNNste4v9:server.example")
        .expect("valid did")
}

fn document(key_id: &str) -> DidDocument {
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key().verifying_key().as_bytes(),
    );
    DidDocument {
        id: did(),
        verification_methods: BTreeMap::from([(key_id.to_owned(), multibase)]),
        also_known_as: Vec::new(),
        updated_at: None,
        raw_properties: BTreeMap::new(),
    }
}

fn verification_method() -> DidUrl {
    DidUrl::new(format!("{}#key-1", did())).expect("valid did url")
}

fn accepted(document: &DidDocument) -> AcceptedDidBinding {
    let receipt = EvidenceReceipt::new(
        did().method(),
        document_canonical_digest(document).expect("digest"),
        &MethodEvidence::none(),
    );
    let binding = VerifiedDidBinding::from_verified_document(
        document,
        VerifiedDidBindingDocumentInput {
            trust_domain: trust_domain(),
            purpose: DidBindingPurpose::Principal,
            verification_method: Some(verification_method()),
            history_head: None,
            version_id: None,
            limited_trust: LimitedTrust::for_proofless_method(None, None).record_for(),
            evidence_digest: receipt.digest().expect("digest"),
            evidence_dependencies: receipt.evidence_dependencies().expect("dependencies"),
            policy_digest: hash(0x44),
            verified_at: protocol_now(),
            refresh_at: None,
            expires_at: None,
            status: DidBindingStatus::Active,
        },
    )
    .expect("valid binding");
    AcceptedDidBinding::new(binding, document.clone(), receipt).expect("consistent pairing")
}

#[test]
fn verify_with_document_round_trips() {
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    verify_jws_with_document(
        canonical,
        &jws,
        &verification_method(),
        &did(),
        &document(&format!("{}#key-1", did())),
    )
    .expect("verify");
}

#[test]
fn published_fixture_key_cannot_verify_a_claim_after_renaming_or_reencoding() {
    let fixture: serde_json::Value =
        serde_json::from_slice(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../arkret-spec/spec/v1/artifacts/fixtures/crypto-signature-fixture.json",
            ))
            .unwrap(),
        )
        .unwrap();
    let vector = &fixture["vectors"][0];
    let seed = arkret_canonical::base64url::base64url_decode(
        vector["test_private_key_jwk"]["d"].as_str().unwrap(),
    )
    .unwrap();
    let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
    let canonical = br#"{"claim":"accepted-only-after-verification"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key).unwrap();
    let raw_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signing_key.verifying_key().to_bytes().to_vec(),
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&jws, canonical, &raw_key)
        .expect("the published fixture signature is cryptographically valid");

    let method = DidUrl::new(format!("{}#live-key", did())).unwrap();
    let jwk = serde_json::json!({
        "x": vector["did_document_fragment"]["publicKeyJwk"]["x"],
        "kty": "OKP",
        "crv": "Ed25519"
    });
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key.verifying_key().as_bytes(),
    );
    for material in [jwk.to_string(), multibase] {
        let document = DidDocument {
            id: did(),
            verification_methods: BTreeMap::from([(method.as_str().to_owned(), material)]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        };
        let error = verify_jws_with_document(canonical, &jws, &method, &did(), &document)
            .expect_err("published key must not authorize the claim");
        let BindingVerifyError::TestMaterial(FormalTestMaterialPolicyError::Denied(denial)) = error
        else {
            panic!("expected the exact test-material denial")
        };
        assert_eq!(
            denial.published_key_fingerprint.as_deref(),
            Some(crate::test_material::PUBLISHED_TEST_KEY_FINGERPRINTS[0])
        );
        assert!(!denial.reserved_identifiers.any());
        assert!(matches!(
            verify_jws_with_document(canonical, "malformed-jws", &method, &did(), &document),
            Err(BindingVerifyError::TestMaterial(
                FormalTestMaterialPolicyError::Denied(_)
            ))
        ));
    }
}

#[test]
fn reserved_key_id_rejects_an_otherwise_valid_unlisted_claim_key() {
    let canonical = br#"{"claim":"ordinary-key"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).unwrap();
    let method = DidUrl::new(format!("{}#claim-fixture", did())).unwrap();
    let document = document(method.as_str());
    let error = verify_jws_with_document(canonical, &jws, &method, &did(), &document)
        .expect_err("reserved key id must not authorize the claim");
    let BindingVerifyError::TestMaterial(FormalTestMaterialPolicyError::Denied(denial)) = error
    else {
        panic!("expected the exact test-material denial")
    };
    assert_eq!(denial.published_key_fingerprint, None);
    assert!(denial.reserved_identifiers.key_id);
    assert!(!denial.reserved_identifiers.did);
}

#[test]
fn assertion_relationship_requires_current_membership_and_authority() {
    let method = verification_method();
    let mut pinned = document(method.as_str());
    let validate = |document: &DidDocument| {
        validate_verification_method_relationship(
            document,
            &method,
            &did(),
            DidVerificationRelationship::AssertionMethod,
        )
    };
    assert!(matches!(
        validate(&pinned),
        Err(BindingVerifyError::VerificationRelationshipMissing { .. })
    ));
    pinned.raw_properties.insert(
        "assertionMethod".to_owned(),
        serde_json::json!(["#other-key"]),
    );
    assert!(matches!(
        validate(&pinned),
        Err(BindingVerifyError::VerificationMethodRelationshipMismatch { .. })
    ));
    pinned
        .raw_properties
        .insert("assertionMethod".to_owned(), serde_json::json!(["#key-1"]));
    validate(&pinned).expect("current assertion method");
    pinned.raw_properties.insert(
        "verificationMethod".to_owned(),
        serde_json::json!([{"id": method, "controller": "did:web:other.example"}]),
    );
    assert!(matches!(
        validate(&pinned),
        Err(BindingVerifyError::VerificationMethodControllerMismatch { .. })
    ));
    pinned.id = Did::new("did:web:other.example").unwrap();
    assert!(matches!(
        validate(&pinned),
        Err(BindingVerifyError::DocumentIssuerMismatch { .. })
    ));
}

#[test]
fn normalized_assertion_relationship_preserves_membership_and_controller_checks() {
    let method = verification_method();
    let mut pinned = document(method.as_str());
    pinned
        .raw_properties
        .insert("assertionMethod".to_owned(), serde_json::json!([method]));
    let projection = arkret_models_identity::normalized_did_document(&pinned).unwrap();
    let mut normalized: DidDocument = serde_json::from_value(projection).unwrap();
    let validate = |document: &DidDocument| {
        validate_verification_method_relationship(
            document,
            &method,
            &did(),
            DidVerificationRelationship::AssertionMethod,
        )
    };
    validate(&normalized)
        .expect("the authenticated normalized form retains the same assertion authority");
    normalized
        .raw_properties
        .get_mut("verification_methods")
        .unwrap()[0]["controller_did"] = serde_json::json!("did:web:other.example");
    assert!(matches!(
        validate(&normalized),
        Err(BindingVerifyError::VerificationMethodControllerMismatch { .. })
    ));
    normalized
        .raw_properties
        .get_mut("verification_methods")
        .unwrap()[0]["controller_did"] = serde_json::to_value(did()).unwrap();
    normalized.raw_properties.insert(
        "assertion_methods".to_owned(),
        serde_json::json!([{"verification_method":"did:web:other.example#key-1"}]),
    );
    assert!(matches!(
        validate(&normalized),
        Err(BindingVerifyError::VerificationMethodRelationshipMismatch { .. })
    ));
    normalized.raw_properties.remove("assertion_methods");
    assert!(matches!(
        validate(&normalized),
        Err(BindingVerifyError::VerificationRelationshipMissing { .. })
    ));
}

#[test]
fn verify_with_document_accepts_a_relative_fragment_key_id() {
    // DID Documents commonly store `verificationMethod[].id` relative.
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    verify_jws_with_document(
        canonical,
        &jws,
        &verification_method(),
        &did(),
        &document("key-1"),
    )
    .expect("relative key id must resolve");
    verify_jws_with_document(
        canonical,
        &jws,
        &verification_method(),
        &did(),
        &document("#key-1"),
    )
    .expect("`#key-1` key id must resolve");
}

#[test]
fn verify_with_document_enforces_the_issuer_argument() {
    // The removed resolver-driven verifier took `issuer` and never used it.
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    let other = Did::new("did:webvh:z6mkfixture:other.example".to_owned()).expect("valid did");
    let error = verify_jws_with_document(
        canonical,
        &jws,
        &verification_method(),
        &other,
        &document(&format!("{}#key-1", did())),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BindingVerifyError::VerificationMethodIssuerMismatch { .. }
    ));
}

#[test]
fn verify_with_document_rejects_a_document_for_another_did() {
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    let mut foreign = document(&format!("{}#key-1", did()));
    foreign.id = Did::new("did:webvh:z6mkfixture:other.example".to_owned()).expect("valid did");
    let error = verify_jws_with_document(canonical, &jws, &verification_method(), &did(), &foreign)
        .unwrap_err();
    assert!(matches!(
        error,
        BindingVerifyError::DocumentIssuerMismatch { .. }
    ));
}

#[test]
fn verify_with_document_rejects_a_duplicate_protected_header_key() {
    // A protected header that repeats a member is not canonical JSON, so
    // the detached-JWS verifier refuses it before any signature check.
    let header = arkret_canonical::base64url_encode(br#"{"alg":"Ed25519","alg":"Ed25519"}"#);
    let signature = arkret_canonical::base64url_encode([1u8; 64]);
    let jws = format!("{header}..{signature}");
    let error = verify_jws_with_document(
        br#"{}"#,
        &jws,
        &verification_method(),
        &did(),
        &document(&format!("{}#key-1", did())),
    )
    .expect_err("a duplicate protected-header key must be rejected");
    let rendered = error.to_string();
    assert!(
        rendered.contains("duplicate key") || rendered.contains("canonical JSON"),
        "got `{rendered}`"
    );
}

#[test]
fn verify_with_document_rejects_a_tampered_payload() {
    let jws = sign_jws_ed25519(b"original", &signing_key()).expect("sign");
    let error = verify_jws_with_document(
        b"tampered",
        &jws,
        &verification_method(),
        &did(),
        &document(&format!("{}#key-1", did())),
    )
    .unwrap_err();
    assert!(matches!(error, BindingVerifyError::Proof { .. }));
}

#[test]
fn verify_with_binding_round_trips() {
    let document = document(&format!("{}#key-1", did()));
    let accepted = accepted(&document);
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    verify_jws_with_binding(canonical, &jws, &verification_method(), &accepted).expect("verify");
}

#[test]
fn verify_with_binding_refuses_a_deactivated_binding() {
    let document = document(&format!("{}#key-1", did()));
    let accepted = accepted(&document).with_binding_status(DidBindingStatus::Deactivated);
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    let error =
        verify_jws_with_binding(canonical, &jws, &verification_method(), &accepted).unwrap_err();
    assert!(matches!(
        error,
        BindingVerifyError::BindingStatusNotUsable {
            status: DidBindingStatus::Deactivated
        }
    ));
}

#[test]
fn verify_with_binding_refuses_a_different_verification_method() {
    let document = document(&format!("{}#key-1", did()));
    let accepted = accepted(&document);
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    let other = DidUrl::new(format!("{}#key-2", did())).expect("valid did url");
    let error = verify_jws_with_binding(canonical, &jws, &other, &accepted).unwrap_err();
    assert!(matches!(
        error,
        BindingVerifyError::BindingVerificationMethodMismatch { .. }
    ));
}

#[test]
fn verify_with_binding_serves_a_stale_binding_without_a_resolver() {
    let document = document(&format!("{}#key-1", did()));
    let accepted = accepted(&document).with_binding_status(DidBindingStatus::Stale);
    let canonical = br#"{"hello":"world"}"#;
    let jws = sign_jws_ed25519(canonical, &signing_key()).expect("sign");
    verify_jws_with_binding(canonical, &jws, &verification_method(), &accepted)
        .expect("stale bindings still verify ordinary signatures");
}

#[test]
fn freshness_requirement_gates_stale_reuse() {
    let stale = BindingFreshness::Stale {
        age: Duration::minutes(1),
    };
    let high = FreshnessRequirement {
        max_age: Some(Duration::hours(1)),
        require_fresh: true,
    };
    let accepted_only = FreshnessRequirement {
        max_age: None,
        require_fresh: false,
    };
    assert!(!freshness_satisfies(&stale, &high));
    assert!(freshness_satisfies(&stale, &accepted_only));
    assert!(!freshness_satisfies(
        &BindingFreshness::Expired,
        &accepted_only
    ));
    assert!(!freshness_satisfies(
        &BindingFreshness::Missing,
        &accepted_only
    ));
}

// ------------------------------------------------------------------
// Event proof verification against an accepted binding (DID-P1-B)
// ------------------------------------------------------------------

mod event_proof {
    use arkret_canonical::base64url::base64url_encode;
    use arkret_signatures::{
        Ed25519DetachedJwsVerifier, EventProofBuilder, sign_ed25519_detached_jws,
    };
    use arkret_wire::{EventId, RealmId, ScopeRef, proof_kind};
    use chrono::TimeZone;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").expect("valid realm")
    }

    fn event() -> Event {
        Event {
            event_id: EventId::new("ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6")
                .expect("valid event id"),
            kind: "ak.message.create".into(),
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            actor_id: ActorId::service(
                arkret_wire::project_did_to_core_id(&did()).expect("registered DID adapter"),
            ),
            created_at: Utc
                .with_ymd_and_hms(2026, 4, 26, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            semantic_refs: Vec::new(),
            payload: BTreeMap::from([("body".to_owned(), serde_json::json!("hello"))]),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            producer_proof: None,
        }
    }

    fn envelope_bytes(event: &Event) -> Vec<u8> {
        EventProofBuilder::new()
            .envelope_bytes(event)
            .expect("canonical envelope bytes")
    }

    /// A proof whose `jws` still has to be filled in.
    fn unsigned_proof(event: &Event) -> ProducerEventProof {
        ProducerEventProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: verification_method(),
            event_digest: Hash::new(arkret_canonical::canonical::sha256_digest(envelope_bytes(
                event,
            )))
            .expect("valid digest"),
            created_at: arkret_canonical::canonical::normalize_timestamp_canonical(
                Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 0)
                    .single()
                    .expect("valid timestamp"),
            ),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        }
    }

    /// Sign the canonical proof **binding object** — the bytes an Event
    /// proof actually covers (`encoding.md` §6).
    fn signed_proof(event: &Event) -> ProducerEventProof {
        let mut proof = unsigned_proof(event);
        let binding_bytes = proof
            .canonical_binding_bytes(&event.actor_id)
            .expect("binding bytes");
        proof.jws = sign_ed25519_detached_jws(&signing_key(), &binding_bytes).expect("sign");
        proof
    }

    /// Hand-assemble a detached JWS with an arbitrary protected header, so
    /// the header hygiene of the Event profile can be exercised directly.
    fn detached_jws_with_header(header: serde_json::Value, payload: &[u8]) -> String {
        use ed25519_dalek::Signer;
        let header_b64 = base64url_encode(
            arkret_canonical::canonical::canonical_json_bytes(&header).expect("header bytes"),
        );
        let signing_input = format!("{header_b64}.{}", base64url_encode(payload));
        let signature = signing_key().sign(signing_input.as_bytes());
        format!(
            "{header_b64}..{}",
            base64url_encode(signature.to_bytes().as_slice())
        )
    }

    fn public_key() -> PublicKeyMaterial {
        PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key().verifying_key().to_bytes().to_vec(),
        }
    }

    #[test]
    fn verifies_against_an_accepted_binding_without_a_resolver() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let proof = signed_proof(&event);
        verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .expect("an accepted binding verifies an Event proof");
    }

    #[test]
    fn published_fixture_key_cannot_authorize_a_valid_event_proof_after_rehosting() {
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../arkret-spec/spec/v1/artifacts/fixtures/crypto-signature-fixture.json",
            ))
            .unwrap(),
        )
        .unwrap();
        let vector = &fixture["vectors"][0];
        let seed = arkret_canonical::base64url::base64url_decode(
            vector["test_private_key_jwk"]["d"].as_str().unwrap(),
        )
        .unwrap();
        let fixture_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
        let x = vector["did_document_fragment"]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap();
        assert_eq!(
            arkret_canonical::base64url::base64url_decode(x).unwrap(),
            fixture_key.verifying_key().as_bytes()
        );
        let event = event();
        let envelope = envelope_bytes(&event);
        let mut proof = unsigned_proof(&event);
        let binding_bytes = proof.canonical_binding_bytes(&event.actor_id).unwrap();
        proof.jws = sign_ed25519_detached_jws(&fixture_key, &binding_bytes).unwrap();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: fixture_key.verifying_key().as_bytes().to_vec(),
        };
        arkret_signatures::verify_ed25519_detached_jws_proof(
            &proof,
            &envelope,
            &event.actor_id,
            &public_key,
        )
        .expect("the published fixture signature satisfies the Event proof profile");

        let jwk = format!(r#"{{"x":"{x}","crv":"Ed25519","kty":"OKP"}}"#);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            fixture_key.verifying_key().as_bytes(),
        );
        for material in [jwk, multibase] {
            let mut pinned = document(verification_method().as_str());
            pinned
                .verification_methods
                .insert(verification_method().as_str().to_owned(), material);
            let accepted = accepted(&pinned);
            let error =
                verify_event_proof_with_binding(&proof, &envelope, &event.actor_id, &accepted)
                    .expect_err("published signing material must not authorize an Event");
            let BindingVerifyError::TestMaterial(FormalTestMaterialPolicyError::Denied(denial)) =
                error
            else {
                panic!("expected exact test-material denial")
            };
            assert_eq!(
                denial.published_key_fingerprint.as_deref(),
                Some(crate::test_material::PUBLISHED_TEST_KEY_FINGERPRINTS[0])
            );
            assert!(!denial.reserved_identifiers.any());
            assert!(matches!(
                verify_event_proof_with_binding(
                    &ProducerEventProof {
                        jws: "malformed-jws".to_owned(),
                        ..proof.clone()
                    },
                    &envelope,
                    &event.actor_id,
                    &accepted,
                ),
                Err(BindingVerifyError::TestMaterial(
                    FormalTestMaterialPolicyError::Denied(_)
                ))
            ));
        }
    }

    #[test]
    fn signature_must_cover_the_binding_object_not_the_envelope() {
        // The single most important reason this cannot route through
        // `verify_jws_with_binding`: that path verifies the JWS over the
        // bytes it is handed, and the Event profile signs a different
        // transcript.
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let bytes = envelope_bytes(&event);
        let mut proof = unsigned_proof(&event);
        proof.jws = sign_ed25519_detached_jws(&signing_key(), &bytes).expect("sign");

        let error = verify_event_proof_with_binding(&proof, &bytes, &event.actor_id, &accepted)
            .unwrap_err();
        assert!(
            matches!(error, BindingVerifyError::Proof { .. }),
            "a signature over the envelope bytes must not satisfy an Event proof, got {error}"
        );
        // ...while the generic detached-JWS primitive happily accepts it,
        // which is exactly the relaxation this API exists to prevent.
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(&proof.jws, &bytes, &public_key())
            .expect("the generic profile verifies the envelope-bytes signature");
    }

    #[test]
    fn a_kid_bearing_protected_header_is_rejected() {
        // `DetachedJwsProtectedHeader` is `deny_unknown_fields` and has no
        // `kid`; the generic `JwsProtectedHeader` accepts and returns one.
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let mut proof = unsigned_proof(&event);
        let binding_bytes = proof
            .canonical_binding_bytes(&event.actor_id)
            .expect("binding bytes");
        proof.jws = detached_jws_with_header(
            serde_json::json!({"alg": "Ed25519", "kid": verification_method().as_str()}),
            &binding_bytes,
        );

        let error = verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .unwrap_err();
        assert!(
            matches!(error, BindingVerifyError::Proof { .. }),
            "the Event profile must reject a `kid` header member, got {error}"
        );
        // The generic profile accepts the very same JWS — proving the
        // header hygiene is genuinely stricter here, not incidentally so.
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(&proof.jws, &binding_bytes, &public_key())
            .expect("the generic profile accepts a `kid` header");
    }

    #[test]
    fn an_unsupported_protected_header_algorithm_is_rejected() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let mut proof = unsigned_proof(&event);
        let binding_bytes = proof
            .canonical_binding_bytes(&event.actor_id)
            .expect("binding bytes");
        proof.jws = detached_jws_with_header(serde_json::json!({"alg": "ES256"}), &binding_bytes);

        let error = verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .unwrap_err();
        assert!(
            matches!(error, BindingVerifyError::Proof { .. }),
            "an unsupported protected header algorithm must be rejected, got {error}"
        );
        let generic_error = Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(&proof.jws, &binding_bytes, &public_key())
            .unwrap_err();
        assert!(
            matches!(generic_error, arkret_signatures::VerifierError::Backend(_)),
            "the generic Ed25519 verifier must also reject ES256, got {generic_error}"
        );
    }

    #[test]
    fn a_crit_header_is_rejected() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let mut proof = unsigned_proof(&event);
        let binding_bytes = proof
            .canonical_binding_bytes(&event.actor_id)
            .expect("binding bytes");
        proof.jws = detached_jws_with_header(
            serde_json::json!({"alg": "Ed25519", "crit": ["b64"]}),
            &binding_bytes,
        );
        assert!(
            verify_event_proof_with_binding(
                &proof,
                &envelope_bytes(&event),
                &event.actor_id,
                &accepted,
            )
            .is_err()
        );
    }

    #[test]
    fn a_tampered_event_breaks_the_digest_binding() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let proof = signed_proof(&event);
        let mut tampered = event.clone();
        tampered
            .payload
            .insert("body".to_owned(), serde_json::json!("goodbye"));

        let error = verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&tampered),
            &event.actor_id,
            &accepted,
        )
        .unwrap_err();
        assert!(matches!(error, BindingVerifyError::Proof { .. }));
    }

    #[test]
    fn a_deactivated_binding_stops_authorizing_event_proofs() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document).with_binding_status(DidBindingStatus::Deactivated);
        let event = event();
        let proof = signed_proof(&event);
        let error = verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::BindingStatusNotUsable {
                status: DidBindingStatus::Deactivated
            }
        ));
    }

    #[test]
    fn a_stale_binding_still_verifies_ordinary_event_proofs() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document).with_binding_status(DidBindingStatus::Stale);
        let event = event();
        let proof = signed_proof(&event);
        verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .expect("TTL expiry alone must not turn an ordinary Event into a resolution");
    }

    #[test]
    fn a_method_the_binding_did_not_accept_is_refused() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let mut proof = signed_proof(&event);
        proof.verification_method = DidUrl::new(format!("{}#key-2", did())).expect("valid did url");
        let error = verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::BindingVerificationMethodMismatch { .. }
        ));
    }

    #[test]
    fn a_method_controlled_by_another_did_is_refused() {
        let document = document(&format!("{}#key-1", did()));
        let accepted = accepted(&document);
        let event = event();
        let mut proof = signed_proof(&event);
        proof.verification_method =
            DidUrl::new("did:webvh:z6mkfixture:other.example#key-1".to_owned())
                .expect("valid did url");
        let error = verify_event_proof_with_binding(
            &proof,
            &envelope_bytes(&event),
            &event.actor_id,
            &accepted,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BindingVerifyError::VerificationMethodIssuerMismatch { .. }
        ));
    }

    #[test]
    fn key_material_comes_from_the_pinned_document_for_every_id_spelling() {
        // The `#key-1` spelling is the one that used to need a downstream
        // retry; all three must resolve identically.
        for key_id in [
            format!("{}#key-1", did()),
            "key-1".to_owned(),
            "#key-1".to_owned(),
        ] {
            let document = document(&key_id);
            let accepted = accepted(&document);
            let material = public_key_material_from_binding(&accepted, &verification_method())
                .unwrap_or_else(|error| panic!("`{key_id}` must resolve: {error}"));
            assert_eq!(material, public_key());
        }
    }
}

// ------------------------------------------------------------------
// Verification-method lookup convergence (DID-P1-B, gap 4)
// ------------------------------------------------------------------

#[test]
fn lookups_agree_on_every_document_shape() {
    // `resolve_verification_method_key_from_document` used to lack the
    // `#key-1` branch that this module's private lookup had, so a document
    // could verify a JWS and still fail key resolution. Both must now
    // accept and reject exactly the same shapes.
    let target = format!("{}#key-1", did());
    for key_id in [target.clone(), "key-1".to_owned(), "#key-1".to_owned()] {
        let document = document(&key_id);
        let resolver_side =
            crate::resolve_verification_method_key_from_document(&document, &target);
        let verifier_side = lookup_verification_method_material(&document, &target);
        assert!(
            resolver_side.is_ok(),
            "resolver-side lookup must accept `{key_id}`"
        );
        assert!(
            verifier_side.is_ok(),
            "verifier-side lookup must accept `{key_id}`"
        );
    }

    let absent = document("key-9");
    assert!(crate::resolve_verification_method_key_from_document(&absent, &target).is_err());
    assert!(lookup_verification_method_material(&absent, &target).is_err());
}

// ------------------------------------------------------------------
// Authority path: evidence comes out of the resolver, not the caller
// ------------------------------------------------------------------

struct OneShotResolver {
    document: DidDocument,
    method_evidence: MethodEvidence,
    calls: std::sync::atomic::AtomicUsize,
}

impl OneShotResolver {
    fn new(document: DidDocument) -> Self {
        Self {
            document,
            method_evidence: MethodEvidence::none(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn with_evidence(document: DidDocument, method_evidence: MethodEvidence) -> Self {
        Self {
            document,
            method_evidence,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl DidResolver for OneShotResolver {
    fn supports(&self, _did: &Did) -> bool {
        true
    }

    fn resolve_did(&self, _did: &Did) -> crate::Result<ResolvedDid> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ResolvedDid::new(
            self.document.clone(),
            self.method_evidence.clone(),
        ))
    }
}

/// A `high` tier profile: no stale window, one hour of freshness.
fn high_profile() -> FreshnessProfile {
    FreshnessProfile {
        freshness_profile_id: "ak.did_freshness.test_high.v1".to_owned(),
        risk_tier: crate::binding::DidFreshnessRiskTier::High,
        did_method_selector: vec!["*".to_owned()],
        fresh_for_seconds: Some(3_600),
        stale_grace_seconds: None,
        hard_expiry_seconds: Some(86_400),
        stale_behavior: crate::binding::StaleBehavior::SynchronousRefreshOrFailClosed,
    }
}

fn request() -> BindingResolveRequest {
    BindingResolveRequest {
        did: did(),
        trust_domain: trust_domain(),
        purpose: DidBindingPurpose::Principal,
        policy_digest: hash(0x44),
        verification_method: Some(verification_method()),
        freshness: high_profile(),
    }
}

#[test]
fn authority_rejects_published_key_before_accepting_a_new_binding() {
    let fixture_key = published_fixture_signing_key();
    let claim = br#"{"claim":"valid-published-key"}"#;
    let jws = sign_jws_ed25519(claim, &fixture_key).unwrap();
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &jws,
            claim,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: fixture_key.verifying_key().as_bytes().to_vec(),
            },
        )
        .expect("the publicly known private key makes a valid signature");

    let x = arkret_canonical::base64url_encode(fixture_key.verifying_key().as_bytes());
    let jwk = format!(r#"{{"x":"{x}","crv":"Ed25519","kty":"OKP"}}"#);
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        fixture_key.verifying_key().as_bytes(),
    );
    for material in [jwk, multibase] {
        let mut pinned = document(verification_method().as_str());
        pinned
            .verification_methods
            .insert(verification_method().as_str().to_owned(), material);
        let resolver = OneShotResolver::new(pinned);
        let store = InMemoryVerifiedDidBindingStore::default();
        let error = resolve_and_verify_binding(&resolver, &store, &request(), protocol_now())
            .expect_err("published material must not become an accepted binding");
        let BindingResolveError::TestMaterial(FormalTestMaterialPolicyError::Denied(denial)) =
            error
        else {
            panic!("expected the exact test-material denial")
        };
        assert_eq!(
            denial.published_key_fingerprint.as_deref(),
            Some(crate::test_material::PUBLISHED_TEST_KEY_FINGERPRINTS[0])
        );
        assert!(!denial.reserved_identifiers.any());
        assert_eq!(resolver.calls(), 1);
        assert!(store.snapshot().is_empty());
    }
}

#[test]
fn authority_evicts_a_previously_cached_published_key_without_fallback() {
    let fixture_key = published_fixture_signing_key();
    let material = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        fixture_key.verifying_key().as_bytes(),
    );
    let mut pinned = document(verification_method().as_str());
    pinned
        .verification_methods
        .insert(verification_method().as_str().to_owned(), material);
    let store = InMemoryVerifiedDidBindingStore::default();
    store.accept(accepted(&pinned)).unwrap();
    assert_eq!(store.len(), 1);
    let resolver = OneShotResolver::new(document(verification_method().as_str()));

    let error = resolve_and_verify_binding(&resolver, &store, &request(), protocol_now())
        .expect_err("a cached published key cannot remain an authority basis");
    assert!(matches!(
        error,
        BindingResolveError::TestMaterial(FormalTestMaterialPolicyError::Denied(_))
    ));
    assert_eq!(
        resolver.calls(),
        0,
        "rejection must not retry a weaker path"
    );
    assert!(
        store.snapshot().is_empty(),
        "the old binding must be removed"
    );
    assert!(store.get(&request().key(), protocol_now()).is_none());
}

#[test]
fn authority_checks_the_registered_p256_and_mldsa_public_key_encodings() {
    let fixture: serde_json::Value =
        serde_json::from_slice(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../arkret-spec/spec/v1/artifacts/fixtures/crypto-signature-fixture.json",
            ))
            .unwrap(),
        )
        .unwrap();
    let p256 = &fixture["vectors"][1]["did_document_fragment"]["publicKeyJwk"];
    let mldsa_public = fixture["vectors"][2]["public_key_base64url"]
        .as_str()
        .unwrap();
    let materials = [
        (
            serde_json::json!({"kty":"EC", "crv":"P-256", "x":p256["x"], "y":p256["y"]})
                .to_string(),
            crate::test_material::PUBLISHED_TEST_KEY_FINGERPRINTS[1],
        ),
        (
            serde_json::json!({"kty":"AKP", "alg":"ML-DSA-65", "pub":mldsa_public}).to_string(),
            crate::test_material::PUBLISHED_TEST_KEY_FINGERPRINTS[2],
        ),
    ];
    for (material, fingerprint) in materials {
        let mut pinned = document(verification_method().as_str());
        pinned
            .verification_methods
            .insert(verification_method().as_str().to_owned(), material);
        let store = InMemoryVerifiedDidBindingStore::default();
        let error = resolve_and_verify_binding(
            &OneShotResolver::new(pinned),
            &store,
            &request(),
            protocol_now(),
        )
        .unwrap_err();
        let BindingResolveError::TestMaterial(FormalTestMaterialPolicyError::Denied(denial)) =
            error
        else {
            panic!("registered P-256 and ML-DSA keys must be denied")
        };
        assert_eq!(
            denial.published_key_fingerprint.as_deref(),
            Some(fingerprint)
        );
        assert!(store.snapshot().is_empty());
    }
}

fn webvh_evidence() -> MethodEvidence {
    MethodEvidence {
        proofs: vec![crate::MethodEvidenceProof::WebvhLog(
            crate::WebvhLogEvidence {
                history_head: "3-QmFixtureHead".to_owned(),
                witnesses: vec![crate::WebvhWitnessIdentity {
                    witness_did: Did::new("did:webvh:z6mkfixture:witness.example".to_owned())
                        .expect("valid did"),
                    controlling_organization_did: Did::new(
                        "did:webvh:z6mkfixture:witness-org.example".to_owned(),
                    )
                    .expect("valid did"),
                }],
                witness_proofs_digest: hash(0x77),
            },
        )],
        history_head: Some("3-QmFixtureHead".to_owned()),
        version_id: Some("3-QmFixtureHead".to_owned()),
    }
}

/// The whole point of the resolver channel: the acceptance's evidence digest
/// is derived from what the resolver returned, and an auditor recomputes it
/// from the retained receipt.
#[test]
fn the_evidence_digest_is_recomputable_from_the_retained_receipt() {
    let resolver =
        OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence());
    let store = InMemoryVerifiedDidBindingStore::default();
    let accepted =
        resolve_and_verify_binding(&resolver, &store, &request(), protocol_now()).expect("resolve");

    assert_eq!(
        accepted.binding().evidence_digest(),
        &accepted
            .evidence_receipt()
            .digest()
            .expect("recomputed digest")
    );
    assert_ne!(
        accepted.binding().evidence_digest(),
        accepted.binding().document_digest(),
        "a canonical evidence digest is never the bare document digest"
    );
    assert_eq!(
        accepted.evidence_receipt().document_digest,
        *accepted.binding().document_digest()
    );
}

/// §5.6: the dependency record is what makes a witness revocation selective.
#[test]
fn evidence_dependencies_are_carried_and_index_the_witness() {
    let resolver =
        OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence());
    let store = InMemoryVerifiedDidBindingStore::default();
    let accepted =
        resolve_and_verify_binding(&resolver, &store, &request(), protocol_now()).expect("resolve");

    let witness = Did::new("did:webvh:z6mkfixture:witness.example".to_owned()).expect("valid did");
    assert_eq!(
        accepted.binding().evidence_dependencies().witness_dids,
        vec![witness.clone()]
    );
    assert_eq!(
        store.invalidate(&BindingInvalidation {
            evidence_witness_did: Some(witness),
            ..Default::default()
        }),
        1
    );
}

/// §5.5: an evidence-bearing method that surfaced both pins records no
/// limited trust at all; a proofless one records `method_unsupported`.
#[test]
fn limited_trust_follows_what_the_resolver_surfaced() {
    let store = InMemoryVerifiedDidBindingStore::default();
    let pinned = resolve_and_verify_binding(
        &OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence()),
        &store,
        &request(),
        protocol_now(),
    )
    .expect("resolve");
    assert_eq!(pinned.binding().limited_trust(), None);
    assert_eq!(pinned.binding().history_head(), Some("3-QmFixtureHead"));

    let proofless_store = InMemoryVerifiedDidBindingStore::default();
    let proofless = resolve_and_verify_binding(
        &OneShotResolver::new(document(&format!("{}#key-1", did()))),
        &proofless_store,
        &request(),
        protocol_now(),
    )
    .expect("resolve");
    assert_eq!(
        proofless.binding().limited_trust(),
        Some(LimitedTrust {
            history_head_status: crate::PinState::MethodUnsupported,
            version_id_status: crate::PinState::MethodUnsupported,
        })
    );
}

#[test]
fn a_store_hit_keeps_its_evidence_and_never_reaches_the_resolver_again() {
    let resolver =
        OneShotResolver::with_evidence(document(&format!("{}#key-1", did())), webvh_evidence());
    let store = InMemoryVerifiedDidBindingStore::default();
    let now = protocol_now();

    let first = resolve_and_verify_binding(&resolver, &store, &request(), now).expect("first");
    let second =
        resolve_and_verify_binding(&resolver, &store, &request(), now + Duration::minutes(1))
            .expect("store hit");

    assert_eq!(resolver.calls(), 1);
    assert_eq!(
        first.binding().evidence_digest(),
        second.binding().evidence_digest()
    );
}

/// The freshness profile is the single source of the reuse threshold,
/// `refresh_at` and `expires_at`.
#[test]
fn the_freshness_profile_drives_every_window() {
    let resolver = OneShotResolver::new(document(&format!("{}#key-1", did())));
    let store = InMemoryVerifiedDidBindingStore::default();
    let now = protocol_now();
    let request = request();
    let accepted = resolve_and_verify_binding(&resolver, &store, &request, now).expect("resolve");

    assert_eq!(accepted.binding().verified_at(), now);
    assert_eq!(
        accepted.binding().refresh_at(),
        Some(now + Duration::hours(1)),
        "refresh_at is verified_at + fresh_for_seconds"
    );
    assert_eq!(
        accepted.binding().expires_at(),
        Some(now + Duration::hours(24))
    );
    assert_eq!(
        request.freshness.requirement().max_age,
        Some(Duration::hours(1)),
        "max_age is the same fresh_for_seconds, never a second constant"
    );
    assert_eq!(store.len(), 1);
    assert!(store.get(&request.key(), now).is_some());
}
