//! Executable consumer for the spec fixture
//! `fixtures/crypto-signature-fixture.json`.
//!
//! The ed25519 detached-JWS vector is executed end-to-end at the primitive
//! level: canonical event bytes + digests, canonical binding payload +
//! digest, protected-header canonicalization, detached payload / signing
//! input reconstruction, real Ed25519 verification of the fixture JWS, and
//! deterministic re-signing with the published test key. The negative cases
//! exercise the reject paths (bit flip, truncated key, alg gate, non-empty
//! payload segment).
//!
//! Known profile divergence (reported, deliberately NOT painted over): the
//! fixture's proof transcript signs a binding object of
//! `{actor_id, created_at, domain, verification_method, event_digest,
//! payload_digest}` under a protected header
//! `{"alg":"EdDSA","kid":...,"typ":"JOSE"}`, while the SDK event-proof
//! profile (`Proof::canonical_binding_bytes` +
//! `verify_eddsa_detached_jws_proof`) signs
//! `{event_digest, actor_id, verification_method, created_at, domain?,
//! audience?}` under `{"alg":"EdDSA"}` and rejects `typ`/unknown header
//! members. The SDK therefore cannot verify this vector through its
//! high-level event-proof verifier; this file pins everything below that
//! divergence so the canonicalizer / digest / raw-signature layers carry
//! spec anchors while the transcript question is adjudicated.

use cokret_core::schema::embedded_json_artifact;
use cokret_core::{Did, Hash, Proof, base64url_decode, base64url_encode, canonical};
use cokret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use cokret_signatures::{FUTURE_ALGORITHMS, PRODUCTION_ALGORITHMS, verify_eddsa_detached_jws_proof};
use ed25519_dalek::Signer as _;
use serde_json::Value;

const FIXTURE_PATH: &str = "fixtures/crypto-signature-fixture.json";
const ED25519_VECTOR: &str = "ck.vector.encoding.crypto.ed25519_detached_jws.v1";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded crypto-signature fixture must load")
}

fn vector(fixture: &Value, name: &str) -> Value {
    fixture["vectors"]
        .as_array()
        .expect("fixture vectors must be an array")
        .iter()
        .find(|vector| vector["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("fixture vector {name} missing"))
        .clone()
}

fn negative_case(fixture: &Value, name: &str) -> Value {
    fixture["negative_cases"]
        .as_array()
        .expect("fixture negative_cases must be an array")
        .iter()
        .find(|case| case["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("fixture negative case {name} missing"))
        .clone()
}

fn s<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {key} must be a string"))
}

/// Canonical bytes + digest chain for a detached-JWS vector: event payload,
/// binding payload, protected header, detached payload and signing input.
fn assert_canonical_chain(vector: &Value) {
    let name = s(vector, "name");

    let event_bytes = canonical::canonical_json_bytes(&vector["event_without_proofs"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&event_bytes).unwrap(),
        s(vector, "canonical_event_payload"),
        "{name}: canonical event payload drifted"
    );
    assert_eq!(
        canonical::sha256_digest(&event_bytes),
        s(vector, "event_digest"),
        "{name}: event digest drifted"
    );
    assert_eq!(
        canonical::sha256_digest(&event_bytes),
        s(vector, "payload_digest"),
        "{name}: payload digest drifted"
    );

    let binding_bytes = canonical::canonical_json_bytes(&vector["binding_object"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&binding_bytes).unwrap(),
        s(vector, "canonical_binding_payload"),
        "{name}: canonical binding payload drifted"
    );
    assert_eq!(
        canonical::sha256_digest(&binding_bytes),
        s(vector, "binding_digest"),
        "{name}: binding digest drifted"
    );

    assert_eq!(
        base64url_encode(&binding_bytes),
        s(vector, "detached_payload_b64u"),
        "{name}: detached payload segment drifted"
    );

    if let Some(header) = vector.get("protected_header") {
        let header_bytes = canonical::canonical_json_bytes(header).unwrap();
        assert_eq!(
            std::str::from_utf8(&header_bytes).unwrap(),
            s(vector, "protected_header_canonical"),
            "{name}: canonical protected header drifted"
        );
        assert_eq!(
            format!(
                "{}.{}",
                base64url_encode(&header_bytes),
                base64url_encode(&binding_bytes)
            ),
            s(vector, "jws_signing_input"),
            "{name}: JWS signing input drifted"
        );
    }
}

#[test]
fn ed25519_detached_jws_vector_verifies_with_sdk_primitives() {
    let fixture = fixture();
    let vector = vector(&fixture, ED25519_VECTOR);
    assert_canonical_chain(&vector);

    let signing_input = s(&vector, "jws_signing_input");
    let jws = s(&vector["proof"], "jws");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "detached JWS must have 3 segments");
    assert!(parts[1].is_empty(), "detached JWS payload segment must be empty");
    assert_eq!(
        format!("{}.{}", parts[0], s(&vector, "detached_payload_b64u")),
        signing_input,
        "proof JWS header does not reconstruct the fixture signing input"
    );

    // Real Ed25519 verification of the fixture signature under the DID
    // Document public key (JWK decode exercised through the SDK type).
    let public_key = PublicKeyMaterial::Jwk {
        value: vector["did_document_fragment"]["publicKeyJwk"].clone(),
    };
    assert!(
        verify_detached_ed25519_signature(&public_key, signing_input.as_bytes(), parts[2]),
        "fixture Ed25519 signature must verify over the fixture signing input"
    );

    // Ed25519 signing is deterministic: re-signing with the published test
    // key must reproduce the fixture signature byte-for-byte.
    let seed_bytes = base64url_decode(s(&vector["test_private_key_jwk"], "d")).unwrap();
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .expect("test key seed must be 32 bytes");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let resigned = base64url_encode(signing_key.sign(signing_input.as_bytes()).to_bytes());
    assert_eq!(
        resigned, parts[2],
        "deterministic re-signing must reproduce the fixture signature"
    );

    // The event_with_proof embedding must carry the identical proof JWS.
    assert_eq!(
        vector["event_with_proof"]["proofs"][0]["jws"].as_str(),
        Some(jws),
        "event_with_proof must embed the same detached JWS"
    );
}

/// ES256 and ML-DSA-65 vectors: the canonical byte / digest chain is
/// SDK-executable (the canonicalizer is algorithm-agnostic); the signature
/// itself is not verifiable here because the SDK ships no P-256 / FIPS 204
/// verifier — both algorithms are wire-reserved and MUST fail closed.
#[test]
fn non_eddsa_vectors_pin_canonical_chain_and_stay_wire_reserved() {
    let fixture = fixture();

    let es256 = vector(&fixture, "ck.vector.encoding.crypto.es256_detached_jws.v1");
    assert_canonical_chain(&es256);
    assert!(!PRODUCTION_ALGORITHMS.contains(&"ES256"));
    assert!(FUTURE_ALGORITHMS.contains(&"ES256"));

    let mldsa = vector(
        &fixture,
        "ck.vector.encoding.crypto.mldsa65_raw_detached_signature.v1",
    );
    // Raw detached signature vector: no JWS header, but the canonical event
    // + binding chain still pins the canonicalizer.
    let event_bytes = canonical::canonical_json_bytes(&mldsa["event_without_proofs"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&event_bytes).unwrap(),
        s(&mldsa, "canonical_event_payload")
    );
    assert_eq!(
        canonical::sha256_digest(&event_bytes),
        s(&mldsa, "event_digest")
    );
    let binding_bytes = canonical::canonical_json_bytes(&mldsa["binding_object"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&binding_bytes).unwrap(),
        s(&mldsa, "canonical_binding_payload")
    );
    assert_eq!(
        canonical::sha256_digest(&binding_bytes),
        s(&mldsa, "binding_digest")
    );
    assert!(!PRODUCTION_ALGORITHMS.contains(&"ML-DSA-65"));
    assert!(FUTURE_ALGORITHMS.contains(&"ML-DSA-65"));
}

/// Build a well-formed SDK `Proof` around a negative-case JWS so the reject
/// path under test (alg gate / payload segment) is reached with everything
/// else valid.
fn proof_for_negative(base: &Value, alg: &str, jws: &str) -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: alg.to_owned(),
        verification_method: s(&base["proof"], "verification_method").to_owned(),
        event_digest: Hash::new(s(base, "event_digest")).unwrap(),
        created_at: s(&base["proof"], "created_at").parse().unwrap(),
        domain: base["proof"]["domain"].as_str().map(str::to_owned),
        audience: None,
        jws: jws.to_owned(),
    }
}

#[test]
fn negative_cases_reject_through_sdk_verifiers() {
    let fixture = fixture();
    let base = vector(&fixture, ED25519_VECTOR);
    let base_signing_input = s(&base, "jws_signing_input");
    let base_public_key = PublicKeyMaterial::Jwk {
        value: base["did_document_fragment"]["publicKeyJwk"].clone(),
    };
    let actor = Did::new(s(&base["binding_object"], "actor_id")).unwrap();
    let canonical_event_bytes =
        canonical::canonical_json_bytes(&base["event_without_proofs"]).unwrap();

    // reject_flipped_signature_bit: raw Ed25519 verification must fail.
    let flipped = negative_case(&fixture, "reject_flipped_signature_bit");
    let flipped_sig = s(&flipped, "proof_jws").rsplit('.').next().unwrap().to_owned();
    let flipped_input = flipped["jws_signing_input"]
        .as_str()
        .unwrap_or(base_signing_input);
    let flipped_key = flipped
        .get("public_key_jwk")
        .map(|jwk| PublicKeyMaterial::Jwk { value: jwk.clone() })
        .unwrap_or_else(|| base_public_key.clone());
    assert!(
        !verify_detached_ed25519_signature(&flipped_key, flipped_input.as_bytes(), &flipped_sig),
        "flipped signature bit must fail Ed25519 verification"
    );

    // reject_truncated_public_key: 31-byte key must fail closed.
    let truncated = negative_case(&fixture, "reject_truncated_public_key");
    let truncated_key = PublicKeyMaterial::Jwk {
        value: truncated["public_key_jwk"].clone(),
    };
    assert!(truncated_key.ed25519_bytes().is_err() || {
        let sig = s(&truncated, "proof_jws").rsplit('.').next().unwrap();
        !verify_detached_ed25519_signature(&truncated_key, base_signing_input.as_bytes(), sig)
    });

    // reject_alg_none / reject_alg_key_type_mismatch: the SDK verifier's
    // algorithm gate must reject before any signature math.
    for (case_name, alg) in [
        ("reject_alg_none", "none"),
        ("reject_alg_key_type_mismatch", "ES256"),
    ] {
        let case = negative_case(&fixture, case_name);
        assert_eq!(
            case["protected_header"]["alg"].as_str(),
            Some(alg),
            "{case_name}: fixture header alg drifted"
        );
        let proof = proof_for_negative(&base, alg, s(&case, "proof_jws"));
        let err = verify_eddsa_detached_jws_proof(
            &proof,
            &canonical_event_bytes,
            &actor,
            &base_public_key,
        )
        .expect_err(case_name);
        let text = format!("{err}");
        assert!(
            text.contains("non-EdDSA"),
            "{case_name}: expected the algorithm gate, got: {text}"
        );
    }

    // reject_non_empty_payload_segment: the detached profile must refuse an
    // attached payload segment even though the signature would verify.
    let attached = negative_case(&fixture, "reject_non_empty_payload_segment");
    let proof = proof_for_negative(&base, "EdDSA", s(&attached, "proof_jws"));
    let err = verify_eddsa_detached_jws_proof(
        &proof,
        &canonical_event_bytes,
        &actor,
        &base_public_key,
    )
    .expect_err("attached payload segment must be rejected");
    assert!(
        format!("{err}").contains("empty payload segment"),
        "expected the detached-profile gate, got: {err}"
    );
}
