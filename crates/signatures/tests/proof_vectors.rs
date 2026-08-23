//! Known-answer tests (KAT) for `arkret_signatures::proof`.
//!
//! These vectors are the migration checkpoint between coauth, soland and
//! inkson: every downstream implementation MUST reproduce the canonical
//! bytes, payload hashes, and Ed25519 signatures below. Drift here is a
//! breaking protocol change.

use arkret_wire::DidUrl;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CanonicalVector {
    name: String,
    value: serde_json::Value,
    canonical_bytes: String,
    payload_digest: String,
}

#[derive(Debug, Deserialize)]
struct CanonicalVectors {
    vectors: Vec<CanonicalVector>,
}

#[cfg(feature = "signer")]
#[derive(Debug, Deserialize)]
struct Ed25519Vector {
    name: String,
    seed_hex: String,
    public_key_hex: String,
    value: serde_json::Value,
    canonical_bytes: String,
    payload_digest: String,
    /// Raw 64-byte signature, lowercase hex.
    signature_hex: String,
    /// Full detached-JWS string (`header..signature`).
    detached_jws: String,
}

#[cfg(feature = "signer")]
#[derive(Debug, Deserialize)]
struct Ed25519Vectors {
    vectors: Vec<Ed25519Vector>,
}

#[derive(Debug, Deserialize)]
struct DevProofVector {
    name: String,
    kind: String,
    /// Reason the verifier MUST reject this proof under production.
    expect_rejected: bool,
}

#[derive(Debug, Deserialize)]
struct DevProofVectors {
    vectors: Vec<DevProofVector>,
}

fn read_vectors<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!("failed to parse {}: {err}", path.display());
    })
}

#[test]
fn canonical_json_vectors_match_event_proof_builder() {
    use arkret_signatures::EventProofBuilder;
    let suite: CanonicalVectors = read_vectors("canonical_json.json");
    assert!(
        suite.vectors.len() >= 5,
        "must ship at least 5 canonical JSON vectors"
    );

    let builder = EventProofBuilder::new();
    for v in suite.vectors {
        let bytes = builder
            .canonical_bytes(&v.value)
            .unwrap_or_else(|err| panic!("vector '{}' failed canonical_bytes: {err}", v.name));
        let bytes_str = String::from_utf8(bytes.clone())
            .unwrap_or_else(|err| panic!("vector '{}' canonical bytes not UTF-8: {err}", v.name));
        assert_eq!(
            bytes_str, v.canonical_bytes,
            "vector '{}' canonical bytes drift",
            v.name
        );

        let hash = builder
            .payload_digest(&v.value)
            .unwrap_or_else(|err| panic!("vector '{}' failed payload_digest: {err}", v.name));
        assert_eq!(
            hash.as_str(),
            v.payload_digest,
            "vector '{}' payload_digest drift",
            v.name
        );
    }
}

#[cfg(feature = "signer")]
#[test]
fn ed25519_vectors_round_trip_through_signer_and_verifier() {
    use arkret_signatures::proof::{
        Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, EventProofBuilder, EventSigner,
        EventVerifier, PublicKeyMaterial,
    };

    let suite: Ed25519Vectors = read_vectors("ed25519_jws.json");
    assert!(
        suite.vectors.len() >= 3,
        "must ship at least 3 Ed25519 vectors"
    );

    let builder = EventProofBuilder::new();
    let verifier = Ed25519DetachedJwsVerifier::new();

    for v in suite.vectors {
        // Decode seed.
        let seed_bytes = hex_decode(&v.seed_hex);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let signer = Ed25519DetachedJwsSigner::from_seed(seed, "did:web:test.example#key-1");

        // Public key matches recorded value.
        let pubkey = signer.verifying_key().to_bytes();
        assert_eq!(
            hex_encode(&pubkey),
            v.public_key_hex,
            "vector '{}' public key drift",
            v.name
        );

        // Canonical bytes match.
        let bytes = builder.canonical_bytes(&v.value).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            v.canonical_bytes,
            "vector '{}' canonical bytes drift",
            v.name
        );

        // Payload hash matches.
        let hash = builder.payload_digest(&v.value).unwrap();
        assert_eq!(
            hash.as_str(),
            v.payload_digest,
            "vector '{}' payload hash drift",
            v.name
        );

        // Raw signature bytes match.
        let sig = signer.sign(&bytes).unwrap();
        assert_eq!(
            hex_encode(&sig),
            v.signature_hex,
            "vector '{}' signature drift",
            v.name
        );

        // Generic detached JWS over the supplied canonical bytes matches.
        let jws = signer.sign_detached_jws(&bytes);
        assert_eq!(
            jws, v.detached_jws,
            "vector '{}' detached JWS drift",
            v.name
        );

        // Verifier accepts.
        let key_material = PublicKeyMaterial::Ed25519Raw {
            bytes: pubkey.to_vec(),
        };
        verifier
            .verify(&bytes, &sig, &key_material)
            .expect("verifier accepts signature");
        verifier
            .verify_detached_jws(&jws, &bytes, &key_material)
            .expect("verifier accepts detached JWS");

        // Tampered bytes rejected.
        let mut tampered = bytes.clone();
        tampered.push(b'!');
        assert!(verifier.verify(&tampered, &sig, &key_material).is_err());
    }
}

#[test]
fn dev_proof_kind_vectors_match_wire_validation() {
    use arkret_signatures::proof::build_proof_envelope;
    use arkret_wire::Hash;

    let suite: DevProofVectors = read_vectors("dev_proofs.json");
    assert!(
        suite.vectors.len() >= 2,
        "must ship at least 2 dev-proof rejection vectors"
    );

    let dummy_hash =
        Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();

    for v in suite.vectors {
        let proof = build_proof_envelope(
            v.kind.clone(),
            DidUrl::new("did:web:test.example#key-1").unwrap(),
            dummy_hash.clone(),
            None,
            None,
            "header..signature",
        );
        let envelope_result = proof.validate_production();
        if v.expect_rejected {
            assert!(
                envelope_result.is_err(),
                "vector '{}' envelope should be rejected",
                v.name
            );
        } else {
            assert!(
                envelope_result.is_ok(),
                "vector '{}' envelope should be accepted: {:?}",
                v.name,
                envelope_result.err()
            );
        }
    }
}

#[cfg(feature = "signer")]
fn hex_decode(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = decode_hex_nibble(bytes[i]);
        let lo = decode_hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

#[cfg(feature = "signer")]
fn decode_hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex byte: {b}"),
    }
}

#[cfg(feature = "signer")]
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
