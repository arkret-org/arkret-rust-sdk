//! Cross-crate byte-level golden vector guard for the unified signing/encoding
//! source of truth (T1.B).
//!
//! These vectors pin the converged bytes that must not drift:
//!
//! 1. The detached-JWS protected header is exactly `{"alg":"EdDSA"}` across the ecosystem
//!    (base64url `eyJhbGciOiJFZERTQSJ9`), matching spec §6, soland `move_seal_wire`, cotest and
//!    teabay `sdk::jws`.
//! 2. `Ed25519PayloadSigner` (Move/Seal signing) and the generic detached-JWS signer produce the
//!    same signing input and same 64-byte signature for identical canonical bytes, proving the
//!    historical JWS forks have converged.
//! 3. base58btc (`arkret-canonical`, `bs58` backend) stays stable for the did:key Ed25519
//!    multiencoding stack.
//! 4. base64url (`arkret-canonical`) remains unpadded and URL-safe.

use arkret_canonical::{base64url_decode, base64url_encode, ed25519_pubkey_to_did_key_multibase};

/// SDK-canonical detached-JWS protected header, base64url-no-pad.
const PROTECTED_HEADER_B64URL: &str = "eyJhbGciOiJFZERTQSJ9";

#[test]
fn detached_jws_protected_header_is_alg_eddsa_only() {
    let decoded = base64url_decode(PROTECTED_HEADER_B64URL).unwrap();
    assert_eq!(
        decoded, br#"{"alg":"EdDSA"}"#,
        "JWS header MUST be alg=EdDSA with no typ/crit"
    );
    assert_eq!(
        base64url_encode(br#"{"alg":"EdDSA"}"#),
        PROTECTED_HEADER_B64URL
    );
}

#[cfg(feature = "signer")]
#[test]
fn payload_signer_and_generic_detached_jws_signer_share_one_header_and_signature() {
    use arkret_identifiers::Did;
    use arkret_signatures::Ed25519PayloadSigner;
    use arkret_signatures::proof::{Ed25519DetachedJwsSigner, EventSigner};
    use arkret_wire::signer::PayloadSigner;

    let seed = [7u8; 32];
    let did = Did::new("did:web:alice.example".to_owned()).unwrap();
    let vm = "did:web:alice.example#key-1";

    // The property is that both signing paths share one signing input, so the
    // body only has to be some fixed canonical byte string. It used to be a
    // Move's canonical bytes; v1 deleted Move, and the signer was never
    // body-specific anyway - it signs bytes.
    let canonical_bytes =
        br#"{"actor_id":"did:web:alice.example","kind":"ak.member.state"}"#.to_vec();

    let payload_signer = Ed25519PayloadSigner::from_did_key_seed(seed, did, vm);
    let signature = payload_signer.sign_payload(&canonical_bytes).unwrap();

    // The JWS header segment MUST be the canonical alg=EdDSA header.
    let header_seg = signature.jws.split('.').next().unwrap();
    assert_eq!(
        header_seg, PROTECTED_HEADER_B64URL,
        "payload JWS header drift"
    );

    // The generic signer over the SAME bytes must produce the SAME raw
    // 64-byte signature (proving a single signing input across both paths).
    let detached_signer = Ed25519DetachedJwsSigner::from_seed(seed, vm);
    let detached_sig = detached_signer.sign(&canonical_bytes).unwrap();
    let sig_seg = signature.jws.rsplit('.').next().unwrap();
    assert_eq!(
        base64url_encode(&detached_sig),
        sig_seg,
        "payload/generic detached signature bytes diverge"
    );
}

#[test]
fn base58btc_did_key_ed25519_golden_vector() {
    // Fixed 32-byte key -> deterministic did:key multibase string.
    let key = [42u8; 32];
    let mb = ed25519_pubkey_to_did_key_multibase(&key);
    // Known-answer for the all-0x2A key under the Bitcoin base58 alphabet.
    assert_eq!(mb, "z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5");
    assert_eq!(
        arkret_canonical::decode_ed25519_multibase(&mb).unwrap(),
        key
    );
}

#[test]
fn base64url_golden_vector_is_url_safe_and_unpadded() {
    let data = [0xfb_u8, 0xff, 0xbf];
    let encoded = base64url_encode(data);
    assert_eq!(encoded, "-_-_"); // URL-safe alphabet, no padding.
    assert_eq!(base64url_decode(&encoded).unwrap(), data);
}
