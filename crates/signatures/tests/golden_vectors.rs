//! Cross-crate byte-level golden vector guard for the unified signing/encoding
//! source of truth (T1.B).
//!
//! These vectors pin the converged bytes that must not drift:
//!
//! 1. The detached-JWS protected header is exactly `{"alg":"EdDSA"}` across the ecosystem
//!    (base64url `eyJhbGciOiJFZERTQSJ9`), matching spec §6, soland `move_seal_wire`, cotest and
//!    teabay `sdk::jws`.
//! 2. `Ed25519MoveSigner` (Move/Seal signing) and `Ed25519DetachedJwsSigner` (event-proof signing)
//!    produce the same signing input and same 64-byte signature for identical canonical bytes,
//!    proving the historical JWS forks have converged.
//! 3. base58btc (`core::multibase`, `bs58` backend) stays stable for the did:key Ed25519
//!    multiencoding stack.
//! 4. base64url (`core::base64url`) remains unpadded and URL-safe.

use cokret_core::{base64url_decode, base64url_encode, ed25519_pubkey_to_did_key_multibase};

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
fn move_signer_and_event_proof_signer_share_one_jws_header_and_signature() {
    use cokret_core::move_event::{Effect, LatticeOp, LatticeOpType};
    use cokret_core::{CellRef, Did, Hlc, MoveSigner, RealmId, SealId, UnsignedMove};
    use cokret_signatures::Ed25519MoveSigner;
    use cokret_signatures::proof::{Ed25519DetachedJwsSigner, EventSigner};

    let seed = [7u8; 32];
    let did = Did::new("did:web:alice.example".to_owned()).unwrap();
    let vm = "did:web:alice.example#key-1";

    // Build a Move and grab its canonical bytes + the Move signature JWS.
    let move_signer = Ed25519MoveSigner::from_did_key_seed(seed, did.clone(), vm);
    let unsigned = UnsignedMove::new(
        did.clone(),
        RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap(),
        SealId::new(format!("ck:seal:sha256:{}", "aa".repeat(32))).unwrap(),
        vec![Effect {
            cell: CellRef::new(
                "ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned(),
            )
            .unwrap(),
            op: LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(serde_json::json!("active")),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        }],
        Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
    );
    let signed_move = move_signer.sign_move(&unsigned).unwrap();
    let move_bytes = signed_move.canonical_bytes_for_id().unwrap();

    // The Move JWS header segment MUST be the canonical alg=EdDSA header.
    let move_header_seg = signed_move.sig.jws.split('.').next().unwrap();
    assert_eq!(
        move_header_seg, PROTECTED_HEADER_B64URL,
        "Move JWS header drift"
    );

    // The event-proof signer over the SAME bytes must produce the SAME raw
    // 64-byte signature (proving a single signing input across both paths).
    let event_signer = Ed25519DetachedJwsSigner::from_seed(seed, vm);
    let event_sig = event_signer.sign(&move_bytes).unwrap();
    let move_sig_seg = signed_move.sig.jws.rsplit('.').next().unwrap();
    assert_eq!(
        base64url_encode(&event_sig),
        move_sig_seg,
        "Move/event signature bytes diverge"
    );
}

#[test]
fn base58btc_did_key_ed25519_golden_vector() {
    // Fixed 32-byte key -> deterministic did:key multibase string.
    let key = [42u8; 32];
    let mb = ed25519_pubkey_to_did_key_multibase(&key);
    // Known-answer for the all-0x2A key under the Bitcoin base58 alphabet.
    assert_eq!(mb, "z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5");
    assert_eq!(cokret_core::decode_ed25519_multibase(&mb).unwrap(), key);
}

#[test]
fn base64url_golden_vector_is_url_safe_and_unpadded() {
    let data = [0xfb_u8, 0xff, 0xbf];
    let encoded = base64url_encode(data);
    assert_eq!(encoded, "-_-_"); // URL-safe alphabet, no padding.
    assert_eq!(base64url_decode(&encoded).unwrap(), data);
}
