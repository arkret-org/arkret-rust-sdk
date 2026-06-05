//! Ed25519 backend for the [`MoveSigner`] trait.
//!
//! Round 21 (2026-05-09): production Move/Anchor signer. Wraps an
//! `ed25519_dalek::SigningKey` and produces detached JWS strings whose
//! payload is the canonical bytes of the Move/Anchor body. Available
//! behind the `signer` feature.
//!
//! ```
//! use cokret_signatures::Ed25519MoveSigner;
//! use cokret_core::{Did, MoveSigner};
//!
//! let seed = [0u8; 32];
//! let did = Did::new("did:web:alice.example".to_owned()).unwrap();
//! let signer = Ed25519MoveSigner::from_did_key_seed(seed, did, "did:web:alice.example#key-1");
//! assert_eq!(signer.signer_did().as_str(), "did:web:alice.example");
//! ```

use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};

use cokret_core::canonical;
use cokret_core::move_event::{Move, MoveSignature};
use cokret_core::{
    Did, Error, Hash, MoveSigner, Result, UnsignedMove, base64url_decode, base64url_encode,
};

/// Ed25519 [`MoveSigner`] backend.
///
/// `signing_key` holds the raw 32-byte ed25519 secret; `did` is the issuer
/// DID published as `Move.issuer` (or one of the anchorer set members);
/// `kid` is the verification method id (`<did>#<fragment>`) that goes into
/// `MoveSignature.verification_method`.
pub struct Ed25519MoveSigner {
    signing_key: SigningKey,
    did: Did,
    kid: String,
}

impl Ed25519MoveSigner {
    /// Wrap an existing `ed25519_dalek::SigningKey`.
    pub fn new(
        signing_key: SigningKey,
        did: Did,
        verification_method_id: impl Into<String>,
    ) -> Self {
        Self { signing_key, did, kid: verification_method_id.into() }
    }

    /// Convenience constructor that derives an ed25519 keypair from a 32-byte
    /// seed (RFC 8032 secret-key seed).
    pub fn from_did_key_seed(
        seed: [u8; 32],
        did: Did,
        verification_method_id: impl Into<String>,
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        Self::new(signing_key, did, verification_method_id)
    }

    /// Borrow the verifying public key (32-byte ed25519 verifying key).
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl MoveSigner for Ed25519MoveSigner {
    fn sign_move(&self, unsigned: &UnsignedMove) -> Result<Move> {
        if unsigned.issuer != self.did {
            return Err(Error::Protocol(format!(
                "Move issuer {} does not match Ed25519MoveSigner DID {}",
                unsigned.issuer, self.did
            )));
        }
        let bytes = unsigned.canonical_bytes()?;
        let id = Move::id_from_canonical_bytes(&bytes)?;
        let sig = self.sign_payload(&bytes)?;
        Ok(Move {
            id,
            issuer: unsigned.issuer.clone(),
            realm_id: unsigned.realm_id.clone(),
            preconditions: unsigned.preconditions.clone(),
            effects: unsigned.effects.clone(),
            anchor_ref: unsigned.anchor_ref.clone(),
            refs: unsigned.refs.clone(),
            hlc: unsigned.hlc.clone(),
            sig,
        })
    }

    fn signer_did(&self) -> &Did {
        &self.did
    }

    fn verification_method_id(&self) -> &str {
        &self.kid
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<MoveSignature> {
        // Detached JWS over canonical bytes: SDK-canonical header
        // `{"alg":"EdDSA"}` (no `typ`, matching spec §6 / soland / cotest /
        // teabay), then base64url-no-pad(header) + "." + "" (detached
        // payload) + "." + base64url-no-pad(signature). Per spec §3 the SDK
        // keeps the JWS detached so the receiver re-derives the payload from
        // the canonical body bytes rather than from the JWS itself.
        let header = r#"{"alg":"EdDSA"}"#;
        let header_b64 = base64url_encode(header.as_bytes());
        let signing_input = format!("{header_b64}.{}", base64url_encode(canonical_bytes));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64url_encode(signature.to_bytes());
        let jws = format!("{header_b64}..{sig_b64}");

        let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))
            .map_err(|err| Error::Protocol(format!("invalid canonical hash: {err}")))?;

        Ok(MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: self.kid.clone(),
            payload_digest,
            created_at: Utc::now(),
            jws,
        })
    }
}

/// Best-effort verification of a Move signature produced by an
/// [`Ed25519MoveSigner`]. Useful for tests and round-trip vectors.
///
/// Returns `Ok(())` on success, `Err(Error::Protocol(...))` if the canonical
/// bytes don't match the declared `payload_digest` or the signature fails to
/// verify against the supplied public key.
pub fn verify_ed25519_move_signature(
    canonical_bytes: &[u8],
    sig: &MoveSignature,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let expected = canonical::sha256_digest(canonical_bytes);
    if sig.payload_digest.as_str() != expected {
        return Err(Error::Protocol(format!(
            "payload_digest {} does not match canonical bytes hash {}",
            sig.payload_digest, expected
        )));
    }
    let parts: Vec<&str> = sig.jws.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Protocol(
            "Ed25519 detached JWS must have three '.'-separated parts".to_owned(),
        ));
    }
    let header_b64 = parts[0];
    let sig_b64 = parts[2];
    let sig_bytes = base64url_decode(sig_b64)
        .map_err(|err| Error::Protocol(format!("invalid sig base64: {err}")))?;
    if sig_bytes.len() != 64 {
        return Err(Error::Protocol("Ed25519 signature must be 64 bytes".to_owned()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let signing_input = format!("{header_b64}.{}", base64url_encode(canonical_bytes));
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|err| Error::Protocol(format!("Ed25519 signature verification failed: {err}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cokret_core::move_event::{Effect, LatticeOp, LatticeOpType};
    use cokret_core::{Anchor, AnchorId, AnchorerSig, CellRef, Hlc, MoveId, RealmId, UnsignedMove};
    use serde_json::json;

    fn alice() -> Did {
        Did::new("did:web:alice.example".to_owned()).unwrap()
    }

    fn space() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn anchor_id(byte: u8) -> AnchorId {
        AnchorId::new(format!("ck:anchor:sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap()
    }

    fn sample_unsigned() -> UnsignedMove {
        UnsignedMove::new(
            alice(),
            space(),
            anchor_id(0xaa),
            vec![Effect {
                cell: CellRef::new(
                    "ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned(),
                )
                .unwrap(),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!("active")),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            hlc(),
        )
    }

    #[test]
    fn ed25519_signer_produces_self_consistent_move() {
        let signer =
            Ed25519MoveSigner::from_did_key_seed([7u8; 32], alice(), "did:web:alice.example#key-1");
        let m = signer.sign_move(&sample_unsigned()).unwrap();
        m.validate_id().unwrap();
        m.validate_structural().unwrap();
        // Round-trip verify against verifying key.
        let bytes = m.canonical_bytes_for_id().unwrap();
        verify_ed25519_move_signature(&bytes, &m.sig, &signer.verifying_key()).unwrap();
    }

    #[test]
    fn ed25519_signer_rejects_issuer_mismatch() {
        let signer = Ed25519MoveSigner::from_did_key_seed(
            [7u8; 32],
            Did::new("did:web:bob.example".to_owned()).unwrap(),
            "did:web:bob.example#key-1",
        );
        let err = signer.sign_move(&sample_unsigned()).unwrap_err();
        assert!(format!("{err}").contains("does not match Ed25519MoveSigner DID"));
    }

    #[test]
    fn ed25519_signer_signs_anchor_single() {
        let signer =
            Ed25519MoveSigner::from_did_key_seed([9u8; 32], alice(), "did:web:alice.example#key-1");
        let a = Anchor::sign_single(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            &signer,
        )
        .unwrap();
        a.validate_id().unwrap();
        a.validate_structural().unwrap();
        match &a.anchorer_signature {
            AnchorerSig::Single(sig) => {
                assert_eq!(sig.alg, "EdDSA");
                let bytes = a.canonical_bytes_for_id().unwrap();
                verify_ed25519_move_signature(&bytes, sig, &signer.verifying_key()).unwrap();
            }
            other => panic!("expected single sig, got {other:?}"),
        }
    }

    #[test]
    fn ed25519_signer_deterministic_for_same_seed() {
        let seed = [42u8; 32];
        let s1 = Ed25519MoveSigner::from_did_key_seed(seed, alice(), "did:web:alice.example#key-1");
        let s2 = Ed25519MoveSigner::from_did_key_seed(seed, alice(), "did:web:alice.example#key-1");
        assert_eq!(s1.verifying_key().to_bytes(), s2.verifying_key().to_bytes());
    }

    #[test]
    fn verify_ed25519_rejects_tampered_payload() {
        let signer =
            Ed25519MoveSigner::from_did_key_seed([3u8; 32], alice(), "did:web:alice.example#key-1");
        let m = signer.sign_move(&sample_unsigned()).unwrap();
        let mut bytes = m.canonical_bytes_for_id().unwrap();
        bytes.push(b'X'); // tamper
        let err =
            verify_ed25519_move_signature(&bytes, &m.sig, &signer.verifying_key()).unwrap_err();
        assert!(format!("{err}").contains("payload_digest"));
    }
}
