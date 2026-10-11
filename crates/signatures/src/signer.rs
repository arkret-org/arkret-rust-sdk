//! Ed25519 backend for generic non-Event detached payload signatures.

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical;
use arkret_wire::{
    Did, DidUrl, Hash, PayloadSignature, PayloadSigner, Result as WireResult, WireError,
};
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::{Error, EventSigner, Result, SignerError};

pub struct Ed25519PayloadSigner {
    signing_key: SigningKey,
    did: Did,
    kid: DidUrl,
}

impl Ed25519PayloadSigner {
    pub fn new(signing_key: SigningKey, did: Did, verification_method_id: DidUrl) -> Self {
        Self {
            signing_key,
            did,
            kid: verification_method_id,
        }
    }

    pub fn from_did_key_seed(seed: [u8; 32], did: Did, verification_method_id: DidUrl) -> Self {
        Self::new(SigningKey::from_bytes(&seed), did, verification_method_id)
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl PayloadSigner for Ed25519PayloadSigner {
    fn signer_did(&self) -> &Did {
        &self.did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.kid
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> WireResult<PayloadSignature> {
        let header = r#"{"alg":"Ed25519"}"#;
        let header_b64 = base64url_encode(header.as_bytes());
        let signing_input = format!("{header_b64}.{}", base64url_encode(canonical_bytes));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))
            .map_err(|error| WireError::Protocol(format!("invalid canonical hash: {error}")))?;
        Ok(PayloadSignature {
            verification_method: self.kid.clone(),
            payload_digest,
            created_at: Utc::now(),
            jws: format!("{header_b64}..{}", base64url_encode(signature.to_bytes())),
        })
    }
}

impl EventSigner for Ed25519PayloadSigner {
    fn sign(&self, bytes: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        let header_b64 = base64url_encode(br#"{"alg":"Ed25519"}"#);
        let signing_input = format!("{header_b64}.{}", base64url_encode(bytes));
        Ok(self
            .signing_key
            .sign(signing_input.as_bytes())
            .to_bytes()
            .to_vec())
    }

    fn algorithm(&self) -> &str {
        "Ed25519"
    }

    fn verification_method(&self) -> &str {
        self.kid.as_str()
    }
}

pub fn verify_ed25519_payload_signature(
    canonical_bytes: &[u8],
    signature: &PayloadSignature,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let expected = canonical::sha256_digest(canonical_bytes);
    if signature.payload_digest.as_str() != expected {
        return Err(Error::Protocol(
            "payload_digest does not match canonical payload bytes".to_owned(),
        ));
    }
    let parts: Vec<_> = signature.jws.split('.').collect();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(Error::Protocol(
            "detached JWS must contain an empty payload segment".to_owned(),
        ));
    }
    let header: serde_json::Value = arkret_canonical::from_canonical_json_slice(
        &base64url_decode(parts[0])
            .map_err(|error| Error::Protocol(format!("invalid JWS header: {error}")))?,
    )?;
    if header != serde_json::json!({"alg": "Ed25519"}) {
        return Err(Error::Protocol(
            "detached JWS protected header must be exactly Ed25519".to_owned(),
        ));
    }
    let bytes = base64url_decode(parts[2])
        .map_err(|error| Error::Protocol(format!("invalid JWS signature: {error}")))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| Error::Protocol("Ed25519 signature must be 64 bytes".to_owned()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&bytes);
    let signing_input = format!("{}.{}", parts[0], base64url_encode(canonical_bytes));
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|error| Error::Protocol(format!("Ed25519 signature verification failed: {error}")))
}
