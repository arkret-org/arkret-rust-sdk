//! The single `eddsa-jcs-2022` Data Integrity cryptosuite implementation.
//!
//! `identity-did.md` §3.4 delegates `did:webvh` log-entry and witness proof
//! construction to DIF did:webvh v1.0, whose only permitted cryptosuite is
//! `eddsa-jcs-2022`. The signing input is the 64-byte concatenation
//!
//! ```text
//!   SHA-256(JCS(proofConfig)) || SHA-256(JCS(transformedDocument))
//! ```
//!
//! where `proofConfig` is the proof object with `proofValue` removed and
//! `transformedDocument` is the signed document with its `proof` member
//! removed. Every producer and verifier in this workspace routes through
//! [`eddsa_jcs_2022_signing_input`] so a document signed by one component
//! verifies byte-for-byte in every other.

use arkret_canonical::canonical::{canonical_json_bytes, sha256_bytes};
use arkret_canonical::{
    decode_ed25519_multibase, decode_ed25519_signature_multibase, encode_multibase_base58btc,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use thiserror::Error;

/// The only Data Integrity proof `type` this workspace produces or accepts.
pub const DATA_INTEGRITY_PROOF_TYPE: &str = "DataIntegrityProof";

/// The only Ed25519 Data Integrity cryptosuite permitted by DIF did:webvh
/// v1.0. `ecdsa-jcs-2022` MUST be backed by an ECDSA key and is therefore
/// never a valid label for an Ed25519 verification method.
pub const EDDSA_JCS_2022_CRYPTOSUITE: &str = "eddsa-jcs-2022";

/// Closed set of `proofPurpose` values used by Arkret Data Integrity proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataIntegrityProofPurpose {
    /// did:webvh log-entry and `did-witness.json` record proofs.
    AssertionMethod,
    /// Holder-authentication proofs over a challenge document.
    Authentication,
}

impl DataIntegrityProofPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AssertionMethod => "assertionMethod",
            Self::Authentication => "authentication",
        }
    }
}

#[derive(Debug, Error)]
pub enum EddsaJcs2022Error {
    #[error("eddsa-jcs-2022 input is not canonical JSON: {0}")]
    Canonical(String),
    #[error("proof type must be DataIntegrityProof, got {0:?}")]
    UnsupportedType(String),
    #[error("proof cryptosuite must be eddsa-jcs-2022, got {0:?}")]
    UnsupportedCryptosuite(String),
    #[error("proof is missing proofValue")]
    MissingProofValue,
    #[error("proofValue is not a base58btc multibase Ed25519 signature: {0}")]
    InvalidProofValue(String),
    #[error("verification key is not an Ed25519 multikey: {0}")]
    InvalidPublicKey(String),
    #[error("eddsa-jcs-2022 signature is invalid")]
    SignatureInvalid,
}

/// Build the `eddsa-jcs-2022` proof configuration a signer commits to.
///
/// The returned object deliberately carries no `proofValue`: it is both the
/// pre-image half hashed by [`eddsa_jcs_2022_signing_input`] and the base the
/// finished proof is assembled from.
#[must_use]
pub fn eddsa_jcs_2022_proof_config(
    verification_method: &str,
    proof_purpose: DataIntegrityProofPurpose,
) -> Value {
    json!({
        "type": DATA_INTEGRITY_PROOF_TYPE,
        "cryptosuite": EDDSA_JCS_2022_CRYPTOSUITE,
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose.as_str(),
    })
}

/// The 64-byte `eddsa-jcs-2022` signing input for `document` under
/// `proof_config`.
///
/// `proofValue` is stripped from `proof_config` and `proof` is stripped from
/// `document`, so the same call works before signing and during verification.
pub fn eddsa_jcs_2022_signing_input(
    proof_config: &Value,
    document: &Value,
) -> Result<Vec<u8>, EddsaJcs2022Error> {
    let mut proof_config = proof_config.clone();
    if let Value::Object(map) = &mut proof_config {
        map.remove("proofValue");
    }
    let mut document = document.clone();
    if let Value::Object(map) = &mut document {
        map.remove("proof");
    }
    let proof_config_bytes = canonical_bytes(&proof_config)?;
    let document_bytes = canonical_bytes(&document)?;
    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&sha256_bytes(&proof_config_bytes));
    signing_input.extend_from_slice(&sha256_bytes(&document_bytes));
    Ok(signing_input)
}

/// Sign `document` and return the complete `eddsa-jcs-2022` proof object.
pub fn build_eddsa_jcs_2022_proof(
    document: &Value,
    signing_key: &SigningKey,
    verification_method: &str,
    proof_purpose: DataIntegrityProofPurpose,
) -> Result<Value, EddsaJcs2022Error> {
    let mut proof = eddsa_jcs_2022_proof_config(verification_method, proof_purpose);
    let signing_input = eddsa_jcs_2022_signing_input(&proof, document)?;
    let signature = signing_key.sign(&signing_input);
    if let Value::Object(map) = &mut proof {
        map.insert(
            "proofValue".to_owned(),
            Value::String(encode_multibase_base58btc(signature.to_bytes())),
        );
    }
    Ok(proof)
}

/// Verify one `eddsa-jcs-2022` proof over `document` with the Ed25519 public
/// key `public_key_multibase` names.
///
/// This checks the cryptosuite binding and the signature only. Which key is
/// authorised to sign, and which `proofPurpose` a given document family
/// requires, stay with the caller's method rules.
pub fn verify_eddsa_jcs_2022_proof(
    document: &Value,
    proof: &Value,
    public_key_multibase: &str,
) -> Result<(), EddsaJcs2022Error> {
    let proof_type = proof
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proof_type != DATA_INTEGRITY_PROOF_TYPE {
        return Err(EddsaJcs2022Error::UnsupportedType(proof_type.to_owned()));
    }
    let cryptosuite = proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if cryptosuite != EDDSA_JCS_2022_CRYPTOSUITE {
        return Err(EddsaJcs2022Error::UnsupportedCryptosuite(
            cryptosuite.to_owned(),
        ));
    }
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or(EddsaJcs2022Error::MissingProofValue)?;
    let signature = decode_ed25519_signature_multibase(proof_value)
        .map_err(|error| EddsaJcs2022Error::InvalidProofValue(error.to_string()))?;
    let public_key = decode_ed25519_multibase(public_key_multibase)
        .map_err(|error| EddsaJcs2022Error::InvalidPublicKey(error.to_string()))
        .and_then(|bytes| {
            VerifyingKey::from_bytes(&bytes)
                .map_err(|error| EddsaJcs2022Error::InvalidPublicKey(error.to_string()))
        })?;
    let signing_input = eddsa_jcs_2022_signing_input(proof, document)?;
    public_key
        .verify_strict(&signing_input, &Signature::from_bytes(&signature))
        .map_err(|_| EddsaJcs2022Error::SignatureInvalid)
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, EddsaJcs2022Error> {
    canonical_json_bytes(value).map_err(|error| EddsaJcs2022Error::Canonical(error.to_string()))
}

#[cfg(test)]
mod tests {
    use arkret_canonical::ed25519_pubkey_to_did_key_multibase;

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn key_multibase(key: &SigningKey) -> String {
        ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes())
    }

    #[test]
    fn round_trips_a_built_proof() {
        let key = signing_key();
        let multibase = key_multibase(&key);
        let document = json!({
            "versionId": "1-QmFixture",
            "parameters": {"updateKeys": [multibase]},
            "state": {"id": "did:webvh:QmFixture:example.test"},
        });
        let proof = build_eddsa_jcs_2022_proof(
            &document,
            &key,
            &format!("did:key:{multibase}#{multibase}"),
            DataIntegrityProofPurpose::AssertionMethod,
        )
        .unwrap();

        verify_eddsa_jcs_2022_proof(&document, &proof, &multibase).unwrap();

        // Attaching the proof to the document does not change the document
        // half of the signing input.
        let mut signed = document;
        signed["proof"] = Value::Array(vec![proof.clone()]);
        verify_eddsa_jcs_2022_proof(&signed, &proof, &multibase).unwrap();
    }

    #[test]
    fn rejects_document_and_proof_config_mutation() {
        let key = signing_key();
        let multibase = key_multibase(&key);
        let document = json!({"state": {"foo": "bar"}});
        let proof = build_eddsa_jcs_2022_proof(
            &document,
            &key,
            &format!("did:key:{multibase}#{multibase}"),
            DataIntegrityProofPurpose::AssertionMethod,
        )
        .unwrap();

        let mut mutated_document = document.clone();
        mutated_document["state"]["foo"] = Value::String("baz".to_owned());
        assert!(matches!(
            verify_eddsa_jcs_2022_proof(&mutated_document, &proof, &multibase),
            Err(EddsaJcs2022Error::SignatureInvalid)
        ));

        let mut mutated_proof = proof;
        mutated_proof["proofPurpose"] = Value::String("authentication".to_owned());
        assert!(matches!(
            verify_eddsa_jcs_2022_proof(&document, &mutated_proof, &multibase),
            Err(EddsaJcs2022Error::SignatureInvalid)
        ));
    }

    #[test]
    fn rejects_an_ecdsa_cryptosuite_label() {
        let key = signing_key();
        let multibase = key_multibase(&key);
        let document = json!({"state": {}});
        let mut proof = build_eddsa_jcs_2022_proof(
            &document,
            &key,
            &format!("did:key:{multibase}#{multibase}"),
            DataIntegrityProofPurpose::AssertionMethod,
        )
        .unwrap();
        proof["cryptosuite"] = Value::String("ecdsa-jcs-2022".to_owned());

        assert!(matches!(
            verify_eddsa_jcs_2022_proof(&document, &proof, &multibase),
            Err(EddsaJcs2022Error::UnsupportedCryptosuite(suite)) if suite == "ecdsa-jcs-2022"
        ));
    }
}
