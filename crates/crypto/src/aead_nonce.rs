//! MLS-Exporter AEAD nonce derivation + encrypted-envelope AAD digest helpers.
//!
//! v1 deterministic AEAD sender-nonce construction
//! (`nonce = sender_nonce_prefix || counter_be64`, per
//! `crypto-media/encryption-and-audit.md`) plus the canonical
//! encrypted-envelope AAD digest. These moved here from the SDK so the MLS
//! behavior layer can reach them without a dependency cycle back through the
//! umbrella crate; the SDK keeps the `arkret::crypto::*` surface via re-export
//! and the byte-level outputs are unchanged.

use arkret_canonical::canonical::{canonical_json_bytes, sha256_digest};
use arkret_models_crypto::EncryptedEnvelopeAad;
use arkret_wire::{ExporterLabelId, ReasonCode};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::{Error, Result};

/// MLS exporter label domain-separating the v1 AEAD sender nonce prefix.
pub const AEAD_NONCE_EXPORTER_LABEL: &str = ExporterLabelId::AEAD_SENDER_NONCE_PREFIX_V1;
/// Length of the big-endian device nonce counter suffix.
pub const AEAD_NONCE_COUNTER_LEN: usize = 8;
/// AEAD profile id for the XChaCha20-Poly1305 exporter content scheme.
pub const AEAD_PROFILE_XCHACHA20_POLY1305: &str = "mls_exporter_aead_xchacha20poly1305";
/// Domain-separation context prefix bound into canonical encrypted-envelope AAD.
pub const ENCRYPTED_ENVELOPE_AAD_CONTEXT: &str = "arkret-encrypted-envelope-aad-v1";

/// Canonical context for v1 AEAD sender nonce prefix derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadNonceContext {
    pub key_ref: Value,
    pub epoch: u64,
    pub device_id: String,
    pub purpose: String,
    pub aead_profile: String,
}

fn protocol_error(reason: &str, detail: &str) -> Error {
    Error::Protocol(format!("{reason}: {detail}"))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    // Authoritative `sha256:<lowercase-hex>` formatter (single source of truth
    // for the digest prefix/encoding).
    sha256_digest(bytes)
}

fn aead_nonce_prefix_len(nonce_len: usize) -> Result<usize> {
    if nonce_len <= AEAD_NONCE_COUNTER_LEN {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce length must reserve an 8-byte counter suffix",
        ));
    }
    Ok(nonce_len - AEAD_NONCE_COUNTER_LEN)
}

fn validate_aead_nonce_context(context: &AeadNonceContext) -> Result<()> {
    if context.key_ref.is_null() {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "key_ref must be present in the AEAD nonce exporter context",
        ));
    }
    if context.device_id.is_empty() || context.purpose.is_empty() || context.aead_profile.is_empty()
    {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "device_id, purpose and aead_profile must be non-empty",
        ));
    }
    Ok(())
}

/// Canonical JSON bytes used as MLS-Exporter Context for v1 AEAD nonce prefixes.
pub fn aead_sender_nonce_context_bytes(context: &AeadNonceContext) -> Result<Vec<u8>> {
    validate_aead_nonce_context(context)?;
    Ok(canonical_json_bytes(context)?)
}

/// Derive the sender nonce prefix from a fixed exporter secret for tests and adapters.
///
/// Live MLS integrations should call the MLS exporter with
/// [`AEAD_NONCE_EXPORTER_LABEL`], [`aead_sender_nonce_context_bytes`] and
/// `nonce_len - 8`. This helper mirrors that exporter input with HKDF-SHA256
/// so conformance tests can pin deterministic bytes without a live MLS group.
pub fn derive_aead_sender_nonce_prefix(
    exporter_secret: &[u8],
    context: &AeadNonceContext,
    nonce_len: usize,
) -> Result<Vec<u8>> {
    let prefix_len = aead_nonce_prefix_len(nonce_len)?;
    let context_bytes = aead_sender_nonce_context_bytes(context)?;
    let mut info = Vec::with_capacity(AEAD_NONCE_EXPORTER_LABEL.len() + 1 + context_bytes.len());
    info.extend_from_slice(AEAD_NONCE_EXPORTER_LABEL.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&context_bytes);

    let hkdf = Hkdf::<Sha256>::new(None, exporter_secret);
    let mut prefix = vec![0u8; prefix_len];
    hkdf.expand(&info, &mut prefix)
        .map_err(|_| Error::Crypto("AEAD nonce prefix derivation failed".to_owned()))?;
    Ok(prefix)
}

/// Compose `nonce = sender_nonce_prefix || device_nonce_counter_be64`.
pub fn compose_aead_nonce(sender_nonce_prefix: &[u8], counter: u64) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(sender_nonce_prefix.len() + AEAD_NONCE_COUNTER_LEN);
    nonce.extend_from_slice(sender_nonce_prefix);
    nonce.extend_from_slice(&counter.to_be_bytes());
    nonce
}

/// Canonicalize encrypted-envelope AAD and bind it to a domain-separated context.
pub fn canonical_envelope_aad(aad: &EncryptedEnvelopeAad) -> Result<Vec<u8>> {
    let mut bytes = ENCRYPTED_ENVELOPE_AAD_CONTEXT.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&canonical_json_bytes(aad)?);
    Ok(bytes)
}

/// Compute a SHA-256 digest over canonical encrypted-envelope AAD.
pub fn envelope_aad_digest(aad: &EncryptedEnvelopeAad) -> Result<String> {
    Ok(sha256_prefixed(&canonical_envelope_aad(aad)?))
}

/// Compute a SHA-256 digest over arbitrary JSON AAD using canonical JSON.
pub fn json_aad_digest(aad: &Value) -> Result<String> {
    let mut bytes = ENCRYPTED_ENVELOPE_AAD_CONTEXT.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&canonical_json_bytes(aad)?);
    Ok(sha256_prefixed(&bytes))
}
