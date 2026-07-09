use cokret_core::canonical::{canonical_json_bytes, sha256_digest};

use super::envelopes::KeyVerificationStart;
use crate::{Error, Result};

/// SHA-256 commitment over the responder's ephemeral public key and the
/// canonical `start` message (`device-lifecycle.md` §10.3:
/// "`accept.commitment` MUST be a hash commitment over this side's ephemeral
/// public key and the canonical `start` message"). The responder calls this
/// when building the `accept` envelope; the initiator recomputes it in
/// [`KeyVerificationStrand::on_key`] once the responder reveals its key.
///
/// Construction: `"sha256:" + hex(SHA256(key_b64 || canonical_json(start)))`.
pub fn compute_key_commitment(
    ephemeral_public_b64: &str,
    start: &KeyVerificationStart,
) -> Result<String> {
    let start_value = serde_json::to_value(start)
        .map_err(|err| Error::Protocol(format!("serialize start for commitment: {err}")))?;
    let canonical_start = canonical_json_bytes(&start_value)
        .map_err(|err| Error::Protocol(format!("canonicalize start for commitment: {err}")))?;
    // SHA256(key_b64 || canonical_json(start)); the concatenation is
    // equivalent to the streaming `update` form. `sha256_digest` is the
    // authoritative `sha256:<hex>` formatter in `arkret-core`.
    let mut input = Vec::with_capacity(ephemeral_public_b64.len() + canonical_start.len());
    input.extend_from_slice(ephemeral_public_b64.as_bytes());
    input.extend_from_slice(&canonical_start);
    Ok(sha256_digest(&input))
}

/// Constant-time string equality for MAC / commitment comparisons —
/// delegates to the single crate-wide [`crate::crypto::constant_time_eq`].
pub(super) fn ct_eq(a: &str, b: &str) -> bool {
    crate::crypto::constant_time_eq(a, b)
}
