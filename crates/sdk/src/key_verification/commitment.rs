use cokret_core::canonical::canonical_json_bytes;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use super::envelopes::KeyVerificationStart;
use crate::{Error, Result};

/// SHA-256 commitment over the responder's ephemeral public key and the
/// canonical `start` message (`device-lifecycle.md` §10.3:
/// "`accept.commitment` MUST 是对本端 ephemeral public key 与 canonical
/// `start` 消息的哈希承诺"). The responder calls this when building the
/// `accept` envelope; the initiator recomputes it in
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
    let mut hasher = Sha256::new();
    hasher.update(ephemeral_public_b64.as_bytes());
    hasher.update(&canonical_start);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Constant-time string equality for MAC / commitment comparisons.
pub(super) fn ct_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
