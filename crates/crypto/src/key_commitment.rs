//! The shared pre-AEAD content-key commitment for body and attachment contexts.

use arkret_canonical::canonical_json_bytes;
use arkret_wire::Hash;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::Result;

pub fn content_key_commitment_sha256(context: &impl Serialize, key: &[u8]) -> Result<Hash> {
    let mut digest = Sha256::new();
    digest.update(b"ak.content.key_commitment.v1\n");
    digest.update(canonical_json_bytes(context)?);
    digest.update(key);
    Ok(Hash::new(format!(
        "sha256:{}",
        hex::encode(digest.finalize())
    ))?)
}
