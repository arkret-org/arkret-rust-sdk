//! Single source of truth for base58btc / multicodec / `did:key` encoding.
//!
//! Historically the `did:key` ↔ Ed25519 multiencoding stack had separate
//! hand-rolled base58 implementations in `sdk/src/jws.rs`,
//! `sdk/src/identity/helpers.rs` and `signatures/src/proof.rs`. This module
//! centralizes the lower-level base58btc behavior on the mature `bs58` crate and
//! exposes:
//!
//! - [`encode_base58btc`] / [`decode_base58btc`]: Bitcoin-alphabet base58 without the multibase `z`
//!   prefix.
//! - [`encode_multibase_base58btc`] / [`decode_multibase_base58btc`]: `z`-prefixed multibase
//!   base58btc for W3C did:key / verificationMethod shapes.
//! - [`decode_multicodec_varint`]: multicodec unsigned-varint header parsing.
//! - [`ed25519_pubkey_to_did_key_multibase`] / [`decode_ed25519_multibase`]: Ed25519 public key ↔
//!   `z<base58btc(0xed01||key)>`.
//!
//! webvh SCID / entry-hash multihash shapes also reuse these base58btc
//! primitives through the multihash wrapper above [`encode_multibase_base58btc`].
//! The underlying bytes match the previous hand-rolled implementations, so
//! existing did:key and did:webvh tests remain stable.

use sha2::{Digest, Sha256};

use crate::{CanonicalError as Error, Result};

/// Multicodec code for an Ed25519 public key (`0xed`, encoded as unsigned-varint
/// bytes `0xed 0x01`).
pub const MULTICODEC_ED25519_PUB: u64 = 0xed;

/// Encode `bytes` as base58btc (Bitcoin alphabet), without a multibase prefix.
pub fn encode_base58btc(bytes: impl AsRef<[u8]>) -> String {
    bs58::encode(bytes.as_ref()).into_string()
}

/// Decode a base58btc (Bitcoin alphabet) string. Returns [`Error::Protocol`]
/// on any invalid character.
pub fn decode_base58btc(input: &str) -> Result<Vec<u8>> {
    bs58::decode(input)
        .into_vec()
        .map_err(|err| Error::Protocol(format!("invalid base58btc: {err}")))
}

/// Encode `bytes` as a multibase base58btc string: a leading `z` followed by
/// the base58btc payload (W3C `did:key` / verificationMethod form).
pub fn encode_multibase_base58btc(bytes: impl AsRef<[u8]>) -> String {
    format!("z{}", encode_base58btc(bytes))
}

/// Decode a multibase base58btc string (`z<base58btc>`). Rejects inputs that
/// do not start with the `z` multibase prefix.
pub fn decode_multibase_base58btc(input: &str) -> Result<Vec<u8>> {
    let body = input
        .strip_prefix('z')
        .ok_or_else(|| Error::Protocol(format!("multibase value missing 'z' prefix: {input}")))?;
    decode_base58btc(body)
}

/// Parse a leading multicodec unsigned-varint from `bytes`.
///
/// Returns `(code, header_len)` where `header_len` is the number of bytes the
/// varint consumed (so `&bytes[header_len..]` is the payload). Returns `None`
/// for a truncated or overlong (> 64-bit) varint.
pub fn decode_multicodec_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index == 9 {
            if byte > 1 {
                return None;
            }
            return Some((value | (u64::from(byte) << 63), index + 1));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Wrap a raw 32-byte Ed25519 public key in the `did:key` multibase form:
/// `z` + base58btc(`0xed 0x01` multicodec prefix || 32-byte key).
pub fn ed25519_pubkey_to_did_key_multibase(pubkey: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(pubkey);
    encode_multibase_base58btc(bytes)
}

/// Decode a `z<base58btc(0xed01 || key)>` multibase string into the raw
/// 32-byte Ed25519 public key. Rejects a missing `z` prefix, a wrong
/// multicodec, or a non-32-byte key.
pub fn decode_ed25519_multibase(multibase: &str) -> Result<[u8; 32]> {
    let decoded = decode_multibase_base58btc(multibase)?;
    if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(Error::Protocol(format!(
            "expected ed25519-pub multicodec (0xed 0x01) in `{multibase}`"
        )));
    }
    let key = &decoded[2..];
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| Error::Protocol(format!("Ed25519 key must be 32 bytes, got {}", key.len())))?;
    Ok(key)
}

/// Encode a DIF did:webvh sha2-256 multihash as bare base58btc:
/// `base58btc(0x12 || 0x20 || sha256(bytes))`.
///
/// SCIDs, entry hashes, and `nextKeyHashes` use this form without a multibase
/// `z` prefix.
pub fn sha256_multihash_base58btc(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    encode_base58btc(multihash)
}

/// Decode a bare 64-byte Ed25519 signature carried as multibase base58btc.
///
/// DIF did:webvh `proofValue` uses this shape and does not prepend an
/// Ed25519 multicodec tag.
pub fn decode_ed25519_signature_multibase(multibase: &str) -> Result<[u8; 64]> {
    let decoded = decode_multibase_base58btc(multibase)?;
    decoded.try_into().map_err(|value: Vec<u8>| {
        Error::Protocol(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            value.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58btc_round_trips_with_leading_zeros() {
        let data = [0u8, 0, 1, 2, 3, 0xff];
        let encoded = encode_base58btc(data);
        // Leading zero bytes encode as leading '1's.
        assert!(encoded.starts_with("11"));
        assert_eq!(decode_base58btc(&encoded).unwrap(), data);
    }

    #[test]
    fn multibase_requires_z_prefix() {
        assert!(decode_multibase_base58btc("not-multibase").is_err());
        let mb = encode_multibase_base58btc([1u8, 2, 3]);
        assert!(mb.starts_with('z'));
        assert_eq!(decode_multibase_base58btc(&mb).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn webvh_sha256_multihash_uses_the_bare_qm_form() {
        let encoded = sha256_multihash_base58btc(b"arkret");
        assert!(encoded.starts_with("Qm"));
        let decoded = decode_base58btc(&encoded).unwrap();
        assert_eq!(&decoded[..2], &[0x12, 0x20]);
        assert_eq!(&decoded[2..], Sha256::digest(b"arkret").as_slice());
    }

    #[test]
    fn bare_ed25519_signature_multibase_round_trips() {
        let signature = [0x5au8; 64];
        let encoded = encode_multibase_base58btc(signature);
        assert_eq!(
            decode_ed25519_signature_multibase(&encoded).unwrap(),
            signature
        );
        assert!(decode_ed25519_signature_multibase("z1").is_err());
    }

    #[test]
    fn ed25519_did_key_multibase_round_trips() {
        let key = [42u8; 32];
        let mb = ed25519_pubkey_to_did_key_multibase(&key);
        assert!(mb.starts_with('z'));
        assert_eq!(decode_ed25519_multibase(&mb).unwrap(), key);
    }

    #[test]
    fn decode_ed25519_rejects_wrong_multicodec() {
        // 0xe7 = secp256k1-pub, not ed25519.
        let mut bytes = vec![0xe7u8, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        let mb = encode_multibase_base58btc(bytes);
        assert!(decode_ed25519_multibase(&mb).is_err());
    }

    #[test]
    fn multicodec_varint_parses_ed25519_header() {
        let bytes = [0xed, 0x01, 0xaa, 0xbb];
        let (code, len) = decode_multicodec_varint(&bytes).unwrap();
        assert_eq!(code, MULTICODEC_ED25519_PUB);
        assert_eq!(len, 2);
        assert_eq!(&bytes[len..], &[0xaa, 0xbb]);
    }

    // ── SDK-TEST-06 negative coverage ────────────────────────────────────

    #[test]
    fn base58btc_rejects_non_alphabet_characters() {
        // '0', 'O', 'I', 'l' are excluded from the Bitcoin base58 alphabet;
        // '+' and '/' come from base64 confusion; whitespace must not pass.
        for bad in [
            "0", "O", "I", "l", "abc0def", "ab+cd", "ab/cd", "ab cd", "café",
        ] {
            assert!(
                decode_base58btc(bad).is_err(),
                "base58btc must reject {bad:?}"
            );
            assert!(
                decode_multibase_base58btc(&format!("z{bad}")).is_err(),
                "multibase base58btc must reject z{bad}"
            );
        }
        // Empty multibase payload decodes to empty bytes but the ed25519
        // decoder must still reject it (no multicodec header).
        assert!(decode_ed25519_multibase("z").is_err());
    }

    #[test]
    fn decode_ed25519_rejects_wrong_payload_length() {
        // Correct multicodec prefix but a key that is not 32 bytes: the
        // total decoded payload must be exactly 34 bytes (0xed 0x01 + 32).
        for key_len in [0usize, 1, 31, 33, 64] {
            let mut bytes = vec![0xedu8, 0x01];
            bytes.extend_from_slice(&vec![7u8; key_len]);
            let mb = encode_multibase_base58btc(&bytes);
            assert!(
                decode_ed25519_multibase(&mb).is_err(),
                "ed25519 multibase must reject {key_len}-byte keys"
            );
        }
        // Bare prefix shorter than the 2-byte multicodec header.
        let mb = encode_multibase_base58btc([0xedu8]);
        assert!(decode_ed25519_multibase(&mb).is_err());
    }

    #[test]
    fn multicodec_varint_rejects_truncated_and_overlong_headers() {
        // Truncated: continuation bit set with no following byte.
        assert!(decode_multicodec_varint(&[0x80]).is_none());
        assert!(decode_multicodec_varint(&[0xff, 0x80]).is_none());
        // Empty input carries no varint at all.
        assert!(decode_multicodec_varint(&[]).is_none());
        // Overlong: ten continuation bytes exceed the 64-bit ceiling.
        let overlong = [0xffu8; 10];
        assert!(decode_multicodec_varint(&overlong).is_none());
        // The tenth byte contributes only bit 63. Any higher bit overflows u64.
        let mut overflowing_terminal = [0xffu8; 10];
        overflowing_terminal[9] = 0x02;
        assert!(decode_multicodec_varint(&overflowing_terminal).is_none());

        let mut max_u64 = [0xffu8; 10];
        max_u64[9] = 0x01;
        assert_eq!(decode_multicodec_varint(&max_u64), Some((u64::MAX, 10)));
    }
}
