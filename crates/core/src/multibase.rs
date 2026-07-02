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

use crate::{Error, Result};

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
}
