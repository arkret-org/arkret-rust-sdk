//! Single base64 helper surface for the whole SDK.
//!
//! The protocol layer (encoding.md §2) standardizes on **base64url without
//! padding** for `_b64u`, cursor, cell subject and JWS segment encodings; `b64`
//! is not a protocol wire alphabet. Historically 9+ files inlined
//! `URL_SAFE_NO_PAD` and bespoke error mapping, which made padding/alphabet
//! drift easy. This module keeps the primitives in one place:
//!
//! - [`base64url_encode`] / [`base64url_decode`] are URL-safe, unpadded and the protocol default.
//!   All wire/signing-input base64 must go through this pair.
//! - [`base64_standard_encode`] / [`base64_standard_decode`] are only for the RFC 9421 HTTP Message
//!   Signature `Signature` header and RFC 9530 `Content-Digest`, where the standard alphabet with
//!   `=` padding is required.
//!
//! Decode errors map uniformly to [`Error::Protocol`] and retain the underlying
//! base64 error text.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::{Error, Result};

/// Encode `bytes` as base64url **without** padding (RFC 4648 §5).
///
/// This is the protocol default — every `_b64u` wire field, cursor body,
/// composite cell subject and detached-JWS segment uses this alphabet.
pub fn base64url_encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

/// Decode a base64url (no padding) string into raw bytes.
///
/// Returns [`Error::Protocol`] on any malformed input so call-sites get a
/// uniform error category instead of nine bespoke conversions.
pub fn base64url_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(input.as_ref())
        .map_err(|err| Error::Protocol(format!("invalid base64url: {err}")))
}

/// Encode `bytes` as standard base64 **with** padding (RFC 4648 §4).
///
/// Standard-alphabet base64 is only for RFC 9421 `Signature` header Inner List
/// Byte Sequences (§3.1) and RFC 9530 `Content-Digest` (`sha-256=:<b64>:`).
/// Every other wire context must use [`base64url_encode`].
pub fn base64_standard_encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes.as_ref())
}

/// Decode a standard base64 (with padding) string into raw bytes.
///
/// See [`base64_standard_encode`] for the (narrow) set of legitimate
/// call-sites.
pub fn base64_standard_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    STANDARD
        .decode(input.as_ref())
        .map_err(|err| Error::Protocol(format!("invalid base64 (standard alphabet): {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_without_padding() {
        let data = b"\x00\x01\xfe\xff hello";
        let encoded = base64url_encode(data);
        assert!(!encoded.contains('='), "base64url is unpadded");
        assert!(
            !encoded.contains('+') && !encoded.contains('/'),
            "URL-safe alphabet"
        );
        assert_eq!(base64url_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn base64url_decode_rejects_garbage() {
        assert!(matches!(
            base64url_decode("not valid!!!"),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn base64_standard_round_trips_with_padding() {
        let data = b"\x00\x01\xfe\xff";
        let encoded = base64_standard_encode(data);
        assert_eq!(base64_standard_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn standard_and_url_safe_diverge_on_alphabet() {
        let data = [0xfb_u8, 0xff, 0xbf];
        let std = base64_standard_encode(data);
        let url = base64url_encode(data);
        assert_ne!(std, url);
    }
}
