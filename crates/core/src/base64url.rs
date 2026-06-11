//! Single base64 helper surface for the whole SDK.
//!
//! 协议层(encoding.md §2)统一约定使用 **base64url(无 padding)** 作为
//! `_b64u` / cursor / cell subject / JWS 段等的编码字母表;禁止 `b64`。
//! 历史上 9+ 个文件各自内联 `URL_SAFE_NO_PAD` 引擎与各自的错误映射,极易
//! 在 padding / alphabet 规则上漂移。本模块把这两个原语收敛到一处:
//!
//! - [`base64url_encode`] / [`base64url_decode`] —— URL-safe、无 padding, 是协议默认编码。所有 wire
//!   / 签名输入 base64 都 MUST 走这一对。
//! - [`base64_standard_encode`] / [`base64_standard_decode`] —— **仅** RFC 9421 HTTP Message
//!   Signature 的 `Signature` header 与 RFC 9530 `Content-Digest` 用标准字母表(带 `=`
//!   padding),其余场景禁止使用。
//!
//! 解码错误统一映射为 [`Error::Protocol`],携带原始 base64 错误文本。

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
/// 标准字母表 base64 **只**用于 RFC 9421 `Signature` header 的 Inner List
/// Byte Sequence(§3.1)与 RFC 9530 `Content-Digest`(`sha-256=:<b64>:`);
/// 其余一切 wire 场景 MUST 用 [`base64url_encode`]。
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
