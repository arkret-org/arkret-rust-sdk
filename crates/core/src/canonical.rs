use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::io::Write as _;

use crate::{Error, Result};

/// Serialize a value with Contrix canonical JSON.
///
/// The v1 SDK uses an integer-only number profile for signing and hashing. This
/// rejects JSON floats even if serde_json can represent them.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_canonical_value(&value, &mut out)?;
    Ok(out)
}

pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String> {
    let bytes = canonical_json_bytes(value)?;
    String::from_utf8(bytes)
        .map_err(|err| Error::Protocol(format!("canonical JSON produced invalid UTF-8: {err}")))
}

/// Compute the SHA-256 of `bytes` and return the **bare** 64-character
/// lowercase hex digest (no `sha256:` prefix).
///
/// 返回不带 `sha256:` 前缀的裸 hex 摘要(固定 64 位小写十六进制),供需要
/// 原始 hash 原语的下游直接使用。[`sha256_digest`] 在此之上加前缀。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", sha256_hex(bytes.as_ref()))
}

/// Canonical digest helper for already-canonicalized JSON byte streams.
///
/// Downstream services that have already produced canonical JSON bytes
/// (e.g. via [`canonical_json_bytes`]) call this to derive the wire-form
/// `canonical_digest` / `request_canonical_digest` value used in event
/// envelopes, anchors, and policy-check payloads.
///
/// The output format is `sha256:<lowercase-hex>` and is byte-stable for
/// a given input. All downstream services (soland, yougen, floria, chime)
/// MUST go through this helper so the same canonical bytes produce
/// byte-identical digest strings everywhere.
///
/// This is a thin alias for [`sha256_digest`] kept distinct so the
/// call-site intent ("this is the wire-form canonical digest") is
/// self-documenting.
pub fn canonical_digest(bytes: &[u8]) -> String {
    sha256_digest(bytes)
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_digest(canonical_json_bytes(value)?))
}

/// Encode a composite **cell subject** from its parts.
///
/// The composite subject is derived from typed payload fields per the
/// spec event-kind-registry's `cell_subject` (composite form). This
/// helper preserves percent-encoding (`%` → `%25`, `|` → `%7C`) so
/// callers building a reducer-internal projection key
/// (`(space_id, kind, subject)`) get an unambiguous round-trip.
///
/// Wire-canonical composite subject is base64url(sha256(canonical_json([...])))
/// per `encoding.md` §9.5; this `|`-joined form is reducer-internal only.
///
/// Empty input returns an empty string. Each part MUST be valid UTF-8.
pub fn encode_state_subject(parts: &[&str]) -> String {
    let mut out = String::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            out.push('|');
        }
        for ch in part.chars() {
            match ch {
                '%' => out.push_str("%25"),
                '|' => out.push_str("%7C"),
                _ => out.push(ch),
            }
        }
    }
    out
}

/// Inverse of [`encode_state_subject`]. Returns each part as a decoded `String`.
pub fn decode_state_subject_parts(encoded: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in encoded.split('|') {
        let mut decoded = String::with_capacity(raw.len());
        let mut bytes = raw.bytes();
        while let Some(b) = bytes.next() {
            if b == b'%' {
                let hi = bytes.next().ok_or_else(|| {
                    Error::Protocol("state subject percent-encoding truncated".to_owned())
                })?;
                let lo = bytes.next().ok_or_else(|| {
                    Error::Protocol("state subject percent-encoding truncated".to_owned())
                })?;
                let code = u8::from_str_radix(&format!("{}{}", hi as char, lo as char), 16)
                    .map_err(|_| {
                        Error::Protocol(
                            "state subject percent-encoding has non-hex digits".to_owned(),
                        )
                    })?;
                decoded.push(code as char);
            } else {
                decoded.push(b as char);
            }
        }
        out.push(decoded);
    }
    Ok(out)
}

/// Validate that a timestamp string is in canonical RFC 3339 UTC form.
///
/// Canonical form: `YYYY-MM-DDTHH:MM:SSZ` — no fractional seconds, no `+00:00`
/// offset (must use `Z`), no lowercase `t` or `z`.
pub fn validate_timestamp_canonical(timestamp: &str) -> Result<()> {
    // Must end with 'Z' (not '+00:00' or lowercase 'z')
    if !timestamp.ends_with('Z') {
        return Err(Error::Protocol(format!("canonical timestamp must end with 'Z': {timestamp}")));
    }
    // Reject lowercase 't' separator
    if timestamp.contains('t') {
        return Err(Error::Protocol(format!(
            "canonical timestamp must use uppercase 'T': {timestamp}"
        )));
    }
    // Must have 'T' separator at position 10
    if timestamp.len() < 20 || timestamp.as_bytes().get(10) != Some(&b'T') {
        return Err(Error::Protocol(format!(
            "canonical timestamp must be YYYY-MM-DDTHH:MM:SSZ: {timestamp}"
        )));
    }
    // No fractional seconds (no '.' before 'Z')
    let time_part = &timestamp[11..];
    if time_part.contains('.') {
        return Err(Error::Protocol(format!(
            "canonical timestamp must not have fractional seconds: {timestamp}"
        )));
    }
    // Length must be exactly 20: "YYYY-MM-DDTHH:MM:SSZ"
    if timestamp.len() != 20 {
        return Err(Error::Protocol(format!(
            "canonical timestamp must be exactly YYYY-MM-DDTHH:MM:SSZ: {timestamp}"
        )));
    }
    // Verify it parses as a valid DateTime
    chrono::DateTime::parse_from_rfc3339(timestamp).map_err(|_| {
        Error::Protocol(format!("canonical timestamp is not a valid RFC 3339 date: {timestamp}"))
    })?;
    Ok(())
}

/// Format a [`chrono::DateTime<chrono::Utc>`] into the canonical
/// `YYYY-MM-DDTHH:MM:SSZ` timestamp string accepted by
/// [`validate_timestamp_canonical`].
///
/// The output is RFC 3339 UTC, ends with `Z`, has **no** fractional
/// seconds, and is exactly 20 characters long. Sub-second precision in
/// the input is truncated.
///
/// 产出与 [`validate_timestamp_canonical`] 接受口径完全一致的规范时间戳串:
/// RFC3339 UTC、以 `Z` 结尾、无小数秒、固定 20 字符。亚秒精度被截断。
pub fn format_timestamp_canonical(when: chrono::DateTime<chrono::Utc>) -> String {
    when.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Convenience: format a Unix timestamp in **milliseconds** (UTC) into the
/// canonical `YYYY-MM-DDTHH:MM:SSZ` string. Returns `None` if the value is
/// out of the representable range. Sub-second milliseconds are truncated.
///
/// 便捷重载:从 Unix 毫秒构造规范时间戳串(超出可表示范围时返回 `None`)。
pub fn format_timestamp_canonical_millis(unix_millis: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_millis)
        .map(format_timestamp_canonical)
}

/// Convenience: format a Unix timestamp in **seconds** (UTC) into the
/// canonical `YYYY-MM-DDTHH:MM:SSZ` string. Returns `None` if the value is
/// out of the representable range.
///
/// 便捷重载:从 Unix 秒构造规范时间戳串(超出可表示范围时返回 `None`)。
pub fn format_timestamp_canonical_secs(unix_secs: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, 0).map(format_timestamp_canonical)
}

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(string) => write_string(string, out),
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(map, out)?,
    }

    Ok(())
}

fn write_number(number: &Number, out: &mut Vec<u8>) -> Result<()> {
    // Reject any number that doesn't round-trip cleanly as i64 or u64.
    // Per `encoding.md` §3.2, the v1 number profile forbids floats —
    // even integer-valued floats like `1.0` MUST be rejected.
    if number.as_f64().is_some() && number.as_i64().is_none() && number.as_u64().is_none() {
        return Err(Error::NonCanonicalNumber);
    }
    if let Some(n) = number.as_i64() {
        let s = n.to_string();
        reject_leading_zeros(&s)?;
        out.extend_from_slice(s.as_bytes());
    } else if let Some(n) = number.as_u64() {
        let s = n.to_string();
        reject_leading_zeros(&s)?;
        out.extend_from_slice(s.as_bytes());
    } else {
        return Err(Error::NonCanonicalNumber);
    }

    Ok(())
}

fn reject_leading_zeros(s: &str) -> Result<()> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.len() > 1 && digits.as_bytes()[0] == b'0' {
        return Err(Error::NonCanonicalNumber);
    }
    Ok(())
}

fn write_string(string: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in string.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{08}' => out.extend_from_slice(br#"\b"#),
            '\t' => out.extend_from_slice(br#"\t"#),
            '\n' => out.extend_from_slice(br#"\n"#),
            '\u{0c}' => out.extend_from_slice(br#"\f"#),
            '\r' => out.extend_from_slice(br#"\r"#),
            '\u{00}'..='\u{1f}' => {
                write!(out, "\\u{:04x}", ch as u32).expect("writing to Vec cannot fail");
            }
            _ => {
                let mut buf = [0_u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<()> {
    out.push(b'{');

    let mut keys = map.keys().collect::<Vec<_>>();
    keys.sort_unstable_by(|a, b| compare_utf16(a, b));

    for (idx, key) in keys.into_iter().enumerate() {
        if idx > 0 {
            out.push(b',');
        }
        write_string(key, out);
        out.push(b':');
        write_canonical_value(&map[key], out)?;
    }

    out.push(b'}');
    Ok(())
}

fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = json!({ "b": 2, "a": 1 });
        let actual = canonical_json_string(&value).unwrap();
        assert_eq!(actual, r#"{"a":1,"b":2}"#);
        assert_eq!(
            sha256_digest(actual.as_bytes()),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn canonical_json_rejects_float_numbers() {
        let value = json!({ "n": 1.5 });
        assert!(matches!(canonical_json_string(&value), Err(Error::NonCanonicalNumber)));
    }

    #[test]
    fn canonical_json_rejects_float_zero() {
        let value = json!({ "n": 0.0 });
        assert!(matches!(canonical_json_string(&value), Err(Error::NonCanonicalNumber)));
    }

    #[test]
    fn validate_timestamp_canonical_accepts_rfc3339_utc() {
        assert!(validate_timestamp_canonical("2026-04-26T00:00:00Z").is_ok());
        assert!(validate_timestamp_canonical("2026-12-31T23:59:59Z").is_ok());
    }

    #[test]
    fn validate_timestamp_canonical_rejects_offset_form() {
        assert!(validate_timestamp_canonical("2026-04-26T00:00:00+00:00").is_err());
        assert!(validate_timestamp_canonical("2026-04-26T00:00:00+05:30").is_err());
    }

    #[test]
    fn validate_timestamp_canonical_rejects_fractional_seconds() {
        assert!(validate_timestamp_canonical("2026-04-26T00:00:00.000Z").is_err());
        assert!(validate_timestamp_canonical("2026-04-26T00:00:00.123456Z").is_err());
    }

    #[test]
    fn validate_timestamp_canonical_rejects_lowercase_t_or_z() {
        assert!(validate_timestamp_canonical("2026-04-26t00:00:00Z").is_err());
        assert!(validate_timestamp_canonical("2026-04-26T00:00:00z").is_err());
    }

    #[test]
    fn format_timestamp_canonical_roundtrips_through_validate() {
        let when = chrono::DateTime::parse_from_rfc3339("2026-06-03T12:34:56.789Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let formatted = format_timestamp_canonical(when);
        // Fractional seconds are truncated and the string is exactly 20 chars.
        assert_eq!(formatted, "2026-06-03T12:34:56Z");
        assert_eq!(formatted.len(), 20);
        // The formatter's output MUST be accepted by the validator.
        validate_timestamp_canonical(&formatted).expect("formatted timestamp must validate");
    }

    #[test]
    fn format_timestamp_canonical_from_unix_passes_validate() {
        let millis = format_timestamp_canonical_millis(1_780_000_000_999).unwrap();
        validate_timestamp_canonical(&millis).expect("millis form must validate");
        let secs = format_timestamp_canonical_secs(1_780_000_000).unwrap();
        validate_timestamp_canonical(&secs).expect("secs form must validate");
        // The two forms agree once sub-second precision is dropped.
        assert_eq!(millis, secs);
    }

    #[test]
    fn sha256_hex_has_no_prefix_and_matches_digest() {
        let hex = sha256_hex(b"hello");
        assert_eq!(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(hex.len(), 64);
        assert!(!hex.starts_with("sha256:"));
        assert_eq!(sha256_digest(b"hello"), format!("sha256:{hex}"));
    }

    #[test]
    fn validate_timestamp_canonical_rejects_invalid_date() {
        assert!(validate_timestamp_canonical("2026-13-01T00:00:00Z").is_err());
        assert!(validate_timestamp_canonical("2026-02-30T00:00:00Z").is_err());
    }

    #[test]
    fn validate_timestamp_canonical_rejects_empty_and_garbage() {
        assert!(validate_timestamp_canonical("").is_err());
        assert!(validate_timestamp_canonical("not-a-timestamp").is_err());
        assert!(validate_timestamp_canonical("Z").is_err());
    }

    #[test]
    fn canonical_json_integer_roundtrip_preserves_sign() {
        assert_eq!(canonical_json_string(&json!(0)).unwrap(), "0");
        assert_eq!(canonical_json_string(&json!(1)).unwrap(), "1");
        assert_eq!(canonical_json_string(&json!(-1)).unwrap(), "-1");
        assert_eq!(canonical_json_string(&json!(i64::MAX)).unwrap(), "9223372036854775807");
        assert_eq!(canonical_json_string(&json!(i64::MIN)).unwrap(), "-9223372036854775808");
    }

    #[test]
    fn canonical_json_nested_object_key_order() {
        let value = json!({ "z": { "b": 1, "a": 2 }, "a": 1 });
        let actual = canonical_json_string(&value).unwrap();
        assert_eq!(actual, r#"{"a":1,"z":{"a":2,"b":1}}"#);
    }

    #[test]
    fn canonical_json_sorts_object_keys_by_utf16_code_units() {
        let supplementary = char::from_u32(0x10000).unwrap().to_string();
        let private_use = char::from_u32(0xE000).unwrap().to_string();
        let value = json!({ private_use.clone(): 2, supplementary.clone(): 1 });
        let actual = canonical_json_string(&value).unwrap();
        let supplementary_pos = actual.find(&format!("\"{supplementary}\"")).unwrap();
        let private_use_pos = actual.find(&format!("\"{private_use}\"")).unwrap();
        assert!(
            supplementary_pos < private_use_pos,
            "JCS sorts by UTF-16 code units, so U+10000 sorts before U+E000"
        );
    }

    #[test]
    fn canonical_json_string_escapes_special_characters() {
        let value = json!({ "key": "value\nwith\ttabs\"quotes\u{0001}" });
        let actual = canonical_json_string(&value).unwrap();
        assert!(actual.contains("\\n"));
        assert!(actual.contains("\\t"));
        assert!(actual.contains("\\\""));
        assert!(actual.contains("\\u0001"));
    }

    #[test]
    fn state_subject_encoding_roundtrips_simple_parts() {
        let parts =
            ["did:web:alice.example", "discussion", "cx:flow:01904100-0000-7000-8000-6c663fa0205f"];
        let encoded = encode_state_subject(&parts);
        assert_eq!(
            encoded,
            "did:web:alice.example|discussion|cx:flow:01904100-0000-7000-8000-6c663fa0205f"
        );
        let decoded = decode_state_subject_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn state_subject_encoding_escapes_pipes_and_percents() {
        // A DID method-specific id that legitimately contains '|' must be
        // round-trippable without colliding with the part separator.
        let parts = ["did:web:alice|bar", "100%great", "plain"];
        let encoded = encode_state_subject(&parts);
        assert_eq!(encoded, "did:web:alice%7Cbar|100%25great|plain");
        let decoded = decode_state_subject_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn state_subject_decode_rejects_truncated_percent() {
        assert!(decode_state_subject_parts("abc%2").is_err());
        assert!(decode_state_subject_parts("abc%").is_err());
    }

    #[test]
    fn canonical_digest_is_byte_stable_for_fixed_input() {
        // The empty-input digest is the canonical sha256(b"") value;
        // any drift here is a backwards-incompatible change downstream
        // (soland event_log, anchorer, policy hashing).
        assert_eq!(
            canonical_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            canonical_digest(b"hello"),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn canonical_digest_matches_sha256_digest_alias() {
        let bytes = canonical_json_bytes(&json!({ "b": 2, "a": 1 })).unwrap();
        assert_eq!(canonical_digest(&bytes), sha256_digest(&bytes));
    }

    #[test]
    fn canonical_digest_round_trips_through_canonical_json_bytes() {
        // Reordering object keys MUST yield the same digest because
        // canonical_json_bytes sorts them; the digest is taken over the
        // sorted byte stream.
        let a = canonical_json_bytes(&json!({ "a": 1, "b": 2 })).unwrap();
        let b = canonical_json_bytes(&json!({ "b": 2, "a": 1 })).unwrap();
        assert_eq!(canonical_digest(&a), canonical_digest(&b));
        assert!(canonical_digest(&a).starts_with("sha256:"));
    }
}
