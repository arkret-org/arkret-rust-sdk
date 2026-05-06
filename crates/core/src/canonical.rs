use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

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

pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    format!("sha256:{digest:x}")
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_digest(canonical_json_bytes(value)?))
}

/// Encode a composite `state_key` from its parts (B-18 in `_report.md`).
///
/// State events that key on multiple identifiers (e.g. `flow_id|branch|did`)
/// MUST escape any literal `|` in a part because DID grammar permits the
/// pipe character. This helper percent-encodes `%` and `|` in each part and
/// joins with `|` so the inverse [`decode_state_key_parts`] is unambiguous.
///
/// Empty input returns an empty string. Each part MUST be valid UTF-8.
pub fn encode_state_key(parts: &[&str]) -> String {
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

/// Inverse of [`encode_state_key`]. Returns each part as a decoded `String`.
pub fn decode_state_key_parts(encoded: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in encoded.split('|') {
        let mut decoded = String::with_capacity(raw.len());
        let mut bytes = raw.bytes();
        while let Some(b) = bytes.next() {
            if b == b'%' {
                let hi = bytes.next().ok_or_else(|| {
                    Error::Protocol("state_key percent-encoding truncated".to_owned())
                })?;
                let lo = bytes.next().ok_or_else(|| {
                    Error::Protocol("state_key percent-encoding truncated".to_owned())
                })?;
                let code = u8::from_str_radix(&format!("{}{}", hi as char, lo as char), 16)
                    .map_err(|_| {
                        Error::Protocol("state_key percent-encoding has non-hex digits".to_owned())
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

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(string) => {
            serde_json::to_writer(out, string)?;
        }
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
    let bytes = s.as_bytes();
    if bytes.len() > 1 && bytes[0] == b'0' && bytes[1] != b'-' {
        return Err(Error::NonCanonicalNumber);
    }
    if bytes.len() > 2 && bytes[0] == b'-' && bytes[1] == b'0' && bytes[2] != b'\0' {
        // -0 is fine, but -01 is not
        if bytes.len() > 2 && bytes[1] == b'0' && bytes[2] != b'0' {
            return Err(Error::NonCanonicalNumber);
        }
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<()> {
    out.push(b'{');

    let mut keys = map.keys().collect::<Vec<_>>();
    keys.sort_unstable();

    for (idx, key) in keys.into_iter().enumerate() {
        if idx > 0 {
            out.push(b',');
        }
        serde_json::to_writer(&mut *out, key)?;
        out.push(b':');
        write_canonical_value(&map[key], out)?;
    }

    out.push(b'}');
    Ok(())
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
    fn canonical_json_string_escapes_special_characters() {
        let value = json!({ "key": "value\nwith\ttabs\"quotes" });
        let actual = canonical_json_string(&value).unwrap();
        assert!(actual.contains("\\n"));
        assert!(actual.contains("\\t"));
        assert!(actual.contains("\\\""));
    }

    #[test]
    fn state_key_encoding_roundtrips_simple_parts() {
        let parts = ["did:web:alice.example", "discussion", "cx:flow:01"];
        let encoded = encode_state_key(&parts);
        assert_eq!(encoded, "did:web:alice.example|discussion|cx:flow:01");
        let decoded = decode_state_key_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn state_key_encoding_escapes_pipes_and_percents() {
        // A DID method-specific id that legitimately contains '|' must be
        // round-trippable without colliding with the part separator.
        let parts = ["did:web:alice|bar", "100%great", "plain"];
        let encoded = encode_state_key(&parts);
        assert_eq!(encoded, "did:web:alice%7Cbar|100%25great|plain");
        let decoded = decode_state_key_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn state_key_decode_rejects_truncated_percent() {
        assert!(decode_state_key_parts("abc%2").is_err());
        assert!(decode_state_key_parts("abc%").is_err());
    }
}
