use std::io::Write as _;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Serialize a value with Cokret canonical JSON.
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

/// Returns `true` if `s` is already in Unicode NFC (Normalization Form C).
///
/// `encoding.md` §2.1: every wire string MUST be NFC *before* it is written to
/// canonical JSON, and a receiver MUST reject a non-NFC string rather than
/// silently normalising it during verify — two visually identical strings that
/// differ only in composition (precomposed vs decomposed) otherwise produce
/// different digests, a hash/signature false-negative vector.
pub fn is_nfc(s: &str) -> bool {
    unicode_normalization::is_nfc(s)
}

/// Normalize a string to Unicode NFC. Producers MAY call this before
/// placing free-text fields (e.g. `contact_requested_payload.message`)
/// into canonical JSON, since the receiver-side validators reject non-NFC
/// input rather than normalizing it. Already-NFC input is returned
/// unchanged (cheap fast path).
pub fn to_nfc(s: &str) -> String {
    if unicode_normalization::is_nfc(s) {
        return s.to_owned();
    }
    use unicode_normalization::UnicodeNormalization as _;
    s.nfc().collect()
}

/// Hard byte cap enforced on every canonical-JSON ingress entry point.
///
/// `scalability-constraints.md` §2: a single envelope larger than 1 MiB
/// (1,048,576 bytes) MUST be rejected. The canonical ingress helpers
/// ([`parse_canonical_json`] / [`from_canonical_json_slice`] /
/// [`validate_canonical_bytes`]) are the SDK's wire-input parsing surface, so
/// the cap is built in and fail-closed — there is no opt-out parameter.
/// Egress ([`canonical_json_bytes`]) is not capped.
pub const MAX_CANONICAL_JSON_INGRESS_BYTES: usize = 1_048_576;

/// Maximum container nesting depth accepted on canonical-JSON ingress
/// (`scalability-constraints.md` §2: objects and arrays combined, the
/// top-level container counts as depth 1, the limit is inclusive). Depth 64
/// MUST be accepted, depth 65 MUST be rejected
/// (`ck.vector.encoding.reject_structure_depth_exceeded.v1`). The cap keeps
/// hand-crafted deep nesting from turning recursive parsing into a
/// stack-overflow abort independently of `serde_json`'s own 128-level guard.
pub const MAX_CANONICAL_JSON_NESTING_DEPTH: usize = 64;

/// Unified inbound canonical-JSON validation entry point (`encoding.md` §2 / §2.1).
///
/// Layers the receiver-side MUSTs that `serde_json::from_slice` does **not**
/// enforce, so every inbound envelope / proof / cursor / receipt can validate
/// through one call:
/// - input larger than [`MAX_CANONICAL_JSON_INGRESS_BYTES`] rejected before any
///   parsing work (`scalability-constraints.md` §2);
/// - UTF-8 BOM / `U+FEFF` rejected (byte scan in [`parse_canonical_json`]);
/// - duplicate object keys rejected at any depth ([`parse_canonical_json`]);
/// - every string value / object key rejected if non-NFC or containing an (escaped) `U+FEFF`;
/// - every JSON number rejected if it falls outside the canonical integer profile or the JSON
///   safe-integer range (reuses [`write_number`]).
/// - raw input bytes MUST exactly equal the canonical serialization of the parsed value, rejecting
///   unsorted object keys, whitespace, alternate string escapes, and non-minimal number forms.
pub fn validate_canonical_bytes(bytes: &[u8]) -> Result<()> {
    parse_canonical_json(bytes).map(|_| ())
}

/// Deserialize typed inbound canonical JSON after applying the receiver-side
/// canonical profile checks.
pub fn from_canonical_json_slice<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    let value = parse_canonical_json(bytes)?;
    serde_json::from_value(value).map_err(Error::from)
}

/// UTF-8 string overload of [`from_canonical_json_slice`].
pub fn from_canonical_json_str<T>(s: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    from_canonical_json_slice(s.as_bytes())
}

fn validate_canonical_value(value: &Value) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(s) => validate_canonical_string(s),
        Value::Number(number) => {
            let mut sink = Vec::new();
            write_number(number, &mut sink)
        }
        Value::Array(items) => items.iter().try_for_each(validate_canonical_value),
        Value::Object(map) => {
            for (key, val) in map {
                validate_canonical_string(key)?;
                validate_canonical_value(val)?;
            }
            Ok(())
        }
    }
}

fn validate_canonical_string(s: &str) -> Result<()> {
    // A raw U+FEFF is already rejected at the byte level, but an escaped
    // `﻿` survives JSON string decoding — reject it here too.
    if s.contains('\u{feff}') {
        return Err(Error::NonCanonicalString(
            "string value contains U+FEFF".to_owned(),
        ));
    }
    if !is_nfc(s) {
        return Err(Error::NonCanonicalString(format!(
            "string value is not Unicode NFC: {s:?}"
        )));
    }
    Ok(())
}

/// Parse inbound JSON bytes into a [`Value`] with the canonical-JSON ingress
/// rules that `serde_json::from_slice` does **not** enforce.
///
/// Per `encoding.md` §2, a JSON object with a duplicate key MUST be rejected —
/// last-wins / first-wins are both forbidden because they let an attacker craft
/// two byte-different inputs that parse to the "same" object, a signature
/// malleability vector. `serde_json` silently takes last-wins, so every inbound
/// envelope / proof / cursor / receipt path MUST go through this entry point
/// instead of a bare `serde_json::from_slice`.
///
/// This rejects duplicate keys at **any** nesting depth, then re-canonicalizes
/// the parsed value and compares the result to the original bytes. Any mismatch
/// means the ingress bytes were not the unique Cokret canonical JSON form.
pub fn parse_canonical_json(bytes: &[u8]) -> Result<Value> {
    // scalability-constraints.md §2: a single envelope over 1 MiB MUST be
    // rejected. Enforce the cap before any BOM scan / parse work so an
    // oversized input cannot be materialised into a `Value`.
    if bytes.len() > MAX_CANONICAL_JSON_INGRESS_BYTES {
        return Err(Error::Protocol(format!(
            "canonical JSON input is {} bytes, exceeding the v1 ingress maximum of {MAX_CANONICAL_JSON_INGRESS_BYTES} bytes (scalability-constraints.md §2)",
            bytes.len()
        )));
    }
    // encoding.md §2: reject any UTF-8 BOM / U+FEFF — at the stream start *or*
    // embedded inside a string value. U+FEFF is `EF BB BF` in UTF-8 and the
    // encoding is self-synchronising, so a raw byte-window scan catches every
    // occurrence (escaped `﻿` is rejected separately by `write_string` on
    // the canonical emit path).
    if bytes.windows(3).any(|w| w == [0xEF, 0xBB, 0xBF]) {
        return Err(Error::NonCanonicalString(
            "input contains a UTF-8 BOM / U+FEFF".to_owned(),
        ));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = serde::de::DeserializeSeed::deserialize(CanonicalValueSeed { depth: 1 }, &mut de)
        .map_err(canonical_parse_error)?;
    de.end().map_err(canonical_parse_error)?;
    validate_canonical_bytes_match(bytes, &value)?;
    Ok(value)
}

fn validate_canonical_bytes_match(bytes: &[u8], value: &Value) -> Result<()> {
    validate_canonical_value(value)?;
    let canonical = canonical_json_bytes(value)?;
    if canonical.as_slice() == bytes {
        return Ok(());
    }
    Err(Error::Protocol(
        "canonical JSON input is not byte-for-byte canonical".to_owned(),
    ))
}

/// Map a parser error into the right [`Error`] variant. A duplicate key is
/// surfaced through serde's `custom` message with a stable prefix so the
/// strongly-typed [`Error::DuplicateObjectKey`] survives the round-trip.
fn canonical_parse_error(err: serde_json::Error) -> Error {
    let message = err.to_string();
    if let Some(rest) = message.strip_prefix(DUPLICATE_KEY_MARKER) {
        let key = rest.split(" at ").next().unwrap_or(rest);
        return Error::DuplicateObjectKey(key.to_owned());
    }
    if message.contains(DEPTH_EXCEEDED_MARKER) {
        // Wire reason: structure_depth_exceeded (scalability-constraints.md §2).
        return Error::Protocol(format!(
            "canonical JSON nesting exceeds the v1 maximum depth of {MAX_CANONICAL_JSON_NESTING_DEPTH} (structure_depth_exceeded)"
        ));
    }
    Error::CanonicalJson(err)
}

const DUPLICATE_KEY_MARKER: &str = "cokret-duplicate-object-key:";
const DEPTH_EXCEEDED_MARKER: &str = "cokret-structure-depth-exceeded:";

/// `DeserializeSeed` that builds a [`Value`] while rejecting duplicate object
/// keys at every depth and enforcing the v1 nesting-depth cap
/// ([`MAX_CANONICAL_JSON_NESTING_DEPTH`]). Mirrors `serde_json`'s own `Value`
/// visitor but swaps the last-wins map insert for a duplicate-detecting one.
/// `depth` is the container depth this value sits at if it turns out to be an
/// object or array (top-level container = depth 1).
struct CanonicalValueSeed {
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for CanonicalValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(CanonicalValueVisitor { depth: self.depth })
    }
}

struct CanonicalValueVisitor {
    depth: usize,
}

impl<'de> serde::de::Visitor<'de> for CanonicalValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        if self.depth > MAX_CANONICAL_JSON_NESTING_DEPTH {
            return Err(serde::de::Error::custom(format!(
                "{DEPTH_EXCEEDED_MARKER}{MAX_CANONICAL_JSON_NESTING_DEPTH}"
            )));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(CanonicalValueSeed {
            depth: self.depth + 1,
        })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if self.depth > MAX_CANONICAL_JSON_NESTING_DEPTH {
            return Err(serde::de::Error::custom(format!(
                "{DEPTH_EXCEEDED_MARKER}{MAX_CANONICAL_JSON_NESTING_DEPTH}"
            )));
        }
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(CanonicalValueSeed {
                depth: self.depth + 1,
            })?;
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "{DUPLICATE_KEY_MARKER}{key}"
                )));
            }
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Active canonical JSON digest suites for v1 typed digest values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DigestSuite {
    #[default]
    Sha256,
    Blake3,
}

impl DigestSuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }
}

pub fn digest_suite(suite: &str) -> Result<DigestSuite> {
    match suite {
        "sha256" => Ok(DigestSuite::Sha256),
        "blake3" => Ok(DigestSuite::Blake3),
        _ => Err(Error::Protocol(format!(
            "unsupported digest algorithm: {suite}"
        ))),
    }
}

/// Compute the SHA-256 of `bytes` and return the bare 64-character lowercase
/// hex digest (no `sha256:` prefix).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", sha256_hex(bytes.as_ref()))
}

pub fn blake3_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

pub fn blake3_digest(bytes: impl AsRef<[u8]>) -> String {
    format!("blake3:{}", blake3_hex(bytes.as_ref()))
}

pub fn digest_hex(suite: DigestSuite, bytes: &[u8]) -> String {
    match suite {
        DigestSuite::Sha256 => sha256_hex(bytes),
        DigestSuite::Blake3 => blake3_hex(bytes),
    }
}

pub fn digest(suite: DigestSuite, bytes: impl AsRef<[u8]>) -> String {
    format!("{}:{}", suite.as_str(), digest_hex(suite, bytes.as_ref()))
}

pub fn digest_with_suite(suite: &str, bytes: impl AsRef<[u8]>) -> Result<String> {
    Ok(digest(digest_suite(suite)?, bytes))
}

/// Canonical digest helper for already-canonicalized JSON byte streams.
///
/// Downstream services that have already produced canonical JSON bytes
/// (e.g. via [`canonical_json_bytes`]) call this to derive the wire-form
/// `canonical_digest` / `request_canonical_digest` value used in event
/// envelopes, seals, and policy-check payloads.
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

pub fn canonical_digest_with_suite(bytes: &[u8], suite: &str) -> Result<String> {
    digest_with_suite(suite, bytes)
}

pub fn canonical_hash<T: Serialize>(value: &T, suite: &str) -> Result<String> {
    let bytes = canonical_json_bytes(value)?;
    canonical_digest_with_suite(&bytes, suite)
}

pub fn verify_digest(bytes: &[u8], expected_digest: &str) -> Result<()> {
    let Some((suite, _)) = expected_digest.split_once(':') else {
        return Err(Error::Protocol(
            "digest must use <suite>:<lowercase_hex> wire form".to_owned(),
        ));
    };
    let actual = digest_with_suite(suite, bytes)?;
    if actual == expected_digest {
        Ok(())
    } else {
        Err(Error::Protocol("digest mismatch".to_owned()))
    }
}

/// Encode a composite **cell subject** from its parts.
///
/// The composite subject is derived from typed payload fields per the
/// spec event-kind-registry's `cell_subject` (composite form). This
/// helper preserves percent-encoding (`%` → `%25`, `|` → `%7C`) so
/// callers building a reducer-internal projection key
/// (`(realm_id, kind, subject)`) get an unambiguous round-trip.
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
///
/// The encoder preserves each part's raw UTF-8 bytes verbatim (only `%`/`|`
/// are escaped), so the decoder accumulates raw and percent-decoded bytes
/// into a byte buffer and interprets the whole part as UTF-8 at the end.
/// Decoding byte-by-byte as `b as char` would mis-read every multi-byte
/// UTF-8 sequence as Latin-1 and break the round-trip for non-ASCII parts.
pub fn decode_state_subject_parts(encoded: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in encoded.split('|') {
        let mut decoded = Vec::<u8>::with_capacity(raw.len());
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
                decoded.push(code);
            } else {
                decoded.push(b);
            }
        }
        let part = String::from_utf8(decoded).map_err(|_| {
            Error::Protocol("state subject is not valid UTF-8 after decoding".to_owned())
        })?;
        out.push(part);
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
        return Err(Error::Protocol(format!(
            "canonical timestamp must end with 'Z': {timestamp}"
        )));
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
        Error::Protocol(format!(
            "canonical timestamp is not a valid RFC 3339 date: {timestamp}"
        ))
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
pub fn format_timestamp_canonical(when: chrono::DateTime<chrono::Utc>) -> String {
    when.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Convenience: format a Unix timestamp in **milliseconds** (UTC) into the
/// canonical `YYYY-MM-DDTHH:MM:SSZ` string. Returns `None` if the value is
/// out of the representable range. Sub-second milliseconds are truncated.
pub fn format_timestamp_canonical_millis(unix_millis: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_millis)
        .map(format_timestamp_canonical)
}

/// Convenience: format a Unix timestamp in **seconds** (UTC) into the
/// canonical `YYYY-MM-DDTHH:MM:SSZ` string. Returns `None` if the value is
/// out of the representable range.
pub fn format_timestamp_canonical_secs(unix_secs: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, 0).map(format_timestamp_canonical)
}

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(string) => write_string(string, out)?,
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

/// JSON safe-integer bound per `encoding.md` §2 (`2^53 - 1`). Canonical JSON
/// numbers MUST lie within `[-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER]`; counters or
/// offsets needing a wider range MUST be encoded as an explicitly-formatted
/// string, never as a JSON number that would lose precision in a JS/browser
/// verifier recomputing the digest.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

fn write_number(number: &Number, out: &mut Vec<u8>) -> Result<()> {
    // Reject any number that doesn't round-trip cleanly as i64 or u64.
    // Per `encoding.md` §3.2, the v1 number profile forbids floats —
    // even integer-valued floats like `1.0` MUST be rejected.
    if number.as_f64().is_some() && number.as_i64().is_none() && number.as_u64().is_none() {
        return Err(Error::NonCanonicalNumber);
    }
    if let Some(n) = number.as_i64() {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) {
            return Err(Error::NumberOutOfSafeRange);
        }
        let s = n.to_string();
        reject_leading_zeros(&s)?;
        out.extend_from_slice(s.as_bytes());
    } else if let Some(n) = number.as_u64() {
        if n > MAX_SAFE_INTEGER as u64 {
            return Err(Error::NumberOutOfSafeRange);
        }
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

fn write_string(string: &str, out: &mut Vec<u8>) -> Result<()> {
    validate_canonical_string(string)?;
    out.push(b'"');
    for ch in string.chars() {
        match ch {
            // encoding.md §2: any U+FEFF (BOM), whether at stream start or inside a
            // string value, MUST be rejected as schema_violation — never emitted.
            '\u{feff}' => {
                return Err(Error::NonCanonicalString(
                    "string value contains U+FEFF".to_owned(),
                ));
            }
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
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<()> {
    out.push(b'{');

    let mut keys = map.keys().collect::<Vec<_>>();
    keys.sort_unstable_by(|a, b| compare_utf16(a, b));

    for (idx, key) in keys.into_iter().enumerate() {
        if idx > 0 {
            out.push(b',');
        }
        write_string(key, out)?;
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
        assert!(matches!(
            canonical_json_string(&value),
            Err(Error::NonCanonicalNumber)
        ));
    }

    #[test]
    fn canonical_json_rejects_float_zero() {
        let value = json!({ "n": 0.0 });
        assert!(matches!(
            canonical_json_string(&value),
            Err(Error::NonCanonicalNumber)
        ));
    }

    #[test]
    fn is_nfc_distinguishes_composition() {
        assert!(is_nfc("caf\u{e9}")); // precomposed é
        assert!(!is_nfc("cafe\u{301}")); // e + combining acute
    }

    #[test]
    fn write_string_rejects_embedded_feff() {
        let value = json!({ "x": "a\u{feff}b" });
        assert!(matches!(
            canonical_json_bytes(&value),
            Err(Error::NonCanonicalString(_))
        ));
    }

    #[test]
    fn canonical_json_rejects_non_nfc_string() {
        let value = json!({ "name": "cafe\u{301}" }); // decomposed e + acute
        assert!(matches!(
            canonical_json_bytes(&value),
            Err(Error::NonCanonicalString(_))
        ));
    }

    #[test]
    fn from_canonical_json_slice_rejects_non_nfc_string() {
        let json = "{\"name\":\"cafe\u{301}\"}";
        let err = from_canonical_json_slice::<Value>(json.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::NonCanonicalString(_)));
    }

    #[test]
    fn parse_canonical_json_rejects_leading_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(br#"{"a":1}"#);
        assert!(matches!(
            parse_canonical_json(&bytes),
            Err(Error::NonCanonicalString(_))
        ));
    }

    #[test]
    fn validate_canonical_bytes_rejects_non_nfc_string() {
        let json = "{\"name\":\"cafe\u{301}\"}"; // decomposed é in a value
        assert!(matches!(
            validate_canonical_bytes(json.as_bytes()),
            Err(Error::NonCanonicalString(_))
        ));
    }

    #[test]
    fn validate_canonical_bytes_accepts_nfc() {
        let json = r#"{"a":1,"name":"abc"}"#;
        assert!(validate_canonical_bytes(json.as_bytes()).is_ok());
    }

    #[test]
    fn validate_canonical_bytes_rejects_unsorted_object_keys() {
        let bytes = br#"{"b":2,"a":1}"#;
        let err = validate_canonical_bytes(bytes).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));

        let err = from_canonical_json_slice::<Value>(bytes).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn validate_canonical_bytes_accepts_byte_for_byte_canonical_json() {
        let value = json!({ "b": 2, "a": { "d": 4, "c": 3 } });
        let bytes = canonical_json_bytes(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"a":{"c":3,"d":4},"b":2}"#
        );

        validate_canonical_bytes(&bytes).unwrap();
        let parsed = from_canonical_json_slice::<Value>(&bytes).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn validate_canonical_bytes_rejects_whitespace() {
        let err = validate_canonical_bytes(br#"{ "a":1}"#).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn validate_canonical_bytes_rejects_alternate_string_escape() {
        let err = validate_canonical_bytes(br#"{"a":"\u0062"}"#).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
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
        assert_eq!(
            hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
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
        // The JSON safe-integer boundary `±(2^53 - 1)` MUST round-trip exactly.
        assert_eq!(
            canonical_json_string(&json!(MAX_SAFE_INTEGER)).unwrap(),
            "9007199254740991"
        );
        assert_eq!(
            canonical_json_string(&json!(-MAX_SAFE_INTEGER)).unwrap(),
            "-9007199254740991"
        );
    }

    #[test]
    fn canonical_json_rejects_integers_outside_safe_range() {
        // Per encoding.md §2, integers beyond ±(2^53 - 1) MUST be rejected;
        // values that wide MUST be carried as explicitly-formatted strings so a
        // JS/browser verifier recomputing the digest cannot lose precision.
        assert!(matches!(
            canonical_json_string(&json!(MAX_SAFE_INTEGER + 1)),
            Err(Error::NumberOutOfSafeRange)
        ));
        assert!(matches!(
            canonical_json_string(&json!(-MAX_SAFE_INTEGER - 1)),
            Err(Error::NumberOutOfSafeRange)
        ));
        assert!(matches!(
            canonical_json_string(&json!(i64::MAX)),
            Err(Error::NumberOutOfSafeRange)
        ));
        assert!(matches!(
            canonical_json_string(&json!(i64::MIN)),
            Err(Error::NumberOutOfSafeRange)
        ));
        // u64 values above the safe-integer ceiling are rejected on the u64 arm.
        assert!(matches!(
            canonical_json_string(&json!(u64::MAX)),
            Err(Error::NumberOutOfSafeRange)
        ));
    }

    #[test]
    fn parse_canonical_json_rejects_input_over_one_mebibyte() {
        // scalability-constraints.md §2: a single envelope over 1 MiB MUST
        // be rejected — the ingress helpers enforce the cap before parsing.
        let big_string = "a".repeat(MAX_CANONICAL_JSON_INGRESS_BYTES);
        let oversized = format!("{{\"k\":\"{big_string}\"}}");
        assert!(oversized.len() > MAX_CANONICAL_JSON_INGRESS_BYTES);
        let err = parse_canonical_json(oversized.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
        assert!(err.to_string().contains("ingress maximum"));

        let err = from_canonical_json_slice::<Value>(oversized.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
        assert!(validate_canonical_bytes(oversized.as_bytes()).is_err());

        // Exactly at the cap is still accepted (the bound is exclusive).
        let at_cap_payload = "a".repeat(MAX_CANONICAL_JSON_INGRESS_BYTES - 8);
        let at_cap = format!("{{\"k\":\"{at_cap_payload}\"}}");
        assert_eq!(at_cap.len(), MAX_CANONICAL_JSON_INGRESS_BYTES);
        parse_canonical_json(at_cap.as_bytes()).unwrap();
    }

    #[test]
    fn parse_canonical_json_rejects_duplicate_keys() {
        // serde_json's bare from_slice silently takes last-wins; the canonical
        // ingress entry point MUST reject duplicate keys (signature malleability).
        let err = parse_canonical_json(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(matches!(err, Error::DuplicateObjectKey(ref k) if k == "a"));
    }

    #[test]
    fn parse_canonical_json_rejects_nested_duplicate_keys() {
        let err = parse_canonical_json(br#"{"outer":{"b":1,"b":2}}"#).unwrap_err();
        assert!(matches!(err, Error::DuplicateObjectKey(ref k) if k == "b"));
    }

    #[test]
    fn parse_canonical_json_accepts_distinct_keys() {
        let value = parse_canonical_json(br#"{"a":1,"b":{"c":2},"d":[1,2,3]}"#).unwrap();
        assert_eq!(value, json!({ "a": 1, "b": { "c": 2 }, "d": [1, 2, 3] }));
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
    fn canonical_json_sorts_supplementary_before_u_ffff() {
        // Mirrors ck.vector.encoding.canonical_json.utf16_supplementary_order.v1:
        // U+1F600 (UTF-16 D83D DE00) sorts before U+FFFF because the high
        // surrogate 0xD83D compares below 0xFFFF, while code-point order would
        // reverse the two keys.
        let grin = char::from_u32(0x1F600).unwrap().to_string();
        let ffff = char::from_u32(0xFFFF).unwrap().to_string();
        let value = json!({ ffff.clone(): 2, grin.clone(): 1 });
        let actual = canonical_json_string(&value).unwrap();
        assert_eq!(actual, format!("{{\"{grin}\":1,\"{ffff}\":2}}"));
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
        let parts = [
            "did:webvh:z6mkfixture:alice.example",
            "discussion",
            "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
        ];
        let encoded = encode_state_subject(&parts);
        assert_eq!(
            encoded,
            "did:webvh:z6mkfixture:alice.example|discussion|ck:strand:01904100-0000-7000-8000-6c663fa0205f"
        );
        let decoded = decode_state_subject_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn state_subject_encoding_escapes_pipes_and_percents() {
        // A DID method-specific id that legitimately contains '|' must be
        // round-trippable without colliding with the part separator.
        let parts = ["did:webvh:z6mkfixture:alice|bar", "100%great", "plain"];
        let encoded = encode_state_subject(&parts);
        assert_eq!(encoded, "did:webvh:z6mkfixture:alice%7Cbar|100%25great|plain");
        let decoded = decode_state_subject_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn state_subject_decode_rejects_truncated_percent() {
        assert!(decode_state_subject_parts("abc%2").is_err());
        assert!(decode_state_subject_parts("abc%").is_err());
    }

    #[test]
    fn state_subject_encoding_roundtrips_non_ascii() {
        // Subjects can carry user-controlled labels/names with multi-byte
        // UTF-8 (CJK, emoji). The decoder must reproduce the exact bytes.
        let parts = ["标签", "naïve|café", "🚀rocket", "100%🎉"];
        let encoded = encode_state_subject(&parts);
        let decoded = decode_state_subject_parts(&encoded).unwrap();
        assert_eq!(decoded, parts);
    }

    #[test]
    fn canonical_digest_is_byte_stable_for_fixed_input() {
        // The empty-input digest is the canonical sha256(b"") value;
        // any drift here is a backwards-incompatible change downstream
        // (soland event_log, notary, policy hashing).
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
    fn blake3_digest_matches_known_vectors_and_verifies() {
        assert_eq!(
            blake3_digest(b""),
            "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            blake3_digest(b"abc"),
            "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        verify_digest(b"abc", &blake3_digest(b"abc")).unwrap();
        assert!(verify_digest(b"abd", &blake3_digest(b"abc")).is_err());
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
