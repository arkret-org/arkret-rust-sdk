//! Cursor encoding, decoding, and validation.
//!
//! This module implements the Arkret v1 cursor specification. Cursors are
//! opaque `ak:cursor:<base64url(canonical_json)>` tokens used for stream
//! continuation and read-your-writes barriers.

use serde::{Deserialize, Serialize};
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Result, SchemaId};

/// Round R2/R3 (2026-05-20) — minimum length of a stateful cursor handle's
/// base64url alphabet representation. Schema `cursor.schema.json` raises
/// `h.minLength` to 22 so the decoded handle has ≥128 bits of entropy
/// (`128 / 6 ≈ 21.33` → at least 22 base64url characters).
pub const CURSOR_HANDLE_MIN_LEN: usize = 22;

/// Generate a fresh ≥22-character base64url cursor handle.
///
/// Output uses only `[A-Za-z0-9_-]` with no padding, satisfying schema
/// `cursor.schema.json` `h` constraints (minLength 22, pattern
/// `^[A-Za-z0-9_-]+$`).
pub fn generate_cursor_handle() -> Result<String> {
    let mut handle = [0u8; 16];
    getrandom::fill(&mut handle)
        .map_err(|error| Error::Protocol(format!("cursor_handle_rng_unavailable: {error}")))?;
    // Take 16 bytes — 128 bits — and base64url-encode (no pad).
    let encoded = arkret_canonical::base64url::base64url_encode(handle);
    debug_assert!(encoded.len() >= CURSOR_HANDLE_MIN_LEN);
    Ok(encoded)
}

/// Arkret v1 sync cursor.
///
/// Core v1 cursor bodies are stateful handles:
/// `{v, purpose, issued_at, expires_at, h}`.
/// Positions and barrier targets are bound server-side to `h` and never
/// appear in the wire body.
///
/// # Issuing-service only
///
/// Per spec `conformance/conformance-vectors.md` ("cursor 不透明性" vector,
/// expected client behaviour): clients MUST treat a cursor as an opaque
/// string, MUST NOT parse its internal fields to build requests, and MUST
/// NOT rely on the base64url-decoded `h` / timestamps / any other internal field —
/// those fields belong exclusively to the issuing service. This struct (and
/// [`Cursor::decode`]) exists for the *service* side of that contract:
/// validating, minting and re-binding cursors a service itself issued.
/// Client SDKs / application layers MUST carry the encoded token verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct Cursor {
    /// Cursor version. Must be "1" for Arkret v1.
    ///
    /// Issuing-service internal field — clients MUST NOT read or depend on
    /// it (`conformance-vectors.md`: cursor opacity).
    pub v: String,
    /// Cursor purpose.
    ///
    /// Issuing-service internal field — clients MUST NOT read or depend on
    /// it (`conformance-vectors.md`: cursor opacity).
    pub purpose: CursorPurpose,
    /// Cursor generation instant in the canonical Arkret millisecond profile.
    ///
    /// Issuing-service internal field — clients MUST NOT read or depend on
    /// it (`conformance-vectors.md`: cursor opacity).
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// Expiration instant in the same canonical Arkret profile.
    ///
    /// Issuing-service internal field — clients MUST NOT inspect it (e.g. to
    /// pre-check expiry) or depend on it (`conformance-vectors.md`: cursor
    /// opacity; expiry is signalled by the service via `cursor_expired`).
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Stateful cursor handle.
    ///
    /// Issuing-service internal field — clients MUST NOT read or depend on
    /// it to construct follow-up requests (`conformance-vectors.md`: the
    /// handle binding belongs to the issuing service).
    pub h: String,
}

/// Cursor purpose discriminator.
///
/// `#[non_exhaustive]`: a future spec revision may register additional
/// purposes. Downstream `match` expressions MUST carry a `_` arm with
/// fail-closed semantics (reject a cursor whose purpose is unrecognised).
/// Deserialisation itself stays closed-set: an unknown wire value still
/// fails the parse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CursorPurpose {
    Stream,
    Barrier,
}

impl Cursor {
    pub const SCHEMA: &'static str = SchemaId::CURSOR_V1;
    /// Default expiration duration for cursors (7 days).
    pub const DEFAULT_EXPIRATION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

    /// Maximum cursor size after encoding (4KB).
    pub const MAX_ENCODED_SIZE: usize = 4096;

    /// §8.3 rule 12 TTL hard upper bound for `barrier` cursors: 1 hour.
    pub const BARRIER_TTL_MAX_MS: i64 = 3_600_000;

    /// §8.3 rule 12 TTL hard upper bound for `stream` cursors: 7 days.
    pub const STREAM_TTL_MAX_MS: i64 = 604_800_000;

    /// §8.3 clock-skew tolerance for `issued_at` future checks.
    pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 5 * 60 * 1000;

    /// Create a new cursor with current timestamp and default expiration.
    pub fn new() -> Result<Self> {
        Self::new_at(chrono::Utc::now(), Self::DEFAULT_EXPIRATION_MS)
    }

    /// Create a stream cursor at an explicit instant and TTL.
    pub fn new_at(now: chrono::DateTime<chrono::Utc>, ttl_ms: i64) -> Result<Self> {
        if !(1..=Self::STREAM_TTL_MAX_MS).contains(&ttl_ms) {
            return Err(Error::Protocol(format!(
                "stream cursor TTL must be between 1 and {} ms",
                Self::STREAM_TTL_MAX_MS
            )));
        }
        let issued_at = arkret_canonical::canonical::normalize_timestamp_canonical(now);
        let expires_at = chrono::DateTime::from_timestamp_millis(
            issued_at
                .timestamp_millis()
                .checked_add(ttl_ms)
                .ok_or_else(|| {
                    Error::Protocol("cursor expiry overflows i64 milliseconds".to_owned())
                })?,
        )
        .ok_or_else(|| {
            Error::Protocol("cursor expiry is outside the supported UTC range".to_owned())
        })?;

        Ok(Self {
            v: "1".to_owned(),
            purpose: CursorPurpose::Stream,
            issued_at,
            expires_at,
            h: generate_cursor_handle()?,
        })
    }

    /// Convert this cursor to stateful-handle form.
    pub fn with_stateful_handle(mut self, handle: impl Into<String>) -> Self {
        self.h = handle.into();
        self
    }

    /// Convert this stream cursor into a barrier cursor.
    ///
    /// Re-clamps `expires_at` so the barrier TTL does not exceed the §8.3
    /// rule-12 hard cap (1 hour) — a barrier cursor carrying the default
    /// 7-day stream expiry would otherwise be rejected by any conformant
    /// receiver.
    pub fn with_barrier(mut self) -> Self {
        self.purpose = CursorPurpose::Barrier;
        let max_expiry_ms = self.issued_at.timestamp_millis() + Self::BARRIER_TTL_MAX_MS;
        if self.expires_at.timestamp_millis() > max_expiry_ms
            && let Some(max_expiry) = chrono::DateTime::from_timestamp_millis(max_expiry_ms)
        {
            self.expires_at = max_expiry;
        }
        self
    }

    /// Encode the cursor to its wire token.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - JSON serialization fails
    /// - Cursor size exceeds MAX_ENCODED_SIZE
    /// - Base64URL encoding fails
    pub fn encode(&self) -> Result<String> {
        self.validate_core_wire_shape()?;

        let json = arkret_canonical::canonical::canonical_json_bytes(self)?;

        if json.len() > Self::MAX_ENCODED_SIZE {
            return Err(Error::Protocol(format!(
                "cursor too large: {} bytes (max {})",
                json.len(),
                Self::MAX_ENCODED_SIZE
            )));
        }

        // Encode to Base64URL without padding
        let encoded = arkret_canonical::base64url::base64url_encode(&json);

        Ok(format!("ak:cursor:{encoded}"))
    }

    /// Decode a cursor from its wire token.
    ///
    /// # Issuing-service only
    ///
    /// This is a *service-side* entry point: it exists so the issuing
    /// service can validate and re-bind cursors it minted. Per spec
    /// `conformance/conformance-vectors.md` (cursor opacity, expected
    /// client behaviour), client SDKs / application layers MUST NOT decode
    /// a cursor to inspect or act on its internal fields (`h`, timestamps, ...)
    /// — clients MUST treat the token as an opaque string and return it
    /// verbatim. Calling `decode` from client-side code to e.g. pre-check
    /// expiry or build a follow-up request is a spec MUST NOT violation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token exceeds the encoded form of [`Self::MAX_ENCODED_SIZE`]
    /// - Base64URL decoding fails
    /// - JSON parsing fails
    /// - Cursor structure is invalid
    /// - Cursor version is unsupported
    /// - Cursor has expired
    pub fn decode(encoded: &str) -> Result<Self> {
        Self::decode_at(encoded, unix_time_millis()?)
    }

    /// Decode and validate a cursor against an explicit receiver clock.
    pub fn decode_at(encoded: &str, now_ms: i64) -> Result<Self> {
        let encoded = encoded
            .strip_prefix("ak:cursor:")
            .ok_or_else(|| Error::Protocol("cursor token must start with ak:cursor:".to_owned()))?;

        // Receivers MUST enforce the same 4KB body cap that `encode`
        // enforces — reject oversized tokens before spending any base64 /
        // JSON parsing work on them. Unpadded base64url emits
        // ceil(4n/3) characters for n payload bytes.
        let max_token_len = Self::MAX_ENCODED_SIZE.div_ceil(3) * 4;
        if encoded.len() > max_token_len {
            return Err(Error::Protocol(format!(
                "cursor token too large: {} chars (max {max_token_len})",
                encoded.len()
            )));
        }

        // Decode from unpadded Base64URL, the only v1 cursor transport form.
        let json = arkret_canonical::base64url::base64url_decode(encoded)
            .map_err(|_| Error::Protocol("invalid Base64URL encoding".to_owned()))?;

        // Exact symmetric bound: the pre-decode character check is a
        // ceiling, this is the byte-precise cap `encode` enforces.
        if json.len() > Self::MAX_ENCODED_SIZE {
            return Err(Error::Protocol(format!(
                "cursor too large: {} bytes (max {})",
                json.len(),
                Self::MAX_ENCODED_SIZE
            )));
        }

        let cursor: Cursor = arkret_canonical::canonical::from_canonical_json_slice(&json)
            .map_err(|_| Error::Protocol("invalid cursor JSON".to_owned()))?;

        cursor.validate_at(now_ms)?;

        Ok(cursor)
    }

    fn validate_at(&self, now_ms: i64) -> Result<()> {
        // Check version
        if self.v != "1" {
            return Err(Error::Protocol(format!(
                "unsupported cursor version: {}",
                self.v
            )));
        }

        self.validate_core_wire_shape()?;

        if self.expires_at.timestamp_millis() < now_ms {
            return Err(Error::Protocol("cursor has expired".to_owned()));
        }

        self.validate_ttl_bound(now_ms)?;

        Ok(())
    }

    /// §8.3 rule 12 (TTL hard upper bound). `now_ms` is the receiver's
    /// current Unix-ms clock.
    ///
    /// Both instants have already passed the strict serde parser. This check
    /// enforces ordering, clock skew, and purpose-specific TTL bounds.
    fn validate_ttl_bound(&self, now_ms: i64) -> Result<()> {
        let issued_at_ms = self.issued_at.timestamp_millis();
        let expires_at_ms = self.expires_at.timestamp_millis();
        if issued_at_ms > expires_at_ms {
            return Err(Error::Protocol(
                "cursor `issued_at` is after `expires_at`; param_invalid".to_owned(),
            ));
        }
        if issued_at_ms > now_ms + Self::CLOCK_SKEW_TOLERANCE_MS {
            return Err(Error::Protocol(
                "cursor `issued_at` is in the future beyond clock-skew tolerance; param_invalid"
                    .to_owned(),
            ));
        }

        let ttl = expires_at_ms - issued_at_ms;
        let cap = match self.purpose {
            CursorPurpose::Barrier => Self::BARRIER_TTL_MAX_MS,
            CursorPurpose::Stream => Self::STREAM_TTL_MAX_MS,
        };
        if ttl > cap {
            return Err(Error::Protocol(format!(
                "cursor TTL {ttl} ms exceeds the {:?} hard upper bound {cap} ms; param_invalid",
                self.purpose
            )));
        }
        Ok(())
    }

    fn validate_cursor_handle(handle: &str) -> Result<()> {
        // Round R2/R3 (2026-05-20): schema raises minLength to 22 so the
        // base64url-decoded handle has ≥128 bits of entropy (128/6 = 21.33).
        let len = handle.len();
        if !(CURSOR_HANDLE_MIN_LEN..=256).contains(&len)
            || !handle
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::Protocol("invalid cursor handle".to_owned()));
        }
        Ok(())
    }

    fn validate_core_wire_shape(&self) -> Result<()> {
        Self::validate_cursor_handle(&self.h)?;
        for (name, value) in [
            ("issued_at", self.issued_at),
            ("expires_at", self.expires_at),
        ] {
            if arkret_canonical::canonical::normalize_timestamp_canonical(value) != value {
                return Err(Error::Protocol(format!(
                    "cursor `{name}` contains sub-millisecond precision"
                )));
            }
        }
        Ok(())
    }

    /// Check if the cursor is expired.
    pub fn is_expired(&self) -> bool {
        unix_time_millis().map_or(true, |now_ms| self.expires_at.timestamp_millis() < now_ms)
    }
}

fn unix_time_millis() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::Protocol(format!("cursor_clock_before_unix_epoch: {error}")))?
        .as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_encode_decode_roundtrip() {
        let cursor = Cursor::new().unwrap();

        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();

        assert_eq!(decoded.h, cursor.h);
        assert_eq!(decoded.v, cursor.v);
        assert_eq!(decoded.purpose, CursorPurpose::Stream);
        assert!(encoded.starts_with("ak:cursor:"));
    }

    #[test]
    fn cursor_new_at_preserves_milliseconds_and_exact_ttl() {
        let issued_at = chrono::DateTime::parse_from_rfc3339("2026-07-18T12:34:56.789Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cursor = Cursor::new_at(issued_at, 3_600_000).unwrap();

        assert_eq!(
            arkret_canonical::format_timestamp_canonical(cursor.issued_at),
            "2026-07-18T12:34:56.789Z"
        );
        assert_eq!(
            cursor.expires_at.timestamp_millis() - cursor.issued_at.timestamp_millis(),
            3_600_000
        );
    }

    #[test]
    fn cursor_decode_at_rejects_missing_millisecond_fraction() {
        let json = br#"{"v":"1","purpose":"stream","issued_at":"2026-07-18T12:34:56.000Z","expires_at":"2026-07-18T13:34:56.000Z","h":"ABCDEFGHIJKLMNOPQRSTUV"}"#;
        let encoded = format!(
            "ak:cursor:{}",
            arkret_canonical::base64url::base64url_encode(json)
        );

        assert!(matches!(
            Cursor::decode_at(&encoded, 1_753_011_296_000),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn cursor_rejects_invalid_version() {
        let cursor = Cursor {
            v: "2".to_owned(),
            purpose: CursorPurpose::Stream,
            issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            expires_at: chrono::DateTime::from_timestamp_millis(4_102_444_800_000).unwrap(),
            h: generate_cursor_handle().unwrap(),
        };

        let encoded = cursor.encode().unwrap();
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_decode_rejects_non_nfc_json_string() {
        let json = "{\"v\":\"1\",\"purpose\":\"stream\",\"issued_at\":\"2026-06-06T00:00:00.000Z\",\"expires_at\":\"2099-12-31T00:00:00.000Z\",\"h\":\"cafe\u{301}ABCDEFGHIJKLMNOPQ\"}";
        let encoded = format!(
            "ak:cursor:{}",
            arkret_canonical::base64url::base64url_encode(json.as_bytes())
        );
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_decode_rejects_short_handle_below_min_len() {
        // 21 chars is one below CURSOR_HANDLE_MIN_LEN (22): the decoded handle
        // would carry <128 bits of entropy, so the wire layer must reject it
        // outright (encoding.md §handle: minLength 22).
        let encode_with_handle = |handle: &str| {
            let json = arkret_canonical::canonical::canonical_json_bytes(&serde_json::json!({
                "v": "1",
                "purpose": "stream",
                "issued_at": "2026-07-18T12:34:56.789Z",
                "expires_at": "2026-07-18T13:34:56.789Z",
                "h": handle,
            }))
            .unwrap();
            format!(
                "ak:cursor:{}",
                arkret_canonical::base64url::base64url_encode(&json)
            )
        };

        let now_ms = chrono::DateTime::parse_from_rfc3339("2026-07-18T12:34:56.789Z")
            .unwrap()
            .timestamp_millis();

        let short_handle = "A".repeat(CURSOR_HANDLE_MIN_LEN - 1);
        assert_eq!(short_handle.len(), 21);
        let err = Cursor::decode_at(&encode_with_handle(&short_handle), now_ms).unwrap_err();
        assert!(
            matches!(&err, Error::Protocol(message) if message.contains("invalid cursor handle")),
            "{err}"
        );

        // Positive control: the same token with a 22-char handle decodes.
        let ok_handle = "A".repeat(CURSOR_HANDLE_MIN_LEN);
        assert!(Cursor::decode_at(&encode_with_handle(&ok_handle), now_ms).is_ok());
    }

    #[test]
    fn cursor_decode_rejects_oversized_token() {
        // 6000 chars of valid base64url alphabet — over the encoded form
        // of MAX_ENCODED_SIZE, must be rejected before any decode work.
        let oversized = format!("ak:cursor:{}", "A".repeat(6000));
        assert!(matches!(
            Cursor::decode(&oversized),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn cursor_decode_rejects_duplicate_json_key() {
        let json = br#"{"v":"1","v":"1","purpose":"stream","issued_at":"2026-06-06T00:00:00.000Z","expires_at":"2099-12-31T00:00:00.000Z","h":"ABCDEFGHIJKLMNOPQRSTUV"}"#;
        let encoded = format!(
            "ak:cursor:{}",
            arkret_canonical::base64url::base64url_encode(json)
        );
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_decode_rejects_additional_properties() {
        let json = br#"{"v":"1","purpose":"stream","issued_at":"2099-12-30T23:59:59.000Z","expires_at":"2099-12-31T23:59:59.000Z","h":"abcdefghijklmnopqrstuv","_compression":"none"}"#;
        let encoded = format!(
            "ak:cursor:{}",
            arkret_canonical::base64url::base64url_encode(json)
        );
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn core_cursor_rejects_inline_positions() {
        let json = br#"{"v":"1","purpose":"stream","issued_at":"2026-06-06T00:00:00.000Z","expires_at":"2026-06-07T00:00:00.000Z","h":"ABCDEFGHIJKLMNOPQRSTUV","s":{}}"#;
        let encoded = format!(
            "ak:cursor:{}",
            arkret_canonical::base64url::base64url_encode(json)
        );
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_expires_after_7_days() {
        let mut cursor = Cursor::new().unwrap();
        // Simulate a cursor from 1 day ago
        cursor.expires_at = chrono::DateTime::from_timestamp_millis(
            cursor.expires_at.timestamp_millis() - 6 * 24 * 60 * 60 * 1000,
        )
        .unwrap();

        assert!(!cursor.is_expired());
    }

    #[test]
    fn stateful_handle_cursor_excludes_inline_state() {
        let cursor = Cursor::new()
            .unwrap()
            .with_stateful_handle("cursor_handle_12345678");
        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();

        assert_eq!(decoded.h, "cursor_handle_12345678");
    }
}
