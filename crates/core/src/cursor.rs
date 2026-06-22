//! Cursor encoding, decoding, and validation.
//!
//! This module implements the Cokret v1 cursor specification. Cursors are
//! opaque `ck:cursor:<base64url(canonical_json)>` tokens used for stream
//! continuation and read-your-writes barriers.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

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
    let encoded = crate::base64url::base64url_encode(handle);
    debug_assert!(encoded.len() >= CURSOR_HANDLE_MIN_LEN);
    Ok(encoded)
}

/// Cokret v1 sync cursor.
///
/// Core v1 cursor bodies are stateful handles: `{v, purpose, t, x, h}`.
/// Positions and barrier targets are bound server-side to `h` and never
/// appear in the wire body.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Cursor {
    /// Cursor version. Must be "1" for Cokret v1.
    pub v: String,
    /// Cursor purpose.
    pub purpose: CursorPurpose,
    /// Cursor generation timestamp (RFC 3339).
    pub t: String,
    /// Expiration timestamp (Unix milliseconds).
    pub x: i64,
    /// Stateful cursor handle.
    pub h: String,
}

/// Cursor purpose discriminator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum CursorPurpose {
    Stream,
    Barrier,
}

impl Cursor {
    /// Default expiration duration for cursors (7 days).
    pub const DEFAULT_EXPIRATION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

    /// Maximum cursor size after encoding (4KB).
    pub const MAX_ENCODED_SIZE: usize = 4096;

    /// §8.3 rule 12 TTL hard upper bound for `barrier` cursors: 1 hour.
    pub const BARRIER_TTL_MAX_MS: i64 = 3_600_000;

    /// §8.3 rule 12 TTL hard upper bound for `stream` cursors: 7 days.
    pub const STREAM_TTL_MAX_MS: i64 = 604_800_000;

    /// §8.3 rule 5/12 clock-skew tolerance for `t`/`x` future checks.
    pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 5 * 60 * 1000;

    /// Create a new cursor with current timestamp and default expiration.
    pub fn new() -> Result<Self> {
        let now = chrono::Utc::now();
        // `cursor.schema.json` `$defs.timestamp` / encoding.md §8.2 require
        // `t` to be a canonical RFC 3339 UTC timestamp ending in `Z`.
        // chrono's `to_rfc3339()` emits a `+00:00` offset with sub-second
        // digits, which the schema (and our own `validate_timestamp_canonical`)
        // would reject — use the canonical formatter (whole-second `Z`) instead.
        let t = crate::canonical::format_timestamp_canonical(now);
        // Base `x` on the *floored* `t` (whole seconds) so the nominal TTL
        // `x - t_ms` is exactly `DEFAULT_EXPIRATION_MS` and never overshoots
        // the §8.3 rule-12 hard cap by the sub-second remainder of `now`.
        let t_ms = now.timestamp() * 1000;

        Ok(Self {
            v: "1".to_owned(),
            purpose: CursorPurpose::Stream,
            t,
            x: t_ms + Self::DEFAULT_EXPIRATION_MS,
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
    /// Re-clamps `x` so the barrier TTL (`x - t`) does not exceed the §8.3
    /// rule-12 hard cap (1 hour) — a barrier cursor carrying the default
    /// 7-day stream expiry would otherwise be rejected by any conformant
    /// receiver.
    pub fn with_barrier(mut self) -> Self {
        self.purpose = CursorPurpose::Barrier;
        if let Ok(t_ms) =
            chrono::DateTime::parse_from_rfc3339(&self.t).map(|t| t.timestamp_millis())
        {
            let max_x = t_ms + Self::BARRIER_TTL_MAX_MS;
            if self.x > max_x {
                self.x = max_x;
            }
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

        let json = crate::canonical::canonical_json_bytes(self)?;

        if json.len() > Self::MAX_ENCODED_SIZE {
            return Err(Error::Protocol(format!(
                "cursor too large: {} bytes (max {})",
                json.len(),
                Self::MAX_ENCODED_SIZE
            )));
        }

        // Encode to Base64URL without padding
        let encoded = crate::base64url::base64url_encode(&json);

        Ok(format!("ck:cursor:{encoded}"))
    }

    /// Decode a cursor from its wire token.
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
        let encoded = encoded
            .strip_prefix("ck:cursor:")
            .ok_or_else(|| Error::Protocol("cursor token must start with ck:cursor:".to_owned()))?;

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
        let json = crate::base64url::base64url_decode(encoded)
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

        let cursor: Cursor = crate::canonical::from_canonical_json_slice(&json)
            .map_err(|_| Error::Protocol("invalid cursor JSON".to_owned()))?;

        cursor.validate()?;

        Ok(cursor)
    }

    /// Validate the cursor structure and expiration.
    fn validate(&self) -> Result<()> {
        // Check version
        if self.v != "1" {
            return Err(Error::Protocol(format!(
                "unsupported cursor version: {}",
                self.v
            )));
        }

        self.validate_core_wire_shape()?;

        let now_ms = unix_time_millis()?;

        // §8.3 rule 5: `x` MUST NOT be in the past (TTL expiry).
        if self.x < now_ms {
            return Err(Error::Protocol("cursor has expired".to_owned()));
        }

        // §8.3 rule 12: `t` well-formedness + TTL hard upper bound.
        self.validate_ttl_bound(now_ms)?;

        Ok(())
    }

    /// §8.3 rule 12 (TTL hard upper bound). `now_ms` is the receiver's
    /// current Unix-ms clock.
    ///
    /// Order matters: validate `t` well-formedness (canonical UTC `Z` form)
    /// first, then `t_ms <= x`, then `t` not in the future (5-min skew),
    /// then `x - t_ms <= per-purpose cap`. Any failure maps to
    /// `invalid_param` (here `Error::Protocol`), preventing a corrupt or
    /// malicious cursor from bypassing the cap via a negative/overflowing
    /// or future-stamped `t`.
    fn validate_ttl_bound(&self, now_ms: i64) -> Result<()> {
        crate::canonical::validate_timestamp_canonical(&self.t).map_err(|_| {
            Error::Protocol(format!(
                "cursor `t` is not a canonical UTC `Z` timestamp: {}",
                self.t
            ))
        })?;
        let t_ms = chrono::DateTime::parse_from_rfc3339(&self.t)
            .map_err(|err| Error::Protocol(format!("cursor `t` is unparseable: {err}")))?
            .timestamp_millis();

        if t_ms > self.x {
            return Err(Error::Protocol(
                "cursor `t` is after `x` (negative TTL); invalid_param".to_owned(),
            ));
        }
        if t_ms > now_ms + Self::CLOCK_SKEW_TOLERANCE_MS {
            return Err(Error::Protocol(
                "cursor `t` is in the future beyond clock-skew tolerance; invalid_param".to_owned(),
            ));
        }

        let ttl = self.x - t_ms;
        let cap = match self.purpose {
            CursorPurpose::Barrier => Self::BARRIER_TTL_MAX_MS,
            CursorPurpose::Stream => Self::STREAM_TTL_MAX_MS,
        };
        if ttl > cap {
            return Err(Error::Protocol(format!(
                "cursor TTL {ttl} ms exceeds the {:?} hard upper bound {cap} ms; invalid_param",
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
        Ok(())
    }

    /// Create a cursor from sync positions.
    pub fn from_positions(_positions: SyncPositions) -> Result<Self> {
        // v1 core cursor bytes carry only an opaque server handle. Callers that
        // need to preserve positions must store them server-side keyed by `h`.
        Self::new()
    }

    /// Extract sync positions from the cursor.
    pub fn to_positions(&self) -> Result<SyncPositions> {
        self.validate_core_wire_shape()?;
        Ok(SyncPositions::default())
    }

    /// Check if the cursor is expired.
    pub fn is_expired(&self) -> bool {
        unix_time_millis().map_or(true, |now_ms| self.x < now_ms)
    }

    /// Get the remaining time before expiration.
    pub fn time_until_expiration(&self) -> Option<Duration> {
        let now_ms = unix_time_millis().ok()?;

        if self.x > now_ms {
            Some(Duration::from_millis((self.x - now_ms) as u64))
        } else {
            None
        }
    }
}

fn unix_time_millis() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::Protocol(format!("cursor_clock_before_unix_epoch: {error}")))?
        .as_millis() as i64)
}

/// Sync positions extracted from a cursor.
#[derive(Clone, Debug, Default)]
pub struct SyncPositions {
    /// Realm positions by Realm ID.
    pub realms: BTreeMap<String, RealmSyncPosition>,
    /// Device positions by device ID.
    pub devices: Option<BTreeMap<String, String>>,
}

/// Sync position for a single Realm.
#[derive(Clone, Debug)]
pub struct RealmSyncPosition {
    /// Causal frontier (event IDs).
    pub frontier: Vec<String>,
    /// Timeline order HLC.
    pub timeline_order: String,
    /// State digest at this position.
    pub state_digest: String,
}

/// Sync positions for tracking incremental synchronization.
#[derive(Clone, Debug, Default)]
pub struct SyncTracker {
    /// Current sync positions.
    pub positions: SyncPositions,
    /// Received sync tokens for different services.
    pub sync_tokens: HashMap<String, String>,
}

impl SyncTracker {
    /// Create a new sync tracker.
    pub fn new() -> Self {
        Self {
            positions: SyncPositions {
                realms: BTreeMap::new(),
                devices: None,
            },
            sync_tokens: HashMap::new(),
        }
    }

    /// Update the tracker with a sync response.
    pub fn update(&mut self, response: &crate::SyncOutcome) -> Result<()> {
        // Update the sync token
        self.sync_tokens
            .insert("default".to_owned(), response.cursor.clone());

        // Update positions from the response
        // (Implementation would parse the response and update realms/devices)

        Ok(())
    }

    /// Get the current cursor for resuming sync.
    pub fn current_cursor(&self) -> Result<Cursor> {
        Cursor::from_positions(self.positions.clone())
    }

    /// Clear all tracked positions.
    pub fn clear(&mut self) {
        self.positions.realms.clear();
        self.positions.devices = None;
    }
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
        assert!(encoded.starts_with("ck:cursor:"));
    }

    #[test]
    fn cursor_rejects_invalid_version() {
        let cursor = Cursor {
            v: "2".to_owned(),
            purpose: CursorPurpose::Stream,
            t: crate::canonical::format_timestamp_canonical(chrono::Utc::now()),
            x: 1714080000000,
            h: generate_cursor_handle().unwrap(),
        };

        let encoded = cursor.encode().unwrap();
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_decode_rejects_non_nfc_json_string() {
        let json = "{\"v\":\"1\",\"purpose\":\"stream\",\"t\":\"cafe\u{301}\",\"x\":4102444800000,\"h\":\"ABCDEFGHIJKLMNOPQRSTUV\"}";
        let encoded = format!("ck:cursor:{}", crate::base64url_encode(json.as_bytes()));
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_decode_rejects_oversized_token() {
        // 6000 chars of valid base64url alphabet — over the encoded form
        // of MAX_ENCODED_SIZE, must be rejected before any decode work.
        let oversized = format!("ck:cursor:{}", "A".repeat(6000));
        assert!(matches!(
            Cursor::decode(&oversized),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn cursor_decode_rejects_duplicate_json_key() {
        let json = br#"{"v":"1","v":"1","purpose":"stream","t":"2026-06-06T00:00:00Z","x":4102444800000,"h":"ABCDEFGHIJKLMNOPQRSTUV"}"#;
        let encoded = format!("ck:cursor:{}", crate::base64url_encode(json));
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_decode_rejects_additional_properties() {
        let json = br#"{"v":"1","purpose":"stream","t":"2099-12-30T23:59:59Z","x":4102444799000,"h":"abcdefghijklmnopqrstuv","_compression":"none"}"#;
        let encoded = format!("ck:cursor:{}", crate::base64url_encode(json));
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn core_cursor_rejects_inline_positions() {
        let json = br#"{"v":"1","purpose":"stream","t":"2026-06-06T00:00:00Z","x":4102444800000,"h":"ABCDEFGHIJKLMNOPQRSTUV","s":{}}"#;
        let encoded = format!("ck:cursor:{}", crate::base64url_encode(json));
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_expires_after_7_days() {
        let mut cursor = Cursor::new().unwrap();
        // Simulate a cursor from 1 day ago
        cursor.x -= 6 * 24 * 60 * 60 * 1000;

        assert!(!cursor.is_expired());
        assert!(cursor.time_until_expiration().is_some());
    }

    #[test]
    fn sync_positions_are_server_side_for_core_cursor() {
        let positions = SyncPositions {
            realms: BTreeMap::from([(
                "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                RealmSyncPosition {
                    frontier: vec!["ck:event:0196419b-0000-7000-8000-000000000001".to_owned()],
                    timeline_order: "01970e589d21-0004-a13f9c2e".to_owned(),
                    state_digest:
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_owned(),
                },
            )]),
            devices: Some(BTreeMap::from([(
                "device-laptop".to_owned(),
                "ck:device_message:019640da-0000-7000-8000-000000000000".to_owned(),
            )])),
        };

        let cursor = Cursor::from_positions(positions).unwrap();

        assert!(cursor.h.len() >= CURSOR_HANDLE_MIN_LEN);
        assert!(cursor.to_positions().unwrap().realms.is_empty());
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
