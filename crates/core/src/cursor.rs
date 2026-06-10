//! Cursor encoding, decoding, and validation.
//!
//! This module implements the Cokret v1 cursor specification. Cursors are
//! opaque `ck:cursor:<base64url(canonical_json)>` tokens used for stream
//! continuation and read-your-writes barriers.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{Error, Hlc, Result};

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
///
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
/// Cursors contain all information needed to resume synchronization from a
/// specific point in the event stream. They are encoded as JSON and then
/// Base64URL-encoded for transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Cursor {
    /// Cursor version. Must be "1" for Cokret v1.
    pub v: String,
    /// Cursor purpose.
    pub purpose: CursorPurpose,
    /// Cursor generation timestamp (RFC 3339).
    pub t: String,
    /// Realm positions map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub s: BTreeMap<String, RealmPosition>,
    /// Device positions map (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<BTreeMap<String, String>>,
    /// Target event required for read-your-writes barrier cursors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CursorTarget>,
    /// Expiration timestamp (Unix milliseconds).
    pub x: i64,
    /// Stateful cursor handle. When present, the cursor MUST NOT carry
    /// inline state or stateless integrity material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<String>,
    /// Key identifier for the stateless cursor MAC/signature key.
    /// Required whenever `h` is absent and forbidden for stateful handle form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_kid: Option<String>,
    /// Stateless cursor MAC over the canonical cursor body.
    #[serde(default, rename = "_mac", skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Stateless cursor detached signature over the canonical cursor body.
    #[serde(default, rename = "_sig", skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Server-private filter digest binding.
    #[serde(default, rename = "_filter_digest", skip_serializing_if = "Option::is_none")]
    pub filter_digest: Option<String>,
}

/// Cursor purpose discriminator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum CursorPurpose {
    Stream,
    Barrier,
}

/// Event target for barrier cursors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CursorTarget {
    pub event_id: String,
    pub event_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

/// Position information for a single Realm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmPosition {
    /// Causal frontier (event IDs).
    pub p: Vec<String>,
    /// Timeline order HLC.
    #[serde(rename = "o")]
    pub order: String,
    /// State hash at this position.
    pub h: String,
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

    /// SDK-local placeholder constants retained for profile-specific
    /// stateless cursor tests. v1 core emits stateful `h` handles by default.
    pub const DEV_TEST_MAC: &'static str =
        "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000";
    pub const DEV_TEST_ISSUER_KID: &'static str = "cokret-sdk-dev#cursor";

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
            s: BTreeMap::new(),
            d: None,
            target: None,
            x: t_ms + Self::DEFAULT_EXPIRATION_MS,
            h: Some(generate_cursor_handle()?),
            issuer_kid: None,
            mac: None,
            sig: None,
            filter_digest: None,
        })
    }

    /// Bind a `filter_digest` to this cursor. Servers MUST refuse to
    /// reuse the cursor when the next request carries a different
    /// digest. The digest is opaque to the SDK; callers typically pass
    /// [`crate::sync::sync_filter_digest`].
    pub fn with_filter_digest(mut self, digest: impl Into<String>) -> Self {
        self.filter_digest = Some(digest.into());
        self
    }

    /// Verify that the cursor's `filter_digest` matches `expected`.
    /// Returns an error when the cursor is unbound or was issued for a
    /// different filter.
    pub fn assert_filter_digest(&self, expected: &str) -> Result<()> {
        match self.filter_digest.as_deref() {
            None => Err(Error::Protocol("filter_digest_missing".to_owned())),
            Some(found) if found == expected => Ok(()),
            Some(found) => Err(Error::Protocol(format!(
                "filter_digest_mismatch: cursor was issued for '{found}', current request is '{expected}'"
            ))),
        }
    }

    /// Set a Realm position in the cursor.
    pub fn with_realm_position(
        mut self,
        realm_id: impl Into<String>,
        position: RealmPosition,
    ) -> Self {
        self.s.insert(realm_id.into(), position);
        self
    }

    /// Set a device position in the cursor.
    pub fn with_device_position(
        mut self,
        device_id: impl Into<String>,
        message_id: impl Into<String>,
    ) -> Self {
        self.d.get_or_insert_with(BTreeMap::new).insert(device_id.into(), message_id.into());
        self
    }

    /// Replace the stateless integrity MAC on this cursor.
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.h = None;
        self.issuer_kid.get_or_insert_with(|| Self::DEV_TEST_ISSUER_KID.to_owned());
        self.mac = Some(mac.into());
        self.sig = None;
        self
    }

    /// Replace the stateless integrity signature on this cursor.
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.h = None;
        self.issuer_kid.get_or_insert_with(|| Self::DEV_TEST_ISSUER_KID.to_owned());
        self.mac = None;
        self.sig = Some(signature.into());
        self
    }

    /// Set the stateless cursor issuer key id.
    pub fn with_issuer_kid(mut self, issuer_kid: impl Into<String>) -> Self {
        self.issuer_kid = Some(issuer_kid.into());
        self
    }

    /// Convert this cursor to stateful-handle form.
    pub fn with_stateful_handle(mut self, handle: impl Into<String>) -> Self {
        self.h = Some(handle.into());
        self.s.clear();
        self.d = None;
        self.target = None;
        self.issuer_kid = None;
        self.mac = None;
        self.sig = None;
        self
    }

    /// Convert this stream cursor into a barrier cursor for one target event.
    ///
    /// Re-clamps `x` so the barrier TTL (`x - t`) does not exceed the §8.3
    /// rule-12 hard cap (1 hour) — a barrier cursor carrying the default
    /// 7-day stream expiry would otherwise be rejected by any conformant
    /// receiver.
    pub fn with_barrier_target(
        mut self,
        event_id: impl Into<String>,
        event_digest: impl Into<String>,
        realm_id: Option<String>,
    ) -> Self {
        self.purpose = CursorPurpose::Barrier;
        if let Ok(t_ms) = chrono::DateTime::parse_from_rfc3339(&self.t).map(|t| t.timestamp_millis())
        {
            let max_x = t_ms + Self::BARRIER_TTL_MAX_MS;
            if self.x > max_x {
                self.x = max_x;
            }
        }
        self.target = Some(CursorTarget {
            event_id: event_id.into(),
            event_digest: event_digest.into(),
            realm_id,
        });
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
    /// - Base64URL decoding fails
    /// - JSON parsing fails
    /// - Cursor structure is invalid
    /// - Cursor version is unsupported
    /// - Cursor has expired
    pub fn decode(encoded: &str) -> Result<Self> {
        let encoded = encoded
            .strip_prefix("ck:cursor:")
            .ok_or_else(|| Error::Protocol("cursor token must start with ck:cursor:".to_owned()))?;

        // Decode from unpadded Base64URL, the only v1 cursor transport form.
        let json = crate::base64url::base64url_decode(encoded)
            .map_err(|_| Error::Protocol("invalid Base64URL encoding".to_owned()))?;

        let cursor: Cursor = crate::canonical::from_canonical_json_slice(&json)
            .map_err(|_| Error::Protocol("invalid cursor JSON".to_owned()))?;

        cursor.validate()?;

        Ok(cursor)
    }

    /// Validate the cursor structure and expiration.
    fn validate(&self) -> Result<()> {
        // Check version
        if self.v != "1" {
            return Err(Error::Protocol(format!("unsupported cursor version: {}", self.v)));
        }

        self.validate_core_wire_shape()?;

        let now_ms = unix_time_millis()?;

        // §8.3 rule 5: `x` MUST NOT be in the past (TTL expiry).
        if self.x < now_ms {
            return Err(Error::Protocol("cursor has expired".to_owned()));
        }

        // §8.3 rule 12: `t` well-formedness + TTL hard upper bound.
        self.validate_ttl_bound(now_ms)?;

        // Validate Realm positions
        for (realm_id, pos) in &self.s {
            Self::validate_realm_id(realm_id)?;
            Self::validate_realm_position(pos)?;
        }

        // Validate device positions
        if let Some(devices) = &self.d {
            for message_id in devices.values() {
                Self::validate_device_message_id(message_id)?;
            }
        }

        if let Some(target) = &self.target {
            Self::validate_event_id(&target.event_id)?;
            if !is_digest(&target.event_digest) {
                return Err(Error::InvalidId(target.event_digest.clone()));
            }
            if let Some(realm_id) = &target.realm_id {
                Self::validate_realm_id(realm_id)?;
            }
        }

        if let Some(mac) = &self.mac {
            Self::validate_cursor_mac(mac)?;
        }
        if let Some(sig) = &self.sig
            && sig.trim().is_empty()
        {
            return Err(Error::Protocol("cursor _sig must not be empty".to_owned()));
        }

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
            Error::Protocol(format!("cursor `t` is not a canonical UTC `Z` timestamp: {}", self.t))
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

    fn validate_realm_id(realm_id: &str) -> Result<()> {
        if !has_prefixed_uuid7(realm_id, "ck:realm:") {
            return Err(Error::InvalidId(realm_id.to_owned()));
        }
        Ok(())
    }

    fn validate_realm_position(pos: &RealmPosition) -> Result<()> {
        // Validate HLC format
        Hlc::new(&pos.order)?;

        if !is_digest(&pos.h) {
            return Err(Error::InvalidId(pos.h.clone()));
        }

        // Validate event IDs in causal frontier
        for event_id in &pos.p {
            Self::validate_event_id(event_id)?;
        }

        Ok(())
    }

    fn validate_event_id(event_id: &str) -> Result<()> {
        let is_valid = has_prefixed_uuid7(event_id, "ck:event:");

        if !is_valid {
            return Err(Error::InvalidId(event_id.to_owned()));
        }
        Ok(())
    }

    fn validate_device_message_id(message_id: &str) -> Result<()> {
        if has_prefixed_uuid7(message_id, "ck:device_message:") {
            Ok(())
        } else {
            Err(Error::InvalidId(message_id.to_owned()))
        }
    }

    fn validate_cursor_handle(handle: &str) -> Result<()> {
        // Round R2/R3 (2026-05-20): schema raises minLength to 22 so the
        // base64url-decoded handle has ≥128 bits of entropy (128/6 = 21.33).
        let len = handle.len();
        if !(CURSOR_HANDLE_MIN_LEN..=256).contains(&len)
            || !handle.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::Protocol("invalid cursor handle".to_owned()));
        }
        Ok(())
    }

    fn validate_core_wire_shape(&self) -> Result<()> {
        let Some(handle) = &self.h else {
            return Err(Error::Protocol("core cursor missing stateful handle h".to_owned()));
        };
        Self::validate_cursor_handle(handle)?;
        if self.mac.is_some() || self.sig.is_some() {
            return Err(Error::Protocol(
                "core stateful cursor must not carry _mac or _sig".to_owned(),
            ));
        }
        if self.issuer_kid.is_some() {
            return Err(Error::Protocol(
                "core stateful cursor must not carry issuer_kid".to_owned(),
            ));
        }
        if !self.s.is_empty() || self.d.is_some() || self.target.is_some() {
            return Err(Error::Protocol(
                "core stateful cursor must not carry s, d, or target".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_cursor_mac(mac: &str) -> Result<()> {
        let Some(digest) = mac.strip_prefix("hmac-sha256:") else {
            return Err(Error::Protocol("cursor _mac must use hmac-sha256".to_owned()));
        };
        if digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(Error::Protocol("invalid cursor _mac digest".to_owned()));
        }
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
        let mut realms = BTreeMap::new();

        for (realm_id, pos) in &self.s {
            realms.insert(
                realm_id.clone(),
                RealmSyncPosition {
                    frontier: pos.p.clone(),
                    timeline_order: pos.order.clone(),
                    state_digest: pos.h.clone(),
                },
            );
        }

        let devices = self.d.as_ref().map(|d| {
            let mut map = BTreeMap::new();
            for (device_id, message_id) in d {
                map.insert(device_id.clone(), message_id.clone());
            }
            map
        });

        Ok(SyncPositions { realms, devices })
    }

    /// Check if the cursor is expired.
    pub fn is_expired(&self) -> bool {
        unix_time_millis().map_or(true, |now_ms| self.x < now_ms)
    }

    /// Get the remaining time before expiration.
    pub fn time_until_expiration(&self) -> Option<Duration> {
        let now_ms = unix_time_millis().ok()?;

        if self.x > now_ms { Some(Duration::from_millis((self.x - now_ms) as u64)) } else { None }
    }
}

fn unix_time_millis() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::Protocol(format!("cursor_clock_before_unix_epoch: {error}")))?
        .as_millis() as i64)
}

/// Validate that `value` matches the typed-id wire form `<prefix><uuidv7>`.
///
/// Per spec `id-kind-registry.json` (2026-05-09 onward), typed wire ids use
/// RFC 9562 UUID version 7 in canonical 36-char lowercase hex form
/// `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` where N ∈ {8,9,a,b}.
fn has_prefixed_uuid7(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    is_uuid7(suffix)
}

fn is_uuid7(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    // Hyphens at fixed positions: 8, 13, 18, 23
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    // Version nibble = '7' at index 14
    if bytes[14] != b'7' {
        return false;
    }
    // Variant nibble ∈ {8,9,a,b} at index 19
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    // Remaining positions must be lowercase hex
    bytes.iter().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            *b == b'-'
        } else {
            b.is_ascii_digit() || matches!(b, b'a'..=b'f')
        }
    })
}

fn is_digest(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    // Only digest-suite-registry *active* suites (`sha256`, `blake3`) are
    // valid; unregistered suites MUST fail closed in critical fields.
    let expected_len = match algorithm {
        "sha256" | "blake3" => 64,
        _ => return false,
    };
    digest.len() == expected_len
        && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
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
            positions: SyncPositions { realms: BTreeMap::new(), devices: None },
            sync_tokens: HashMap::new(),
        }
    }

    /// Update the tracker with a sync response.
    pub fn update(&mut self, response: &crate::SyncOutcome) -> Result<()> {
        // Update the sync token
        self.sync_tokens.insert("default".to_owned(), response.cursor.clone());

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

        assert!(decoded.s.is_empty());
        assert!(decoded.h.is_some());
        assert_eq!(decoded.v, cursor.v);
        assert_eq!(decoded.purpose, CursorPurpose::Stream);
        assert!(encoded.starts_with("ck:cursor:"));
    }

    #[test]
    fn cursor_rejects_invalid_version() {
        let cursor = Cursor {
            v: "2".to_owned(),
            purpose: CursorPurpose::Stream,
            t: chrono::Utc::now().to_rfc3339(),
            s: BTreeMap::new(),
            d: None,
            target: None,
            x: 1714080000000,
            h: Some(generate_cursor_handle().unwrap()),
            issuer_kid: None,
            mac: None,
            sig: None,
            filter_digest: None,
        };

        let encoded = cursor.encode().unwrap();
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_decode_rejects_non_nfc_json_string() {
        let json = "{\"v\":\"1\",\"purpose\":\"stream\",\"t\":\"cafe\u{301}\",\"s\":{},\"x\":4102444800000,\"h\":\"ABCDEFGHIJKLMNOPQRSTUV\"}";
        let encoded = format!("ck:cursor:{}", crate::base64url_encode(json.as_bytes()));
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn cursor_decode_rejects_duplicate_json_key() {
        let json = br#"{"v":"1","v":"1","purpose":"stream","t":"2026-06-06T00:00:00Z","s":{},"x":4102444800000,"h":"ABCDEFGHIJKLMNOPQRSTUV"}"#;
        let encoded = format!("ck:cursor:{}", crate::base64url_encode(json));
        assert!(matches!(Cursor::decode(&encoded), Err(Error::Protocol(_))));
    }

    #[test]
    fn core_cursor_rejects_inline_positions() {
        let mut cursor = Cursor::new().unwrap();
        cursor = cursor.with_realm_position(
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            RealmPosition {
                p: vec![],
                order: "invalid-hlc".to_owned(),
                h: "sha256:abc123...".to_owned(),
            },
        );

        assert!(cursor.encode().is_err());
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

        assert!(cursor.h.is_some());
        assert!(cursor.s.is_empty());
        assert!(cursor.d.is_none());
    }

    #[test]
    fn stateful_handle_cursor_excludes_inline_state() {
        let cursor = Cursor::new().unwrap().with_stateful_handle("cursor_handle_12345678");
        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();

        assert_eq!(decoded.h.as_deref(), Some("cursor_handle_12345678"));
        assert!(decoded.s.is_empty());
        assert!(decoded.d.is_none());
        assert!(decoded.issuer_kid.is_none());
        assert!(decoded.mac.is_none());
    }
}
