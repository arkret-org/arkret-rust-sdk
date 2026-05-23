//! Cursor encoding, decoding, and validation.
//!
//! This module implements the Contrix v1 cursor specification. Cursors are
//! opaque `cx:cursor:<base64url(canonical_json)>` tokens used for stream
//! continuation and read-your-writes barriers.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{Hlc, Result};

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
/// Round R2/R3 (2026-05-20). Servers SHOULD replace this fallback with a
/// CSPRNG-backed implementation (per schema description the handle MUST be
/// unguessable). This implementation derives 16 bytes from process pid +
/// monotonic time + thread id + an internal counter, mixed with SHA-256.
// TODO(round23-T9): replace this fallback with a CSPRNG-backed generator
// once servers move to a runtime that exposes one (rand_core or getrandom).
pub fn generate_cursor_handle() -> String {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    let now_ns =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    hasher.update(now_ns.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    // Pointer to a stack local mixes in ASLR + thread layout entropy.
    let local: u64 = 0;
    let local_ptr: *const u64 = &local;
    hasher.update((local_ptr as usize).to_le_bytes());
    let digest = hasher.finalize();
    // Take 16 bytes — 128 bits — and base64url-encode (no pad).
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16]);
    debug_assert!(encoded.len() >= CURSOR_HANDLE_MIN_LEN);
    encoded
}

/// Contrix v1 sync cursor.
///
/// Cursors contain all information needed to resume synchronization from a
/// specific point in the event stream. They are encoded as JSON and then
/// Base64URL-encoded for transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Cursor {
    /// Cursor version. Must be "1" for Contrix v1.
    pub v: String,
    /// Cursor purpose.
    pub purpose: CursorPurpose,
    /// Cursor generation timestamp (RFC 3339).
    pub t: String,
    /// Space positions map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub s: BTreeMap<String, SpacePosition>,
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
    /// Server-private filter hash binding.
    #[serde(default, rename = "_filter_hash", skip_serializing_if = "Option::is_none")]
    pub filter_hash: Option<String>,
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
    pub space_id: Option<String>,
}

/// Position information for a single Space.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpacePosition {
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

    /// SDK-local placeholder integrity binding used by offline builders and
    /// tests. Servers should replace it with a keyed `_mac`, `_sig`, or
    /// stateful `h` before issuing production cursors.
    pub const DEV_TEST_MAC: &'static str =
        "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000";
    pub const DEV_TEST_ISSUER_KID: &'static str = "contrix-sdk-dev#cursor";

    /// Create a new cursor with current timestamp and default expiration.
    pub fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        Self {
            v: "1".to_owned(),
            purpose: CursorPurpose::Stream,
            t: chrono::Utc::now().to_rfc3339(),
            s: BTreeMap::new(),
            d: None,
            target: None,
            x: now + Self::DEFAULT_EXPIRATION_MS,
            h: None,
            issuer_kid: Some(Self::DEV_TEST_ISSUER_KID.to_owned()),
            mac: Some(Self::DEV_TEST_MAC.to_owned()),
            sig: None,
            filter_hash: None,
        }
    }

    /// Bind a `filter_hash` to this cursor. Servers MUST refuse to
    /// reuse the cursor when the next request carries a different
    /// hash (M-15 / M-16). The hash is opaque to the SDK; callers
    /// typically pass [`crate::sync::sync_filter_hash`].
    pub fn with_filter_hash(mut self, hash: impl Into<String>) -> Self {
        self.filter_hash = Some(hash.into());
        self
    }

    /// Verify that the cursor's `filter_hash` matches `expected`.
    /// Returns an error when the cursor is unbound or was issued for a
    /// different filter.
    pub fn assert_filter_hash(&self, expected: &str) -> Result<()> {
        match self.filter_hash.as_deref() {
            None => Err(crate::Error::Protocol("filter_hash_missing".to_owned())),
            Some(found) if found == expected => Ok(()),
            Some(found) => Err(crate::Error::Protocol(format!(
                "filter_hash_mismatch: cursor was issued for '{found}', current request is '{expected}'"
            ))),
        }
    }

    /// Set a space position in the cursor.
    pub fn with_space_position(
        mut self,
        space_id: impl Into<String>,
        position: SpacePosition,
    ) -> Self {
        self.s.insert(space_id.into(), position);
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
    pub fn with_barrier_target(
        mut self,
        event_id: impl Into<String>,
        event_digest: impl Into<String>,
        space_id: Option<String>,
    ) -> Self {
        self.purpose = CursorPurpose::Barrier;
        self.target = Some(CursorTarget {
            event_id: event_id.into(),
            event_digest: event_digest.into(),
            space_id,
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
        let json = crate::canonical::canonical_json_bytes(self)?;

        if json.len() > Self::MAX_ENCODED_SIZE {
            return Err(crate::Error::Protocol(format!(
                "cursor too large: {} bytes (max {})",
                json.len(),
                Self::MAX_ENCODED_SIZE
            )));
        }

        // Encode to Base64URL without padding
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);

        Ok(format!("cx:cursor:{encoded}"))
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
        let encoded = encoded.strip_prefix("cx:cursor:").ok_or_else(|| {
            crate::Error::Protocol("cursor token must start with cx:cursor:".to_owned())
        })?;

        // Decode from unpadded Base64URL, the only v1 cursor transport form.
        use base64::Engine as _;

        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| crate::Error::Protocol("invalid Base64URL encoding".to_owned()))?;

        let cursor: Cursor = serde_json::from_slice(&json)
            .map_err(|_| crate::Error::Protocol("invalid cursor JSON".to_owned()))?;

        cursor.validate()?;

        Ok(cursor)
    }

    /// Validate the cursor structure and expiration.
    fn validate(&self) -> Result<()> {
        // Check version
        if self.v != "1" {
            return Err(crate::Error::Protocol(format!("unsupported cursor version: {}", self.v)));
        }

        let stateful = self.h.is_some();
        if stateful {
            if self.mac.is_some() || self.sig.is_some() {
                return Err(crate::Error::Protocol(
                    "stateful cursor handle must not carry _mac or _sig".to_owned(),
                ));
            }
            if self.issuer_kid.is_some() {
                return Err(crate::Error::Protocol(
                    "stateful cursor handle must not carry issuer_kid".to_owned(),
                ));
            }
            if !self.s.is_empty() || self.d.is_some() || self.target.is_some() {
                return Err(crate::Error::Protocol(
                    "stateful cursor handle must not carry s, d, or target".to_owned(),
                ));
            }
            if let Some(handle) = &self.h {
                Self::validate_cursor_handle(handle)?;
            }
        } else if self.mac.is_none() && self.sig.is_none() {
            return Err(crate::Error::Protocol("stateless cursor missing _mac or _sig".to_owned()));
        } else {
            let issuer_kid = self.issuer_kid.as_deref().ok_or_else(|| {
                crate::Error::Protocol("stateless cursor missing issuer_kid".to_owned())
            })?;
            Self::validate_issuer_kid(issuer_kid)?;
        }

        if matches!(self.purpose, CursorPurpose::Barrier) && self.target.is_none() && !stateful {
            return Err(crate::Error::Protocol("barrier cursor missing target".to_owned()));
        }

        // Check expiration
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        if self.x < now_ms {
            return Err(crate::Error::Protocol("cursor has expired".to_owned()));
        }

        // Validate space positions
        for (space_id, pos) in &self.s {
            Self::validate_space_id(space_id)?;
            Self::validate_space_position(pos)?;
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
                return Err(crate::Error::InvalidId(target.event_digest.clone()));
            }
            if let Some(space_id) = &target.space_id {
                Self::validate_space_id(space_id)?;
            }
        }

        if let Some(mac) = &self.mac {
            Self::validate_cursor_mac(mac)?;
        }
        if let Some(sig) = &self.sig
            && sig.trim().is_empty()
        {
            return Err(crate::Error::Protocol("cursor _sig must not be empty".to_owned()));
        }

        Ok(())
    }

    fn validate_space_id(space_id: &str) -> Result<()> {
        if !has_prefixed_uuid7(space_id, "cx:realm:") && !has_prefixed_uuid7(space_id, "cx:space:")
        {
            return Err(crate::Error::InvalidId(space_id.to_owned()));
        }
        Ok(())
    }

    fn validate_space_position(pos: &SpacePosition) -> Result<()> {
        // Validate HLC format
        Hlc::new(&pos.order)?;

        if !is_digest(&pos.h) {
            return Err(crate::Error::InvalidId(pos.h.clone()));
        }

        // Validate event IDs in causal frontier
        for event_id in &pos.p {
            Self::validate_event_id(event_id)?;
        }

        Ok(())
    }

    fn validate_event_id(event_id: &str) -> Result<()> {
        let is_valid = has_prefixed_uuid7(event_id, "cx:event:");

        if !is_valid {
            return Err(crate::Error::InvalidId(event_id.to_owned()));
        }
        Ok(())
    }

    fn validate_device_message_id(message_id: &str) -> Result<()> {
        if has_prefixed_uuid7(message_id, "cx:devmsg:") {
            Ok(())
        } else {
            Err(crate::Error::InvalidId(message_id.to_owned()))
        }
    }

    fn validate_cursor_handle(handle: &str) -> Result<()> {
        // Round R2/R3 (2026-05-20): schema raises minLength to 22 so the
        // base64url-decoded handle has ≥128 bits of entropy (128/6 = 21.33).
        let len = handle.len();
        if !(CURSOR_HANDLE_MIN_LEN..=256).contains(&len)
            || !handle.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(crate::Error::Protocol("invalid cursor handle".to_owned()));
        }
        Ok(())
    }

    fn validate_cursor_mac(mac: &str) -> Result<()> {
        let Some(digest) = mac.strip_prefix("hmac-sha256:") else {
            return Err(crate::Error::Protocol("cursor _mac must use hmac-sha256".to_owned()));
        };
        if digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(crate::Error::Protocol("invalid cursor _mac digest".to_owned()));
        }
        Ok(())
    }

    fn validate_issuer_kid(issuer_kid: &str) -> Result<()> {
        if issuer_kid.is_empty()
            || issuer_kid.len() > 256
            || issuer_kid.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(crate::Error::Protocol("invalid cursor issuer_kid".to_owned()));
        }
        Ok(())
    }

    /// Create a cursor from sync positions.
    pub fn from_positions(positions: SyncPositions) -> Self {
        let mut cursor = Self::new();

        for (space_id, pos) in positions.spaces {
            cursor = cursor.with_space_position(
                space_id,
                SpacePosition { p: pos.frontier, order: pos.timeline_order, h: pos.state_hash },
            );
        }

        if let Some(devices) = positions.devices {
            for (device_id, message_id) in devices {
                cursor = cursor.with_device_position(device_id, message_id);
            }
        }

        cursor
    }

    /// Extract sync positions from the cursor.
    pub fn to_positions(&self) -> Result<SyncPositions> {
        let mut spaces = BTreeMap::new();

        for (space_id, pos) in &self.s {
            spaces.insert(
                space_id.clone(),
                SpaceSyncPosition {
                    frontier: pos.p.clone(),
                    timeline_order: pos.order.clone(),
                    state_hash: pos.h.clone(),
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

        Ok(SyncPositions { spaces, devices })
    }

    /// Check if the cursor is expired.
    pub fn is_expired(&self) -> bool {
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        self.x < now_ms
    }

    /// Get the remaining time before expiration.
    pub fn time_until_expiration(&self) -> Option<Duration> {
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        if self.x > now_ms { Some(Duration::from_millis((self.x - now_ms) as u64)) } else { None }
    }
}

impl Default for Cursor {
    fn default() -> Self {
        Self::new()
    }
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
    let expected_len = match algorithm {
        "sha256" | "sha3_256" | "blake3" => 64,
        "sha512" => 128,
        _ => return false,
    };
    digest.len() == expected_len
        && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Sync positions extracted from a cursor.
#[derive(Clone, Debug, Default)]
pub struct SyncPositions {
    /// Space positions by space ID.
    pub spaces: BTreeMap<String, SpaceSyncPosition>,
    /// Device positions by device ID.
    pub devices: Option<BTreeMap<String, String>>,
}

/// Sync position for a single Space.
#[derive(Clone, Debug)]
pub struct SpaceSyncPosition {
    /// Causal frontier (event IDs).
    pub frontier: Vec<String>,
    /// Timeline order HLC.
    pub timeline_order: String,
    /// State hash at this position.
    pub state_hash: String,
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
            positions: SyncPositions { spaces: BTreeMap::new(), devices: None },
            sync_tokens: HashMap::new(),
        }
    }

    /// Update the tracker with a sync response.
    pub fn update(&mut self, response: &crate::SyncResBody) -> Result<()> {
        // Update the sync token
        self.sync_tokens.insert("default".to_owned(), response.cursor.clone());

        // Update positions from the response
        // (Implementation would parse the response and update spaces/devices)

        Ok(())
    }

    /// Get the current cursor for resuming sync.
    pub fn current_cursor(&self) -> Result<Cursor> {
        Ok(Cursor::from_positions(self.positions.clone()))
    }

    /// Clear all tracked positions.
    pub fn clear(&mut self) {
        self.positions.spaces.clear();
        self.positions.devices = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_encode_decode_roundtrip() {
        let mut cursor = Cursor::new();
        cursor = cursor.with_space_position(
            "cx:realm:0196419b-0000-7000-8000-000000000000",
            SpacePosition {
                p: vec!["cx:event:0196419b-0000-7000-8000-000000000001".to_owned()],
                order: "01970e589d21-0004-a13f9c2e".to_owned(),
                h: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            },
        );

        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();

        assert_eq!(decoded.s.len(), cursor.s.len());
        assert_eq!(decoded.v, cursor.v);
        assert_eq!(decoded.purpose, CursorPurpose::Stream);
        assert!(encoded.starts_with("cx:cursor:"));
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
            h: None,
            issuer_kid: Some(Cursor::DEV_TEST_ISSUER_KID.to_owned()),
            mac: Some(Cursor::DEV_TEST_MAC.to_owned()),
            sig: None,
            filter_hash: None,
        };

        let encoded = cursor.encode().unwrap();
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_rejects_invalid_hlc_format() {
        let mut cursor = Cursor::new();
        cursor = cursor.with_space_position(
            "cx:realm:01904100-0000-7000-8000-9b64700c6ee8",
            SpacePosition {
                p: vec![],
                order: "invalid-hlc".to_owned(),
                h: "sha256:abc123...".to_owned(),
            },
        );

        let encoded = cursor.encode().unwrap();
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_expires_after_7_days() {
        let mut cursor = Cursor::new();
        // Simulate a cursor from 1 day ago
        cursor.x -= 6 * 24 * 60 * 60 * 1000;

        assert!(!cursor.is_expired());
        assert!(cursor.time_until_expiration().is_some());
    }

    #[test]
    fn sync_positions_roundtrip() {
        let positions = SyncPositions {
            spaces: BTreeMap::from([(
                "cx:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                SpaceSyncPosition {
                    frontier: vec!["cx:event:0196419b-0000-7000-8000-000000000001".to_owned()],
                    timeline_order: "01970e589d21-0004-a13f9c2e".to_owned(),
                    state_hash:
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_owned(),
                },
            )]),
            devices: Some(BTreeMap::from([(
                "device-laptop".to_owned(),
                "cx:devmsg:019640da-0000-7000-8000-000000000000".to_owned(),
            )])),
        };

        let cursor = Cursor::from_positions(positions.clone());
        let extracted = cursor.to_positions().unwrap();

        assert_eq!(extracted.spaces.len(), positions.spaces.len());
        assert_eq!(extracted.devices, positions.devices);
    }

    #[test]
    fn stateful_handle_cursor_excludes_inline_state() {
        let cursor = Cursor::new().with_stateful_handle("cursor_handle_12345678");
        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();

        assert_eq!(decoded.h.as_deref(), Some("cursor_handle_12345678"));
        assert!(decoded.s.is_empty());
        assert!(decoded.d.is_none());
        assert!(decoded.issuer_kid.is_none());
        assert!(decoded.mac.is_none());
    }
}
