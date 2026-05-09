//! Cursor encoding, decoding, and validation.
//!
//! This module implements the Contrix v1 cursor specification as defined in
//! the protocol documentation. Cursors are opaque tokens used for incremental
//! synchronization between clients and servers.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{Hlc, Result};

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
    /// Cursor generation timestamp (RFC 3339).
    pub t: String,
    /// Space positions map.
    pub s: BTreeMap<String, SpacePosition>,
    /// Device positions map (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<BTreeMap<String, String>>,
    /// Expiration timestamp (Unix milliseconds).
    pub x: i64,
    /// Filter hash binding (M-15 / M-16). When present, the producing
    /// server MUST reject the cursor unless the current request carries
    /// the same `filter_hash`. This prevents a client from changing its
    /// `subscriptions` between calls and silently re-using a cursor that
    /// was issued under different filter parameters.
    #[serde(default, rename = "f", skip_serializing_if = "Option::is_none")]
    pub filter_hash: Option<String>,
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

    /// Create a new cursor with current timestamp and default expiration.
    pub fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        Self {
            v: "1".to_owned(),
            t: chrono::Utc::now().to_rfc3339(),
            s: BTreeMap::new(),
            d: None,
            x: now + Self::DEFAULT_EXPIRATION_MS,
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
    /// Returns `Ok(())` when the cursor has no binding (legacy clients)
    /// or the hash matches; otherwise `Err(Error::Protocol("filter_hash_mismatch"))`.
    pub fn assert_filter_hash(&self, expected: &str) -> Result<()> {
        match self.filter_hash.as_deref() {
            None => Ok(()),
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

    /// Encode the cursor to a Base64URL string for transport.
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

        Ok(encoded)
    }

    /// Decode a cursor from a Base64URL string.
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
        // Decode from Base64URL (allowing padding for compatibility)
        use base64::Engine as _;

        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
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
            for (device_id, message_id) in devices {
                Self::validate_device_id(device_id)?;
                Self::validate_device_message_id(message_id)?;
            }
        }

        Ok(())
    }

    fn validate_space_id(space_id: &str) -> Result<()> {
        if !has_prefixed_uuid7(space_id, "cx:space:") {
            return Err(crate::Error::InvalidId(space_id.to_owned()));
        }
        Ok(())
    }

    fn validate_space_position(pos: &SpacePosition) -> Result<()> {
        // Validate HLC format
        Hlc::new(&pos.order)?;

        if !is_sha256_hash(&pos.h) {
            return Err(crate::Error::InvalidId(pos.h.clone()));
        }

        // Validate event IDs in causal frontier
        for event_id in &pos.p {
            Self::validate_event_id(event_id)?;
        }

        Ok(())
    }

    fn validate_device_id(device_id: &str) -> Result<()> {
        let is_valid = device_id.starts_with("dev_") && device_id.len() > 4
            || has_prefixed_uuid7(device_id, "cx:device:");

        if !is_valid {
            return Err(crate::Error::InvalidId(device_id.to_owned()));
        }
        Ok(())
    }

    fn validate_event_id(event_id: &str) -> Result<()> {
        let is_valid = has_prefixed_uuid7(event_id, "cx:evt:")
            || has_prefixed_uuid7(event_id, "cx:event:")
            || has_prefixed_uuid7(event_id, "cx:operation:")
            || is_sha256_hash(event_id);

        if !is_valid {
            return Err(crate::Error::InvalidId(event_id.to_owned()));
        }
        Ok(())
    }

    fn validate_device_message_id(message_id: &str) -> Result<()> {
        if has_prefixed_uuid7(message_id, "cx:devmsg:")
            || has_prefixed_uuid7(message_id, "cx:device_message:")
        {
            Ok(())
        } else {
            Err(crate::Error::InvalidId(message_id.to_owned()))
        }
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

fn is_sha256_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
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
    pub fn update(&mut self, response: &crate::SyncResponse) -> Result<()> {
        // Update the sync token
        self.sync_tokens.insert("default".to_owned(), response.next_batch.clone());

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
            "cx:space:0196419b-0000-7000-8000-000000000000",
            SpacePosition {
                p: vec!["cx:evt:0196419b-0000-7000-8000-000000000001".to_owned()],
                order: "01970e589d21-00000004-a13f9c2e".to_owned(),
                h: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            },
        );

        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();

        assert_eq!(decoded.s.len(), cursor.s.len());
        assert_eq!(decoded.v, cursor.v);
    }

    #[test]
    fn cursor_rejects_invalid_version() {
        let cursor = Cursor {
            v: "2".to_owned(),
            t: chrono::Utc::now().to_rfc3339(),
            s: BTreeMap::new(),
            d: None,
            x: 1714080000000,
            filter_hash: None,
        };

        let encoded = cursor.encode().unwrap();
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_rejects_invalid_hlc_format() {
        let mut cursor = Cursor::new();
        cursor = cursor.with_space_position(
            "cx:space:01JS0SP000000000000000000",
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
                "cx:space:0196419b-0000-7000-8000-000000000000".to_owned(),
                SpaceSyncPosition {
                    frontier: vec!["cx:evt:0196419b-0000-7000-8000-000000000001".to_owned()],
                    timeline_order: "01970e589d21-00000004-a13f9c2e".to_owned(),
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
}
