//! Validated Contrix v1 identifiers.
//!
//! The types in this crate are the protocol boundary for DIDs, object IDs,
//! content hashes, cursors and HLC values. Constructors and Serde decoding both
//! validate their input so malformed wire identifiers fail at the edge.

use std::{cmp::Ordering, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, IdentifierError>;

#[derive(Debug, Error)]
pub enum IdentifierError {
    #[error("invalid Contrix identifier: {0}")]
    InvalidId(String),

    #[error("identifier random generation failed: {0}")]
    Random(String),
}

macro_rules! id_type {
    ($name:ident, $expect:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$expect(&value) {
                    return Err(IdentifierError::InvalidId(value));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

fn is_did(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("did:") else {
        return false;
    };
    let Some((method, method_specific_id)) = remainder.split_once(':') else {
        return false;
    };
    if method.is_empty()
        || method_specific_id.is_empty()
        || !method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }

    if method == "uuid" {
        return is_canonical_uuid(method_specific_id);
    }

    true
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return false;
    }

    let mut non_zero = false;
    for (idx, byte) in value.bytes().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            continue;
        }
        if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
            return false;
        }
        non_zero |= byte != b'0';
    }
    if !non_zero {
        return false;
    }

    let version = value.as_bytes()[14];
    let variant = value.as_bytes()[19];
    matches!(version, b'4' | b'7' | b'8') && matches!(variant, b'8' | b'9' | b'a' | b'b')
}

fn is_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn has_prefix<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.starts_with(prefix) && value.len() > prefix.len()
}

/// Strict typed-ID validator: payload MUST be a canonical RFC 9562 UUID
/// version 7 (36 chars, lower-case hex `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx`
/// where N ∈ {8,9,a,b}) per `conformance/encoding.md` §4. Use this when
/// you need to reject malformed wire input (e.g. ULIDs, UUIDv4); the
/// default `has_prefix` only checks the kind prefix and is more permissive.
pub fn is_strict_typed_id(value: &str, prefix: &str) -> bool {
    match value.strip_prefix(prefix) {
        Some(payload) => is_lowercase_uuidv7(payload),
        None => false,
    }
}

/// Generate a fresh canonical `<prefix><uuidv7>` identifier string using a
/// freshly generated RFC 9562 UUIDv7. The output is always lowercase hex per
/// `conformance/encoding.md` §4 and is the canonical wire form for typed
/// `cx:<kind>:` identifiers (Contrix v1, 2026-05-09 onward).
pub fn new_prefixed_uuid7(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Validate that `value` is a canonical lower-case RFC 9562 UUIDv7 in the
/// 36-character `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` form (N ∈ {8,9,a,b}),
/// per `conformance/encoding.md` §4.
///
/// The v1 wire forbids upper-case hex, missing dashes, URN/Microsoft braces,
/// and any UUID version other than 7.
pub fn is_lowercase_uuidv7(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    // Reject upper-case hex.
    for &b in bytes {
        if b.is_ascii_uppercase() {
            return false;
        }
    }
    // Position structure check, then version + variant nibble check.
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                let c = b as char;
                if !c.is_ascii_digit() && !matches!(c, 'a'..='f') {
                    return false;
                }
            }
        }
    }
    // Version nibble at byte position 14 (third group: 7xxx).
    if bytes[14] != b'7' {
        return false;
    }
    // Variant nibble at byte position 19 (fourth group: Nxxx, N ∈ {8,9,a,b}).
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    true
}

id_type!(Did, is_did);
// Protocol object IDs use typed prefixes with canonical RFC 9562 UUIDv7 payloads.
id_type!(SpaceId, |value: &str| is_strict_typed_id(value, "cx:space:"));
id_type!(FlowId, |value: &str| is_strict_typed_id(value, "cx:flow:"));
id_type!(MorphId, |value: &str| is_strict_typed_id(value, "cx:morph:"));
id_type!(PlaceId, |value: &str| is_strict_typed_id(value, "cx:place:"));
id_type!(MessageId, |value: &str| is_strict_typed_id(value, "cx:message:"));
id_type!(ActorProfileId, |value: &str| is_strict_typed_id(value, "cx:actor_profile:"));
id_type!(RelationId, |value: &str| is_strict_typed_id(value, "cx:relation:"));
id_type!(EventId, |value: &str| is_strict_typed_id(value, "cx:event:"));
id_type!(OperationId, |value: &str| is_strict_typed_id(value, "cx:operation:") || is_hash(value));
id_type!(GrantId, |value: &str| is_strict_typed_id(value, "cx:grant:"));
id_type!(InviteId, |value: &str| is_strict_typed_id(value, "cx:invite:"));
id_type!(DeviceId, |value: &str| (value.starts_with("dev_") && value.len() > "dev_".len())
    || is_strict_typed_id(value, "cx:device:"));
id_type!(PolicyId, |value: &str| is_strict_typed_id(value, "cx:policy:"));
id_type!(BlobRef, |value: &str| value.starts_with("cx:blob:") || is_hash(value));
id_type!(ViewId, |value: &str| is_strict_typed_id(value, "cx:view:"));
id_type!(Hash, is_hash);
id_type!(Cursor, has_prefix("cx:cursor:"));

fn is_content_addressed<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| match value.strip_prefix(prefix) {
        Some(rest) => {
            rest.len() == 64
                && rest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }
        None => false,
    }
}

id_type!(MoveId, is_content_addressed("cx:move:sha256:"));
id_type!(AnchorId, is_content_addressed("cx:anchor:sha256:"));
id_type!(CellRef, has_prefix("cx:cell:"));

impl BlobRef {
    /// Create a content-addressed `sha256:...` blob reference from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        Self(digest)
    }
}

impl Did {
    /// Generate a random canonical `did:uuid` value using UUIDv4 layout.
    pub fn new_uuid_v4() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| IdentifierError::Random(error.to_string()))?;
        Self::uuid_v4_from_bytes(bytes)
    }

    /// Build a canonical `did:uuid` value from raw UUIDv4 bytes.
    pub fn uuid_v4_from_bytes(mut bytes: [u8; 16]) -> Result<Self> {
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self::new(format!("did:uuid:{}", format_uuid_bytes(bytes)))
    }

    /// Return the DID method name.
    pub fn method(&self) -> &str {
        self.0
            .strip_prefix("did:")
            .and_then(|remainder| remainder.split_once(':').map(|(method, _)| method))
            .expect("DID constructed with method")
    }

    /// Return whether this DID uses the canonical `did:uuid` method form.
    pub fn is_uuid(&self) -> bool {
        self.method() == "uuid"
    }
}

fn format_uuid_bytes(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hlc(String);

impl Hlc {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        Self::parse_parts(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    fn parse_parts(value: &str) -> Result<(u64, u64, &str)> {
        let mut parts = value.split('-');
        let unix_ms = parts
            .next()
            .ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let logical = parts
            .next()
            .ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let node = parts.next().ok_or_else(|| IdentifierError::InvalidId(value.to_owned()))?;
        if parts.next().is_some()
            || value.len() != 30
            || value.as_bytes().get(12) != Some(&b'-')
            || value.as_bytes().get(21) != Some(&b'-')
            || node.is_empty()
            || node.len() != 8
            || !node.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(IdentifierError::InvalidId(value.to_owned()));
        }
        Ok((unix_ms, logical, node))
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Hlc {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_ms, self_logical, self_node) =
            Self::parse_parts(&self.0).expect("HLC constructed with valid parts");
        let (other_ms, other_logical, other_node) =
            Self::parse_parts(&other.0).expect("HLC constructed with valid parts");
        (self_ms, self_logical, self_node).cmp(&(other_ms, other_logical, other_node))
    }
}

impl Serialize for Hlc {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

fn parse_lower_hex(part: &str, original: &str) -> Result<u64> {
    if part.is_empty()
        || !matches!(part.len(), 8 | 12)
        || !part.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(IdentifierError::InvalidId(original.to_owned()));
    }
    u64::from_str_radix(part, 16).map_err(|_| IdentifierError::InvalidId(original.to_owned()))
}

#[cfg(feature = "salvo")]
mod oapi;

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn did_validation_rejects_handles() {
        assert!(Did::new("did:web:alice.example").is_ok());
        assert!(Did::new("alice.example").is_err());
    }

    #[test]
    fn did_uuid_validation_checks_uuid_layout() {
        let did = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(did.method(), "uuid");
        assert!(did.is_uuid());
        assert!(Did::new("did:uuid:19dbd742-a001-834d-91b6-b01c2e3b76d9").unwrap().is_uuid());

        assert!(Did::new("did:uuid:550e8400-e29b-11d4-a716-446655440000").is_err());
        assert!(Did::new("did:uuid:550e8400-e29b-41d4-c716-446655440000").is_err());
        assert!(Did::new("did:uuid:550E8400-e29b-41d4-a716-446655440000").is_err());
        assert!(Did::new("did:uuid:00000000-0000-4000-8000-000000000000").is_ok());
        assert!(Did::new("did:uuid:00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn did_uuid_generation_sets_version_and_variant_bits() {
        let did = Did::uuid_v4_from_bytes([0xff; 16]).unwrap();
        assert_eq!(did.as_str(), "did:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert!(did.is_uuid());

        let generated = Did::new_uuid_v4().unwrap();
        assert!(generated.is_uuid());
    }

    #[test]
    fn device_id_accepts_protocol_device_forms() {
        assert!(DeviceId::new("dev_alice_1").is_ok());
        assert!(DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(DeviceId::new("device-1").is_err());
        // Legacy mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(DeviceId::new("cx:device:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn flow_id_accepts_active_flow_prefix() {
        assert!(FlowId::new("cx:flow:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(FlowId::new("cx:room:01904100-0000-7000-8000-000000000001").is_err());
        // Legacy mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(FlowId::new("cx:flow:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn new_prefixed_uuid7_produces_strict_typed_id() {
        // C19.B: helper for newly-issued Contrix wire ids.
        let id = new_prefixed_uuid7("cx:space:");
        assert!(is_strict_typed_id(&id, "cx:space:"));
        // Two consecutive calls produce different ids.
        let id2 = new_prefixed_uuid7("cx:space:");
        assert_ne!(id, id2);
        // Resulting id is accepted by the SpaceId validator.
        assert!(SpaceId::new(id).is_ok());
    }

    #[test]
    fn is_strict_typed_id_rejects_ulid_and_bad_uuid_payloads() {
        // C19 wire-break: typed wire ids MUST be canonical lowercase UUIDv7.
        // Legacy mixed-case ULID-form is rejected (intentionally non-UUIDv7).
        assert!(!is_strict_typed_id("cx:space:01js0ke000000000000000000", "cx:space:"));
        // Uppercase hex forbidden.
        assert!(!is_strict_typed_id("cx:space:0196419B-0000-7000-8000-000000000000", "cx:space:"));
        // Wrong UUID version (4 instead of 7).
        assert!(!is_strict_typed_id("cx:space:0196419b-0000-4000-8000-000000000000", "cx:space:"));
        // Wrong variant nibble (c not in {8,9,a,b}).
        assert!(!is_strict_typed_id("cx:space:0196419b-0000-7000-c000-000000000000", "cx:space:"));
        // Canonical UUIDv7 accepted.
        assert!(is_strict_typed_id("cx:space:0196419b-0000-7000-8000-000000000000", "cx:space:"));
    }

    #[test]
    fn serde_deserialization_validates_identifier_values() {
        #[derive(Deserialize)]
        struct Envelope {
            space_id: SpaceId,
            hlc: Hlc,
        }

        let valid: Envelope = serde_json::from_value(serde_json::json!({
            "space_id": "cx:space:01904100-0000-7000-8000-000000000001",
            "hlc": "01970e589d21-00000004-a13f9c2e",
        }))
        .unwrap();
        assert_eq!(valid.space_id.as_str(), "cx:space:01904100-0000-7000-8000-000000000001");
        assert_eq!(valid.hlc.as_str(), "01970e589d21-00000004-a13f9c2e");

        let invalid_id = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "space-01",
            "hlc": "01970e589d21-00000004-a13f9c2e",
        }));
        assert!(invalid_id.is_err());

        let invalid_hlc = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "cx:space:01904100-0000-7000-8000-000000000001",
            "hlc": "1970",
        }));
        assert!(invalid_hlc.is_err());
    }
}
