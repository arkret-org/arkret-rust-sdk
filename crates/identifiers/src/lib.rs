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
    method != "uuid"
}

fn is_hash(value: &str) -> bool {
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
id_type!(ActorProfileId, |value: &str| is_strict_typed_id(value, "cx:actor_profile:"));
id_type!(AgentSessionId, |value: &str| is_strict_typed_id(value, "cx:agent_session:"));
id_type!(AppletId, |value: &str| is_strict_typed_id(value, "cx:applet:"));
id_type!(SpaceId, |value: &str| is_strict_typed_id(value, "cx:space:"));
id_type!(BackupId, |value: &str| is_strict_typed_id(value, "cx:backup:"));
id_type!(BatchId, |value: &str| is_strict_typed_id(value, "cx:batch:"));
id_type!(BlobId, |value: &str| is_strict_typed_id(value, "cx:blob:"));
id_type!(BlockId, |value: &str| is_strict_typed_id(value, "cx:block:"));
id_type!(CallId, |value: &str| is_strict_typed_id(value, "cx:call:"));
id_type!(CapabilityId, |value: &str| is_strict_typed_id(value, "cx:capability:"));
id_type!(ChunkId, |value: &str| is_strict_typed_id(value, "cx:chunk:"));
id_type!(ClaimId, |value: &str| is_strict_typed_id(value, "cx:claim:"));
id_type!(DevmsgId, |value: &str| is_strict_typed_id(value, "cx:devmsg:"));
id_type!(FlowId, |value: &str| is_strict_typed_id(value, "cx:flow:"));
id_type!(FilterId, |value: &str| is_strict_typed_id(value, "cx:filter:"));
id_type!(FrameId, |value: &str| is_strict_typed_id(value, "cx:frame:"));
id_type!(FrankId, |value: &str| is_strict_typed_id(value, "cx:frank:"));
id_type!(MorphId, |value: &str| is_strict_typed_id(value, "cx:morph:"));
id_type!(PlaceId, |value: &str| is_strict_typed_id(value, "cx:place:"));
id_type!(MessageId, |value: &str| is_strict_typed_id(value, "cx:message:"));
id_type!(RelationId, |value: &str| is_strict_typed_id(value, "cx:relation:"));
id_type!(EventId, |value: &str| is_strict_typed_id(value, "cx:event:"));
id_type!(OperationId, |value: &str| is_strict_typed_id(value, "cx:operation:") || is_hash(value));
id_type!(GrantId, |value: &str| is_strict_typed_id(value, "cx:grant:"));
id_type!(InviteId, |value: &str| is_strict_typed_id(value, "cx:invite:"));
id_type!(KeyevtId, |value: &str| is_strict_typed_id(value, "cx:keyevt:"));
id_type!(DeviceId, |value: &str| is_strict_typed_id(value, "cx:device:"));
id_type!(NotifId, |value: &str| is_strict_typed_id(value, "cx:notif:"));
id_type!(PolicyId, |value: &str| is_strict_typed_id(value, "cx:policy:"));
id_type!(PresentationId, |value: &str| is_strict_typed_id(value, "cx:presentation:"));
id_type!(ReceiptId, |value: &str| is_strict_typed_id(value, "cx:receipt:"));
id_type!(ReportId, |value: &str| is_strict_typed_id(value, "cx:report:"));
id_type!(ModqId, |value: &str| is_strict_typed_id(value, "cx:modq:"));
id_type!(ReqId, |value: &str| is_strict_typed_id(value, "cx:req:"));
id_type!(SnapshotId, |value: &str| is_strict_typed_id(value, "cx:snapshot:"));
id_type!(TxnId, |value: &str| is_strict_typed_id(value, "cx:txn:"));
id_type!(BlobRef, is_blob_ref);
id_type!(ViewId, |value: &str| is_strict_typed_id(value, "cx:view:"));
id_type!(Hash, is_hash);
id_type!(Cursor, has_prefix("cx:cursor:"));

fn is_blob_ref(value: &str) -> bool {
    if is_hash(value) || is_strict_typed_id(value, "cx:blob:") {
        return true;
    }
    value.strip_prefix("cx:blob:").is_some_and(is_hash)
}

fn is_content_addressed<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.strip_prefix(prefix).is_some_and(is_hash)
}

id_type!(MoveId, is_content_addressed("cx:move:"));
id_type!(AnchorId, is_content_addressed("cx:anchor:"));
id_type!(CellRef, has_prefix("cx:cell:"));

impl BlobRef {
    /// Create a content-addressed `sha256:...` blob reference from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        Self(digest)
    }
}

impl Did {
    /// Return the DID method name.
    pub fn method(&self) -> &str {
        self.0
            .strip_prefix("did:")
            .and_then(|remainder| remainder.split_once(':').map(|(method, _)| method))
            .expect("DID constructed with method")
    }
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
    fn did_validation_rejects_removed_uuid_method() {
        assert!(Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").is_err());
    }

    #[test]
    fn device_id_accepts_protocol_device_forms() {
        assert!(DeviceId::new("dev_alice_1").is_err());
        assert!(DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(DeviceId::new("device-1").is_err());
        // Mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(DeviceId::new("cx:device:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn active_id_kind_wrappers_accept_uuidv7_wire_forms() {
        macro_rules! assert_id {
            ($ty:ty, $prefix:literal) => {{
                let value = format!("{}01904100-0000-7000-8000-000000000001", $prefix);
                assert!(<$ty>::new(value).is_ok(), "{}", stringify!($ty));
            }};
        }

        assert_id!(ActorProfileId, "cx:actor_profile:");
        assert_id!(AgentSessionId, "cx:agent_session:");
        assert_id!(AppletId, "cx:applet:");
        assert_id!(BackupId, "cx:backup:");
        assert_id!(BatchId, "cx:batch:");
        assert_id!(BlobId, "cx:blob:");
        assert_id!(BlockId, "cx:block:");
        assert_id!(CallId, "cx:call:");
        assert_id!(CapabilityId, "cx:capability:");
        assert_id!(ChunkId, "cx:chunk:");
        assert_id!(ClaimId, "cx:claim:");
        assert_id!(DeviceId, "cx:device:");
        assert_id!(DevmsgId, "cx:devmsg:");
        assert_id!(EventId, "cx:event:");
        assert_id!(FilterId, "cx:filter:");
        assert_id!(FlowId, "cx:flow:");
        assert_id!(FrameId, "cx:frame:");
        assert_id!(FrankId, "cx:frank:");
        assert_id!(GrantId, "cx:grant:");
        assert_id!(InviteId, "cx:invite:");
        assert_id!(KeyevtId, "cx:keyevt:");
        assert_id!(MessageId, "cx:message:");
        assert_id!(ModqId, "cx:modq:");
        assert_id!(MorphId, "cx:morph:");
        assert_id!(NotifId, "cx:notif:");
        assert_id!(PlaceId, "cx:place:");
        assert_id!(PolicyId, "cx:policy:");
        assert_id!(PresentationId, "cx:presentation:");
        assert_id!(ReceiptId, "cx:receipt:");
        assert_id!(RelationId, "cx:relation:");
        assert_id!(ReportId, "cx:report:");
        assert_id!(ReqId, "cx:req:");
        assert_id!(SnapshotId, "cx:snapshot:");
        assert_id!(SpaceId, "cx:space:");
        assert_id!(TxnId, "cx:txn:");
        assert_id!(ViewId, "cx:view:");
    }

    #[test]
    fn hash_and_content_addressed_ids_accept_registry_algorithms() {
        let digest64 = "0".repeat(64);
        let digest128 = "0".repeat(128);

        assert!(Hash::new(format!("sha256:{digest64}")).is_ok());
        assert!(Hash::new(format!("sha3_256:{digest64}")).is_ok());
        assert!(Hash::new(format!("blake3:{digest64}")).is_ok());
        assert!(Hash::new(format!("sha512:{digest128}")).is_ok());
        assert!(BlobRef::new(format!("cx:blob:sha3_256:{digest64}")).is_ok());
        assert!(MoveId::new(format!("cx:move:blake3:{digest64}")).is_ok());
        assert!(AnchorId::new(format!("cx:anchor:sha512:{digest128}")).is_ok());
    }

    #[test]
    fn flow_id_accepts_active_flow_prefix() {
        assert!(FlowId::new("cx:flow:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(FlowId::new("cx:space:01904100-0000-7000-8000-000000000001").is_err());
        // Mixed-case ULID-form rejected by the strict UUIDv7 validator.
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
        // Mixed-case ULID-form is rejected (intentionally non-UUIDv7).
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
