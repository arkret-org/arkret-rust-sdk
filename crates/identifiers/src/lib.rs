//! Validated Cokret v1 identifiers.
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
    #[error("invalid Cokret identifier: {0}")]
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

/// Validate a DID scalar against the Round 4 tightened pattern. Method name
/// MUST be lowercase ASCII alpha + digits only (no `.`/`-`/`_`/`:`);
/// method-specific-id MUST be non-empty and contain no whitespace, fragment,
/// or query marker. DID URL fields use a separate string surface and require a
/// `#key` fragment.
///
/// 零分配的公开校验入口:对任意 `&str` 返回它是否为合法 DID 标量。
/// 与 `id_type!(Did, is_did)` 内部使用的判定完全一致,供下游直接复用而无需
/// 构造 `Did`。Zero-allocation public validator for the DID scalar form.
pub fn is_did(value: &str) -> bool {
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
    if method_specific_id.bytes().any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'#' | b'?')) {
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

/// Validate the `ck:trust_domain:<scope>` wire form. Scope MUST be lowercase
/// `[a-z0-9._:-]` (alphanumerics + dot/dash/underscore/colon), max 128 chars,
/// non-empty. Round R2/R3 (2026-05-20). Spec: id-kind-registry.json
/// special_forms[trust_domain]; pattern matches cross-signing-reset.schema.json
/// `^ck:trust_domain:[a-z0-9][a-z0-9._\-:]{0,127}$`.
///
/// 零分配的公开校验入口:对任意 `&str` 返回它是否为合法 `ck:trust_domain:<scope>`
/// 线格式。与 `id_type!(TypedTrustDomainId, is_trust_domain)` 内部判定一致。
/// Zero-allocation public validator for the trust-domain wire form.
pub fn is_trust_domain(value: &str) -> bool {
    let Some(scope) = value.strip_prefix("ck:trust_domain:") else {
        return false;
    };
    if scope.is_empty() || scope.len() > 128 {
        return false;
    }
    let bytes = scope.as_bytes();
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
        return false;
    }
    scope.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b':'
        )
    })
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
/// `ck:<kind>:` identifiers (Cokret v1, 2026-05-09 onward).
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
id_type!(ActorProfileId, |value: &str| is_strict_typed_id(value, "ck:actor_profile:"));
// CKP-0008/0009 (spec head 37ce729) — personal agent auxiliary typed ids.
// `agent_principal_id` is a DID scalar, represented by `Did`.
id_type!(AgentSessionId, |value: &str| is_strict_typed_id(value, "ck:agent_session:"));
id_type!(AgentKeyId, |value: &str| is_strict_typed_id(value, "ck:agent_key:"));
id_type!(AgentDraftId, |value: &str| is_strict_typed_id(value, "ck:agent_draft:"));
id_type!(AccountabilityGrantId, |value: &str| is_strict_typed_id(
    value,
    "ck:accountability_grant:"
));
id_type!(SidecarCircleId, |value: &str| is_strict_typed_id(value, "ck:sidecar_circle:"));
// Key-backup hardening (B-C) typed ids.
id_type!(BackupSeriesId, |value: &str| is_strict_typed_id(value, "ck:backup_series:"));
id_type!(RecoverySessionId, |value: &str| is_strict_typed_id(value, "ck:recovery_session:"));
id_type!(AnnounceId, |value: &str| is_strict_typed_id(value, "ck:announce:"));
id_type!(AppletId, |value: &str| is_strict_typed_id(value, "ck:applet:"));
// `RealmId` is the protocol security-boundary key type (Realm/Space
// inversion). It accepts the canonical `ck:realm:*` form and — for backward
// compatibility with reducer/store layers that historically keyed boundary
// state on a `ck:space:*` mirror — also the `ck:space:*` form. The narrower
// `ck:realm:*`-only validation that the old standalone `RealmId` carried is
// intentionally widened here so the single boundary-key type round-trips
// every wire value that the former `SpaceId` accepted; no current wire field
// is tightened by this merge.
id_type!(RealmId, |value: &str| is_strict_typed_id(value, "ck:realm:")
    || is_strict_typed_id(value, "ck:space:"));
id_type!(BackupId, |value: &str| is_strict_typed_id(value, "ck:backup:"));
id_type!(BatchId, |value: &str| is_strict_typed_id(value, "ck:batch:"));
id_type!(BlobId, |value: &str| is_strict_typed_id(value, "ck:blob:"));
id_type!(BlockId, |value: &str| is_strict_typed_id(value, "ck:block:"));
id_type!(CallId, |value: &str| is_strict_typed_id(value, "ck:call:"));
id_type!(CapabilityId, |value: &str| is_strict_typed_id(value, "ck:capability:"));
id_type!(ChunkId, |value: &str| is_strict_typed_id(value, "ck:chunk:"));
// CKP-0007 (2026-05-08) — Circle id-kind. Intra-Realm cryptographic
// sub-boundary; see spec artifacts/registry/id-kind-registry.json and
// zh/models/circle.md.
id_type!(CircleId, |value: &str| is_strict_typed_id(value, "ck:circle:"));
id_type!(ClaimId, |value: &str| is_strict_typed_id(value, "ck:claim:"));
id_type!(DeviceMessageId, |value: &str| is_strict_typed_id(value, "ck:device_message:"));
id_type!(FlowId, |value: &str| is_strict_typed_id(value, "ck:flow:"));
id_type!(FilterId, |value: &str| is_strict_typed_id(value, "ck:filter:"));
id_type!(FrameId, |value: &str| is_strict_typed_id(value, "ck:frame:"));
id_type!(FrankingProofId, |value: &str| is_strict_typed_id(value, "ck:franking_proof:"));
id_type!(MorphId, |value: &str| is_strict_typed_id(value, "ck:morph:"));
// Round R2/R3 (2026-05-20) — moderation appeal cell key (`ck:appeal:<uuidv7>`).
// id-kind-registry kind=appeal; see schemas/moderation-appeal.schema.json.
id_type!(TypedAppealId, |value: &str| is_strict_typed_id(value, "ck:appeal:"));
// Round R2/R3 (2026-05-20) — deployment-scope trust domain identifier.
// Wire form `ck:trust_domain:<scope>` where scope is lowercase
// `[a-z0-9._:-]` max 128 chars. NOT a typed-UUIDv7 object id. Used to
// prevent cross-deployment replay of high-risk proofs (cross-signing reset).
id_type!(TypedTrustDomainId, is_trust_domain);
id_type!(MessageId, |value: &str| is_strict_typed_id(value, "ck:message:"));
id_type!(RelationId, |value: &str| is_strict_typed_id(value, "ck:relation:"));
id_type!(EventId, |value: &str| is_strict_typed_id(value, "ck:event:"));
id_type!(OperationId, |value: &str| is_strict_typed_id(value, "ck:operation:") || is_hash(value));
id_type!(GrantId, |value: &str| is_strict_typed_id(value, "ck:grant:"));
id_type!(InviteId, |value: &str| is_strict_typed_id(value, "ck:invite:"));
id_type!(KeyEventId, |value: &str| is_strict_typed_id(value, "ck:key_event:"));
id_type!(DeviceId, |value: &str| is_strict_typed_id(value, "ck:device:"));
id_type!(NotificationId, |value: &str| is_strict_typed_id(value, "ck:notification:"));
id_type!(PolicyId, |value: &str| is_strict_typed_id(value, "ck:policy:"));
id_type!(PresentationId, |value: &str| is_strict_typed_id(value, "ck:presentation:"));
id_type!(ReceiptId, |value: &str| is_strict_typed_id(value, "ck:receipt:"));
id_type!(ReportId, |value: &str| is_strict_typed_id(value, "ck:report:"));
id_type!(ReadCursorId, |value: &str| is_strict_typed_id(value, "ck:read_cursor:"));
id_type!(ModerationQueueItemId, |value: &str| is_strict_typed_id(
    value,
    "ck:moderation_queue_item:"
));
id_type!(RequestId, |value: &str| is_strict_typed_id(value, "ck:request:"));
id_type!(SnapshotId, |value: &str| is_strict_typed_id(value, "ck:snapshot:"));
id_type!(TransactionId, |value: &str| is_strict_typed_id(value, "ck:transaction:"));
id_type!(BlobRef, is_blob_ref);
id_type!(ViewId, |value: &str| is_strict_typed_id(value, "ck:view:"));
id_type!(Hash, is_hash);
id_type!(Cursor, has_prefix("ck:cursor:"));

fn is_blob_ref(value: &str) -> bool {
    if is_hash(value) || is_strict_typed_id(value, "ck:blob:") {
        return true;
    }
    value.strip_prefix("ck:blob:").is_some_and(is_hash)
}

fn is_content_addressed<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.strip_prefix(prefix).is_some_and(is_hash)
}

// Anchor frontier items are bare `<algo>:<hex>` hashes equal to the
// reducer-input event's `proof.payload_digest` (spec field name
// `event_digest`).
id_type!(MoveId, is_hash);
id_type!(AnchorId, is_content_addressed("ck:anchor:"));
id_type!(CellRef, has_prefix("ck:cell:"));

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
            || value.len() != 26
            || value.as_bytes().get(12) != Some(&b'-')
            || value.as_bytes().get(17) != Some(&b'-')
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
        || !matches!(part.len(), 4 | 8 | 12)
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

    /// Round 4 (spec a77b995): method-name segment is `[a-z0-9]+` only;
    /// `.`/`-`/`_`/`:` and whitespace MUST be rejected. DID scalar fields
    /// also reject DID URL query / fragment markers.
    #[test]
    fn did_validation_rejects_method_punctuation() {
        // Method-segment with dot/dash/underscore/colon — all rejected.
        assert!(Did::new("did:web.test:example").is_err()); // DRIFT-ALLOW: negative test
        assert!(Did::new("did:web-test:example").is_err()); // DRIFT-ALLOW: negative test
        assert!(Did::new("did:web_test:example").is_err()); // DRIFT-ALLOW: negative test
        // Method-specific-id containing whitespace — rejected.
        assert!(Did::new("did:web:exa mple").is_err());
        assert!(Did::new("did:web:exa\tmple").is_err());
        // Pure alnum method — accepted.
        assert!(Did::new("did:webvh:example").is_ok());
        assert!(Did::new("did:web:host.example/path").is_ok());
        assert!(Did::new("did:web:host.example/path#frag").is_err());
        assert!(Did::new("did:web:host.example/path?versionId=1").is_err());
    }

    #[test]
    fn device_id_accepts_protocol_device_forms() {
        assert!(DeviceId::new("dev_alice_1").is_err());
        assert!(DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(DeviceId::new("device-1").is_err());
        // Mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(DeviceId::new("ck:device:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn active_id_kind_wrappers_accept_uuidv7_wire_forms() {
        macro_rules! assert_id {
            ($ty:ty, $prefix:literal) => {{
                let value = format!("{}01904100-0000-7000-8000-000000000001", $prefix);
                assert!(<$ty>::new(value).is_ok(), "{}", stringify!($ty));
            }};
        }

        assert_id!(ActorProfileId, "ck:actor_profile:");
        assert_id!(AgentSessionId, "ck:agent_session:");
        assert_id!(AgentKeyId, "ck:agent_key:");
        assert_id!(AgentDraftId, "ck:agent_draft:");
        assert_id!(AccountabilityGrantId, "ck:accountability_grant:");
        assert_id!(SidecarCircleId, "ck:sidecar_circle:");
        assert_id!(BackupSeriesId, "ck:backup_series:");
        assert_id!(RecoverySessionId, "ck:recovery_session:");
        assert_id!(AnnounceId, "ck:announce:");
        assert_id!(AppletId, "ck:applet:");
        assert_id!(BackupId, "ck:backup:");
        assert_id!(BatchId, "ck:batch:");
        assert_id!(BlobId, "ck:blob:");
        assert_id!(BlockId, "ck:block:");
        assert_id!(CallId, "ck:call:");
        assert_id!(CapabilityId, "ck:capability:");
        assert_id!(ChunkId, "ck:chunk:");
        assert_id!(ClaimId, "ck:claim:");
        assert_id!(DeviceId, "ck:device:");
        assert_id!(DeviceMessageId, "ck:device_message:");
        assert_id!(EventId, "ck:event:");
        assert_id!(FilterId, "ck:filter:");
        assert_id!(FlowId, "ck:flow:");
        assert_id!(FrameId, "ck:frame:");
        assert_id!(FrankingProofId, "ck:franking_proof:");
        assert_id!(GrantId, "ck:grant:");
        assert_id!(InviteId, "ck:invite:");
        assert_id!(KeyEventId, "ck:key_event:");
        assert_id!(MessageId, "ck:message:");
        assert_id!(ModerationQueueItemId, "ck:moderation_queue_item:");
        assert_id!(MorphId, "ck:morph:");
        assert_id!(NotificationId, "ck:notification:");
        assert_id!(RealmId, "ck:realm:");
        assert_id!(PolicyId, "ck:policy:");
        assert_id!(PresentationId, "ck:presentation:");
        assert_id!(ReceiptId, "ck:receipt:");
        assert_id!(RelationId, "ck:relation:");
        assert_id!(ReportId, "ck:report:");
        assert_id!(ReadCursorId, "ck:read_cursor:");
        assert_id!(RequestId, "ck:request:");
        assert_id!(SnapshotId, "ck:snapshot:");
        // RealmId is the merged boundary-key type: it accepts both the
        // canonical `ck:realm:*` form (asserted above) and the historical
        // `ck:space:*` boundary mirror.
        assert_id!(RealmId, "ck:space:");
        assert_id!(TransactionId, "ck:transaction:");
        assert_id!(ViewId, "ck:view:");
    }

    #[test]
    fn hash_and_content_addressed_ids_accept_registry_algorithms() {
        let digest64 = "0".repeat(64);
        let digest128 = "0".repeat(128);

        assert!(Hash::new(format!("sha256:{digest64}")).is_ok());
        assert!(Hash::new(format!("sha3_256:{digest64}")).is_ok());
        assert!(Hash::new(format!("blake3:{digest64}")).is_ok());
        assert!(Hash::new(format!("sha512:{digest128}")).is_ok());
        assert!(BlobRef::new(format!("ck:blob:sha3_256:{digest64}")).is_ok());
        // event_digest (C47 / spec e10b6ad): bare hash, no `ck:move:` prefix.
        assert!(MoveId::new(format!("blake3:{digest64}")).is_ok());
        assert!(MoveId::new(format!("sha256:{digest64}")).is_ok());
        assert!(MoveId::new(format!("sha512:{digest128}")).is_ok());
        assert!(AnchorId::new(format!("ck:anchor:sha512:{digest128}")).is_ok());
    }

    #[test]
    fn flow_id_accepts_active_flow_prefix() {
        assert!(FlowId::new("ck:flow:01904100-0000-7000-8000-000000000001").is_ok());
        assert!(FlowId::new("ck:space:01904100-0000-7000-8000-000000000001").is_err());
        // Mixed-case ULID-form rejected by the strict UUIDv7 validator.
        // (Suffix intentionally non-UUIDv7 to exercise the rejection path.)
        assert!(FlowId::new("ck:flow:01js0ke000000000000000000").is_err());
    }

    #[test]
    fn new_prefixed_uuid7_produces_strict_typed_id() {
        // C19.B: helper for newly-issued Cokret wire ids.
        let id = new_prefixed_uuid7("ck:space:");
        assert!(is_strict_typed_id(&id, "ck:space:"));
        // Two consecutive calls produce different ids.
        let id2 = new_prefixed_uuid7("ck:space:");
        assert_ne!(id, id2);
        // Resulting id is accepted by the RealmId boundary-key validator
        // (which accepts the `ck:space:*` mirror form).
        assert!(RealmId::new(id).is_ok());
    }

    #[test]
    fn is_strict_typed_id_rejects_ulid_and_bad_uuid_payloads() {
        // C19 wire-break: typed wire ids MUST be canonical lowercase UUIDv7.
        // Mixed-case ULID-form is rejected (intentionally non-UUIDv7).
        assert!(!is_strict_typed_id("ck:space:01js0ke000000000000000000", "ck:space:"));
        // Uppercase hex forbidden.
        assert!(!is_strict_typed_id("ck:space:0196419B-0000-7000-8000-000000000000", "ck:space:"));
        // Wrong UUID version (4 instead of 7).
        assert!(!is_strict_typed_id("ck:space:0196419b-0000-4000-8000-000000000000", "ck:space:"));
        // Wrong variant nibble (c not in {8,9,a,b}).
        assert!(!is_strict_typed_id("ck:space:0196419b-0000-7000-c000-000000000000", "ck:space:"));
        // Canonical UUIDv7 accepted.
        assert!(is_strict_typed_id("ck:space:0196419b-0000-7000-8000-000000000000", "ck:space:"));
    }

    #[test]
    fn serde_deserialization_validates_identifier_values() {
        #[derive(Deserialize)]
        struct Envelope {
            space_id: RealmId,
            hlc: Hlc,
        }

        let valid: Envelope = serde_json::from_value(serde_json::json!({
            "space_id": "ck:space:01904100-0000-7000-8000-000000000001",
            "hlc": "01970e589d21-0004-a13f9c2e",
        }))
        .unwrap();
        assert_eq!(valid.space_id.as_str(), "ck:space:01904100-0000-7000-8000-000000000001");
        assert_eq!(valid.hlc.as_str(), "01970e589d21-0004-a13f9c2e");

        let invalid_id = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "space-01",
            "hlc": "01970e589d21-0004-a13f9c2e",
        }));
        assert!(invalid_id.is_err());

        let invalid_hlc = serde_json::from_value::<Envelope>(serde_json::json!({
            "space_id": "ck:space:01904100-0000-7000-8000-000000000001",
            "hlc": "1970",
        }));
        assert!(invalid_hlc.is_err());
    }
}
