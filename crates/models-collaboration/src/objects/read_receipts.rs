//! Read-cursor, read-receipt, and notification wire shapes.

use std::collections::BTreeMap;
use std::fmt;

use arkret_wire::{
    AccountId, ActorId, BlobRef, DeviceId, EventId, Hlc, MessageId, MorphId, NotificationId,
    NotificationKind, NotificationPriority, NotificationProjectionId, NotificationState,
    OpaqueLocalId, OrdinaryNotificationKind, ReadCursorScope, RealmId, RelationId, Result,
    SchemaId, StrandId, ViewId, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The identity branches have disjoint lexical spaces and authority contracts.
///
/// Deserialization selects the branch from the `ak:` prefix rather than trying
/// each variant in turn: the two branches carry different authority (a
/// deterministic projection token the recipient recomputes, versus an
/// account-private approval UUID), so a first-variant-that-parses match would
/// silently reclassify a malformed token instead of rejecting it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NotificationIdentity {
    Projection(NotificationProjectionId),
    AgentApproval(NotificationId),
}

impl<'de> Deserialize<'de> for NotificationIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl NotificationIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.starts_with(NotificationProjectionId::KIND_PREFIX) {
            Ok(Self::Projection(NotificationProjectionId::new(value)?))
        } else {
            Ok(Self::AgentApproval(NotificationId::new(value)?))
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Projection(id) => id.as_str(),
            Self::AgentApproval(id) => id.as_str(),
        }
    }
}

impl From<NotificationId> for NotificationIdentity {
    fn from(id: NotificationId) -> Self {
        Self::AgentApproval(id)
    }
}

impl From<NotificationProjectionId> for NotificationIdentity {
    fn from(id: NotificationProjectionId) -> Self {
        Self::Projection(id)
    }
}

impl fmt::Display for NotificationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Derive an ordinary notification identity from immutable, verified inputs.
/// Callers must separately authenticate the source and authorize its display.
///
/// This is the identity recomputation every recipient owes an account-subscribe
/// ordinary notification row: the preimage is the registered
/// `notification.schema.json#/$defs/projection_preimage`, the domain separator
/// is `ak.notification-projection.v1` followed by LF, the body is RFC 8785 JCS,
/// and the token is the SHA-256 suite byte `0x01` followed by the complete
/// 32-byte digest, base64url without padding.
pub fn derive_notification_projection_id(
    recipient_account_id: &AccountId,
    realm_id: &RealmId,
    source_event_id: &EventId,
    notification_kind: OrdinaryNotificationKind,
) -> Result<NotificationProjectionId> {
    recipient_account_id.validate()?;
    #[derive(Serialize)]
    struct Preimage<'a> {
        recipient_account_id: &'a AccountId,
        realm_id: &'a RealmId,
        source_event_id: &'a EventId,
        notification_kind: OrdinaryNotificationKind,
    }
    let preimage = Preimage {
        recipient_account_id,
        realm_id,
        source_event_id,
        notification_kind,
    };
    let mut bytes = b"ak.notification-projection.v1\n".to_vec();
    bytes.extend_from_slice(&canonical::canonical_json_bytes(&preimage)?);
    Ok(NotificationProjectionId::from_projection_digest(
        canonical::sha256_bytes(bytes),
    ))
}

/// `notification.schema.json#/properties/track_name`: a Strand track key on the
/// source Strand. Shared by the full Notification object and by the ordinary
/// account-subscribe projection row so both reject the same values.
fn validate_notification_track_name(track_name: &str) -> Result<()> {
    if track_name.is_empty()
        || track_name.len() > 64
        || !track_name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || index > 0 && (byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(WireError::Protocol(
            "notification track_name is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Actor-private read cursor payload of `ak.read_cursor.advance`.
///
/// The object carries neither a typed `id` nor an `updated_at`
/// (private-objects.md §2.3, read-receipts.md §6.1). A cursor is never
/// updated in place (no revision / CAS): its identity is the
/// `(actor_id, realm_id, read_scope)` tuple, one "update" is a freshly
/// authored advance Event, and the time of that update is that Event envelope
/// `created_at`. There is no `read_cursor` typed id kind in the id-kind
/// registry and no id-addressed read surface. Derived views that need a time —
/// `ReadMarkerOutcome` and account-subscribe private projections take
/// `updated_at` from the accepted advance envelope, never from this payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `read-cursor.schema.json`.
pub struct ReadCursor {
    pub schema: String,
    pub actor_id: ActorId,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
}

impl ReadCursor {
    pub const SCHEMA: &'static str = SchemaId::READ_CURSOR_V1;
    /// Deserialize an inbound read cursor after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }
}

/// The position one read cursor stands at.
///
/// `read-cursor.schema.json#/$defs/position` carries exactly the Event
/// identity plus the authoring HLC. It is a single point on the actor's own
/// stream, not a set: the multi-device merge rule below compares two positions
/// by causal reachability between those two Event ids, and the HLC is a
/// tie-break input only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// Field declaration order is byte-for-byte the `properties` order of
// `read-cursor.schema.json#/$defs/position`.
pub struct ReadCursorPosition {
    pub event_id: EventId,
    pub hlc: Hlc,
}

/// Causal relationship between an incoming cursor position and the currently
/// stored position.
///
/// The caller decides this from the Event closure it has actually acquired;
/// HLC MUST NOT be used to guess an unknown relationship
/// (`zh/discovery/read-receipts.md` §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadCursorCausalRelation {
    CandidateDominatesCurrent,
    CurrentDominatesCandidate,
    Concurrent,
    Undecidable,
}

/// Result of the normative causal-first read cursor merge.
#[derive(Clone, Copy, Debug)]
pub struct ReadCursorMerge<'a> {
    pub winner: &'a ReadCursor,
    /// `true` means the acquired causal closure was not enough to decide.
    /// The winner is the preserved current position and MUST NOT be persisted
    /// or reported as final (`zh/conformance/encoding.md` §7.3).
    pub provisional: bool,
}

/// Merge two cursors for the same `(actor_id, realm_id, read_scope)`.
///
/// `zh/discovery/read-receipts.md` §6.5 fixes the three stages: causal
/// dominance wins regardless of HLC; only causally concurrent positions
/// compare HLC; only equal HLCs compare `device_id`. An undecidable closure
/// preserves the current cursor provisionally rather than letting HLC decide.
pub fn merge_read_cursors<'a>(
    current: &'a ReadCursor,
    candidate: &'a ReadCursor,
    relation: ReadCursorCausalRelation,
) -> Result<ReadCursorMerge<'a>> {
    if current.actor_id != candidate.actor_id
        || current.realm_id != candidate.realm_id
        || current.read_scope != candidate.read_scope
    {
        return Err(WireError::Protocol(
            "read cursor merge requires identical actor_id, realm_id, and read_scope".to_owned(),
        ));
    }

    let (winner, provisional) = match relation {
        ReadCursorCausalRelation::CandidateDominatesCurrent => (candidate, false),
        ReadCursorCausalRelation::CurrentDominatesCandidate => (current, false),
        ReadCursorCausalRelation::Concurrent => {
            let order = arkret_wire::hlc::compare_hlc(
                candidate.position.hlc.as_str(),
                current.position.hlc.as_str(),
            )?;
            let winner = match order {
                std::cmp::Ordering::Greater => candidate,
                std::cmp::Ordering::Less => current,
                std::cmp::Ordering::Equal => {
                    if candidate.device_id.as_str() > current.device_id.as_str() {
                        candidate
                    } else {
                        current
                    }
                }
            };
            (winner, false)
        }
        ReadCursorCausalRelation::Undecidable => (current, true),
    };
    Ok(ReadCursorMerge {
        winner,
        provisional,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadCursorAdvanceRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub advance_event: arkret_wire::EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// Field declaration order is byte-for-byte the `properties` order of
// `read-cursor-operations.schema.json#/$defs/read_marker_outcome`.
pub struct ReadMarkerOutcome {
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub device_id: DeviceId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadCursorList {
    #[serde(default)]
    pub markers: Vec<ReadMarkerOutcome>,
}

#[cfg(test)]
mod read_cursor_tests {
    use serde_json::json;

    use super::*;

    const EVENT_A: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EVENT_B: &str = "ak:event:Abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn position_value(event_id: &str, hlc: &str) -> Value {
        json!({ "event_id": event_id, "hlc": hlc })
    }

    fn cursor(device_suffix: u32, event_id: &str, hlc: &str) -> ReadCursor {
        serde_json::from_value(json!({
            "schema": ReadCursor::SCHEMA,
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "device_id": format!("ak:device:01964137-0000-7000-8000-{device_suffix:012x}"),
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "read_scope": {"kind": "realm"},
            "position": position_value(event_id, hlc)
        }))
        .unwrap()
    }

    #[test]
    fn position_round_trips_through_canonical_json() {
        let value = position_value(EVENT_A, "01970e589d21-0001-a13f9c2e");
        let decoded: ReadCursorPosition = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.event_id.as_str(), EVENT_A);
        assert_eq!(decoded.hlc.as_str(), "01970e589d21-0001-a13f9c2e");
        assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
    }

    #[test]
    fn position_rejects_a_member_outside_the_closed_field_set() {
        let mut value = position_value(EVENT_A, "01970e589d21-0001-a13f9c2e");
        value["stream_position"] = json!(7);
        assert!(serde_json::from_value::<ReadCursorPosition>(value).is_err());
    }

    #[test]
    fn position_rejects_an_omitted_required_member() {
        assert!(
            serde_json::from_value::<ReadCursorPosition>(json!({ "event_id": EVENT_A })).is_err()
        );
        assert!(
            serde_json::from_value::<ReadCursorPosition>(
                json!({ "hlc": "01970e589d21-0001-a13f9c2e" })
            )
            .is_err()
        );
    }

    #[test]
    fn causal_dominance_wins_regardless_of_hlc() {
        let current = cursor(1, EVENT_A, "01970e589d21-0002-a13f9c2e");
        let candidate = cursor(2, EVENT_B, "01970e589d21-0001-a13f9c2e");
        let merged = merge_read_cursors(
            &current,
            &candidate,
            ReadCursorCausalRelation::CandidateDominatesCurrent,
        )
        .unwrap();
        assert_eq!(merged.winner.position.event_id, candidate.position.event_id);
        assert!(!merged.provisional);

        let merged = merge_read_cursors(
            &current,
            &candidate,
            ReadCursorCausalRelation::CurrentDominatesCandidate,
        )
        .unwrap();
        assert_eq!(merged.winner.position.event_id, current.position.event_id);
        assert!(!merged.provisional);
    }

    #[test]
    fn concurrent_positions_compare_hlc_then_device_id() {
        let current = cursor(1, EVENT_A, "01970e589d21-0001-a13f9c2e");
        let higher_hlc = cursor(2, EVENT_B, "01970e589d21-0002-a13f9c2e");
        assert_eq!(
            merge_read_cursors(&current, &higher_hlc, ReadCursorCausalRelation::Concurrent)
                .unwrap()
                .winner
                .device_id,
            higher_hlc.device_id
        );

        let equal_hlc_higher_device = cursor(2, EVENT_B, "01970e589d21-0001-a13f9c2e");
        assert_eq!(
            merge_read_cursors(
                &current,
                &equal_hlc_higher_device,
                ReadCursorCausalRelation::Concurrent
            )
            .unwrap()
            .winner
            .device_id,
            equal_hlc_higher_device.device_id
        );
    }

    #[test]
    fn undecidable_closure_preserves_the_current_position_provisionally() {
        let current = cursor(1, EVENT_A, "01970e589d21-0001-a13f9c2e");
        let candidate = cursor(2, EVENT_B, "01970e589d21-0002-a13f9c2e");
        let merged =
            merge_read_cursors(&current, &candidate, ReadCursorCausalRelation::Undecidable)
                .unwrap();
        assert_eq!(merged.winner.position.event_id, current.position.event_id);
        assert!(merged.provisional);
    }

    #[test]
    fn merge_rejects_two_cursors_from_different_scopes() {
        let current = cursor(1, EVENT_A, "01970e589d21-0001-a13f9c2e");
        let mut other = cursor(2, EVENT_B, "01970e589d21-0002-a13f9c2e");
        other.realm_id =
            RealmId::new("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5").unwrap();
        assert!(
            merge_read_cursors(&current, &other, ReadCursorCausalRelation::Concurrent).is_err()
        );
    }

    #[test]
    fn read_marker_outcome_round_trips_and_rejects_unknown_members() {
        let value = json!({
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
            "read_scope": {"kind": "realm"},
            "position": position_value(EVENT_A, "01970e589d21-0001-a13f9c2e"),
            "updated_at": "2026-08-15T00:00:00.000Z"
        });
        let decoded: ReadMarkerOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.position.event_id.as_str(), EVENT_A);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), value);

        let mut unknown = value.clone();
        unknown["stream_position"] = json!(3);
        assert!(serde_json::from_value::<ReadMarkerOutcome>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("position");
        assert!(serde_json::from_value::<ReadMarkerOutcome>(missing).is_err());
    }
}

/// `ak.receipt.read` is a Signal plaintext profile, not a durable object, so
/// its type lives with the rest of the Signal plaintext family. Re-exported
/// here because the read-receipt policy types it is governed by are in this
/// module.
pub use crate::signal_plaintext::ReadReceipt;

/// Whether compliant clients generate read receipts for a Realm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadReceiptDisclosure {
    Required,
    #[default]
    Optional,
    Disabled,
}

/// Audience allowed to receive read receipts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadReceiptVisibility {
    Public,
    #[default]
    Members,
    Private,
}

impl ReadReceiptVisibility {
    fn privacy_rank(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Members => 1,
            Self::Private => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptPolicy {
    #[serde(default)]
    pub disclosure: ReadReceiptDisclosure,
    #[serde(default)]
    pub visibility: ReadReceiptVisibility,
    #[serde(default = "default_read_receipt_scope_overrides_allowed")]
    pub scope_overrides_allowed: bool,
    #[serde(default)]
    pub child_privacy_tightening_against_required: bool,
}

impl Default for ReadReceiptPolicy {
    fn default() -> Self {
        Self {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Members,
            scope_overrides_allowed: true,
            child_privacy_tightening_against_required: false,
        }
    }
}

fn default_read_receipt_scope_overrides_allowed() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadReceiptPolicyChildViolation {
    ScopeOverridesDisabled,
    DisclosurePrivacyLoosened,
    ComplianceFloorViolated,
    VisibilityLoosened,
}

impl fmt::Display for ReadReceiptPolicyChildViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopeOverridesDisabled => {
                formatter.write_str("child read-receipt policy must inherit parent exactly")
            }
            Self::DisclosurePrivacyLoosened => {
                formatter.write_str("child read-receipt disclosure loosens parent privacy")
            }
            Self::ComplianceFloorViolated => {
                formatter.write_str("child read-receipt policy crosses parent compliance floor")
            }
            Self::VisibilityLoosened => {
                formatter.write_str("child read-receipt visibility loosens parent visibility")
            }
        }
    }
}

impl std::error::Error for ReadReceiptPolicyChildViolation {}

impl ReadReceiptPolicy {
    pub fn validate_child_policy(
        &self,
        child: &ReadReceiptPolicy,
    ) -> std::result::Result<(), ReadReceiptPolicyChildViolation> {
        if !self.scope_overrides_allowed && child != self {
            return Err(ReadReceiptPolicyChildViolation::ScopeOverridesDisabled);
        }
        self.validate_child_disclosure(child.disclosure)?;
        self.validate_child_visibility(child.visibility)
    }

    fn validate_child_disclosure(
        &self,
        child: ReadReceiptDisclosure,
    ) -> std::result::Result<(), ReadReceiptPolicyChildViolation> {
        match (self.disclosure, child) {
            (ReadReceiptDisclosure::Required, ReadReceiptDisclosure::Required)
            | (ReadReceiptDisclosure::Optional, ReadReceiptDisclosure::Optional)
            | (ReadReceiptDisclosure::Optional, ReadReceiptDisclosure::Disabled)
            | (ReadReceiptDisclosure::Disabled, ReadReceiptDisclosure::Disabled) => Ok(()),
            (
                ReadReceiptDisclosure::Required,
                ReadReceiptDisclosure::Optional | ReadReceiptDisclosure::Disabled,
            ) if self.child_privacy_tightening_against_required => Ok(()),
            (
                ReadReceiptDisclosure::Required,
                ReadReceiptDisclosure::Optional | ReadReceiptDisclosure::Disabled,
            ) => Err(ReadReceiptPolicyChildViolation::ComplianceFloorViolated),
            _ => Err(ReadReceiptPolicyChildViolation::DisclosurePrivacyLoosened),
        }
    }

    fn validate_child_visibility(
        &self,
        child: ReadReceiptVisibility,
    ) -> std::result::Result<(), ReadReceiptPolicyChildViolation> {
        if child.privacy_rank() >= self.visibility.privacy_rank() {
            Ok(())
        } else {
            Err(ReadReceiptPolicyChildViolation::VisibilityLoosened)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationSchema {
    #[serde(rename = "ak.schema.notification.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationAccountArtifactKind {
    AgentRuntimeApproval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAccountArtifact {
    pub kind: NotificationAccountArtifactKind,
    pub id: OpaqueLocalId,
}

/// Closed union for `notification.schema.json#/properties/source_ref`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct NotificationBlobRef(BlobRef);

impl NotificationBlobRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !value.starts_with("ak:blob:") {
            return Err(WireError::Protocol(
                "notification Blob reference must use the ak:blob: prefix".to_owned(),
            ));
        }
        BlobRef::new(value).map(Self).map_err(WireError::from)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for NotificationBlobRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Closed union for `notification.schema.json#/properties/source_ref`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotificationSourceRef {
    Message(MessageId),
    Strand(StrandId),
    Morph(MorphId),
    Relation(RelationId),
    View(ViewId),
    Blob(NotificationBlobRef),
}

impl NotificationSourceRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.starts_with("ak:message:") {
            MessageId::new(value)
                .map(Self::Message)
                .map_err(WireError::from)
        } else if value.starts_with("ak:strand:") {
            StrandId::new(value)
                .map(Self::Strand)
                .map_err(WireError::from)
        } else if value.starts_with("ak:morph:") {
            MorphId::new(value)
                .map(Self::Morph)
                .map_err(WireError::from)
        } else if value.starts_with("ak:relation:") {
            RelationId::new(value)
                .map(Self::Relation)
                .map_err(WireError::from)
        } else if value.starts_with("ak:view:") {
            ViewId::new(value).map(Self::View).map_err(WireError::from)
        } else if value.starts_with("ak:blob:") {
            NotificationBlobRef::new(value).map(Self::Blob)
        } else {
            Err(WireError::Protocol(
                "notification source_ref has an unsupported object kind".to_owned(),
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Message(value) => value.as_str(),
            Self::Strand(value) => value.as_str(),
            Self::Morph(value) => value.as_str(),
            Self::Relation(value) => value.as_str(),
            Self::View(value) => value.as_str(),
            Self::Blob(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEventSource {
    pub source_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<NotificationSourceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAccountArtifactSource {
    pub source_account_artifact: NotificationAccountArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotificationSource {
    Event(NotificationEventSource),
    AccountArtifact(NotificationAccountArtifactSource),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NotificationWire")]
pub struct Notification {
    pub id: NotificationIdentity,
    pub schema: NotificationSchema,
    pub actor_id: ActorId,
    #[serde(flatten)]
    pub source: NotificationSource,
    pub notification_kind: NotificationKind,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<BTreeMap<String, Value>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationWire {
    id: NotificationIdentity,
    schema: NotificationSchema,
    actor_id: ActorId,
    #[serde(default)]
    source_event_id: Option<EventId>,
    #[serde(default)]
    realm_id: Option<RealmId>,
    #[serde(default)]
    source_ref: Option<NotificationSourceRef>,
    #[serde(default)]
    strand_id: Option<StrandId>,
    #[serde(default)]
    track_name: Option<String>,
    #[serde(default)]
    source_account_artifact: Option<NotificationAccountArtifact>,
    notification_kind: NotificationKind,
    priority: NotificationPriority,
    state: NotificationState,
    #[serde(default)]
    preview: Option<BTreeMap<String, Value>>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    updated_at: Option<DateTime<Utc>>,
}

impl TryFrom<NotificationWire> for Notification {
    type Error = WireError;

    fn try_from(wire: NotificationWire) -> Result<Self> {
        let source = match (wire.source_event_id, wire.source_account_artifact) {
            (Some(source_event_id), None) => NotificationSource::Event(NotificationEventSource {
                source_event_id,
                realm_id: wire.realm_id,
                source_ref: wire.source_ref,
                strand_id: wire.strand_id,
                track_name: wire.track_name,
            }),
            (None, Some(source_account_artifact))
                if wire.realm_id.is_none()
                    && wire.source_ref.is_none()
                    && wire.strand_id.is_none()
                    && wire.track_name.is_none() =>
            {
                NotificationSource::AccountArtifact(NotificationAccountArtifactSource {
                    source_account_artifact,
                })
            }
            _ => {
                return Err(WireError::Protocol(
                    "notification must contain exactly one valid source branch".to_owned(),
                ));
            }
        };
        let notification = Self {
            id: wire.id,
            schema: wire.schema,
            actor_id: wire.actor_id,
            source,
            notification_kind: wire.notification_kind,
            priority: wire.priority,
            state: wire.state,
            preview: wire.preview,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        notification.validate()?;
        Ok(notification)
    }
}

impl Notification {
    pub const SCHEMA: &'static str = SchemaId::NOTIFICATION_V1;
    pub fn validate(&self) -> Result<()> {
        match &self.source {
            NotificationSource::Event(source) => {
                let recipient = self.actor_id.as_account_id().ok_or_else(|| {
                    WireError::Protocol("notification recipient must be an AccountId".to_owned())
                })?;
                let realm = source.realm_id.as_ref().ok_or_else(|| {
                    WireError::Protocol("event notification requires its source Realm".to_owned())
                })?;
                let expected = derive_notification_projection_id(
                    recipient,
                    realm,
                    &source.source_event_id,
                    OrdinaryNotificationKind::try_from(&self.notification_kind)?,
                )?;
                if self.id != NotificationIdentity::Projection(expected) {
                    return Err(WireError::Protocol(
                        "notification identity does not bind its source inputs".to_owned(),
                    ));
                }
                if let Some(track_name) = source.track_name.as_deref() {
                    validate_notification_track_name(track_name)?;
                }
            }
            NotificationSource::AccountArtifact(_) => {
                if self.notification_kind != NotificationKind::Agent
                    || !matches!(self.id, NotificationIdentity::AgentApproval(_))
                {
                    return Err(WireError::Protocol(
                        "notification account artifact source is invalid".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Counterpart for
/// `notification.schema.json#/$defs/ordinary_projection_content`: the current
/// content of one ordinary source-Event notification projection as it is
/// delivered on the account-subscribe `notifications` channel.
///
/// Four members of [`Notification`] are deliberately absent, and the absence is
/// the contract, not an omission: `id` is carried by the delta row, `schema` is
/// implied by the channel, `actor_id` is the authenticated account, and `state`
/// stays in the holder-private inbox
/// (`ak.notifications.inbox.<notification_id>` plus the read cursor). A Station
/// that put any of them on this row would be publishing a second source of
/// truth for inbox disposition. [`Self::into_notification`] is the only way
/// back to a full object, and it takes those four from the receiver's own
/// state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdinaryProjectionContent {
    pub realm_id: RealmId,
    pub source_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<NotificationSourceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<String>,
    pub notification_kind: OrdinaryNotificationKind,
    pub priority: NotificationPriority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<BTreeMap<String, Value>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl OrdinaryProjectionContent {
    pub fn validate(&self) -> Result<()> {
        if let Some(track_name) = self.track_name.as_deref() {
            validate_notification_track_name(track_name)?;
        }
        Ok(())
    }

    /// Recompute the deterministic projection identity this row must carry.
    ///
    /// The recipient is the authenticated account, never a wire field, so a
    /// Station cannot hand a client a row addressed to somebody else.
    pub fn derive_id(&self, recipient_account_id: &AccountId) -> Result<NotificationProjectionId> {
        derive_notification_projection_id(
            recipient_account_id,
            &self.realm_id,
            &self.source_event_id,
            self.notification_kind,
        )
    }

    /// Compare the recomputed identity against the delivered row id byte for
    /// byte. A mismatch means the row is discarded, not repaired.
    pub fn verify_id(
        &self,
        recipient_account_id: &AccountId,
        delivered_id: &NotificationProjectionId,
    ) -> Result<()> {
        self.validate()?;
        if &self.derive_id(recipient_account_id)? != delivered_id {
            return Err(WireError::Protocol(
                "ordinary notification row id does not bind its own projection inputs".to_owned(),
            ));
        }
        Ok(())
    }

    /// Rebuild the display-side [`Notification`] from this row plus the four
    /// members the wire deliberately does not carry.
    pub fn into_notification(
        self,
        recipient_account_id: &AccountId,
        delivered_id: NotificationProjectionId,
        state: NotificationState,
    ) -> Result<Notification> {
        self.verify_id(recipient_account_id, &delivered_id)?;
        let notification = Notification {
            id: NotificationIdentity::Projection(delivered_id),
            schema: NotificationSchema::V1,
            actor_id: ActorId::account(recipient_account_id.clone()),
            source: NotificationSource::Event(NotificationEventSource {
                source_event_id: self.source_event_id,
                realm_id: Some(self.realm_id),
                source_ref: self.source_ref,
                strand_id: self.strand_id,
                track_name: self.track_name,
            }),
            notification_kind: self.notification_kind.into(),
            priority: self.priority,
            state,
            preview: self.preview,
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        notification.validate()?;
        Ok(notification)
    }
}

/// Inbox state a client may synchronize cross-device under
/// `ak.notifications.inbox.<notification_id>`.
///
/// Deliberately narrower than [`NotificationState`]: `read` / `unread` stay
/// derived from the read cursor and MUST NOT be written to this key
/// (`zh/discovery/client-preferences.md` §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationInboxState {
    Dismissed,
    Archived,
}

impl From<NotificationInboxState> for NotificationState {
    fn from(state: NotificationInboxState) -> Self {
        match state {
            NotificationInboxState::Dismissed => Self::Dismissed,
            NotificationInboxState::Archived => Self::Archived,
        }
    }
}

/// Plaintext behind the encrypted `ak.notifications.inbox.<notification_id>`
/// account-data value.
///
/// The registry stores this key as a causal register, so concurrent devices
/// converge by re-reading and re-merging rather than by server-side ordering;
/// [`NotificationInboxValue::compare_precedence`] is that merge rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationInboxValue {
    pub notification_id: NotificationIdentity,
    pub state: NotificationInboxState,
    pub updated_hlc: Hlc,
    pub origin_device_id: DeviceId,
}

impl NotificationInboxValue {
    /// Decode a stored value and enforce the spec's binding between the
    /// account-data key and the value it carries. A value whose
    /// `notification_id` disagrees with its key is rejected rather than
    /// silently re-keyed.
    pub fn from_account_data(account_data_key: &str, value: &Value) -> Result<Self> {
        let notification_id =
            crate::events_payloads::notification_inbox_account_data_key_notification_id(
                account_data_key,
            )
            .ok_or_else(|| {
                WireError::Protocol(
                    "notification inbox key must be ak.notifications.inbox.<notification_id>"
                        .to_owned(),
                )
            })?;
        let decoded: Self = serde_json::from_value(value.clone())
            .map_err(|error| WireError::Protocol(format!("notification inbox value: {error}")))?;
        if decoded.notification_id != notification_id {
            return Err(WireError::Protocol(
                "notification inbox value must bind its own account-data key".to_owned(),
            ));
        }
        Ok(decoded)
    }

    /// Account-data key this value belongs under.
    pub fn account_data_key(&self) -> String {
        crate::events_payloads::notification_inbox_account_data_key(&self.notification_id)
    }

    /// Merge order for two writes to the same notification: HLC first, then a
    /// deterministic `device_id` tie-break so every device elects the same
    /// winner without further coordination.
    pub fn compare_precedence(&self, other: &Self) -> Result<std::cmp::Ordering> {
        if self.notification_id != other.notification_id {
            return Err(WireError::Protocol(
                "notification inbox merge requires the same notification_id".to_owned(),
            ));
        }
        match arkret_wire::hlc::compare_hlc(self.updated_hlc.as_str(), other.updated_hlc.as_str())?
        {
            std::cmp::Ordering::Equal => Ok(self
                .origin_device_id
                .as_str()
                .cmp(other.origin_device_id.as_str())),
            other => Ok(other),
        }
    }
}
