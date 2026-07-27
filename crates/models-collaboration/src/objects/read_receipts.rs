//! Read-cursor, read-receipt, and notification wire shapes.

use std::collections::BTreeMap;
use std::fmt;

use arkret_wire::{
    BlobRef, DeviceId, Did, Error, EventId, Hlc, MessageId, MorphId, NotificationId,
    NotificationKind, NotificationPriority, NotificationState, OpaqueLocalId, ReadCursorId,
    ReadCursorScope, ReadReceiptScope, RealmId, RelationId, Result, StrandId, ViewId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCursor {
    pub id: ReadCursorId,
    pub schema: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub updated_at: DateTime<Utc>,
}

impl ReadCursor {
    /// Deserialize an inbound read cursor after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadCursorPosition {
    pub event_id: EventId,
    pub hlc: Hlc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadCursorAdvanceRequestBody {
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadMarkerOutcome {
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadCursorList {
    #[serde(default)]
    pub markers: Vec<ReadMarkerOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceipt {
    pub receipt_kind: String,
    pub schema: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    pub read_scope: ReadReceiptScope,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

impl ReadReceipt {
    /// Deserialize an inbound read receipt after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }
}

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

/// Typed value of the Realm read-receipt policy cell.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptComplianceOptIn {
    #[serde(default)]
    pub child_privacy_tightening_against_required: bool,
    #[serde(default)]
    pub public_receipts_on_world_readable: bool,
    #[serde(default)]
    pub forced_public_world_readable_receipts: bool,
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
    pub receipt_compliance_opt_in: ReadReceiptComplianceOptIn,
}

impl Default for ReadReceiptPolicy {
    fn default() -> Self {
        Self {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Members,
            scope_overrides_allowed: true,
            receipt_compliance_opt_in: ReadReceiptComplianceOptIn::default(),
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
            ) if self
                .receipt_compliance_opt_in
                .child_privacy_tightening_against_required =>
            {
                Ok(())
            }
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
            return Err(Error::Protocol(
                "notification Blob reference must use the ak:blob: prefix".to_owned(),
            ));
        }
        BlobRef::new(value).map(Self).map_err(Error::from)
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
                .map_err(Error::from)
        } else if value.starts_with("ak:strand:") {
            StrandId::new(value).map(Self::Strand).map_err(Error::from)
        } else if value.starts_with("ak:morph:") {
            MorphId::new(value).map(Self::Morph).map_err(Error::from)
        } else if value.starts_with("ak:relation:") {
            RelationId::new(value)
                .map(Self::Relation)
                .map_err(Error::from)
        } else if value.starts_with("ak:view:") {
            ViewId::new(value).map(Self::View).map_err(Error::from)
        } else if value.starts_with("ak:blob:") {
            NotificationBlobRef::new(value).map(Self::Blob)
        } else {
            Err(Error::Protocol(
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
    pub id: NotificationId,
    pub schema: NotificationSchema,
    pub actor_id: Did,
    #[serde(flatten)]
    pub source: NotificationSource,
    pub notification_kind: NotificationKind,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<BTreeMap<String, Value>>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationWire {
    id: NotificationId,
    schema: NotificationSchema,
    actor_id: Did,
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
    type Error = Error;

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
                return Err(Error::Protocol(
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
    pub fn validate(&self) -> Result<()> {
        match &self.source {
            NotificationSource::Event(source) => {
                if source.track_name.as_deref().is_some_and(|track| {
                    track.is_empty()
                        || track.len() > 64
                        || !track.bytes().enumerate().all(|(index, byte)| {
                            byte.is_ascii_lowercase()
                                || index > 0 && (byte.is_ascii_digit() || byte == b'_')
                        })
                }) {
                    return Err(Error::Protocol(
                        "notification track_name is invalid".to_owned(),
                    ));
                }
            }
            NotificationSource::AccountArtifact(_) => {
                if self.notification_kind != NotificationKind::Agent {
                    return Err(Error::Protocol(
                        "notification account artifact source is invalid".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod notification_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn notification_decodes_event_source_branch() {
        let notification = serde_json::from_value::<Notification>(json!({
            "id": "ak:notification:019fa233-5ab8-75c0-8497-376bafe172a4",
            "schema": "ak.schema.notification.v1",
            "actor_id": "did:web:alice.example",
            "realm_id": "ak:realm:019fa233-5ab8-75c0-8497-375d732be737",
            "source_event_id": "ak:event:019fa233-5ab8-75c0-8497-376bafe172a5",
            "source_ref": "ak:message:019fa233-5ab8-75c0-8497-376bafe172a7",
            "strand_id": "ak:strand:019fa233-5ab8-75c0-8497-376bafe172a6",
            "track_name": "discussion",
            "notification_kind": "message",
            "priority": "normal",
            "state": "unread",
            "created_at": "2026-07-27T14:37:51.000Z"
        }))
        .expect("event-sourced notification must decode");

        assert!(matches!(
            notification.source,
            NotificationSource::Event(NotificationEventSource {
                source_ref: Some(NotificationSourceRef::Message(_)),
                ..
            })
        ));
    }

    #[test]
    fn notification_rejects_untyped_source_ref() {
        assert!(
            serde_json::from_value::<Notification>(json!({
                "id": "ak:notification:019fa233-5ab8-75c0-8497-376bafe172a4",
                "schema": "ak.schema.notification.v1",
                "actor_id": "did:web:alice.example",
                "source_event_id": "ak:event:019fa233-5ab8-75c0-8497-376bafe172a5",
                "source_ref": "message-42",
                "notification_kind": "message",
                "priority": "normal",
                "state": "unread",
                "created_at": "2026-07-27T14:37:51.000Z"
            }))
            .is_err()
        );
    }

    #[test]
    fn notification_rejects_bare_blob_digest_source_ref() {
        assert!(
            serde_json::from_value::<Notification>(json!({
                "id": "ak:notification:019fa233-5ab8-75c0-8497-376bafe172a4",
                "schema": "ak.schema.notification.v1",
                "actor_id": "did:web:alice.example",
                "source_event_id": "ak:event:019fa233-5ab8-75c0-8497-376bafe172a5",
                "source_ref": format!("sha256:{}", "ab".repeat(32)),
                "notification_kind": "message",
                "priority": "normal",
                "state": "unread",
                "created_at": "2026-07-27T14:37:51.000Z"
            }))
            .is_err()
        );
    }

    #[test]
    fn notification_decodes_account_artifact_branch() {
        let notification = serde_json::from_value::<Notification>(json!({
            "id": "ak:notification:019fa233-5ab8-75c0-8497-376bafe172a4",
            "schema": "ak.schema.notification.v1",
            "actor_id": "did:web:alice.example",
            "source_account_artifact": {
                "kind": "agent_runtime_approval",
                "id": "agent_runtime_approval:019fa233-5ab8-75c0-8497-376bafe172a4"
            },
            "notification_kind": "agent",
            "priority": "normal",
            "state": "unread",
            "created_at": "2026-07-27T14:37:51.000Z"
        }))
        .expect("account-artifact notification must decode");

        assert!(matches!(
            notification.source,
            NotificationSource::AccountArtifact(_)
        ));
    }

    #[test]
    fn notification_rejects_non_agent_account_artifact() {
        assert!(
            serde_json::from_value::<Notification>(json!({
                "id": "ak:notification:019fa233-5ab8-75c0-8497-376bafe172a4",
                "schema": "ak.schema.notification.v1",
                "actor_id": "did:web:alice.example",
                "source_account_artifact": {
                    "kind": "agent_runtime_approval",
                    "id": "agent_runtime_approval:019fa233-5ab8-75c0-8497-376bafe172a4"
                },
                "notification_kind": "message",
                "priority": "normal",
                "state": "unread",
                "created_at": "2026-07-27T14:37:51.000Z"
            }))
            .is_err()
        );
    }
}
