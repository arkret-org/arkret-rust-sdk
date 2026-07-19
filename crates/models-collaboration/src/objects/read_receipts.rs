//! Read-cursor, read-receipt, notification, and blob-metadata wire shapes.

use std::collections::BTreeMap;

use arkret_models_crypto::encrypted_attachment::EncryptedAttachment;
use arkret_wire::{
    BlobRef, DeviceId, Did, EventId, Hlc, NotificationPriority, NotificationState,
    NotificationType, ReadCursorId, ReadCursorScope, ReadReceiptScope, RealmId, Result, StrandId,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursor {
    pub id: ReadCursorId,
    pub schema: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    pub updated_at: DateTime<Utc>,
}

impl ReadCursor {
    /// Deserialize an inbound read cursor after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursorPosition {
    pub event_id: EventId,
    pub hlc: Hlc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursorAdvanceRequestBody {
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadMarkerOutcome {
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursorList {
    #[serde(default)]
    pub markers: Vec<ReadMarkerOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadReceipt {
    pub receipt_type: String,
    pub schema: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    pub read_scope: ReadReceiptScope,
    pub created_at: DateTime<Utc>,
}

impl ReadReceipt {
    /// Deserialize an inbound read receipt after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct Notification {
    pub schema: String,
    pub id: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    pub source_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    pub notification_type: NotificationType,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<BTreeMap<String, Value>>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct BlobMetadata {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub blob_ref: BlobRef,
    pub content_digest: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub encryption: Option<EncryptedAttachment>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}
