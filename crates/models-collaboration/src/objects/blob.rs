//! Blob object and upload-receipt wire shapes.

pub use arkret_models_crypto::encrypted_attachment::{
    EncryptedAttachment, EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyAlgorithm,
    EncryptedAttachmentKeyRef, EncryptedAttachmentMarker, StreamEncryptedAttachment,
    StreamEncryptionAlgorithm, StreamEncryptionScheme, WholeFileEncryptedAttachment,
    WholeFileEncryptionAlgorithm, WholeFileEncryptionScheme,
};
use arkret_wire::{BlobId, BlobRef, Did, Hash, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/media_type`.
pub type MediaType = String;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/upload_receipt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SignatureValue {
    pub kid: Did,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct UploadReceipt {
    pub blob_ref: BlobRef,
    pub content_digest: Hash,
    pub size_bytes: u64,
    pub received_at: DateTime<Utc>,
    pub issuer_service_id: Did,
    pub signature: SignatureValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub blob_ref: BlobId,
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub content_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptedAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_blob_ref: Option<BlobId>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}
