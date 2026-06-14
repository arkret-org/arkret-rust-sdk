//! Blob schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlobOperations {
    BlobUploadRequestBody(crate::BlobUploadRequestBody),
    BlobUploadOutcome(BlobUploadOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/media_type`.
pub type MediaType = String;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/upload_receipt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureValue {
    pub kid: Did,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadReceipt {
    pub blob_ref: BlobId,
    pub content_digest: Hash,
    pub size_bytes: u64,
    pub received_at: DateTime<Utc>,
    pub issuer_service_did: Did,
    pub signature: SignatureValue,
}

/// Counterpart for `spec/v1/artifacts/schemas/blob.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedAttachmentKeyRef {
    pub algorithm: String,
    pub group_state_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedAttachment {
    pub blob_ref: BlobId,
    pub encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    pub alg: String,
    pub key_ref: EncryptedAttachmentKeyRef,
    pub epoch: u64,
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blob {
    pub blob_ref: BlobId,
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<Value>,
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
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
