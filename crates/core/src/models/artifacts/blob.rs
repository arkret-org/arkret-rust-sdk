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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SignatureValue {
    pub kid: Did,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct UploadReceipt {
    pub blob_ref: BlobRef,
    pub content_digest: Hash,
    pub size_bytes: u64,
    pub received_at: DateTime<Utc>,
    pub issuer_service_id: Did,
    pub signature: SignatureValue,
}

/// Counterpart for `spec/v1/artifacts/schemas/blob.schema.json#/properties/encryption/properties/key_ref`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedAttachmentKeyAlgorithm {
    #[serde(rename = "MLS")]
    Mls,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedAttachmentGroupStateRef {
    Event(EventId),
    Digest(Hash),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedAttachmentKeyRef {
    pub algorithm: EncryptedAttachmentKeyAlgorithm,
    pub group_state_ref: EncryptedAttachmentGroupStateRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedAttachmentMarker;

impl Serialize for EncryptedAttachmentMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for EncryptedAttachmentMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("encrypted must be true"))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WholeFileEncryptionScheme {
    #[serde(rename = "ak.blob.whole_file_aead.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WholeFileEncryptionAlgorithm {
    MlsExporterAeadXchacha20poly1305,
    MlsExporterAeadAes256Gcm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WholeFileEncryptedAttachment {
    pub blob_ref: BlobId,
    pub encrypted: EncryptedAttachmentMarker,
    pub scheme: WholeFileEncryptionScheme,
    pub alg: WholeFileEncryptionAlgorithm,
    pub key_ref: EncryptedAttachmentKeyRef,
    pub epoch: u64,
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    pub nonce: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamEncryptionScheme {
    #[serde(rename = "ak.blob.stream_aead.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamEncryptionAlgorithm {
    MlsExporterAeadXchacha20poly1305Stream,
    MlsExporterAeadAes256GcmStream,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEncryptedAttachment {
    pub blob_ref: BlobId,
    pub encrypted: EncryptedAttachmentMarker,
    pub scheme: StreamEncryptionScheme,
    pub alg: StreamEncryptionAlgorithm,
    pub key_ref: EncryptedAttachmentKeyRef,
    pub epoch: u64,
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    pub nonce_prefix: Base64UrlString,
    pub segment_size: u64,
    pub segment_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedAttachment {
    WholeFile(WholeFileEncryptedAttachment),
    Stream(StreamEncryptedAttachment),
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
