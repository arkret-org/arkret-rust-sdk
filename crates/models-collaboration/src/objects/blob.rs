//! Blob object and upload-receipt wire shapes.

pub use arkret_models_crypto::encrypted_attachment::{
    EncryptedAttachment, EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyAlgorithm,
    EncryptedAttachmentKeyRef, EncryptedAttachmentMarker, StreamEncryptedAttachment,
    StreamEncryptionAlgorithm, StreamEncryptionScheme, WholeFileEncryptedAttachment,
    WholeFileEncryptionAlgorithm, WholeFileEncryptionScheme,
};
use arkret_wire::{ActorId, BlobRef, DidCoreId, Hash, RealmId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/upload_receipt`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureValue {
    pub kid: DidCoreId,
    pub signature_algorithm: String,
    pub sig: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadReceipt {
    pub blob_ref: BlobRef,
    pub content_digest: Hash,
    pub size_bytes: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: SignatureValue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub blob_ref: BlobRef,
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
    pub thumbnail_blob_ref: Option<BlobRef>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Blob {
    pub const SCHEMA: &'static str = SchemaId::BLOB_V1;
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobVisibility {
    Public,
    #[default]
    RealmBound,
    ActorPrivate,
    DeviceBound,
}

impl BlobVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::RealmBound => "realm_bound",
            Self::ActorPrivate => "actor_private",
            Self::DeviceBound => "device_bound",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobUploadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Hash>,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobUploadOutcome {
    pub blob_ref: BlobRef,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub content_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_receipt: Option<UploadReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignRequestBody {
    pub blob_ref: BlobRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignOutcome {
    pub url: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub nonce: String,
    pub access_scope: BlobPresignAccessScope,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignAccessScope {
    pub method: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_range: Option<[u64; 2]>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignPayload {
    pub scheme: String,
    pub blob_ref: BlobRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub purpose: String,
    pub nonce: String,
    pub access_scope: BlobPresignAccessScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience_hint: Option<DidCoreId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignDetachedJwsProof {
    pub kind: String,
    pub kid: String,
    pub jws: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignEnvelope {
    pub payload: BlobPresignPayload,
    pub proof: BlobPresignDetachedJwsProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_upload_outcome_rejects_unknown_fields() {
        let raw = serde_json::json!({
            "blob_ref": "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size_bytes": 1,
            "content_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unexpected": 42
        });
        let error = serde_json::from_value::<BlobUploadOutcome>(raw).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
