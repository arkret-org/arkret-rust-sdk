//! Blob object and upload-receipt wire shapes.

pub use arkret_models_crypto::encrypted_attachment::{
    EncryptedAttachment, EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyAlgorithm,
    EncryptedAttachmentKeyRef, EncryptedAttachmentMarker, StreamEncryptedAttachment,
    StreamEncryptionAlgorithm, StreamEncryptionScheme, WholeFileEncryptedAttachment,
    WholeFileEncryptionAlgorithm, WholeFileEncryptionScheme,
};
use arkret_wire::{ActorId, BlobId, BlobRef, DidCoreId, Hash, RealmId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobStorageEncryptionScheme {
    #[serde(rename = "ak.blob.whole_file_aead.v1")]
    WholeFileV1,
    #[serde(rename = "ak.blob.stream_aead.v1")]
    StreamV1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobStorageEncryption {
    pub scheme: BlobStorageEncryptionScheme,
}

fn deserialize_storage_encryption<'de, D>(
    deserializer: D,
) -> Result<Option<BlobStorageEncryption>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<BlobStorageEncryption>::deserialize(deserializer)
}

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
    pub blob_id: BlobId,
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub content_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(deserialize_with = "deserialize_storage_encryption")]
    pub encryption: Option<BlobStorageEncryption>,
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
#[serde(deny_unknown_fields)]
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
    #[serde(deserialize_with = "deserialize_storage_encryption")]
    pub encryption: Option<BlobStorageEncryption>,
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
mod storage_encryption_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn upload_requires_explicit_storage_classification() {
        let mut body = json!({"size_bytes": 3});
        assert!(serde_json::from_value::<BlobUploadMetadata>(body.clone()).is_err());
        body["encryption"] = serde_json::Value::Null;
        let metadata: BlobUploadMetadata = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(metadata).unwrap()["encryption"],
            json!(null)
        );
        for scheme in ["ak.blob.whole_file_aead.v1", "ak.blob.stream_aead.v1"] {
            body["encryption"] = json!({"scheme": scheme});
            assert!(serde_json::from_value::<BlobUploadMetadata>(body.clone()).is_ok());
        }
        for invalid in [
            json!({"scheme": "unknown"}),
            json!({"scheme": "ak.blob.stream_aead.v1", "key_ref": "private"}),
        ] {
            body["encryption"] = invalid;
            assert!(serde_json::from_value::<BlobUploadMetadata>(body.clone()).is_err());
        }
        body["encryption"] = json!(null);
        body["purpose"] = json!("file_transfer");
        assert!(serde_json::from_value::<BlobUploadMetadata>(body).is_err());
    }
}
