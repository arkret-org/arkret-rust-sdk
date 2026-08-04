//! Encrypted blob attachment key descriptors for `blob.schema.json`.
//!
//! Blob operation DTOs stay in the `arkret` umbrella; this module owns the
//! encryption/key-reference half of the blob artifact.

use arkret_wire::{Base64UrlString, BlobRef, EventId, Hash};
use serde::{Deserialize, Serialize};

/// Counterpart for
/// `spec/v1/artifacts/schemas/blob.schema.json#/properties/encryption/properties/key_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedAttachmentKeyAlgorithm {
    #[serde(rename = "MLS")]
    Mls,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedAttachmentGroupStateRef {
    Event(EventId),
    Digest(Hash),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WholeFileEncryptionScheme {
    #[serde(rename = "ak.blob.whole_file_aead.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WholeFileEncryptionAlgorithm {
    MlsExporterAeadXchacha20poly1305,
    #[serde(rename = "mls_exporter_aead_aes_256_gcm")]
    MlsExporterAeadAes256Gcm,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WholeFileEncryptedAttachment {
    pub blob_ref: BlobRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub encrypted: EncryptedAttachmentMarker,
    pub scheme: WholeFileEncryptionScheme,
    pub encryption_algorithm: WholeFileEncryptionAlgorithm,
    pub key_ref: EncryptedAttachmentKeyRef,
    pub epoch: u64,
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    pub nonce: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamEncryptionScheme {
    #[serde(rename = "ak.blob.stream_aead.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamEncryptionAlgorithm {
    MlsExporterAeadXchacha20poly1305Stream,
    #[serde(rename = "mls_exporter_aead_aes_256_gcm_stream")]
    MlsExporterAeadAes256GcmStream,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEncryptedAttachment {
    pub blob_ref: BlobRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
    pub encrypted: EncryptedAttachmentMarker,
    pub scheme: StreamEncryptionScheme,
    pub encryption_algorithm: StreamEncryptionAlgorithm,
    pub key_ref: EncryptedAttachmentKeyRef,
    pub epoch: u64,
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    pub nonce_prefix: Base64UrlString,
    pub segment_bytes: u64,
    pub segment_count: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedAttachment {
    WholeFile(WholeFileEncryptedAttachment),
    Stream(StreamEncryptedAttachment),
}
