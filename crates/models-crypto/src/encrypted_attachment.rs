//! Encrypted blob attachment key descriptors for `blob.schema.json`.
//!
//! Blob operation DTOs stay in the `arkret` umbrella; this module owns the
//! encryption/key-reference half of the blob artifact.

use arkret_wire::{Base64UrlString, BlobRef, EventId, Hash};
use serde::{Deserialize, Serialize};

pub const MIN_SEGMENT_SIZE: u32 = 1024;
pub const MAX_SEGMENT_SIZE: u32 = 8_388_608;
pub const MAX_SEGMENT_COUNT: u32 = 1_048_576;

/// The shared stream geometry for attachment and file-transfer descriptors.
/// Compute without addition overflow, before allocating or deriving any key.
pub fn stream_segment_count(size_bytes: u64, segment_bytes: u32) -> arkret_wire::Result<u32> {
    if !(MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE).contains(&segment_bytes) {
        return Err(arkret_wire::WireError::Protocol(
            "schema_violation: segment_bounds_invalid: segment_bytes outside v1 bounds".into(),
        ));
    }
    let count = size_bytes.max(1).div_ceil(u64::from(segment_bytes));
    if count > u64::from(MAX_SEGMENT_COUNT) {
        return Err(arkret_wire::WireError::Protocol(
            "schema_violation: segment_bounds_invalid: derived segment count exceeds v1 limit"
                .into(),
        ));
    }
    Ok(count as u32)
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/blob.schema.json#/$defs/encrypted_attachment/properties/key_ref`.
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
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub media_type: String,
    pub nonce_prefix: Base64UrlString,
    pub segment_bytes: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedAttachment {
    WholeFile(WholeFileEncryptedAttachment),
    Stream(StreamEncryptedAttachment),
}

#[cfg(test)]
mod geometry_tests {
    use super::*;

    #[test]
    fn derives_empty_exact_boundary_and_maximum_without_overflow() {
        for (size, expected) in [(0, 1), (1, 1), (1024, 1), (1025, 2), (2048, 2)] {
            assert_eq!(stream_segment_count(size, 1024).unwrap(), expected);
        }
        let max = u64::from(MAX_SEGMENT_COUNT) * u64::from(MAX_SEGMENT_SIZE);
        assert_eq!(
            stream_segment_count(max, MAX_SEGMENT_SIZE).unwrap(),
            MAX_SEGMENT_COUNT
        );
        for size in [max + 1, u64::MAX] {
            assert!(stream_segment_count(size, MAX_SEGMENT_SIZE).is_err());
        }
        for size in [0, 1023, MAX_SEGMENT_SIZE + 1, u32::MAX] {
            assert!(stream_segment_count(0, size).is_err());
        }
    }
}
