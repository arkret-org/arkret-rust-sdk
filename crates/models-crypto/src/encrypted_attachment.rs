//! Encrypted blob attachment key descriptors for `blob.schema.json`.
//!
//! Blob operation DTOs stay in the `arkret` umbrella; this module owns the
//! encryption/key-reference half of the blob artifact.

use arkret_wire::{Base64UrlString, BlobRef, EventId, Hash, ScopeRef};
use serde::{Deserialize, Serialize};

pub const MIN_SEGMENT_SIZE: u32 = 1024;
pub const MAX_SEGMENT_SIZE: u32 = 8_388_608;
pub const MAX_SEGMENT_COUNT: u32 = 1_048_576;

/// Public per-object randomness, never a secret or a storage key.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AttachmentContentKeySalt(String);

impl AttachmentContentKeySalt {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(arkret_canonical::base64url_encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AttachmentContentKeySalt {
    type Error = arkret_wire::WireError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = arkret_canonical::base64url_decode(&value)
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
        if bytes.len() != 32 || arkret_canonical::base64url_encode(&bytes) != value {
            return Err(arkret_wire::WireError::Protocol(
                "content_key_salt must encode exactly 32 canonical base64url octets".into(),
            ));
        }
        Ok(Self(value))
    }
}

impl From<AttachmentContentKeySalt> for String {
    fn from(value: AttachmentContentKeySalt) -> Self {
        value.0
    }
}

/// The exact resolved MLS-Exporter Context from media-and-blob section 3.0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentContentKeyContext {
    pub effective_scope: ScopeRef,
    pub genesis_event_ref: EventId,
    pub epoch: u64,
    pub scheme: String,
    pub encryption_algorithm: String,
    pub content_key_salt: AttachmentContentKeySalt,
}

impl AttachmentContentKeyContext {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.effective_scope.canonical_mls_group_id()?;
        let valid = match self.scheme.as_str() {
            "ak.blob.whole_file_aead.v1" => matches!(
                self.encryption_algorithm.as_str(),
                "mls_exporter_aead_xchacha20poly1305" | "mls_exporter_aead_aes_256_gcm"
            ),
            "ak.blob.stream_aead.v1" => matches!(
                self.encryption_algorithm.as_str(),
                "mls_exporter_aead_xchacha20poly1305_stream"
                    | "mls_exporter_aead_aes_256_gcm_stream"
            ),
            _ => false,
        };
        if !valid {
            return Err(arkret_wire::WireError::Protocol(
                "unsupported_attachment_scheme".into(),
            ));
        }
        Ok(())
    }
}

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

impl Default for WholeFileEncryptionScheme {
    fn default() -> Self {
        Self::V1
    }
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
    #[serde(default)]
    pub scheme: WholeFileEncryptionScheme,
    pub encryption_algorithm: WholeFileEncryptionAlgorithm,
    pub key_ref: EncryptedAttachmentKeyRef,
    pub content_key_salt: AttachmentContentKeySalt,
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
    pub content_key_salt: AttachmentContentKeySalt,
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

impl EncryptedAttachment {
    pub fn key_ref(&self) -> &EncryptedAttachmentKeyRef {
        match self {
            Self::WholeFile(value) => &value.key_ref,
            Self::Stream(value) => &value.key_ref,
        }
    }

    /// Coordinates must come from the same verified winning group state.
    pub fn content_key_context(
        &self,
        effective_scope: ScopeRef,
        genesis_event_ref: EventId,
        epoch: u64,
    ) -> AttachmentContentKeyContext {
        let (scheme, algorithm, salt) = match self {
            Self::WholeFile(value) => (
                "ak.blob.whole_file_aead.v1",
                match value.encryption_algorithm {
                    WholeFileEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305 => {
                        "mls_exporter_aead_xchacha20poly1305"
                    }
                    WholeFileEncryptionAlgorithm::MlsExporterAeadAes256Gcm => {
                        "mls_exporter_aead_aes_256_gcm"
                    }
                },
                &value.content_key_salt,
            ),
            Self::Stream(value) => (
                "ak.blob.stream_aead.v1",
                match value.encryption_algorithm {
                    StreamEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305Stream => {
                        "mls_exporter_aead_xchacha20poly1305_stream"
                    }
                    StreamEncryptionAlgorithm::MlsExporterAeadAes256GcmStream => {
                        "mls_exporter_aead_aes_256_gcm_stream"
                    }
                },
                &value.content_key_salt,
            ),
        };
        AttachmentContentKeyContext {
            effective_scope,
            genesis_event_ref,
            epoch,
            scheme: scheme.into(),
            encryption_algorithm: algorithm.into(),
            content_key_salt: salt.clone(),
        }
    }
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
