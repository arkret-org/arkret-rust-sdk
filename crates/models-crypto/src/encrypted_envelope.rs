//! Encrypted event envelope counterpart for `encrypted-envelope.schema.json`.
//!
//! The envelope is payload-agnostic: the ciphertext is opaque and the AAD
//! carries only routing metadata.

use arkret_wire::{EncryptedPayloadScheme, Error, EventId, Hash, RealmId, Result};
use serde::{Deserialize, Serialize};

/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeAad {
    pub realm_id: RealmId,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_refs: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_ref_digests: Option<Vec<Hash>>,
}

impl EncryptedEnvelopeAad {
    /// Build the minimal AAD allowed for hidden event-id visibility.
    pub fn hidden(realm_id: RealmId, event_kind: impl Into<String>) -> Self {
        Self {
            realm_id,
            event_kind: event_kind.into(),
            event_id: None,
            event_ref_digest: None,
            causal_refs: None,
            causal_ref_digests: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedEnvelopeAadVisibility {
    Hidden,
    RoutingDigest,
    OpaqueId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedEnvelopeKeyAlgorithm {
    #[serde(rename = "MLS")]
    Mls,
    #[serde(rename = "MLS-EXPORTER-AEAD")]
    MlsExporterAead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedEnvelopeGroupStateRef {
    Event(EventId),
    Digest(Hash),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeKeyRef {
    pub algorithm: EncryptedEnvelopeKeyAlgorithm,
    pub group_state_ref: EncryptedEnvelopeGroupStateRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub scheme: EncryptedPayloadScheme,
    pub version: String,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub aad_visibility_event_id: EncryptedEnvelopeAadVisibility,
    pub aad: EncryptedEnvelopeAad,
    pub key_ref: EncryptedEnvelopeKeyRef,
    pub payload_digest: Hash,
    pub aad_digest: Hash,
}

impl EncryptedEnvelope {
    pub fn validate(&self) -> Result<()> {
        if !major_minor_version(&self.version) {
            return Err(Error::Protocol(
                "encrypted envelope version must be major.minor".to_owned(),
            ));
        }
        if !base64url_token(&self.group_id) {
            return Err(Error::Protocol(
                "encrypted envelope group_id is invalid".to_owned(),
            ));
        }
        if !content_type_token(&self.content_type) {
            return Err(Error::Protocol(
                "encrypted envelope content_type is invalid".to_owned(),
            ));
        }
        if !base64url_token(&self.ciphertext) {
            return Err(Error::Protocol(
                "encrypted envelope ciphertext is invalid".to_owned(),
            ));
        }
        let expected_algorithm = match self.scheme {
            EncryptedPayloadScheme::MlsRfc9420 => EncryptedEnvelopeKeyAlgorithm::Mls,
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                EncryptedEnvelopeKeyAlgorithm::MlsExporterAead
            }
        };
        if self.key_ref.algorithm != expected_algorithm {
            return Err(Error::Protocol(
                "encrypted envelope key_ref.algorithm does not match scheme".to_owned(),
            ));
        }
        if self.aad.causal_refs.is_some() && self.aad.causal_ref_digests.is_some() {
            return Err(Error::Protocol(
                "encrypted envelope aad cannot carry both causal_refs and causal_ref_digests"
                    .to_owned(),
            ));
        }
        match self.aad_visibility_event_id {
            EncryptedEnvelopeAadVisibility::Hidden => {
                if self.aad.event_id.is_some() || self.aad.event_ref_digest.is_some() {
                    return Err(Error::Protocol(
                        "hidden encrypted envelope aad forbids event identifiers".to_owned(),
                    ));
                }
            }
            EncryptedEnvelopeAadVisibility::RoutingDigest => {
                if self.aad.event_ref_digest.is_none() || self.aad.event_id.is_some() {
                    return Err(Error::Protocol(
                        "routing_digest encrypted envelope aad requires event_ref_digest only"
                            .to_owned(),
                    ));
                }
            }
            EncryptedEnvelopeAadVisibility::OpaqueId => {
                if self.aad.event_id.is_none() || self.aad.event_ref_digest.is_some() {
                    return Err(Error::Protocol(
                        "opaque_id encrypted envelope aad requires event_id only".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `major.minor` numeric version token (e.g. `1.0`); both parts non-empty and
/// ASCII-digit only. Shared wire-token validator (reused by `arkret-sdk`).
pub fn major_minor_version(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
}

/// Non-empty base64url token (`[A-Za-z0-9_-]+`, no padding). Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// `type/subtype` content-type token with restricted byte alphabet. Shared
/// wire-token validator (reused by `arkret-sdk`).
pub fn content_type_token(value: &str) -> bool {
    let Some((ty, subtype)) = value.split_once('/') else {
        return false;
    };
    !ty.is_empty()
        && !subtype.is_empty()
        && ty.bytes().all(content_type_byte)
        && subtype.bytes().all(content_type_byte)
}

/// Admissible byte inside a [`content_type_token`] segment. Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn content_type_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'+' | b'-')
}
