//! Encrypted event envelope counterpart for `encrypted-envelope.schema.json`.
//!
//! The envelope is payload-agnostic: the ciphertext is opaque and the AAD
//! carries only routing metadata.

use arkret_canonical::canonical;
use arkret_wire::{EncryptedPayloadScheme, Error, EventId, Hash, RealmId, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Profile id whose Realms require the minimal-metadata MLS policy.
pub const MINIMAL_METADATA_REALM_PROFILE: &str = "ak.profile.mls.minimal_metadata_realm.v1";

/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedEnvelopeAadVisibility {
    Hidden,
    RoutingDigest,
    OpaqueId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedEnvelopeKeyAlgorithm {
    #[serde(rename = "MLS")]
    Mls,
    #[serde(rename = "MLS-EXPORTER-AEAD")]
    MlsExporterAead,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedEnvelopeGroupStateRef {
    Event(EventId),
    Digest(Hash),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeKeyRef {
    pub algorithm: EncryptedEnvelopeKeyAlgorithm,
    pub group_state_ref: EncryptedEnvelopeGroupStateRef,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
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

/// Decode and validate an encrypted envelope without initializing an MLS group machine.
pub fn parse_and_validate_encrypted_envelope(value: Value) -> Result<EncryptedEnvelope> {
    let envelope: EncryptedEnvelope = serde_json::from_value(value)
        .map_err(|error| Error::Protocol(format!("encrypted envelope schema: {error}")))?;
    envelope.validate()?;
    Ok(envelope)
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<EncryptedEnvelopeAad>,
    pub payload_digest: Hash,
    /// Reference to the key material that decrypts `ciphertext`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<KeyRefObject>,
}

/// Typed `key_ref` per `media-and-blob.md` §encrypted-payload (B-22).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRefObject {
    pub algorithm: String,
    pub group_state_ref: String,
}

impl KeyRefObject {
    /// Build an MLS-RFC9420 typed `key_ref` from a group id and epoch.
    pub fn mls_rfc9420(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: EncryptedPayloadScheme::MlsRfc9420.as_str().to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }

    /// Build an MLS-EXPORTER-AEAD typed `key_ref` (§2.10) from a group id and
    /// epoch. The `algorithm` token `MLS-EXPORTER-AEAD` is bound by the
    /// `encrypted-envelope.schema.json` if/then to `scheme=mls-exporter-aead-v1`.
    pub fn mls_exporter_aead(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: "MLS-EXPORTER-AEAD".to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        Self::payload_digest_for_scheme(
            EncryptedPayloadScheme::MlsRfc9420,
            epoch,
            content_type,
            aad,
            ciphertext_bytes,
        )
    }

    /// §2.3.3 content payload digest, parameterized by `scheme`. The digest binds
    /// the `scheme` token into the metadata (`encryption` field) so a payload
    /// authored under `mls-exporter-aead-v1` (§2.10) and one under `mls-rfc9420`
    /// never collide, and the receiver's verification is scheme-bound.
    /// `ciphertext_bytes` are the raw decoded ciphertext bytes (for
    /// `mls-exporter-aead-v1` that is the `nonce || AEAD_ct` blob).
    pub fn payload_digest_for_scheme(
        scheme: EncryptedPayloadScheme,
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: scheme.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::payload_digest_for_scheme(
            self.scheme.clone(),
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol(
                "encrypted payload digest mismatch".to_owned(),
            ))
        }
    }

    /// Validate that the key reference, when present, is usable for lookup.
    pub fn validate_key_ref(&self) -> Result<()> {
        if let Some(key_ref) = &self.key_ref
            && key_ref.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.algorithm must not be empty".to_owned(),
            ));
        }
        if let Some(key_ref) = &self.key_ref
            && key_ref.group_state_ref.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.group_state_ref must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EncryptedPayloadDigestMetadata<'a> {
    pub content_type: &'a str,
    pub encryption: &'a str,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<&'a EncryptedEnvelopeAad>,
}
