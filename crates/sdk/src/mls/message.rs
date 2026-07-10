use arkret_core::{base64url_token, content_type_token, major_minor_version};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::group::{ArkretMlsGroup, decode};
use super::security::AadVisibility;
use crate::{EncryptedPayload, EncryptedPayloadScheme, Error, EventId, Hash, RealmId, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

/// Structured AAD for `ak.schema.encrypted_envelope.v1`. `realm_id` +
/// `event_kind` are mandatory; the event-id fields are governed by
/// [`AadVisibility`] and the schema discriminator (a `hidden` envelope MUST
/// omit both `event_id` and `event_ref_digest`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeAadV1 {
    pub realm_id: String,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_ref_digests: Vec<String>,
}

impl EncryptedEnvelopeAadV1 {
    /// Minimal `hidden`-visibility AAD: realm + canonical event kind only.
    pub fn hidden(realm_id: impl Into<String>, event_kind: impl Into<String>) -> Self {
        Self {
            realm_id: realm_id.into(),
            event_kind: event_kind.into(),
            event_id: None,
            event_ref_digest: None,
            causal_refs: Vec::new(),
            causal_ref_digests: Vec::new(),
        }
    }
}

/// `key_ref` for `ak.schema.encrypted_envelope.v1`. `algorithm` is bound to
/// the envelope `scheme`; `group_state_ref` MUST point at an accepted
/// `ak.mls.genesis` / winning `ak.mls.commit` event id (or equivalent group
/// state proof hash).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeKeyRefV1 {
    pub algorithm: String,
    pub group_state_ref: String,
}

/// Wire-canonical encrypted payload envelope matching
/// `ak.schema.encrypted_envelope.v1` — the single source of truth for the
/// encrypted-message wire shape across produce / validate / consume. Build it
/// from an [`EncryptedPayload`] (the MLS encrypt primitive output) plus the
/// caller-supplied AAD context and the `ak.mls.commit` event id that bounds
/// the group state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeV1 {
    pub scheme: EncryptedPayloadScheme,
    pub version: String,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub aad_visibility_event_id: AadVisibility,
    pub aad: EncryptedEnvelopeAadV1,
    pub key_ref: EnvelopeKeyRefV1,
    pub aad_digest: String,
    pub payload_digest: String,
}

impl EncryptedEnvelopeV1 {
    /// Envelope format version (`^\d+\.\d+$`).
    pub const VERSION: &'static str = "1.0";

    pub fn key_ref_algorithm_for_scheme(scheme: &EncryptedPayloadScheme) -> &'static str {
        match scheme {
            EncryptedPayloadScheme::MlsRfc9420 => "MLS",
            EncryptedPayloadScheme::MlsExporterAeadV1 => "MLS-EXPORTER-AEAD",
        }
    }

    pub fn parse_and_validate(value: Value) -> Result<Self> {
        let envelope: Self = serde_json::from_value(value)
            .map_err(|err| Error::Protocol(format!("encrypted envelope schema: {err}")))?;
        envelope.validate_spec()?;
        Ok(envelope)
    }

    pub fn validate_spec(&self) -> Result<()> {
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
        if self.epoch > i64::MAX as u64 {
            return Err(Error::Protocol(
                "encrypted envelope epoch exceeds JSON schema integer range".to_owned(),
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
        validate_envelope_aad(&self.aad, self.aad_visibility_event_id)?;
        let expected_algorithm = Self::key_ref_algorithm_for_scheme(&self.scheme);
        if self.key_ref.algorithm != expected_algorithm {
            return Err(Error::Protocol(format!(
                "encrypted envelope key_ref.algorithm must be {expected_algorithm}"
            )));
        }
        if EventId::new(self.key_ref.group_state_ref.clone()).is_err()
            && Hash::new(self.key_ref.group_state_ref.clone()).is_err()
        {
            return Err(Error::Protocol(
                "encrypted envelope key_ref.group_state_ref is invalid".to_owned(),
            ));
        }
        Hash::new(self.aad_digest.clone())
            .map_err(|_| Error::Protocol("encrypted envelope aad_digest is invalid".to_owned()))?;
        Hash::new(self.payload_digest.clone()).map_err(|_| {
            Error::Protocol("encrypted envelope payload_digest is invalid".to_owned())
        })?;
        Ok(())
    }

    /// Assemble a conforming envelope from an MLS [`EncryptedPayload`].
    ///
    /// The `payload` MUST have been produced by
    /// [`ArkretMlsGroup::encrypt_payload_with_aad`] with AAD equal to
    /// `serde_json::to_value(&aad)` — the AAD is bound into `payload_digest`,
    /// so a mismatch would make the receiver's digest verification fail. We
    /// fail closed if they disagree. `group_state_ref` is the `ak.mls.commit`
    /// (or genesis) event id carrying the epoch this payload was encrypted
    /// under.
    pub fn from_payload(
        payload: &EncryptedPayload,
        aad: EncryptedEnvelopeAadV1,
        visibility: AadVisibility,
        group_state_ref: impl Into<String>,
    ) -> Result<Self> {
        let aad_value = serde_json::to_value(&aad)
            .map_err(|err| Error::Protocol(format!("encode envelope aad: {err}")))?;
        if payload.aad.as_ref() != Some(&aad_value) {
            return Err(Error::Protocol(
                "encrypted envelope aad does not match the aad bound at encryption time".to_owned(),
            ));
        }
        let aad_digest = crate::crypto::json_aad_digest(&aad_value)?;
        Self {
            scheme: payload.scheme.clone(),
            version: Self::VERSION.to_owned(),
            group_id: payload.group_id.clone(),
            epoch: payload.epoch,
            content_type: payload.content_type.clone(),
            ciphertext: payload.ciphertext.clone(),
            aad_visibility_event_id: visibility,
            aad,
            key_ref: EnvelopeKeyRefV1 {
                algorithm: Self::key_ref_algorithm_for_scheme(&payload.scheme).to_owned(),
                group_state_ref: group_state_ref.into(),
            },
            aad_digest,
            payload_digest: payload.payload_digest.as_str().to_owned(),
        }
        .validated()
    }

    /// Reconstruct the MLS [`EncryptedPayload`] needed to decrypt this
    /// envelope. The reconstructed AAD round-trips byte-identically with the
    /// AAD bound at encryption time, so `payload_digest` verification holds.
    pub fn to_payload(&self) -> Result<EncryptedPayload> {
        let aad_value = serde_json::to_value(&self.aad)
            .map_err(|err| Error::Protocol(format!("encode envelope aad: {err}")))?;
        Ok(EncryptedPayload {
            scheme: self.scheme.clone(),
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type.clone(),
            ciphertext: self.ciphertext.clone(),
            aad: Some(aad_value),
            payload_digest: Hash::new(self.payload_digest.clone())?,
            key_ref: Some(match &self.scheme {
                EncryptedPayloadScheme::MlsRfc9420 => {
                    arkret_core::KeyRefObject::mls_rfc9420(self.group_id.clone(), self.epoch)
                }
                EncryptedPayloadScheme::MlsExporterAeadV1 => {
                    arkret_core::KeyRefObject::mls_exporter_aead(self.group_id.clone(), self.epoch)
                }
            }),
        })
    }

    fn validated(self) -> Result<Self> {
        self.validate_spec()?;
        Ok(self)
    }
}

fn validate_envelope_aad(aad: &EncryptedEnvelopeAadV1, visibility: AadVisibility) -> Result<()> {
    RealmId::new(aad.realm_id.clone())
        .map_err(|_| Error::Protocol("encrypted envelope aad.realm_id is invalid".to_owned()))?;
    if !event_kind_token(&aad.event_kind) {
        return Err(Error::Protocol(
            "encrypted envelope aad.event_kind is invalid".to_owned(),
        ));
    }
    if let Some(event_id) = &aad.event_id {
        EventId::new(event_id.clone()).map_err(|_| {
            Error::Protocol("encrypted envelope aad.event_id is invalid".to_owned())
        })?;
    }
    if let Some(event_ref_digest) = &aad.event_ref_digest {
        Hash::new(event_ref_digest.clone()).map_err(|_| {
            Error::Protocol("encrypted envelope aad.event_ref_digest is invalid".to_owned())
        })?;
    }
    for event_id in &aad.causal_refs {
        EventId::new(event_id.clone()).map_err(|_| {
            Error::Protocol("encrypted envelope aad.causal_refs contains invalid id".to_owned())
        })?;
    }
    for digest in &aad.causal_ref_digests {
        Hash::new(digest.clone()).map_err(|_| {
            Error::Protocol(
                "encrypted envelope aad.causal_ref_digests contains invalid digest".to_owned(),
            )
        })?;
    }
    if aad.event_id.is_some() && aad.event_ref_digest.is_some() {
        return Err(Error::Protocol(
            "encrypted envelope aad must not carry both event_id and event_ref_digest".to_owned(),
        ));
    }
    if !aad.causal_refs.is_empty() && !aad.causal_ref_digests.is_empty() {
        return Err(Error::Protocol(
            "encrypted envelope aad must not carry both causal_refs and causal_ref_digests"
                .to_owned(),
        ));
    }
    match visibility {
        AadVisibility::Hidden => {
            if aad.event_id.is_some() || aad.event_ref_digest.is_some() {
                return Err(Error::Protocol(
                    "encrypted envelope hidden aad exposes event id".to_owned(),
                ));
            }
        }
        AadVisibility::RoutingDigest => {
            if aad.event_id.is_some() || aad.event_ref_digest.is_none() {
                return Err(Error::Protocol(
                    "encrypted envelope routing_digest aad requires only event_ref_digest"
                        .to_owned(),
                ));
            }
        }
        AadVisibility::OpaqueId => {
            if aad.event_ref_digest.is_some() || aad.event_id.is_none() {
                return Err(Error::Protocol(
                    "encrypted envelope opaque_id aad requires only event_id".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

// `major_minor_version`, `base64url_token`, `content_type_token` and
// `content_type_byte` are the shared wire-token validators reused from
// `arkret-core` (see `models::artifacts::event_wire`); only the
// MLS-specific `event_kind_token` lives here.
fn event_kind_token(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak.") else {
        return false;
    };
    !rest.is_empty()
        && rest.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoDecrypt {
    Plaintext {
        message_id: String,
        content_type: String,
        plaintext: Vec<u8>,
    },
    Encrypted {
        message_id: String,
        payload: EncryptedPayload,
        reason: MessageCryptoUnavailable,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoUnavailable {
    NoSession,
    WrongGroup {
        expected: String,
        actual: String,
    },
    EpochUnavailable {
        local_epoch: u64,
        required_epoch: u64,
    },
    KeyUnavailable(String),
}

pub struct MessageCrypto;

impl MessageCrypto {
    pub fn encrypt(
        group: &mut ArkretMlsGroup,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload(content_type, plaintext)?,
        })
    }

    pub fn encrypt_with_aad(
        group: &mut ArkretMlsGroup,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        aad: Value,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload_with_aad(content_type, Some(aad), plaintext)?,
        })
    }

    pub fn verify_opaque_payload_digest(message: &EncryptedMessage) -> Result<()> {
        let ciphertext_bytes = decode(&message.payload.ciphertext)?;
        message.payload.verify_mls_payload_digest(&ciphertext_bytes)
    }

    pub fn verify_payload_and_aad_digest(
        message: &EncryptedMessage,
        expected_aad_digest: Option<&str>,
    ) -> Result<()> {
        Self::verify_opaque_payload_digest(message)?;
        if let Some(expected) = expected_aad_digest {
            let aad =
                message.payload.aad.as_ref().ok_or_else(|| {
                    Error::Protocol("encrypted payload AAD is missing".to_owned())
                })?;
            let actual = crate::crypto::json_aad_digest(aad)?;
            if actual != expected {
                return Err(Error::Protocol(
                    "encrypted payload AAD digest mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn decrypt(group: &mut ArkretMlsGroup, message: &EncryptedMessage) -> Result<Vec<u8>> {
        Self::verify_opaque_payload_digest(message)?;
        group.decrypt_payload(&message.payload)
    }

    pub fn decrypt_or_preserve(
        group: Option<&mut ArkretMlsGroup>,
        message: EncryptedMessage,
    ) -> Result<MessageCryptoDecrypt> {
        Self::verify_opaque_payload_digest(&message)?;
        let message_id = message.message_id.clone();
        let content_type = message.payload.content_type.clone();

        let Some(group) = group else {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload,
                reason: MessageCryptoUnavailable::NoSession,
            });
        };

        if message.payload.group_id != group.group_id() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload.clone(),
                reason: MessageCryptoUnavailable::WrongGroup {
                    expected: group.group_id(),
                    actual: message.payload.group_id,
                },
            });
        }
        if message.payload.epoch > group.epoch() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload.clone(),
                reason: MessageCryptoUnavailable::EpochUnavailable {
                    local_epoch: group.epoch(),
                    required_epoch: message.payload.epoch,
                },
            });
        }

        match group.decrypt_payload(&message.payload) {
            Ok(plaintext) => Ok(MessageCryptoDecrypt::Plaintext {
                message_id,
                content_type,
                plaintext,
            }),
            Err(error) => Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload,
                reason: MessageCryptoUnavailable::KeyUnavailable(error.to_string()),
            }),
        }
    }
}
