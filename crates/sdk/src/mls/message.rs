use serde::{Deserialize, Serialize};

use super::group::{CokretMlsGroup, decode};
use super::security::AadVisibility;
use crate::{EncryptedPayload, EncryptedPayloadScheme, Error, Hash, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

/// Structured AAD for `ck.schema.encrypted_envelope.v1`. `realm_id` +
/// `event_kind` are mandatory; the event-id fields are governed by
/// [`AadVisibility`] and the schema discriminator (a `hidden` envelope MUST
/// omit both `event_id` and `event_ref_digest`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// `key_ref` for `ck.schema.encrypted_envelope.v1`. `algorithm` is the fixed
/// const `"MLS"`; `group_state_ref` MUST point at an accepted
/// `ck.mls.genesis` / winning `ck.mls.commit` event id (or equivalent group
/// state proof hash).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeKeyRefV1 {
    pub algorithm: String,
    pub group_state_ref: String,
}

/// Wire-canonical encrypted payload envelope matching
/// `ck.schema.encrypted_envelope.v1` — the single source of truth for the
/// encrypted-message wire shape across produce / validate / consume. Build it
/// from an [`EncryptedPayload`] (the MLS encrypt primitive output) plus the
/// caller-supplied AAD context and the `ck.mls.commit` event id that bounds
/// the group state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Fixed `key_ref.algorithm` const required by the schema.
    pub const KEY_REF_ALGORITHM: &'static str = "MLS";

    /// Assemble a conforming envelope from an MLS [`EncryptedPayload`].
    ///
    /// The `payload` MUST have been produced by
    /// [`CokretMlsGroup::encrypt_payload_with_aad`] with AAD equal to
    /// `serde_json::to_value(&aad)` — the AAD is bound into `payload_digest`,
    /// so a mismatch would make the receiver's digest verification fail. We
    /// fail closed if they disagree. `group_state_ref` is the `ck.mls.commit`
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
        Ok(Self {
            scheme: payload.scheme.clone(),
            version: Self::VERSION.to_owned(),
            group_id: payload.group_id.clone(),
            epoch: payload.epoch,
            content_type: payload.content_type.clone(),
            ciphertext: payload.ciphertext.clone(),
            aad_visibility_event_id: visibility,
            aad,
            key_ref: EnvelopeKeyRefV1 {
                algorithm: Self::KEY_REF_ALGORITHM.to_owned(),
                group_state_ref: group_state_ref.into(),
            },
            aad_digest,
            payload_digest: payload.payload_digest.as_str().to_owned(),
        })
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
            key_ref: Some(cokret_core::KeyRefObject::mls_rfc9420(
                self.group_id.clone(),
                self.epoch,
            )),
        })
    }
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
        group: &mut CokretMlsGroup,
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
        group: &mut CokretMlsGroup,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        aad: serde_json::Value,
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

    pub fn decrypt(group: &mut CokretMlsGroup, message: &EncryptedMessage) -> Result<Vec<u8>> {
        Self::verify_opaque_payload_digest(message)?;
        group.decrypt_payload(&message.payload)
    }

    pub fn decrypt_or_preserve(
        group: Option<&mut CokretMlsGroup>,
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
