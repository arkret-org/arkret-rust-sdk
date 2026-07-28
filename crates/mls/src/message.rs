use arkret_models_crypto::{
    EncryptedEnvelope, EncryptedEnvelopeAad, EncryptedEnvelopeAadVisibility,
    EncryptedEnvelopeGroupStateRef, EncryptedEnvelopeKeyAlgorithm, EncryptedEnvelopeKeyRef,
    EncryptedPayload,
};
use arkret_wire::{EncryptedPayloadScheme, EventId, Hash};
use serde::{Deserialize, Serialize};

use crate::group::{ArkretMlsGroup, decode};
use crate::{MlsError as Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

pub use arkret_models_crypto::parse_and_validate_encrypted_envelope;

pub fn encrypted_envelope_from_payload(
    payload: &EncryptedPayload,
    aad: EncryptedEnvelopeAad,
    visibility: EncryptedEnvelopeAadVisibility,
    group_state_ref: impl Into<String>,
) -> Result<EncryptedEnvelope> {
    if payload.aad.as_ref() != Some(&aad) {
        return Err(Error::Protocol(
            "encrypted envelope aad does not match the aad bound at encryption time".to_owned(),
        ));
    }
    let group_state_ref = group_state_ref.into();
    let group_state_ref = match EventId::new(group_state_ref.clone()) {
        Ok(event_id) => EncryptedEnvelopeGroupStateRef::Event(event_id),
        Err(_) => EncryptedEnvelopeGroupStateRef::Digest(Hash::new(group_state_ref)?),
    };
    let algorithm = match payload.scheme {
        EncryptedPayloadScheme::MlsRfc9420 => EncryptedEnvelopeKeyAlgorithm::Mls,
        EncryptedPayloadScheme::MlsExporterAeadV1 => EncryptedEnvelopeKeyAlgorithm::MlsExporterAead,
    };
    let envelope = EncryptedEnvelope {
        scheme: payload.scheme.clone(),
        version: "1.0".to_owned(),
        group_id: payload.group_id.clone(),
        epoch: payload.epoch,
        content_type: payload.content_type.clone(),
        ciphertext: payload.ciphertext.clone(),
        aad_visibility_event_id: visibility,
        aad_digest: Hash::new(arkret_crypto::envelope_aad_digest(&aad)?)?,
        aad,
        key_ref: EncryptedEnvelopeKeyRef {
            algorithm,
            group_state_ref,
        },
        // Carried through rather than re-derived: the payload was produced by
        // the group that knows its own ciphersuite, and re-deriving here would
        // let the envelope disagree with the bytes it describes.
        purpose: payload.purpose.clone(),
        aead_profile: payload.aead_profile.clone(),
        payload_digest: payload.payload_digest.clone(),
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn encrypted_envelope_to_payload(envelope: &EncryptedEnvelope) -> Result<EncryptedPayload> {
    envelope.validate()?;
    Ok(EncryptedPayload {
        scheme: envelope.scheme.clone(),
        group_id: envelope.group_id.clone(),
        epoch: envelope.epoch,
        content_type: envelope.content_type.clone(),
        ciphertext: envelope.ciphertext.clone(),
        aad: Some(envelope.aad.clone()),
        purpose: envelope.purpose.clone(),
        aead_profile: envelope.aead_profile.clone(),
        payload_digest: envelope.payload_digest.clone(),
        key_ref: Some(match &envelope.scheme {
            EncryptedPayloadScheme::MlsRfc9420 => arkret_models_crypto::KeyRefObject::mls_rfc9420(
                envelope.group_id.clone(),
                envelope.epoch,
            ),
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                arkret_models_crypto::KeyRefObject::mls_exporter_aead(
                    envelope.group_id.clone(),
                    envelope.epoch,
                )
            }
        }),
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
        payload: Box<EncryptedPayload>,
        reason: MessageCryptoUnavailable,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoUnavailable {
    NoSession,
    Removed,
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
        aad: EncryptedEnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload_with_aad(content_type, Some(aad), plaintext)?,
        })
    }

    pub fn verify_opaque_payload_digest(message: &EncryptedMessage) -> Result<()> {
        let ciphertext_bytes = decode(&message.payload.ciphertext)?;
        message
            .payload
            .verify_mls_payload_digest(&ciphertext_bytes)
            .map_err(Into::into)
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
            let aad = serde_json::to_value(aad)?;
            let actual = arkret_crypto::json_aad_digest(&aad)?;
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
                payload: Box::new(message.payload),
                reason: MessageCryptoUnavailable::NoSession,
            });
        };

        if message.payload.group_id != group.group_id() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: Box::new(message.payload.clone()),
                reason: MessageCryptoUnavailable::WrongGroup {
                    expected: group.group_id(),
                    actual: message.payload.group_id,
                },
            });
        }
        if !group.is_active() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: Box::new(message.payload),
                reason: MessageCryptoUnavailable::Removed,
            });
        }
        if message.payload.epoch > group.epoch() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: Box::new(message.payload.clone()),
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
                payload: Box::new(message.payload),
                reason: MessageCryptoUnavailable::KeyUnavailable(error.to_string()),
            }),
        }
    }
}
