use arkret_models_crypto::{EncryptedEnvelope, EncryptedPayload, EventContentPreEncryptionHeader};
use arkret_wire::MlsGroupId;
use serde::{Deserialize, Serialize};

use crate::group::ArkretMlsGroup;
use crate::{MlsError as Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

pub use arkret_models_crypto::parse_and_validate_encrypted_envelope;

/// Assemble the encrypted envelope for an already-encrypted payload.
pub fn encrypted_envelope_from_payload(payload: &EncryptedPayload) -> Result<EncryptedEnvelope> {
    payload.to_envelope().map_err(Into::into)
}

/// Rebuild the internal decryption payload from a validated minimal envelope
/// and context already verified from the signed outer Event and exact winning
/// group state.
pub fn encrypted_envelope_to_payload_with_verified_header(
    envelope: &EncryptedEnvelope,
    header: EventContentPreEncryptionHeader,
) -> Result<EncryptedPayload> {
    envelope.validate()?;
    header.validate()?;
    let epoch = envelope.encryption_context.epoch();
    if header.envelope_version != envelope.version
        || header.content_type != envelope.content_type
        || header.epoch != epoch
        || &header.group_state_ref != envelope.encryption_context.group_state_ref()
    {
        return Err(Error::Protocol(
            "reconstructed pre-encryption header does not match the minimal envelope".to_owned(),
        ));
    }
    Ok(EncryptedPayload {
        scheme: header.scheme.clone(),
        group_id: header.mls_group_id.clone(),
        epoch,
        content_type: envelope.content_type.clone(),
        ciphertext: envelope.ciphertext.clone(),
        pre_encryption_header: header,
        payload_digest: envelope.payload_digest()?,
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
        expected: MlsGroupId,
        actual: MlsGroupId,
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
        header: EventContentPreEncryptionHeader,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload(header, plaintext)?,
        })
    }

    pub fn verify_opaque_payload_digest(message: &EncryptedMessage) -> Result<()> {
        message.payload.verify_payload_digest().map_err(Into::into)
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
