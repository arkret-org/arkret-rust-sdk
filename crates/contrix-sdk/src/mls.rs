use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProcessedMessageContent, ProtocolVersion, RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::{
    DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, Hash, MlsCommitEnvelope,
    MlsKeyPackageRecord, MlsWelcomeEnvelope, Result, canonical,
};

pub const CONTRIX_MLS_ALGORITHM: &str = "cx.mls.v1";
pub const CONTRIX_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct ContrixMlsIdentity {
    pub principal_id: Did,
    pub device_id: DeviceId,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

pub struct ContrixMlsGroup {
    identity: ContrixMlsIdentity,
    group: MlsGroup,
}

#[derive(Clone, Debug)]
pub struct MlsAddMemberResult {
    pub commit: MlsCommitEnvelope,
    pub welcome: MlsWelcomeEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageCryptoUnavailable {
    NoSession,
    KeyUnavailable(String),
}

pub struct MessageCrypto;

impl MessageCrypto {
    pub fn encrypt(
        group: &mut ContrixMlsGroup,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload(content_type, plaintext)?,
        })
    }

    pub fn verify_opaque_payload_digest(message: &EncryptedMessage) -> Result<()> {
        let ciphertext_bytes = decode(&message.payload.ciphertext)?;
        message.payload.verify_mls_payload_digest(&ciphertext_bytes)
    }

    pub fn decrypt(
        group: &mut ContrixMlsGroup,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        Self::verify_opaque_payload_digest(message)?;
        group.decrypt_payload(&message.payload)
    }

    pub fn decrypt_or_preserve(
        group: Option<&mut ContrixMlsGroup>,
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

impl ContrixMlsIdentity {
    pub fn new_basic(principal_id: Did, device_id: DeviceId) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CONTRIX_MLS_CIPHERSUITE.signature_algorithm())
            .map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(principal_id.as_str().as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self { principal_id, device_id, provider, signer, credential })
    }

    pub fn key_package_record(&self) -> Result<MlsKeyPackageRecord> {
        let key_package = KeyPackage::builder()
            .build(CONTRIX_MLS_CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(mls_error)?;
        let key_package = key_package.key_package();
        let key_package_bytes = key_package.tls_serialize_detached().map_err(mls_error)?;
        let key_package_hash = Hash::new(canonical::sha256_digest(&key_package_bytes))?;

        Ok(MlsKeyPackageRecord {
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            key_package: encode(&key_package_bytes),
            key_package_hash,
            cipher_suites: vec![format!("{CONTRIX_MLS_CIPHERSUITE:?}")],
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            device_signature: None,
        })
    }

    pub fn create_group(self, group_id: impl AsRef<[u8]>) -> Result<ContrixMlsGroup> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CONTRIX_MLS_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id.as_ref()),
            self.credential.clone(),
        )
        .map_err(mls_error)?;

        Ok(ContrixMlsGroup { identity: self, group })
    }
}

impl ContrixMlsGroup {
    pub fn identity(&self) -> &ContrixMlsIdentity {
        &self.identity
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn group_id(&self) -> String {
        encode(self.group.group_id().as_slice())
    }

    pub fn ratchet_tree(&self) -> Result<String> {
        let bytes = self.group.export_ratchet_tree().tls_serialize_detached().map_err(mls_error)?;
        Ok(encode(&bytes))
    }

    pub fn add_member(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
    ) -> Result<MlsAddMemberResult> {
        if member_key_package.revoked {
            return Err(Error::Protocol("refusing to add revoked MLS KeyPackage".to_owned()));
        }

        let key_package = decode_key_package(&self.identity.provider, member_key_package)?;
        let (commit, welcome, _) = self
            .group
            .add_members(
                &self.identity.provider,
                &self.identity.signer,
                std::slice::from_ref(&key_package),
            )
            .map_err(mls_error)?;
        self.group.merge_pending_commit(&self.identity.provider).map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let welcome_bytes = welcome.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);

        Ok(MlsAddMemberResult {
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                commit: encode(&commit_bytes),
                commit_hash: Hash::new(canonical::sha256_digest(&commit_bytes))?,
                ratchet_tree: ratchet_tree.clone(),
            },
            welcome: MlsWelcomeEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                recipient_principal_id: member_key_package.principal_id.clone(),
                recipient_device_id: member_key_package.device_id.clone(),
                welcome: encode(&welcome_bytes),
                welcome_hash: Hash::new(canonical::sha256_digest(&welcome_bytes))?,
                ratchet_tree,
            },
        })
    }

    pub fn join_from_welcome(
        identity: ContrixMlsIdentity,
        envelope: &MlsWelcomeEnvelope,
    ) -> Result<Self> {
        if envelope.recipient_principal_id != identity.principal_id
            || envelope.recipient_device_id != identity.device_id
        {
            return Err(Error::Protocol(
                "MLS Welcome recipient does not match identity".to_owned(),
            ));
        }

        let welcome_bytes = decode(&envelope.welcome)?;
        let actual_welcome_hash = canonical::sha256_digest(&welcome_bytes);
        if actual_welcome_hash != envelope.welcome_hash.as_str() {
            return Err(Error::Protocol("MLS Welcome hash mismatch".to_owned()));
        }

        let message =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice()).map_err(mls_error)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::Protocol("MLS message is not a Welcome".to_owned()));
        };
        let ratchet_tree = match &envelope.ratchet_tree {
            Some(tree) => {
                let tree_bytes = decode(tree)?;
                Some(
                    RatchetTreeIn::tls_deserialize_exact(tree_bytes.as_slice())
                        .map_err(mls_error)?,
                )
            }
            None => None,
        };

        let group = StagedWelcome::new_from_welcome(
            &identity.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            ratchet_tree,
        )
        .map_err(mls_error)?
        .into_group(&identity.provider)
        .map_err(mls_error)?;

        Ok(Self { identity, group })
    }

    pub fn encrypt_payload(
        &mut self,
        content_type: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        let content_type = content_type.into();
        let message = self
            .group
            .create_message(&self.identity.provider, &self.identity.signer, plaintext)
            .map_err(mls_error)?;
        let message_bytes = message.tls_serialize_detached().map_err(mls_error)?;
        let epoch = self.epoch();
        let payload_digest =
            EncryptedPayload::mls_payload_digest(epoch, &content_type, None, &message_bytes)?;

        Ok(EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: self.group_id(),
            epoch,
            content_type,
            ciphertext: encode(&message_bytes),
            aad: None,
            payload_digest,
            key_ref: Some(format!("mls_epoch:{epoch}")),
        })
    }

    pub fn decrypt_payload(&mut self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        if payload.scheme != EncryptedPayloadScheme::MlsRfc9420 {
            return Err(Error::Protocol("encrypted payload is not MLS RFC 9420".to_owned()));
        }
        if payload.group_id != self.group_id() {
            return Err(Error::Protocol(
                "encrypted payload belongs to a different MLS group".to_owned(),
            ));
        }
        if payload.epoch > self.epoch() {
            return Err(Error::Protocol("MLS epoch is not available locally".to_owned()));
        }

        let message_bytes = decode(&payload.ciphertext)?;
        payload.verify_mls_payload_digest(&message_bytes)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(message_bytes.as_slice()).map_err(mls_error)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Protocol("MLS message is not a protocol message".to_owned()))?;
        let processed = self
            .group
            .process_message(&self.identity.provider, protocol_message)
            .map_err(mls_error)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.group
                    .merge_staged_commit(&self.identity.provider, *commit)
                    .map_err(mls_error)?;
                Err(Error::Protocol("expected MLS application message, got commit".to_owned()))
            }
            _ => Err(Error::Protocol("expected MLS application message".to_owned())),
        }
    }

    pub fn apply_commit(&mut self, envelope: &MlsCommitEnvelope) -> Result<u64> {
        let commit_bytes = decode(&envelope.commit)?;
        let actual_commit_hash = canonical::sha256_digest(&commit_bytes);
        if actual_commit_hash != envelope.commit_hash.as_str() {
            return Err(Error::Protocol("MLS Commit hash mismatch".to_owned()));
        }

        let message =
            MlsMessageIn::tls_deserialize_exact(commit_bytes.as_slice()).map_err(mls_error)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Protocol("MLS Commit is not a protocol message".to_owned()))?;
        let processed = self
            .group
            .process_message(&self.identity.provider, protocol_message)
            .map_err(mls_error)?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.group
                    .merge_staged_commit(&self.identity.provider, *commit)
                    .map_err(mls_error)?;
                Ok(self.epoch())
            }
            _ => Err(Error::Protocol("expected MLS Commit".to_owned())),
        }
    }
}

fn decode_key_package(
    provider: &OpenMlsRustCrypto,
    record: &MlsKeyPackageRecord,
) -> Result<KeyPackage> {
    let bytes = decode(&record.key_package)?;
    let actual_hash = canonical::sha256_digest(&bytes);
    if actual_hash != record.key_package_hash.as_str() {
        return Err(Error::Protocol("MLS KeyPackage hash mismatch".to_owned()));
    }

    let key_package_in =
        KeyPackageIn::tls_deserialize_exact(bytes.as_slice()).map_err(mls_error)?;
    key_package_in.validate(provider.crypto(), ProtocolVersion::Mls10).map_err(mls_error)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).map_err(|error| Error::Protocol(error.to_string()))
}

fn mls_error(error: impl std::fmt::Debug) -> Error {
    Error::Mls(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openmls_group_can_add_member_encrypt_and_decrypt() {
        let alice = ContrixMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("dev_alice_1").unwrap(),
        )
        .unwrap();
        let bob = ContrixMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("dev_bob_1").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice.create_group(b"cx:space:secure-board").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted =
            alice_group.encrypt_payload("application/json", br#"{"body":"hello"}"#).unwrap();
        let decrypted = bob_group.decrypt_payload(&encrypted).unwrap();

        assert_eq!(decrypted, br#"{"body":"hello"}"#);
        assert_eq!(encrypted.scheme, EncryptedPayloadScheme::MlsRfc9420);
        assert_eq!(encrypted.epoch, alice_group.epoch());
        assert_eq!(bob_group.epoch(), alice_group.epoch());
    }

    #[test]
    fn welcome_recipient_must_match_identity() {
        let alice = ContrixMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("dev_alice_1").unwrap(),
        )
        .unwrap();
        let bob = ContrixMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("dev_bob_1").unwrap(),
        )
        .unwrap();
        let mallory = ContrixMlsIdentity::new_basic(
            Did::new("did:web:mallory.example").unwrap(),
            DeviceId::new("dev_mallory_1").unwrap(),
        )
        .unwrap();

        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice.create_group(b"cx:space:secure-board").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(error) = ContrixMlsGroup::join_from_welcome(mallory, &add_result.welcome) else {
            panic!("Mallory should not be able to consume Bob's Welcome");
        };

        assert!(matches!(error, Error::Protocol(_)));
    }
}
