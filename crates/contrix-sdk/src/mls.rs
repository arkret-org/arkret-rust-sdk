use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProcessedMessageContent, ProtocolVersion, RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::{
    CryptoStore, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, Hash,
    MlsCommitEnvelope, MlsGroupStateRecord, MlsKeyPackageRecord, MlsWelcomeEnvelope, Operation,
    OperationId, Result, SpaceId, ToDeviceMessage, canonical,
};

pub const CONTRIX_MLS_ALGORITHM: &str = "cx.mls.v1";
pub const CONTRIX_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const CONTRIX_OPENMLS_STATE_SNAPSHOT: &str = "contrix-openmls-provider-state-v1";

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OpenMlsStateSnapshot {
    context: String,
    group_id: String,
    epoch: u64,
    principal_id: Did,
    device_id: DeviceId,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsDeviceWorkflowAction {
    PublishKeyPackage,
    RevokeKeyPackage,
    ConsumeWelcome,
    ApplyCommit,
    RequestEpochRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsDeviceWorkflowStep {
    pub action: MlsDeviceWorkflowAction,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub group_id: Option<String>,
    pub from_epoch: Option<u64>,
    pub to_epoch: Option<u64>,
}

impl MlsAddMemberResult {
    pub fn commit_operation(
        &self,
        operation_id: OperationId,
        space_id: SpaceId,
    ) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            space_id,
            "mls_commit",
            serde_json::to_value(&self.commit)?,
        );
        operation.object_id = Some(format!("{}:{}", self.commit.group_id, self.commit.epoch));
        Ok(operation)
    }

    pub fn welcome_to_device_message(&self) -> Result<ToDeviceMessage> {
        Ok(ToDeviceMessage {
            message_type: "cx.mls.welcome.v1".to_owned(),
            content: json!({
                "group_id": self.welcome.group_id,
                "epoch": self.welcome.epoch,
                "recipient_principal_id": self.welcome.recipient_principal_id,
                "recipient_device_id": self.welcome.recipient_device_id,
                "welcome": self.welcome.welcome,
                "welcome_hash": self.welcome.welcome_hash,
                "ratchet_tree": self.welcome.ratchet_tree,
            }),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoDecrypt {
    Plaintext { message_id: String, content_type: String, plaintext: Vec<u8> },
    Encrypted { message_id: String, payload: EncryptedPayload, reason: MessageCryptoUnavailable },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoUnavailable {
    NoSession,
    WrongGroup { expected: String, actual: String },
    EpochUnavailable { local_epoch: u64, required_epoch: u64 },
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

    pub fn encrypt_with_aad(
        group: &mut ContrixMlsGroup,
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
                return Err(Error::Protocol("encrypted payload AAD digest mismatch".to_owned()));
            }
        }
        Ok(())
    }

    pub fn decrypt(group: &mut ContrixMlsGroup, message: &EncryptedMessage) -> Result<Vec<u8>> {
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
            Ok(plaintext) => {
                Ok(MessageCryptoDecrypt::Plaintext { message_id, content_type, plaintext })
            }
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
        signer.store(provider.storage()).map_err(mls_error)?;
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

    pub fn publish_key_package_step(&self, group_id: Option<String>) -> MlsDeviceWorkflowStep {
        MlsDeviceWorkflowStep {
            action: MlsDeviceWorkflowAction::PublishKeyPackage,
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            group_id,
            from_epoch: None,
            to_epoch: None,
        }
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

    pub fn export_state_record(&self) -> Result<MlsGroupStateRecord> {
        let snapshot = OpenMlsStateSnapshot {
            context: CONTRIX_OPENMLS_STATE_SNAPSHOT.to_owned(),
            group_id: self.group_id(),
            epoch: self.epoch(),
            principal_id: self.identity.principal_id.clone(),
            device_id: self.identity.device_id.clone(),
            signer_public_key: encode(self.identity.signer.public()),
            storage_entries: snapshot_provider_storage(&self.identity.provider)?,
        };
        Ok(MlsGroupStateRecord {
            group_id: snapshot.group_id.clone(),
            principal_id: snapshot.principal_id.clone(),
            device_id: snapshot.device_id.clone(),
            epoch: snapshot.epoch,
            serialized_state: serde_json::to_vec(&snapshot)?,
            updated_at: Utc::now(),
        })
    }

    pub fn persist_state(&self, store: &mut impl CryptoStore) -> Result<MlsGroupStateRecord> {
        let record = self.export_state_record()?;
        store.put_mls_group_state(record.clone())?;
        Ok(record)
    }

    pub fn restore_from_state_record(record: &MlsGroupStateRecord) -> Result<Self> {
        let snapshot: OpenMlsStateSnapshot = serde_json::from_slice(&record.serialized_state)?;
        if snapshot.context != CONTRIX_OPENMLS_STATE_SNAPSHOT {
            return Err(Error::Protocol("unsupported OpenMLS state snapshot".to_owned()));
        }
        if snapshot.group_id != record.group_id
            || snapshot.epoch != record.epoch
            || snapshot.principal_id != record.principal_id
            || snapshot.device_id != record.device_id
        {
            return Err(Error::Protocol("OpenMLS state snapshot metadata mismatch".to_owned()));
        }

        let provider = OpenMlsRustCrypto::default();
        restore_provider_storage(&provider, &snapshot.storage_entries)?;
        let signer_public_key = decode(&snapshot.signer_public_key)?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &signer_public_key,
            CONTRIX_MLS_CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| Error::Protocol("OpenMLS signer is missing from snapshot".to_owned()))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(record.principal_id.as_str().as_bytes().to_vec())
                .into(),
            signature_key: signer.public().into(),
        };
        let group_id = GroupId::from_slice(&decode(&record.group_id)?);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(mls_error)?
            .ok_or_else(|| Error::Protocol("OpenMLS group state is missing".to_owned()))?;
        if group.epoch().as_u64() != record.epoch {
            return Err(Error::Protocol("OpenMLS restored epoch mismatch".to_owned()));
        }

        Ok(Self {
            identity: ContrixMlsIdentity {
                principal_id: record.principal_id.clone(),
                device_id: record.device_id.clone(),
                provider,
                signer,
                credential,
            },
            group,
        })
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
        self.encrypt_payload_with_aad(content_type, None, plaintext)
    }

    pub fn encrypt_payload_with_aad(
        &mut self,
        content_type: impl Into<String>,
        aad: Option<serde_json::Value>,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        let content_type = content_type.into();
        let message = self
            .group
            .create_message(&self.identity.provider, &self.identity.signer, plaintext)
            .map_err(mls_error)?;
        let message_bytes = message.tls_serialize_detached().map_err(mls_error)?;
        let epoch = self.epoch();
        let payload_digest = EncryptedPayload::mls_payload_digest(
            epoch,
            &content_type,
            aad.as_ref(),
            &message_bytes,
        )?;

        Ok(EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: self.group_id(),
            epoch,
            content_type,
            ciphertext: encode(&message_bytes),
            aad,
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

    pub fn apply_commits(&mut self, envelopes: &[MlsCommitEnvelope]) -> Result<u64> {
        let mut sorted = envelopes.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|envelope| envelope.epoch);
        for envelope in sorted {
            if envelope.epoch <= self.epoch() {
                continue;
            }
            self.apply_commit(envelope)?;
        }
        Ok(self.epoch())
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

pub fn revoke_key_package(record: &mut MlsKeyPackageRecord) -> MlsDeviceWorkflowStep {
    record.revoked = true;
    MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::RevokeKeyPackage,
        principal_id: record.principal_id.clone(),
        device_id: record.device_id.clone(),
        group_id: None,
        from_epoch: None,
        to_epoch: None,
    }
}

pub fn late_device_join_steps(welcome: &MlsWelcomeEnvelope) -> Vec<MlsDeviceWorkflowStep> {
    vec![MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::ConsumeWelcome,
        principal_id: welcome.recipient_principal_id.clone(),
        device_id: welcome.recipient_device_id.clone(),
        group_id: Some(welcome.group_id.clone()),
        from_epoch: None,
        to_epoch: Some(welcome.epoch),
    }]
}

pub fn epoch_recovery_step(
    principal_id: Did,
    device_id: DeviceId,
    group_id: impl Into<String>,
    from_epoch: u64,
    to_epoch: u64,
) -> MlsDeviceWorkflowStep {
    MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::RequestEpochRecovery,
        principal_id,
        device_id,
        group_id: Some(group_id.into()),
        from_epoch: Some(from_epoch),
        to_epoch: Some(to_epoch),
    }
}

fn snapshot_provider_storage(provider: &OpenMlsRustCrypto) -> Result<BTreeMap<String, String>> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| Error::Protocol("OpenMLS storage lock poisoned".to_owned()))?;
    Ok(values.iter().map(|(key, value)| (encode(key), encode(value))).collect())
}

fn restore_provider_storage(
    provider: &OpenMlsRustCrypto,
    entries: &BTreeMap<String, String>,
) -> Result<()> {
    let mut values = provider
        .storage()
        .values
        .write()
        .map_err(|_| Error::Protocol("OpenMLS storage lock poisoned".to_owned()))?;
    values.clear();
    for (key, value) in entries {
        values.insert(decode(key)?, decode(value)?);
    }
    Ok(())
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
    fn message_crypto_encrypts_decrypts_and_verifies_opaque_digest() {
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

        let mut alice_group = alice.create_group(b"cx:space:message-workflow").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "cx:message:01",
            "application/vnd.contrix.message+json",
            br#"{"body":"hello secure workflow"}"#,
        )
        .unwrap();

        MessageCrypto::verify_opaque_payload_digest(&encrypted).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"hello secure workflow"}"#);
    }

    #[test]
    fn message_crypto_encrypts_with_aad_and_verifies_digest() {
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

        let mut alice_group = alice.create_group(b"cx:space:message-aad").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let aad = serde_json::json!({
            "space_id": "cx:space:message-aad",
            "event_type": "cx.message.create",
            "event_id": "cx:event:encrypted-aad",
            "causal_refs": []
        });
        let aad_digest = crate::crypto::json_aad_digest(&aad).unwrap();

        let encrypted = MessageCrypto::encrypt_with_aad(
            &mut alice_group,
            "cx:message:aad",
            "application/json",
            aad,
            br#"{"body":"aad bound"}"#,
        )
        .unwrap();
        MessageCrypto::verify_payload_and_aad_digest(&encrypted, Some(&aad_digest)).unwrap();
        assert_eq!(
            MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap(),
            br#"{"body":"aad bound"}"#
        );
    }

    #[test]
    fn openmls_state_persists_through_crypto_store_record() {
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

        let mut alice_group = alice.create_group(b"cx:space:persisted-mls").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let mut store = crate::MemoryCryptoStore::new();
        let record = bob_group.persist_state(&mut store).unwrap();
        let mut restored_bob = ContrixMlsGroup::restore_from_state_record(&record).unwrap();

        assert_eq!(restored_bob.epoch(), bob_group.epoch());
        assert_eq!(store.mls_group_state(&record.group_id).unwrap().epoch, record.epoch);

        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"after restore"}"#)
            .unwrap();
        assert_eq!(
            restored_bob.decrypt_payload(&encrypted).unwrap(),
            br#"{"body":"after restore"}"#
        );
    }

    #[test]
    fn multi_device_workflow_applies_missed_commits_and_models_recovery() {
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
        let charlie = ContrixMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("dev_charlie_1").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let charlie_key_package = charlie.key_package_record().unwrap();
        let mut revoked_package = charlie_key_package.clone();
        let revoke_step = revoke_key_package(&mut revoked_package);
        assert!(revoked_package.revoked);
        assert_eq!(revoke_step.action, MlsDeviceWorkflowAction::RevokeKeyPackage);

        let mut alice_group = alice.create_group(b"cx:space:offline-commits").unwrap();
        let bob_add = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_key_package).unwrap();
        let workflow = late_device_join_steps(&charlie_add.welcome);
        assert_eq!(workflow[0].action, MlsDeviceWorkflowAction::ConsumeWelcome);

        bob_group.apply_commits(std::slice::from_ref(&charlie_add.commit)).unwrap();
        assert_eq!(bob_group.epoch(), alice_group.epoch());
        let recovery = epoch_recovery_step(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("dev_bob_1").unwrap(),
            bob_group.group_id(),
            bob_group.epoch() + 1,
            bob_group.epoch() + 3,
        );
        assert_eq!(recovery.action, MlsDeviceWorkflowAction::RequestEpochRecovery);
    }

    #[test]
    fn add_member_result_projects_to_repo_operation_and_to_device_message() {
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

        let mut alice_group = alice.create_group(b"cx:space:mls-workflow").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let operation = add_result
            .commit_operation(
                OperationId::new("cx:operation:mls_commit_1").unwrap(),
                SpaceId::new("cx:space:mls-workflow").unwrap(),
            )
            .unwrap();
        let to_device = add_result.welcome_to_device_message().unwrap();

        assert_eq!(operation.object_type, "mls_commit");
        assert_eq!(to_device.message_type, "cx.mls.welcome.v1");
        assert_eq!(to_device.content["recipient_device_id"], "dev_bob_1");
    }

    #[test]
    fn message_crypto_preserves_encrypted_payload_without_available_key() {
        let alice = ContrixMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("dev_alice_1").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice.create_group(b"cx:space:message-workflow").unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "cx:message:02",
            "application/json",
            br#"{"body":"keep ciphertext"}"#,
        )
        .unwrap();
        let expected_digest = encrypted.payload.payload_digest.clone();
        let expected_ciphertext = encrypted.payload.ciphertext.clone();

        let result = MessageCrypto::decrypt_or_preserve(None, encrypted).unwrap();

        let MessageCryptoDecrypt::Encrypted { message_id, payload, reason } = result else {
            panic!("message should stay encrypted without a local MLS session");
        };
        assert_eq!(message_id, "cx:message:02");
        assert!(matches!(reason, MessageCryptoUnavailable::NoSession));
        assert_eq!(payload.payload_digest, expected_digest);
        assert_eq!(payload.ciphertext, expected_ciphertext);
    }

    #[test]
    fn encrypted_timeline_preserves_then_decrypts_after_welcome_arrives() {
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

        let mut alice_group = alice.create_group(b"cx:space:encrypted-timeline").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "cx:event:encrypted-1",
            "application/vnd.contrix.message+json",
            br#"{"body":"arrives before local key"}"#,
        )
        .unwrap();

        let preserved = MessageCrypto::decrypt_or_preserve(None, encrypted.clone()).unwrap();
        assert!(matches!(preserved, MessageCryptoDecrypt::Encrypted { .. }));

        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"arrives before local key"}"#);
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
