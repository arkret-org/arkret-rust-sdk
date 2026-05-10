use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn,
    LeafNodeIndex, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, OpenMlsProvider, ProcessedMessageContent, ProtocolVersion, RatchetTreeIn,
    StagedWelcome,
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

/// Result of removing one or more leaves from an MLS group.
///
/// Unlike `MlsAddMemberResult`, Remove never produces a Welcome — surviving
/// members simply apply the commit to advance the epoch. The list of
/// `removed_leaves` makes the audit trail explicit so callers can correlate
/// the result with the originating `cx.device.revoked` / `cx.member.state`
/// events.
#[derive(Clone, Debug)]
pub struct MlsRemoveMemberResult {
    pub commit: MlsCommitEnvelope,
    /// Raw OpenMLS leaf indices that were removed by this commit, in the
    /// order they appeared in the original group state.
    pub removed_leaves: Vec<u32>,
    /// The principal DIDs whose leaves were removed (one per leaf, may
    /// contain duplicates if the principal had multiple leaves / devices in
    /// the same group). Useful for downstream `cx.device.revoked` event
    /// envelopes that index by principal.
    pub removed_principals: Vec<Did>,
}

impl MlsRemoveMemberResult {
    /// Project the commit into a canonical `mls_commit` operation envelope,
    /// matching the shape of `MlsAddMemberResult::commit_operation`.
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
            sender_principal_id: None,
            sender_device_id: None,
            recipient_principal_id: None,
            recipient_device_id: None,
            sent_at: None,
            expires_at: None,
            content: json!({
                "group_id": self.welcome.group_id,
                "epoch": self.welcome.epoch,
                "recipient_principal_id": self.welcome.recipient_principal_id,
                "recipient_device_id": self.welcome.recipient_device_id,
                "welcome": self.welcome.welcome,
                "welcome_hash": self.welcome.welcome_hash,
                "ratchet_tree": self.welcome.ratchet_tree,
            }),
            device_proof: None,
            unsigned: None,
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
            keypackage_id: Some(format!("cx:mls:kp:{}", uuid::Uuid::now_v7())),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            key_package: encode(&key_package_bytes),
            key_package_hash,
            cipher_suites: vec![format!("{CONTRIX_MLS_CIPHERSUITE:?}")],
            capabilities: Vec::new(),
            state: contrix_core::MlsKeyPackageState::Published,
            claim_id: None,
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
                app_state_ref: None,
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

    /// Remove every leaf whose BasicCredential identity matches `target`.
    ///
    /// In the current credential encoding (`mls.rs::ContrixMlsIdentity::new_basic`)
    /// the leaf identity bytes are `principal_id.as_str().as_bytes()` — they
    /// do NOT include the device id. Therefore matching by principal removes
    /// **all leaves** owned by that principal in this group. To remove a
    /// specific device, use [`Self::remove_member_by_leaf`] with a leaf
    /// index resolved from out-of-band device → leaf bookkeeping.
    ///
    /// Errors when the target principal has no leaf in this group.
    pub fn remove_member_by_principal(&mut self, target: &Did) -> Result<MlsRemoveMemberResult> {
        let target_bytes = target.as_str().as_bytes();
        let leaves: Vec<LeafNodeIndex> = self
            .group
            .members()
            .filter_map(|member| {
                if member.credential.serialized_content() == target_bytes {
                    Some(member.index)
                } else {
                    None
                }
            })
            .collect();

        if leaves.is_empty() {
            return Err(Error::Protocol(format!(
                "principal {} has no leaf in group {}",
                target.as_str(),
                self.group_id()
            )));
        }

        self.remove_leaves(&leaves)
    }

    /// Remove a single leaf by its raw OpenMLS leaf index. Use this when the
    /// caller maintains an explicit (principal, device_id) → leaf_index map
    /// (e.g. a yougen DeviceManager with leaf bookkeeping) and wants to
    /// revoke just one device of a multi-device principal.
    pub fn remove_member_by_leaf(&mut self, leaf_index: u32) -> Result<MlsRemoveMemberResult> {
        self.remove_leaves(&[LeafNodeIndex::new(leaf_index)])
    }

    fn remove_leaves(&mut self, leaves: &[LeafNodeIndex]) -> Result<MlsRemoveMemberResult> {
        // Capture credential identity bytes before commit so we can report
        // which principal each removed leaf belonged to even after the leaf
        // is gone from the post-commit group state.
        let pre_commit: Vec<(LeafNodeIndex, Vec<u8>)> = self
            .group
            .members()
            .filter_map(|member| {
                if leaves.contains(&member.index) {
                    Some((member.index, member.credential.serialized_content().to_vec()))
                } else {
                    None
                }
            })
            .collect();

        if pre_commit.len() != leaves.len() {
            return Err(Error::Protocol(format!(
                "remove_leaves: {} of {} leaf indices not present in group {}",
                leaves.len() - pre_commit.len(),
                leaves.len(),
                self.group_id()
            )));
        }

        let (commit, _welcome_opt, _) = self
            .group
            .remove_members(&self.identity.provider, &self.identity.signer, leaves)
            .map_err(mls_error)?;
        self.group.merge_pending_commit(&self.identity.provider).map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);

        let mut removed_leaves: Vec<u32> = Vec::with_capacity(pre_commit.len());
        let mut removed_principals: Vec<Did> = Vec::with_capacity(pre_commit.len());
        for (idx, identity_bytes) in pre_commit {
            removed_leaves.push(idx.u32());
            // Reconstruct the principal Did from identity bytes. If the
            // bytes are not valid UTF-8 / not a parseable Did we fall back
            // to a placeholder so the audit trail still records the leaf
            // index; this should never happen in practice because all
            // ContrixMlsIdentity leaves carry UTF-8 DID strings.
            let principal = std::str::from_utf8(&identity_bytes)
                .ok()
                .and_then(|s| Did::new(s.to_owned()).ok())
                .unwrap_or_else(|| {
                    Did::new(format!("did:contrix:unknown-leaf-{}", idx.u32()))
                        .expect("placeholder DID is well-formed")
                });
            removed_principals.push(principal);
        }

        Ok(MlsRemoveMemberResult {
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                commit: encode(&commit_bytes),
                commit_hash: Hash::new(canonical::sha256_digest(&commit_bytes))?,
                ratchet_tree,
                app_state_ref: None,
            },
            removed_leaves,
            removed_principals,
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
            key_ref: Some(contrix_core::EncryptedPayloadKeyRef::mls_rfc9420(
                self.group_id(),
                epoch,
            )),
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

/// Request for epoch recovery sent to a group member that has the missing commits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecoveryRequest {
    /// Group that needs recovery.
    pub group_id: String,
    /// Device requesting recovery.
    pub requesting_principal: Did,
    pub requesting_device: DeviceId,
    /// The epoch the device is currently at.
    pub local_epoch: u64,
    /// The epoch the device needs to reach.
    pub target_epoch: u64,
}

/// Response containing the commits needed for epoch recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecoveryResponse {
    /// Group that was recovered.
    pub group_id: String,
    /// The commits from `local_epoch + 1` through `target_epoch`.
    pub commits: Vec<MlsCommitEnvelope>,
    /// Optional updated ratchet tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// Epoch the responder is at.
    pub responder_epoch: u64,
}

impl EpochRecoveryRequest {
    /// Create a new epoch recovery request.
    pub fn new(
        group_id: impl Into<String>,
        requesting_principal: Did,
        requesting_device: DeviceId,
        local_epoch: u64,
        target_epoch: u64,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            requesting_principal,
            requesting_device,
            local_epoch,
            target_epoch,
        }
    }

    /// Validate the request is well-formed.
    pub fn validate(&self) -> Result<()> {
        if self.group_id.is_empty() {
            return Err(Error::Protocol("epoch recovery group_id is empty".to_owned()));
        }
        if self.local_epoch >= self.target_epoch {
            return Err(Error::Protocol(
                "epoch recovery local_epoch must be less than target_epoch".to_owned(),
            ));
        }
        Ok(())
    }
}

impl EpochRecoveryResponse {
    /// Apply all commits in this recovery response to a group.
    pub fn apply_to_group(&self, group: &mut ContrixMlsGroup) -> Result<u64> {
        group.apply_commits(&self.commits)
    }

    /// Validate that the response covers the requested epoch range.
    pub fn validate_range(&self, request: &EpochRecoveryRequest) -> Result<()> {
        if self.group_id != request.group_id {
            return Err(Error::Protocol("epoch recovery response group_id mismatch".to_owned()));
        }
        for commit in &self.commits {
            if commit.epoch <= request.local_epoch || commit.epoch > request.target_epoch {
                return Err(Error::Protocol(format!(
                    "epoch recovery commit epoch {} is outside requested range ({}, {}]",
                    commit.epoch, request.local_epoch, request.target_epoch
                )));
            }
        }
        Ok(())
    }
}

/// Build an epoch recovery response from a group that has the needed commits.
pub fn build_epoch_recovery_response(
    group: &ContrixMlsGroup,
    store: &impl CryptoStore,
    request: &EpochRecoveryRequest,
) -> Result<EpochRecoveryResponse> {
    request.validate()?;

    let commits = store.commits_for_group(&request.group_id);
    let recovery_commits: Vec<MlsCommitEnvelope> = commits
        .into_iter()
        .filter(|commit| commit.epoch > request.local_epoch && commit.epoch <= request.target_epoch)
        .cloned()
        .collect();

    if recovery_commits.is_empty() {
        return Err(Error::Protocol("no commits available for epoch recovery".to_owned()));
    }

    Ok(EpochRecoveryResponse {
        group_id: request.group_id.clone(),
        commits: recovery_commits,
        ratchet_tree: Some(group.ratchet_tree()?),
        responder_epoch: group.epoch(),
    })
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-d652c78259d9").unwrap();
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-f2f103987ef3").unwrap();
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-65bef476aed3").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let aad = serde_json::json!({
            "space_id": "cx:space:01904100-0000-7000-8000-65bef476aed3",
            "event_type": "cx.message.create",
            "event_id": "cx:event:01904100-0000-7000-8000-d5afe7e3de96",
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-1ad6479d4a3f").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-877788250807").unwrap();
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-4ecefcf31ad2").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let operation = add_result
            .commit_operation(
                OperationId::new("cx:operation:01904100-0000-7000-8000-02369de2e9c6").unwrap(),
                SpaceId::new("cx:space:01904100-0000-7000-8000-4ecefcf31ad2").unwrap(),
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
        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-f2f103987ef3").unwrap();
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

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-469a459e1b8f").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "cx:event:01904100-0000-7000-8000-f2fbe0d55fb4",
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
    fn epoch_recovery_request_and_response_catch_up_offline_device() {
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

        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        // Alice creates group and adds Bob and Charlie.
        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-4cc289f6471e").unwrap();
        let bob_add = alice_group.add_member(&bob_kp).unwrap();
        let mut bob_group = ContrixMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_kp).unwrap();

        // Bob is now offline. Alice adds Charlie (epoch advances).
        // Bob's local epoch is behind.
        let bob_epoch_before = bob_group.epoch();

        // Create a recovery request.
        let request = EpochRecoveryRequest::new(
            bob_group.group_id(),
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("dev_bob_1").unwrap(),
            bob_epoch_before,
            alice_group.epoch(),
        );
        request.validate().unwrap();

        // Store the commits in a crypto store so we can build a response.
        let mut store = crate::MemoryCryptoStore::new();
        store.put_commit(charlie_add.commit).unwrap();

        // Alice (who has the commits) builds the recovery response.
        let response = build_epoch_recovery_response(&alice_group, &store, &request).unwrap();
        response.validate_range(&request).unwrap();
        assert!(!response.commits.is_empty());

        // Bob applies the recovery response.
        let new_epoch = response.apply_to_group(&mut bob_group).unwrap();
        assert_eq!(new_epoch, alice_group.epoch());

        // Bob can now decrypt messages from the current epoch.
        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"after recovery"}"#)
            .unwrap();
        let decrypted = bob_group.decrypt_payload(&encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"after recovery"}"#);
    }

    #[test]
    fn epoch_recovery_request_validates_range() {
        let request = EpochRecoveryRequest::new(
            "",
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("dev_alice_1").unwrap(),
            5,
            3,
        );
        assert!(request.validate().is_err());

        let request = EpochRecoveryRequest::new(
            "group1",
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("dev_alice_1").unwrap(),
            5,
            5,
        );
        assert!(request.validate().is_err());
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
        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-d652c78259d9").unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(error) = ContrixMlsGroup::join_from_welcome(mallory, &add_result.welcome) else {
            panic!("Mallory should not be able to consume Bob's Welcome");
        };

        assert!(matches!(error, Error::Protocol(_)));
    }

    /// T31 — `remove_member_by_principal` removes a leaf, advances the
    /// group's epoch and produces a commit envelope that surviving members
    /// can apply to converge.
    #[test]
    fn remove_member_by_principal_advances_epoch_and_emits_commit() {
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
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-a78a8b504d40").unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let add_charlie = alice_group.add_member(&charlie_kp).unwrap();
        let _charlie_group =
            ContrixMlsGroup::join_from_welcome(charlie, &add_charlie.welcome).unwrap();

        let epoch_before = alice_group.epoch();
        let target = Did::new("did:web:charlie.example").unwrap();
        let result = alice_group.remove_member_by_principal(&target).unwrap();

        // Epoch advanced by exactly one Commit.
        assert_eq!(alice_group.epoch(), epoch_before + 1);
        // Commit envelope reflects the new epoch and same group.
        assert_eq!(result.commit.epoch, alice_group.epoch());
        assert_eq!(result.commit.group_id, alice_group.group_id());
        // Exactly one leaf removed; principal correctly reported.
        assert_eq!(result.removed_leaves.len(), 1);
        assert_eq!(result.removed_principals.len(), 1);
        assert_eq!(result.removed_principals[0].as_str(), "did:web:charlie.example");
    }

    /// T31 — removing an absent principal returns a Protocol error rather
    /// than silently no-op'ing. The orchestration plan in yougen relies on
    /// this to surface "leaf already gone" as a recoverable state.
    #[test]
    fn remove_member_by_principal_errors_when_target_absent() {
        let alice = ContrixMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("dev_alice_1").unwrap(),
        )
        .unwrap();
        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-3cf34eced3c3").unwrap();

        let absent = Did::new("did:web:nobody.example").unwrap();
        let err = alice_group.remove_member_by_principal(&absent);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    /// T31 — `remove_member_by_leaf` accepts a raw OpenMLS leaf index and
    /// produces the same shape of commit envelope. Used when the caller
    /// (yougen DeviceManager) tracks per-device leaf bookkeeping
    /// out-of-band.
    #[test]
    fn remove_member_by_leaf_accepts_raw_index() {
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
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-89444e193497").unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();

        // Bob's leaf is at index 1 (Alice is index 0 as group creator).
        let result = alice_group.remove_member_by_leaf(1).unwrap();
        assert_eq!(result.removed_leaves, vec![1]);
        assert_eq!(result.removed_principals[0].as_str(), "did:web:bob.example");
    }

    /// T31 — `commit_operation` projects the result into the same
    /// canonical operation shape that `MlsAddMemberResult` produces, so
    /// audit pipelines can ingest both consistently.
    #[test]
    fn remove_result_commit_operation_uses_mls_commit_op_type() {
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
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group =
            alice.create_group(b"cx:space:01904100-0000-7000-8000-bd49dfdbc804").unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = ContrixMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let result = alice_group
            .remove_member_by_principal(&Did::new("did:web:bob.example").unwrap())
            .unwrap();

        let op_id = OperationId::new("cx:operation:01904100-0000-7000-8000-00a9123c0f9c").unwrap();
        let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-bd49dfdbc804").unwrap();
        let op = result.commit_operation(op_id, space_id).unwrap();
        assert_eq!(op.object_type, "mls_commit");
        assert!(op.object_id.unwrap().contains(&result.commit.group_id));
    }
}
