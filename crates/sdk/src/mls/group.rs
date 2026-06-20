use std::collections::BTreeMap;

use chrono::Utc;
use cokret_core::{base64url_decode, base64url_encode};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, Extension, ExtensionType, Extensions,
    GroupContext, GroupId, LeafNodeIndex, LeafNodeParameters, MlsGroup, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProcessedMessageContent, RatchetTreeIn,
    RequiredCapabilitiesExtension, StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use super::identity::{COKRET_MLS_CIPHERSUITE, CokretMlsIdentity, decode_key_package};
use crate::{
    CryptoStore, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, Hash,
    MLS_GOVERNANCE_BINDING_EXTENSION_TYPE, MlsCommitEnvelope, MlsGovernanceBindingExtension,
    MlsGovernanceBindingPayload, MlsGovernanceBindingValidationContext, MlsGroupStateRecord,
    MlsKeyPackageRecord, MlsProposalEnvelope, MlsWelcomeEnvelope, Operation, OperationId, RealmId,
    Result, ToDeviceMessage, canonical, verify_mls_governance_binding_extension,
};

const COKRET_OPENMLS_STATE_SNAPSHOT: &str = "cokret-openmls-provider-state-v1";

pub struct CokretMlsGroup {
    pub(super) identity: CokretMlsIdentity,
    pub(super) group: MlsGroup,
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
/// the result with the originating `ck.device.revoke` / `ck.member.state`
/// events.
#[derive(Clone, Debug)]
pub struct MlsRemoveMemberResult {
    pub proposals: Vec<MlsProposalEnvelope>,
    pub commit: MlsCommitEnvelope,
    /// Raw OpenMLS leaf indices that were removed by this commit, in the
    /// order they appeared in the original group state.
    pub removed_leaves: Vec<u32>,
    /// The principal DIDs whose leaves were removed (one per leaf, may
    /// contain duplicates if the principal had multiple leaves / devices in
    /// the same group). Useful for downstream `ck.device.revoke` event
    /// envelopes that index by principal.
    pub removed_principals: Vec<Did>,
}

impl MlsRemoveMemberResult {
    /// Project the commit into a canonical `mls_commit` operation envelope,
    /// matching the shape of `MlsAddMemberResult::commit_operation`.
    pub fn commit_operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
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

impl MlsAddMemberResult {
    pub fn commit_operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_commit",
            serde_json::to_value(&self.commit)?,
        );
        operation.object_id = Some(format!("{}:{}", self.commit.group_id, self.commit.epoch));
        Ok(operation)
    }

    pub fn welcome_to_device_message(&self) -> Result<ToDeviceMessage> {
        Ok(ToDeviceMessage {
            message_type: "ck.mls.welcome.v1".to_owned(),
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

impl CokretMlsGroup {
    pub fn identity(&self) -> &CokretMlsIdentity {
        &self.identity
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn group_id(&self) -> String {
        encode(self.group.group_id().as_slice())
    }

    pub fn ratchet_tree(&self) -> Result<String> {
        let bytes = self
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        Ok(encode(&bytes))
    }

    pub fn governance_binding_extension(&self) -> Option<MlsGovernanceBindingExtension> {
        self.group
            .extensions()
            .unknown(MLS_GOVERNANCE_BINDING_EXTENSION_TYPE)
            .map(|extension| MlsGovernanceBindingExtension {
                extension_type: MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
                extension_data: extension.0.clone(),
            })
    }

    pub fn current_governance_binding(&self) -> Result<Option<MlsGovernanceBindingPayload>> {
        self.governance_binding_extension()
            .map(|extension| extension.decode_payload())
            .transpose()
    }

    pub fn verify_current_governance_binding(
        &self,
        expected: &MlsGovernanceBindingValidationContext<'_>,
    ) -> Result<MlsGovernanceBindingPayload> {
        let extension = self.governance_binding_extension();
        verify_mls_governance_binding_extension(extension.as_ref(), expected)
    }

    pub fn update_governance_binding(
        &mut self,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsCommitEnvelope> {
        binding.validate()?;
        if binding.mls_group_id() != self.group_id() {
            return Err(Error::Protocol(
                "mls_governance_binding.mls_group_id does not match current MLS group".to_owned(),
            ));
        }
        if binding.previous_epoch() != self.epoch() || binding.next_epoch() != self.epoch() + 1 {
            return Err(Error::Protocol(
                "mls_governance_binding epoch does not match current MLS group".to_owned(),
            ));
        }

        let mut extensions = self.group.extensions().clone();
        extensions
            .add_or_replace(governance_binding_required_capabilities_extension())
            .map_err(mls_error)?;
        extensions
            .add_or_replace(governance_binding_openmls_extension(binding)?)
            .map_err(mls_error)?;
        let (commit, _welcome, _group_info) = self
            .group
            .update_group_context_extensions(
                &self.identity.provider,
                extensions,
                &self.identity.signer,
            )
            .map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);
        Ok(MlsCommitEnvelope {
            group_id: self.group_id(),
            epoch: self.epoch(),
            commit: encode(&commit_bytes),
            commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
            ratchet_tree,
            app_state_ref: None,
        })
    }

    /// Content hash of the group's current key schedule, suitable for use as
    /// the `key_schedule_hash` field in `ck.component.key_schedule.v1` cell
    /// values and in `ck.profile.mls_governance_binding.full.v1` binding
    /// payloads. Derived deterministically from the OpenMLS
    /// `epoch_authenticator()` — a value the spec binds to the current
    /// (post-commit) MLS epoch + group state, so two clients on the same
    /// epoch always produce the same hash without exchanging schedule
    /// material.
    ///
    /// Returns a `sha256:`-prefixed lowercase hex `Hash` typed-id so callers
    /// can hand it straight to `GovernanceBindingPayload::from_anchor` /
    /// `Hash::new`. Computing the SHA-256 over the authenticator byte slice
    /// (rather than handing back the raw authenticator) means the value can
    /// be safely written into projection cells and audit logs without
    /// leaking the underlying MLS secret directly — the authenticator MUST
    /// stay scoped to MLS-internal consistency checks per RFC 9420 §8.5.
    pub fn schedule_hash(&self) -> Hash {
        let authenticator = self.group.epoch_authenticator();
        let digest = Sha256::digest(authenticator.as_slice());
        Hash::new(format!("sha256:{}", hex_lower(&digest)))
            .expect("sha256:<hex> is always a valid Hash typed-id")
    }

    /// Derive an MLS RFC 9420 §8.5 exporter secret bound to the current
    /// epoch's key schedule. The output is deterministic for a given
    /// `(group, epoch, label, context, length)` and rotates on every commit,
    /// so two members on the same epoch derive identical bytes without
    /// exchanging material.
    ///
    /// Used for spec-defined key derivations layered on the group secret —
    /// e.g. the reaction routing tag (`encryption-and-audit.md` §2.9, label
    /// `cokret-reaction-routing-v1`, context = `realm_id`) and SFrame media
    /// keys (`media-service-binding.md` §8.1). Callers MUST treat the returned
    /// bytes as secret key material (never log or persist them in the clear).
    pub fn export_secret(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        self.group
            .export_secret(self.identity.provider.crypto(), label, context, length)
            .map_err(mls_error)
    }

    /// Snapshot the current MLS group's member principals as canonical IDs.
    /// Iterates the OpenMLS `members()` view, parses each leaf's credential
    /// content as a UTF-8 DID string, and folds the results into a stable
    /// (deduplicated, BTreeSet-sorted) `Vec<Did>`. Useful for `ck.audit.
    /// ryw_receipt.delivered_to_devices` and for downstream auditors that
    /// want to know "which principals does this commit reach".
    ///
    /// Credentials that don't parse as a [`Did`] (e.g. opaque BasicCredential
    /// payloads) are silently skipped — the caller can
    /// detect this case by comparing `member_principal_ids().len()` against
    /// the group's true member count if it cares.
    pub fn member_principal_ids(&self) -> Vec<Did> {
        let mut seen = std::collections::BTreeSet::new();
        for member in self.group.members() {
            let bytes = member.credential.serialized_content();
            if let Ok(s) = std::str::from_utf8(bytes)
                && let Ok(did) = Did::new(s.to_owned())
            {
                seen.insert(did);
            }
        }
        seen.into_iter().collect()
    }

    pub fn export_state_record(&self) -> Result<MlsGroupStateRecord> {
        let snapshot = OpenMlsStateSnapshot {
            context: COKRET_OPENMLS_STATE_SNAPSHOT.to_owned(),
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
        if snapshot.context != COKRET_OPENMLS_STATE_SNAPSHOT {
            return Err(Error::Protocol(
                "unsupported OpenMLS state snapshot".to_owned(),
            ));
        }
        if snapshot.group_id != record.group_id
            || snapshot.epoch != record.epoch
            || snapshot.principal_id != record.principal_id
            || snapshot.device_id != record.device_id
        {
            return Err(Error::Protocol(
                "OpenMLS state snapshot metadata mismatch".to_owned(),
            ));
        }

        let provider = OpenMlsRustCrypto::default();
        restore_provider_storage(&provider, &snapshot.storage_entries)?;
        let signer_public_key = decode(&snapshot.signer_public_key)?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &signer_public_key,
            COKRET_MLS_CIPHERSUITE.signature_algorithm(),
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
            return Err(Error::Protocol(
                "OpenMLS restored epoch mismatch".to_owned(),
            ));
        }

        Ok(Self {
            identity: CokretMlsIdentity {
                principal_id: record.principal_id.clone(),
                device_id: record.device_id.clone(),
                provider,
                signer,
                credential,
            },
            group,
        })
    }

    /// Produce a "self-update" commit envelope — the MLS commit that
    /// rotates the local member's leaf-node key without changing
    /// membership. Callers (e.g. yougen's chat Send Secure path) use
    /// this to get a real `MlsCommitEnvelope` over the actual ratchet
    /// state instead of synthesizing one with hardcoded epoch / hash
    /// values.
    ///
    /// Returns an `MlsCommitEnvelope` whose `commit` field is the
    /// TLS-serialised commit message (base64-url encoded) and whose
    /// `commit_digest` is the SHA-256 of that wire bytes — the same
    /// shape the SDK already emits from `add_member` / `remove_member_*`.
    /// Side-effect: the group's pending commit is `merge`-d on success
    /// so subsequent `encrypt_payload` calls run against the new
    /// epoch.
    pub fn self_update_commit(&mut self) -> Result<MlsCommitEnvelope> {
        let bundle = self
            .group
            .self_update(
                &self.identity.provider,
                &self.identity.signer,
                LeafNodeParameters::default(),
            )
            .map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;
        let commit_bytes = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);
        Ok(MlsCommitEnvelope {
            group_id: self.group_id(),
            epoch: self.epoch(),
            commit: encode(&commit_bytes),
            commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
            ratchet_tree,
            app_state_ref: None,
        })
    }

    pub fn add_member(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
    ) -> Result<MlsAddMemberResult> {
        if !member_key_package.is_usable() {
            return Err(Error::Protocol(
                "refusing to add revoked MLS KeyPackage".to_owned(),
            ));
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
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let welcome_bytes = welcome.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);

        Ok(MlsAddMemberResult {
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                commit: encode(&commit_bytes),
                commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
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
    /// In the current credential encoding (`mls.rs::CokretMlsIdentity::new_basic`)
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
                    Some((
                        member.index,
                        member.credential.serialized_content().to_vec(),
                    ))
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

        let base_epoch = self.epoch();
        let ratchet_tree = Some(self.ratchet_tree()?);
        let mut proposals = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let (proposal_message, _proposal_ref) = self
                .group
                .propose_remove_member(&self.identity.provider, &self.identity.signer, *leaf)
                .map_err(mls_error)?;
            let proposal_bytes = proposal_message
                .tls_serialize_detached()
                .map_err(mls_error)?;
            proposals.push(MlsProposalEnvelope {
                group_id: self.group_id(),
                epoch: base_epoch,
                proposal_type: "remove".to_owned(),
                proposal: encode(&proposal_bytes),
                proposal_digest: Hash::new(canonical::sha256_digest(&proposal_bytes))?,
                ratchet_tree: ratchet_tree.clone(),
            });
        }

        let (commit, _welcome_opt, _) = self
            .group
            .commit_to_pending_proposals(&self.identity.provider, &self.identity.signer)
            .map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;

        let mut removed_leaves: Vec<u32> = Vec::with_capacity(pre_commit.len());
        let mut removed_principals: Vec<Did> = Vec::with_capacity(pre_commit.len());
        for (idx, identity_bytes) in pre_commit {
            removed_leaves.push(idx.u32());
            // Reconstruct the principal Did from identity bytes. If the
            // bytes are not valid UTF-8 / not a parseable Did we fall back
            // to a placeholder so the audit trail still records the leaf
            // index; this should never happen in practice because all
            // CokretMlsIdentity leaves carry UTF-8 DID strings.
            let principal = std::str::from_utf8(&identity_bytes)
                .ok()
                .and_then(|s| Did::new(s.to_owned()).ok())
                .unwrap_or_else(|| {
                    Did::new(format!("did:cokret:unknown-leaf-{}", idx.u32()))
                        .expect("placeholder DID is well-formed")
                });
            removed_principals.push(principal);
        }

        Ok(MlsRemoveMemberResult {
            proposals,
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                commit: encode(&commit_bytes),
                commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
                ratchet_tree,
                app_state_ref: None,
            },
            removed_leaves,
            removed_principals,
        })
    }

    pub fn join_from_welcome(
        identity: CokretMlsIdentity,
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
            key_ref: Some(cokret_core::KeyRefObject::mls_rfc9420(
                self.group_id(),
                epoch,
            )),
        })
    }

    pub fn decrypt_payload(&mut self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        if payload.scheme != EncryptedPayloadScheme::MlsRfc9420 {
            return Err(Error::Protocol(
                "encrypted payload is not MLS RFC 9420".to_owned(),
            ));
        }
        if payload.group_id != self.group_id() {
            return Err(Error::Protocol(
                "encrypted payload belongs to a different MLS group".to_owned(),
            ));
        }
        if payload.epoch > self.epoch() {
            return Err(Error::Protocol(
                "MLS epoch is not available locally".to_owned(),
            ));
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
                Err(Error::Protocol(
                    "expected MLS application message, got commit".to_owned(),
                ))
            }
            _ => Err(Error::Protocol(
                "expected MLS application message".to_owned(),
            )),
        }
    }

    pub fn apply_commit(&mut self, envelope: &MlsCommitEnvelope) -> Result<u64> {
        let commit_bytes = decode(&envelope.commit)?;
        let actual_commit_digest = canonical::sha256_digest(&commit_bytes);
        if actual_commit_digest != envelope.commit_digest.as_str() {
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

fn snapshot_provider_storage(provider: &OpenMlsRustCrypto) -> Result<BTreeMap<String, String>> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| Error::Protocol("OpenMLS storage lock poisoned".to_owned()))?;
    Ok(values
        .iter()
        .map(|(key, value)| (encode(key), encode(value)))
        .collect())
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

pub(super) fn encode(bytes: &[u8]) -> String {
    base64url_encode(bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

pub(super) fn decode(value: &str) -> Result<Vec<u8>> {
    base64url_decode(value)
}

pub(super) fn governance_binding_openmls_extension(
    binding: &MlsGovernanceBindingPayload,
) -> Result<Extension> {
    Ok(Extension::Unknown(
        MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
        UnknownExtension(binding.to_deterministic_cbor()?),
    ))
}

pub(super) fn governance_binding_required_capabilities_extension() -> Extension {
    Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::Unknown(
            MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
        )],
        &[],
        &[],
    ))
}

pub(super) fn governance_binding_openmls_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(
            MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
        )])
        .build()
}

pub(super) fn governance_binding_group_context_extensions(
    binding: Option<&MlsGovernanceBindingPayload>,
) -> Result<Extensions<GroupContext>> {
    let mut extensions = vec![governance_binding_required_capabilities_extension()];
    if let Some(binding) = binding {
        extensions.push(governance_binding_openmls_extension(binding)?);
    }
    Extensions::from_vec(extensions).map_err(mls_error)
}

pub(super) fn mls_error(error: impl std::fmt::Debug) -> Error {
    Error::Mls(format!("{error:?}"))
}
