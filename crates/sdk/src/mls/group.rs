use std::collections::BTreeMap;

use arkret_canonical::{base64url_decode, base64url_encode};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chrono::Utc;
use hkdf::Hkdf;
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
use sha2::Sha256;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
use zeroize::Zeroizing;

use super::identity::{ARKRET_MLS_CIPHERSUITE, ArkretMlsIdentity, decode_key_package};
use crate::{
    CryptoStore, DeviceId, DeviceMessageTarget, Did, EncryptedPayload, EncryptedPayloadScheme,
    Error, Hash, MLS_GOVERNANCE_BINDING_EXTENSION_TYPE, MlsCommitEnvelope,
    MlsGovernanceBindingExtension, MlsGovernanceBindingPayload,
    MlsGovernanceBindingValidationContext, MlsGroupStateRecord, MlsKeyPackageRecord,
    MlsProposalEnvelope, MlsWelcomeEnvelope, Operation, OperationId, ProtocolKind, RealmId, Result,
    canonical, verify_mls_governance_binding_extension,
};

const ARKRET_OPENMLS_STATE_SNAPSHOT: &str = "arkret-openmls-provider-state-v1";

/// `mls-exporter-aead-v1` content scheme id (spec encryption-and-audit §10.1).
pub const MLS_EXPORTER_AEAD_CONTENT_SCHEME: &str = "mls-exporter-aead-v1";
/// AAD / nonce-context `purpose` for the exporter-aead content scheme.
pub const MLS_EXPORTER_AEAD_CONTENT_PURPOSE: &str = "mls_exporter_aead_content";
/// MLS exporter label for the per-epoch history secret.
const HISTORY_SECRET_LABEL: &str = "ak.history-v1";
/// HKDF-Expand label deriving the content key from the history secret.
const CONTENT_KEY_LABEL: &str = "ak.content-v1";
/// XChaCha20-Poly1305 key length, `AEAD.Nk`.
const CONTENT_AEAD_KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length (24 bytes; §10.1 prefix || counter_be64).
const CONTENT_AEAD_NONCE_LEN: usize = 24;

pub struct ArkretMlsGroup {
    pub(super) identity: ArkretMlsIdentity,
    pub(super) group: MlsGroup,
    /// Per-epoch MLS exporter `history_secret[N]` retained for the
    /// `mls-exporter-aead-v1` content scheme. OpenMLS only evaluates
    /// `export_secret` against the *current* epoch, so a `history_secret`
    /// must be derived (via [`Self::derive_and_retain_history_secret`]) at
    /// the time the group is at epoch `N` and kept here so it can later be
    /// used to decrypt epoch-`N` content or be HPKE-sealed for a joiner.
    /// Empty by default; persisted across reload via [`OpenMlsStateSnapshot`].
    /// Values are [`Zeroizing`] so every retained secret is wiped from memory
    /// when the entry (or the whole group) is dropped.
    pub(super) history_secrets: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    /// Monotonic per-device AEAD nonce counter for the `mls-exporter-aead-v1`
    /// content scheme (`encoding §10.1`: `device_nonce_counter_be64`).
    /// In-memory only; never reused within an epoch because the counter only
    /// ever advances.
    pub(super) content_nonce_counter: u64,
}

#[derive(Clone, Debug)]
pub struct MlsAddMemberResult {
    pub commit: MlsCommitEnvelope,
    pub welcome: MlsWelcomeEnvelope,
}

#[derive(Clone, Debug)]
pub struct MlsAddMembersResult {
    pub commit: MlsCommitEnvelope,
    pub welcomes: Vec<MlsWelcomeEnvelope>,
}

/// Result of removing one or more leaves from an MLS group.
///
/// Unlike `MlsAddMemberResult`, Remove never produces a Welcome — surviving
/// members simply apply the commit to advance the epoch. The list of
/// `removed_leaves` makes the audit trail explicit so callers can correlate
/// the result with the originating `ak.device.revoke` / `ak.member.state`
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
    /// the same group). Useful for downstream `ak.device.revoke` event
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
    /// Retained per-epoch `history_secret[N]` (decimal epoch → base64url
    /// secret bytes). Defaults to empty for snapshots written before the
    /// `mls-exporter-aead-v1` content scheme existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    history_secrets: BTreeMap<String, String>,
    /// Persisted monotonic content AEAD nonce counter so a reloaded group
    /// never re-emits a `(sender_nonce_prefix, counter)` pair. Defaults to 0
    /// for snapshots written before the content scheme existed.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    content_nonce_counter: u64,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
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

    pub fn welcome_device_message_target(
        &self,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<DeviceMessageTarget> {
        Ok(DeviceMessageTarget {
            kind: ProtocolKind::new("ak.mls.welcome.v1")
                .map_err(|error| Error::Protocol(error.to_owned()))?,
            content: serde_json::from_value(json!({
                "group_id": self.welcome.group_id,
                "epoch": self.welcome.epoch,
                "recipient_principal_id": self.welcome.recipient_principal_id,
                "recipient_device_id": self.welcome.recipient_device_id,
                "welcome": self.welcome.welcome,
                "welcome_hash": self.welcome.welcome_hash,
                "ratchet_tree": self.welcome.ratchet_tree,
            }))?,
            expires_at,
        })
    }
}

impl MlsAddMembersResult {
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

impl ArkretMlsGroup {
    /// Whether this member still has an active leaf in the group. A client that
    /// processes a Remove commit targeting itself becomes inactive and must not
    /// treat subsequent epoch failures as an ordinary sync lag.
    pub fn is_active(&self) -> bool {
        self.group.is_active()
    }

    pub fn identity(&self) -> &ArkretMlsIdentity {
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
        let extensions = self.governance_extensions_for_next_epoch(binding)?;

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

    fn governance_extensions_for_next_epoch(
        &self,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<Extensions<GroupContext>> {
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
        Ok(extensions)
    }

    /// Content hash of the group's current key schedule, suitable for use as
    /// the `key_schedule_hash` field in `ak.component.key_schedule.v1` cell
    /// values and in `ak.profile.mls_governance_binding.full.v1` binding
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
        Hash::new(canonical::sha256_digest(authenticator.as_slice()))
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
    /// `arkret-reaction-routing-v1`, context = `realm_id`) and SFrame media
    /// keys (`media-service-binding.md` §8.1). Callers MUST treat the returned
    /// bytes as secret key material (never log or persist them in the clear).
    /// The returned buffer is [`Zeroizing`] — it is wiped on drop.
    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.group
            .export_secret(self.identity.provider.crypto(), label, context, length)
            .map(Zeroizing::new)
            .map_err(mls_error)
    }

    // ── `mls-exporter-aead-v1` history-shareable content scheme ──────────────
    //
    // The content key for epoch `N` is derived purely from the MLS exporter at
    // that epoch:
    //   history_secret[N] = MLS-Exporter("ak.history-v1", realm_id, 32)
    //   K_content[N]      = ExpandWithLabel(history_secret[N], "ak.content-v1", "", 32)
    // Content is XChaCha20-Poly1305 over (nonce, aad, plaintext) with the §10.1
    // nonce `sender_nonce_prefix || counter_be64`. Because `history_secret[N]`
    // is reproducible from `history_secret` alone (no ratchet state), a provider
    // can HPKE-seal a retained `history_secret[N]` to a joiner who can then
    // decrypt every epoch-`N` message — the basis of encrypted history sharing.

    /// Derive `history_secret[N]` for the **current** epoch and retain it for
    /// later history sharing / decryption, returning the 32-byte secret.
    ///
    /// OpenMLS only evaluates `export_secret` against the current epoch, so this
    /// MUST be called while the group is at epoch `N` (e.g. right after each
    /// commit) for the secret to be recoverable afterwards. Idempotent within an
    /// epoch: re-deriving overwrites with the identical value.
    pub fn derive_and_retain_history_secret(
        &mut self,
        realm_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let secret = self.export_secret(HISTORY_SECRET_LABEL, realm_id.as_bytes(), 32)?;
        self.history_secrets.insert(self.epoch(), secret.clone());
        Ok(secret)
    }

    /// Encrypt `plaintext` for the current epoch under the `mls-exporter-aead-v1`
    /// content scheme, returning `nonce || ciphertext` (the 24-byte XChaCha
    /// nonce prepended so the receiver decrypt path is self-describing).
    ///
    /// Side effects: derives + retains `history_secret[epoch]` (so the sender can
    /// later re-decrypt or share it) and advances the device nonce counter.
    /// `aad_bytes` is bound verbatim into the AEAD AAD together with the key_ref,
    /// ciphertext purpose and nonce per §10.1.
    pub fn encrypt_content_exporter_aead(
        &mut self,
        realm_id: &str,
        aad_bytes: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let history_secret = self.derive_and_retain_history_secret(realm_id)?;
        let content_key = derive_content_key(&history_secret)?;

        let epoch = self.epoch();
        let counter = self.content_nonce_counter;
        let nonce = self.content_aead_nonce(realm_id, epoch, counter)?;

        let aad = content_aead_aad(realm_id, &nonce, aad_bytes)?;
        let nonce_arr = content_nonce_array(&nonce)?;
        let cipher = content_cipher(&content_key)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_arr.into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("exporter-aead content encryption failed".to_owned()))?;

        self.content_nonce_counter = self
            .content_nonce_counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("content nonce counter overflow".to_owned()))?;

        let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt content produced by [`Self::encrypt_content_exporter_aead`] using
    /// a supplied `history_secret` (e.g. one retained locally for the sender's
    /// own epoch, or unsealed from a `ak.realm_key.share`). `nonce_and_ct` is the
    /// `nonce || ciphertext` blob; `aad_bytes` MUST be byte-identical to the AAD
    /// passed at encrypt time. Takes `&self` — it does not touch ratchet state.
    pub fn decrypt_content_exporter_aead(
        &self,
        history_secret: &[u8],
        realm_id: &str,
        nonce_and_ct: &[u8],
        aad_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce_and_ct.len() <= CONTENT_AEAD_NONCE_LEN {
            return Err(Error::Protocol(
                "exporter-aead content too short to contain nonce + ciphertext".to_owned(),
            ));
        }
        decrypt_content_exporter_aead_standalone(history_secret, realm_id, nonce_and_ct, aad_bytes)
    }

    /// Return the retained `history_secret[from_epoch..=to_epoch]` subset a
    /// provider seals into a `ak.realm_key.share`. Epochs outside the retained
    /// range (never derived, or pruned) are simply absent from the result.
    pub fn export_history_secret_range(
        &self,
        from_epoch: u64,
        to_epoch: u64,
    ) -> Vec<(u64, Zeroizing<Vec<u8>>)> {
        self.history_secrets
            .range(from_epoch..=to_epoch)
            .map(|(epoch, secret)| (*epoch, secret.clone()))
            .collect()
    }

    /// Compose the §10.1 content nonce for `(epoch, counter)`: the sender prefix
    /// is taken from the MLS exporter so it is bound to this device + epoch +
    /// purpose, followed by the big-endian counter.
    fn content_aead_nonce(&self, realm_id: &str, epoch: u64, counter: u64) -> Result<Vec<u8>> {
        let context = self.content_nonce_context(realm_id, epoch);
        let context_bytes = crate::crypto::aead_sender_nonce_context_bytes(&context)?;
        // Derive the sender_nonce_prefix from the MLS exporter (live MLS path),
        // mirroring `crypto::derive_aead_sender_nonce_prefix`'s exporter input.
        let mut info = Vec::with_capacity(
            crate::crypto::AEAD_NONCE_EXPORTER_LABEL.len() + 1 + context_bytes.len(),
        );
        info.extend_from_slice(crate::crypto::AEAD_NONCE_EXPORTER_LABEL.as_bytes());
        info.push(0x00);
        info.extend_from_slice(&context_bytes);
        let prefix = self.export_secret(
            crate::crypto::AEAD_NONCE_EXPORTER_LABEL,
            &info,
            CONTENT_AEAD_NONCE_LEN - crate::crypto::AEAD_NONCE_COUNTER_LEN,
        )?;
        Ok(crate::crypto::compose_aead_nonce(&prefix, counter))
    }

    fn content_nonce_context(&self, realm_id: &str, epoch: u64) -> crate::crypto::AeadNonceContext {
        crate::crypto::AeadNonceContext {
            key_ref: serde_json::json!({
                "algorithm": MLS_EXPORTER_AEAD_CONTENT_SCHEME,
                "realm_id": realm_id,
            }),
            epoch,
            device_id: self.identity.device_id.as_str().to_owned(),
            purpose: MLS_EXPORTER_AEAD_CONTENT_PURPOSE.to_owned(),
            aead_profile: crate::crypto::AEAD_PROFILE_XCHACHA20_POLY1305.to_owned(),
        }
    }

    /// Snapshot the current MLS group's member principals as canonical IDs.
    /// Iterates the OpenMLS `members()` view, parses each leaf's credential
    /// content as a UTF-8 DID string, and folds the results into a stable
    /// (deduplicated, BTreeSet-sorted) `Vec<Did>`. Useful for `ak.audit.
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

    /// Snapshot the group's active leaves for minimal-metadata author
    /// verification (encryption-and-audit.md §2.10.3). Unlike
    /// [`Self::member_principal_ids`] this does NOT dedupe — duplicate
    /// credential identities must stay visible so
    /// [`super::verify_minimal_metadata_author`] can reject them.
    pub fn active_author_leaves(&self) -> Vec<super::AuthorLeaf> {
        self.group
            .members()
            .map(|member| {
                let credential = if member.credential.credential_type()
                    == openmls::prelude::CredentialType::Basic
                {
                    super::AuthorLeafCredential::Basic {
                        identity: member.credential.serialized_content().to_vec(),
                    }
                } else {
                    super::AuthorLeafCredential::Other {
                        credential_type: format!("{:?}", member.credential.credential_type()),
                    }
                };
                super::AuthorLeaf {
                    leaf_index: member.index.u32(),
                    credential,
                    signature_key: member.signature_key,
                }
            })
            .collect()
    }

    /// Build the [`super::AuthorGroupStateView`] for this group's current
    /// state. The caller supplies the `group_state_ref` it has verified as
    /// the winning group state for this epoch (accepted genesis / winning
    /// commit event id).
    pub fn author_group_state_view(&self, group_state_ref: &str) -> super::AuthorGroupStateView {
        super::AuthorGroupStateView {
            group_id: self.group_id(),
            epoch: self.epoch(),
            group_state_ref: group_state_ref.to_owned(),
            active_leaves: self.active_author_leaves(),
        }
    }

    pub fn export_state_record(&self) -> Result<MlsGroupStateRecord> {
        let snapshot = OpenMlsStateSnapshot {
            context: ARKRET_OPENMLS_STATE_SNAPSHOT.to_owned(),
            group_id: self.group_id(),
            epoch: self.epoch(),
            principal_id: self.identity.principal_id.clone(),
            device_id: self.identity.device_id.clone(),
            signer_public_key: encode(self.identity.signer.public()),
            storage_entries: snapshot_provider_storage(&self.identity.provider)?,
            history_secrets: self
                .history_secrets
                .iter()
                .map(|(epoch, secret)| (epoch.to_string(), encode(secret)))
                .collect(),
            content_nonce_counter: self.content_nonce_counter,
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
        if snapshot.context != ARKRET_OPENMLS_STATE_SNAPSHOT {
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
            ARKRET_MLS_CIPHERSUITE.signature_algorithm(),
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

        let mut history_secrets = BTreeMap::new();
        for (epoch, secret_b64) in &snapshot.history_secrets {
            let epoch: u64 = epoch.parse().map_err(|_| {
                Error::Protocol("OpenMLS snapshot history_secret epoch is not a u64".to_owned())
            })?;
            history_secrets.insert(epoch, Zeroizing::new(decode(secret_b64)?));
        }

        Ok(Self {
            identity: ArkretMlsIdentity {
                principal_id: record.principal_id.clone(),
                device_id: record.device_id.clone(),
                provider,
                signer,
                credential,
            },
            group,
            history_secrets,
            content_nonce_counter: snapshot.content_nonce_counter,
        })
    }

    /// Produce a "self-update" commit envelope — the MLS commit that
    /// rotates the local member's leaf-node key without changing
    /// membership. Callers (e.g. inkson's chat Send Secure path) use
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
        self.add_member_with_optional_governance_binding(member_key_package, None)
    }

    pub fn add_member_with_governance_binding(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsAddMemberResult> {
        self.add_member_with_optional_governance_binding(
            member_key_package,
            Some(governance_binding),
        )
    }

    fn add_member_with_optional_governance_binding(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsAddMemberResult> {
        let result = self.add_members_with_optional_governance_binding(
            std::slice::from_ref(member_key_package),
            governance_binding,
        )?;
        let welcome = result
            .welcomes
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("MLS add_member returned no Welcome".to_owned()))?;
        Ok(MlsAddMemberResult {
            commit: result.commit,
            welcome,
        })
    }

    pub fn add_members(
        &mut self,
        member_key_packages: &[MlsKeyPackageRecord],
    ) -> Result<MlsAddMembersResult> {
        self.add_members_with_optional_governance_binding(member_key_packages, None)
    }

    pub fn add_members_with_governance_binding(
        &mut self,
        member_key_packages: &[MlsKeyPackageRecord],
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsAddMembersResult> {
        self.add_members_with_optional_governance_binding(
            member_key_packages,
            Some(governance_binding),
        )
    }

    fn add_members_with_optional_governance_binding(
        &mut self,
        member_key_packages: &[MlsKeyPackageRecord],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsAddMembersResult> {
        if member_key_packages.is_empty() {
            return Err(Error::Protocol(
                "refusing to add an empty MLS KeyPackage batch".to_owned(),
            ));
        }
        let mut key_packages = Vec::with_capacity(member_key_packages.len());
        for member_key_package in member_key_packages {
            if !member_key_package.is_usable() {
                return Err(Error::Protocol(
                    "refusing to add revoked MLS KeyPackage".to_owned(),
                ));
            }
            key_packages.push(decode_key_package(
                &self.identity.provider,
                member_key_package,
            )?);
        }
        let governance_extensions = governance_binding
            .map(|binding| self.governance_extensions_for_next_epoch(binding))
            .transpose()?;
        let mut builder = self.group.commit_builder().propose_adds(key_packages);
        if let Some(extensions) = governance_extensions {
            builder = builder
                .propose_group_context_extensions(extensions)
                .map_err(mls_error)?;
        }
        let bundle = builder
            .force_self_update(true)
            .load_psks(self.identity.provider.storage())
            .map_err(mls_error)?
            .build(
                self.identity.provider.rand(),
                self.identity.provider.crypto(),
                &self.identity.signer,
                |_| true,
            )
            .map_err(mls_error)?
            .stage_commit(&self.identity.provider)
            .map_err(mls_error)?;
        let welcome = bundle.to_welcome_msg().ok_or_else(|| {
            Error::Protocol("MLS add_members produced no Welcome message".to_owned())
        })?;
        let (commit, ..) = bundle.into_contents();
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let welcome_bytes = welcome.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);
        let commit_digest = Hash::new(canonical::sha256_digest(&commit_bytes))?;
        let welcome_hash = Hash::new(canonical::sha256_digest(&welcome_bytes))?;
        let group_id = self.group_id();
        let epoch = self.epoch();
        let welcomes = member_key_packages
            .iter()
            .map(|member_key_package| MlsWelcomeEnvelope {
                group_id: group_id.clone(),
                epoch,
                recipient_principal_id: member_key_package.principal_id.clone(),
                recipient_device_id: member_key_package.device_id.clone(),
                welcome: encode(&welcome_bytes),
                welcome_hash: welcome_hash.clone(),
                ratchet_tree: ratchet_tree.clone(),
            })
            .collect();

        Ok(MlsAddMembersResult {
            commit: MlsCommitEnvelope {
                group_id,
                epoch,
                commit: encode(&commit_bytes),
                commit_digest,
                ratchet_tree,
                app_state_ref: None,
            },
            welcomes,
        })
    }

    /// Remove every leaf whose BasicCredential identity matches `target`.
    ///
    /// In the current credential encoding (`mls.rs::ArkretMlsIdentity::new_basic`)
    /// the leaf identity bytes are `principal_id.as_str().as_bytes()` — they
    /// do NOT include the device id. Therefore matching by principal removes
    /// **all leaves** owned by that principal in this group. To remove a
    /// specific device, use [`Self::remove_member_by_leaf`] with a leaf
    /// index resolved from out-of-band device → leaf bookkeeping.
    ///
    /// Errors when the target principal has no leaf in this group.
    pub fn remove_member_by_principal(&mut self, target: &Did) -> Result<MlsRemoveMemberResult> {
        self.remove_member_by_principal_with_optional_governance_binding(target, None)
    }

    pub fn remove_member_by_principal_with_governance_binding(
        &mut self,
        target: &Did,
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_member_by_principal_with_optional_governance_binding(
            target,
            Some(governance_binding),
        )
    }

    fn remove_member_by_principal_with_optional_governance_binding(
        &mut self,
        target: &Did,
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
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

        self.remove_leaves(&leaves, governance_binding)
    }

    /// Remove a single leaf by its raw OpenMLS leaf index. Use this when the
    /// caller maintains an explicit (principal, device_id) → leaf_index map
    /// (e.g. a inkson DeviceManager with leaf bookkeeping) and wants to
    /// revoke just one device of a multi-device principal.
    pub fn remove_member_by_leaf(&mut self, leaf_index: u32) -> Result<MlsRemoveMemberResult> {
        self.remove_leaves(&[LeafNodeIndex::new(leaf_index)], None)
    }

    pub fn remove_member_by_leaf_with_governance_binding(
        &mut self,
        leaf_index: u32,
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_leaves(&[LeafNodeIndex::new(leaf_index)], Some(governance_binding))
    }

    fn remove_leaves(
        &mut self,
        leaves: &[LeafNodeIndex],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
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

        let governance_extensions = governance_binding
            .map(|binding| self.governance_extensions_for_next_epoch(binding))
            .transpose()?;
        let mut builder = self.group.commit_builder().consume_proposal_store(true);
        if let Some(extensions) = governance_extensions {
            builder = builder
                .propose_group_context_extensions(extensions)
                .map_err(mls_error)?;
        }
        let (commit, _welcome_opt, _) = builder
            .load_psks(self.identity.provider.storage())
            .map_err(mls_error)?
            .build(
                self.identity.provider.rand(),
                self.identity.provider.crypto(),
                &self.identity.signer,
                |_| true,
            )
            .map_err(mls_error)?
            .stage_commit(&self.identity.provider)
            .map_err(mls_error)?
            .into_contents();
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
            // ArkretMlsIdentity leaves carry UTF-8 DID strings.
            let principal = std::str::from_utf8(&identity_bytes)
                .ok()
                .and_then(|s| Did::new(s.to_owned()).ok())
                .unwrap_or_else(|| {
                    Did::new(format!("did:arkret:unknown-leaf-{}", idx.u32()))
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
        identity: ArkretMlsIdentity,
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

        Ok(Self {
            identity,
            group,
            history_secrets: BTreeMap::new(),
            content_nonce_counter: 0,
        })
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
        aad: Option<arkret_core::EncryptedEnvelopeAad>,
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
            key_ref: Some(arkret_core::KeyRefObject::mls_rfc9420(
                self.group_id(),
                epoch,
            )),
        })
    }

    /// Encrypt `plaintext` under the §2.10 `mls-exporter-aead-v1` content scheme
    /// and return the full [`EncryptedPayload`] (scheme / key_ref / digest set),
    /// so a late joiner granted the epoch's `history_secret` can decrypt it.
    ///
    /// `aead_aad_bytes` is the history-binding AAD (e.g. the per-epoch
    /// `history_content_aad_bytes(realm_id, epoch)`); it MUST be reconstructed
    /// byte-identically on the decrypt side. `payload_aad` is the optional
    /// routing AAD carried in the envelope (mirrors
    /// [`Self::encrypt_payload_with_aad`]). Side effect: derives + retains this
    /// epoch's `history_secret` (so the author can re-decrypt and later share it).
    pub fn encrypt_payload_exporter_aead(
        &mut self,
        content_type: impl Into<String>,
        realm_id: &str,
        aead_aad_bytes: &[u8],
        payload_aad: Option<arkret_core::EncryptedEnvelopeAad>,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        let nonce_and_ct =
            self.encrypt_content_exporter_aead(realm_id, aead_aad_bytes, plaintext)?;
        let epoch = self.epoch();
        let content_type = content_type.into();
        let payload_digest = EncryptedPayload::payload_digest_for_scheme(
            EncryptedPayloadScheme::MlsExporterAeadV1,
            epoch,
            &content_type,
            payload_aad.as_ref(),
            &nonce_and_ct,
        )?;
        Ok(EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsExporterAeadV1,
            group_id: self.group_id(),
            epoch,
            content_type,
            ciphertext: encode(&nonce_and_ct),
            aad: payload_aad,
            payload_digest,
            key_ref: Some(arkret_core::KeyRefObject::mls_exporter_aead(
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

    /// Stage an incoming by-reference MLS proposal so a subsequent
    /// [`apply_commit`] that references it (e.g. a Remove commit produced by
    /// [`remove_member_by_principal`]) can resolve `MissingProposal`.
    ///
    /// The commit envelope produced for Remove carries the proposals
    /// out-of-band in [`MlsRemoveMemberResult::proposals`]; surviving members
    /// MUST apply each of those proposals through this method before applying
    /// the referencing commit. Add commits inline their proposals and never
    /// require this step.
    pub fn apply_proposal(&mut self, envelope: &MlsProposalEnvelope) -> Result<()> {
        let proposal_bytes = decode(&envelope.proposal)?;
        let actual_digest = canonical::sha256_digest(&proposal_bytes);
        if actual_digest != envelope.proposal_digest.as_str() {
            return Err(Error::Protocol("MLS Proposal hash mismatch".to_owned()));
        }

        let message =
            MlsMessageIn::tls_deserialize_exact(proposal_bytes.as_slice()).map_err(mls_error)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Protocol("MLS Proposal is not a protocol message".to_owned()))?;
        let processed = self
            .group
            .process_message(&self.identity.provider, protocol_message)
            .map_err(mls_error)?;

        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(self.identity.provider.storage(), *proposal)
                    .map_err(mls_error)?;
                Ok(())
            }
            _ => Err(Error::Protocol("expected MLS Proposal".to_owned())),
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

/// `K_content = ExpandWithLabel(history_secret, "ak.content-v1", "", AEAD.Nk)`.
///
/// Per spec the history_secret already has full entropy (it is an MLS exporter
/// output), so the history_secret is used directly as the HKDF PRK (Expand-only,
/// no Extract step) — matching `ExpandWithLabel(history_secret, …)`.
/// Standalone (group-free) variant of
/// [`ArkretMlsGroup::decrypt_content_exporter_aead`]. A device that holds a
/// granted `history_secret` but has **no** local MLS group snapshot for the
/// Realm (e.g. a member granted history before processing its own Welcome) can
/// decrypt `mls-exporter-aead-v1` content with this. `nonce_and_ct` is
/// `nonce || ciphertext`; `aad_bytes` MUST be byte-identical to encrypt time.
pub fn decrypt_content_exporter_aead_standalone(
    history_secret: &[u8],
    realm_id: &str,
    nonce_and_ct: &[u8],
    aad_bytes: &[u8],
) -> Result<Vec<u8>> {
    if nonce_and_ct.len() <= CONTENT_AEAD_NONCE_LEN {
        return Err(Error::Protocol(
            "exporter-aead content too short to contain nonce + ciphertext".to_owned(),
        ));
    }
    let (nonce, ciphertext) = nonce_and_ct.split_at(CONTENT_AEAD_NONCE_LEN);
    let content_key = derive_content_key(history_secret)?;
    let aad = content_aead_aad(realm_id, nonce, aad_bytes)?;
    let nonce_arr = content_nonce_array(nonce)?;
    let cipher = content_cipher(&content_key)?;
    cipher
        .decrypt(
            &nonce_arr.into(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("exporter-aead content tag check failed".to_owned()))
}

fn derive_content_key(history_secret: &[u8]) -> Result<Zeroizing<[u8; CONTENT_AEAD_KEY_LEN]>> {
    let hkdf = Hkdf::<Sha256>::from_prk(history_secret)
        .map_err(|_| Error::Crypto("history_secret too short for HKDF PRK".to_owned()))?;
    let info = mls_kdf_label(CONTENT_AEAD_KEY_LEN, CONTENT_KEY_LABEL, &[])?;
    let mut key = Zeroizing::new([0u8; CONTENT_AEAD_KEY_LEN]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| Error::Crypto("content key derivation failed".to_owned()))?;
    Ok(key)
}

fn mls_kdf_label(length: usize, label: &str, context: &[u8]) -> Result<Vec<u8>> {
    let length = u16::try_from(length)
        .map_err(|_| Error::Crypto("MLS KDF output length exceeds uint16".to_owned()))?;
    let full_label = format!("MLS 1.0 {label}");
    let mut encoded = Vec::with_capacity(2 + full_label.len() + context.len() + 8);
    encoded.extend_from_slice(&length.to_be_bytes());
    encode_mls_varint(full_label.len(), &mut encoded)?;
    encoded.extend_from_slice(full_label.as_bytes());
    encode_mls_varint(context.len(), &mut encoded)?;
    encoded.extend_from_slice(context);
    Ok(encoded)
}

fn encode_mls_varint(value: usize, output: &mut Vec<u8>) -> Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| Error::Crypto("MLS vector length exceeds uint32".to_owned()))?;
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => output.extend_from_slice(&(value | 0x8000_0000).to_be_bytes()),
        _ => {
            return Err(Error::Crypto(
                "MLS vector length exceeds varint range".to_owned(),
            ));
        }
    }
    Ok(())
}

fn content_cipher(content_key: &[u8; CONTENT_AEAD_KEY_LEN]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| Error::Crypto("invalid XChaCha20-Poly1305 content key length".to_owned()))
}

fn content_nonce_array(nonce: &[u8]) -> Result<[u8; CONTENT_AEAD_NONCE_LEN]> {
    nonce
        .try_into()
        .map_err(|_| Error::Crypto("exporter-aead content nonce must be 24 bytes".to_owned()))
}

/// Canonical AAD for the exporter-aead content scheme (§10.1): binds the
/// `key_ref` (scheme + realm), `purpose`, `nonce`, and the caller-supplied
/// `aad_bytes` (e.g. an `EncryptedEnvelopeAad` digest). The `epoch` is **not**
/// folded in here — it is not load-bearing for decryption (the content key is
/// the history_secret) and is not recoverable on the decrypt side from the
/// `nonce || ciphertext` blob alone. Any epoch binding the caller needs must be
/// encoded into `aad_bytes`, which both sides reconstruct identically and which
/// is the actual integrity anchor. The nonce already binds device + epoch +
/// purpose via the MLS exporter prefix.
fn content_aead_aad(realm_id: &str, nonce: &[u8], aad_bytes: &[u8]) -> Result<Vec<u8>> {
    let map = serde_json::json!({
        "purpose": MLS_EXPORTER_AEAD_CONTENT_PURPOSE,
        "key_ref": {
            "algorithm": MLS_EXPORTER_AEAD_CONTENT_SCHEME,
            "realm_id": realm_id,
        },
        "nonce": base64url_encode(nonce),
        "aad": base64url_encode(aad_bytes),
    });
    Ok(canonical::canonical_json_bytes(&map)?)
}

pub(super) fn snapshot_provider_storage(
    provider: &OpenMlsRustCrypto,
) -> Result<BTreeMap<String, String>> {
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

pub(super) fn restore_provider_storage(
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

pub(super) fn decode(value: &str) -> Result<Vec<u8>> {
    Ok(base64url_decode(value)?)
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

/// Leaf-node capabilities for a *last-resort* KeyPackage. A KeyPackage marked
/// `mark_as_last_resort()` carries the OpenMLS `last_resort` extension, and
/// RFC 9420 §7.2 requires a leaf node to declare (in its `capabilities`) every
/// extension present on it. Without `ExtensionType::LastResort` here the
/// KeyPackage is self-inconsistent and an `Add` of it fails validation with
/// `UnsupportedExtension` — which is exactly what stalls admin admission of a
/// last-resort invitee. The governance-binding extension stays required for the
/// group; `LastResort` is an extra capability the group never uses, so adding
/// it imposes no requirement on existing members.
pub(super) fn governance_binding_last_resort_openmls_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![
            ExtensionType::Unknown(MLS_GOVERNANCE_BINDING_EXTENSION_TYPE),
            ExtensionType::LastResort,
        ])
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

#[cfg(test)]
mod content_scheme_anchor_tests {
    use chacha20poly1305::aead::{Aead, Payload};
    use serde_json::json;

    use super::{
        MLS_EXPORTER_AEAD_CONTENT_PURPOSE, MLS_EXPORTER_AEAD_CONTENT_SCHEME, content_aead_aad,
        content_cipher, content_nonce_array, decrypt_content_exporter_aead_standalone,
        derive_content_key, mls_kdf_label,
    };
    use crate::crypto::{
        AEAD_PROFILE_XCHACHA20_POLY1305, AeadNonceContext, compose_aead_nonce,
        derive_aead_sender_nonce_prefix,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000042";

    /// Pins the byte-exact `mls-exporter-aead-v1` content-scheme chain from a
    /// fixed history_secret — RFC 9420 ExpandWithLabel content key, exporter
    /// nonce-prefix derivation (`arkret-aead-sender-nonce-prefix-v1` label +
    /// canonical context bytes), canonical AAD construction, and the AEAD
    /// ciphertext itself. Any silent change to a label, context field, AAD
    /// shape or nonce composition breaks these bytes.
    #[test]
    fn exporter_aead_content_scheme_regression_anchor() {
        let history_secret = [0x42u8; 32];
        let content_key = derive_content_key(&history_secret).unwrap();
        assert_eq!(
            hex(content_key.as_ref()),
            "d5060a411113d876e41a0c68710882bdca7b8de490e3b3201668e860098ef9e0",
            "ak.content-v1 ExpandWithLabel content key drifted"
        );

        // Exporter label/context binding: the deterministic mirror of the
        // MLS exporter input (label || 0x00 || canonical context bytes).
        let context = AeadNonceContext {
            key_ref: json!({
                "algorithm": MLS_EXPORTER_AEAD_CONTENT_SCHEME,
                "realm_id": REALM,
            }),
            epoch: 3,
            device_id: "ak:device:01904100-0000-7000-8000-000000000007".to_owned(),
            purpose: MLS_EXPORTER_AEAD_CONTENT_PURPOSE.to_owned(),
            aead_profile: AEAD_PROFILE_XCHACHA20_POLY1305.to_owned(),
        };
        let prefix = derive_aead_sender_nonce_prefix(&[0x24u8; 32], &context, 24).unwrap();
        assert_eq!(
            hex(&prefix),
            "0fc040d005169d79fec51dcd48188a9e",
            "exporter label/context nonce-prefix derivation drifted"
        );

        let nonce = compose_aead_nonce(&prefix, 7);
        assert_eq!(nonce.len(), 24);
        assert_eq!(&nonce[16..], 7u64.to_be_bytes(), "counter suffix drifted");

        let aad_bytes = b"anchor-aad";
        let aad = content_aead_aad(REALM, &nonce, aad_bytes).unwrap();
        assert_eq!(
            std::str::from_utf8(&aad).unwrap(),
            "{\"aad\":\"YW5jaG9yLWFhZA\",\"key_ref\":{\"algorithm\":\"mls-exporter-aead-v1\",\"realm_id\":\"ak:realm:01904100-0000-7000-8000-000000000042\"},\"nonce\":\"D8BA0AUWnXn-xR3NSBiKngAAAAAAAAAH\",\"purpose\":\"mls_exporter_aead_content\"}",
            "canonical content AAD drifted"
        );

        let plaintext: &[u8] = b"exporter-aead regression anchor";
        let cipher = content_cipher(&content_key).unwrap();
        let nonce_arr = content_nonce_array(&nonce).unwrap();
        let ciphertext = cipher
            .encrypt(
                &nonce_arr.into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(
            hex(&ciphertext),
            "6adccf12da17af55e9cda3a5cea7201fd92ca1dab391198f7a906769fe7a6f0a9b3b43b113b80db52347750c8c6dea",
            "exporter-aead ciphertext drifted"
        );

        // Round-trip through the standalone decrypt path.
        let mut nonce_and_ct = nonce.clone();
        nonce_and_ct.extend_from_slice(&ciphertext);
        let recovered = decrypt_content_exporter_aead_standalone(
            &history_secret,
            REALM,
            &nonce_and_ct,
            aad_bytes,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);

        // Tamper negative: a flipped ciphertext byte must fail the tag check.
        let mut tampered = nonce_and_ct;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            decrypt_content_exporter_aead_standalone(&history_secret, REALM, &tampered, aad_bytes)
                .is_err()
        );
    }

    #[test]
    fn content_key_matches_registered_spec_vector() {
        let fixture =
            crate::schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        let case = &fixture["cases"][0];
        let history_secret =
            hex::decode(case["expected"]["history_secret_hex"].as_str().unwrap()).unwrap();
        let expected_info = case["expected"]["content_expand_with_label_info_hex"]
            .as_str()
            .unwrap();
        let expected_key = case["expected"]["content_key_hex"].as_str().unwrap();

        assert_eq!(
            hex(&mls_kdf_label(32, "ak.content-v1", &[]).unwrap()),
            expected_info
        );
        assert_eq!(
            hex(derive_content_key(&history_secret).unwrap().as_ref()),
            expected_key
        );
    }
}
