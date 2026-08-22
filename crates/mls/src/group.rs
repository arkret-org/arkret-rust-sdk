use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_models_crypto::{
    EncryptedPayload, EventContentPreEncryptionHeader, MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
    MlsCommitEnvelope, MlsEndpointIdentity, MlsGovernanceBindingExtension,
    MlsGovernanceBindingPayload, MlsGovernanceBindingValidationContext, MlsGroupStateRecord,
    MlsGroupStateSink, MlsKeyPackageRecord, MlsProposalEnvelope, MlsWelcomeEnvelope,
    verify_mls_governance_binding_extension,
};
use arkret_wire::{
    DeviceId, DidCoreId, EncryptedPayloadScheme, EventCandidateBinding, EventCandidateBindingKey,
    EventCandidateBindingOutcome, EventId, Hash, HistoryCandidateMaterialRecord,
    HistoryEffectiveScope, LocalAuthoritativeHistorySecret, MLS_CIPHERSUITES, ReasonCode, ScopeRef,
    canonical,
};
use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, Extension, ExtensionType, Extensions,
    GroupContext, GroupId, LeafNodeIndex, LeafNodeParameters, MlsGroup, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProcessedMessageContent, RatchetTreeIn,
    RequiredCapabilitiesExtension, StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::identity::{
    ARKRET_MLS_CIPHERSUITE, ARKRET_MLS_CIPHERSUITE_CANONICAL_ID, ArkretMlsIdentity,
    decode_key_package, decode_leaf_credential, leaf_credential_bytes,
};
use crate::{MlsError as Error, Result};

const ARKRET_OPENMLS_STATE_SNAPSHOT: &str = "arkret-openmls-provider-state-v1";

/// MLS exporter label for the per-epoch history secret.
pub(crate) const HISTORY_SECRET_LABEL: &str = arkret_wire::ExporterLabelId::HISTORY_V1;
/// HKDF-Expand label deriving the content key from the history secret.
const CONTENT_KEY_LABEL: &str = arkret_wire::ExporterLabelId::CONTENT_V1;
const REACTION_ROUTING_ROOT_LABEL: &str = arkret_wire::ExporterLabelId::REACTION_ROUTING_ROOT_V1;
const REACTION_ROUTING_LABEL: &str = arkret_wire::ExporterLabelId::REACTION_ROUTING_V1;

/// AEAD parameters an `aead_profile` fixes, shared by both MLS-exporter-derived
/// AEAD domains: `mls_exporter_aead_v1` content (this module) and
/// `ak.signal_exporter_aead.v1` (`crate::signal`).
///
/// `encoding.md` §10.1 splits the `aead_profile` vocabulary by how the key was
/// obtained, not by which envelope carries it: application-layer HPKE sealing
/// surfaces take `hpke-suite-registry.json`, while every domain whose key comes
/// out of the MLS exporter takes the `canonical_id` of the
/// `mls-ciphersuite-registry.json` row the group at `key_ref.group_state_ref`
/// actually negotiated. Content encryption is in the second set
/// (`crypto-media/encryption-and-audit.md` §2.10.2 states it verbatim and
/// forbids an HPKE suite name *or any local alias*), so both domains resolve
/// their algorithm here rather than naming one.
///
/// `#[non_exhaustive]` and resolved through the generated registry so that
/// activating a further ciphersuite is a new variant plus a new arm here — and
/// nothing at all on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExporterAeadSuite {
    /// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`: `AEAD.Nk` = 16,
    /// `N_AEAD` = 12, leaving a 4-byte sender nonce prefix.
    Aes128Gcm,
}

impl ExporterAeadSuite {
    /// `AEAD.Nk` — the key length `ExpandWithLabel` is asked for
    /// (`encryption-and-audit.md` §2.10.1 for content, the `ak.signal-v1`
    /// registry row for the Signal rail).
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
        }
    }

    /// `N_AEAD`, the AEAD's nonce length.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 12,
        }
    }

    /// The `mls-ciphersuite-registry.json` `canonical_id` this suite is.
    ///
    /// The inverse of [`resolve`](Self::resolve). It exists so a producer writes
    /// the registry id onto the wire rather than a local spelling —
    /// `encoding.md` §10.1 forbids inventing a third layer of AEAD names.
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Aes128Gcm => ARKRET_MLS_CIPHERSUITE_CANONICAL_ID,
        }
    }

    /// `N_AEAD - 8`: the exporter output length of the sender nonce prefix.
    pub const fn nonce_prefix_len(self) -> usize {
        self.nonce_len() - arkret_crypto::AEAD_NONCE_COUNTER_LEN
    }

    /// Resolve an `aead_profile` against `mls-ciphersuite-registry.json`.
    ///
    /// Two separate gates, both required by `encoding.md` §10.1: the row must
    /// exist, and it must be `active`. A `reserved` row (the ChaCha20 and the
    /// two PQ hybrid rows today) MUST NOT appear on the wire before its
    /// activation requirements are met and the registry is released, so it is
    /// rejected here rather than silently accepted because the underlying
    /// library happens to implement it.
    pub fn resolve(aead_profile: &str) -> Result<Self> {
        let row = MLS_CIPHERSUITES
            .iter()
            .find(|row| row.canonical_id == aead_profile)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "{}: aead_profile {aead_profile} is not a registered MLS ciphersuite",
                    ReasonCode::UNSUPPORTED_AEAD_PROFILE
                ))
            })?;
        if row.status != "active" {
            return Err(Error::Protocol(format!(
                "{}: MLS ciphersuite {aead_profile} is {} and MUST NOT appear on the wire",
                ReasonCode::UNSUPPORTED_AEAD_PROFILE,
                row.status
            )));
        }
        if aead_profile == ARKRET_MLS_CIPHERSUITE_CANONICAL_ID {
            return Ok(Self::Aes128Gcm);
        }
        // An active registry row this build has no AEAD implementation for.
        // Fail closed rather than fall back to another suite's algorithm.
        Err(Error::Protocol(format!(
            "{}: no exporter AEAD implementation for active MLS ciphersuite {aead_profile}",
            ReasonCode::UNSUPPORTED_AEAD_PROFILE
        )))
    }

    pub(crate) fn seal(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm => aes128_gcm(key)?
                .encrypt(
                    &aes_gcm_nonce(nonce)?.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Error::Crypto("exporter AEAD encryption failed".to_owned())),
        }
    }

    pub(crate) fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm => aes128_gcm(key)?
                .decrypt(
                    &aes_gcm_nonce(nonce)?.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Error::Crypto("exporter AEAD tag check failed".to_owned())),
        }
    }
}

fn aes128_gcm(key: &[u8]) -> Result<Aes128Gcm> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid AES-128-GCM key length".to_owned()))
}

fn aes_gcm_nonce(nonce: &[u8]) -> Result<[u8; 12]> {
    nonce
        .try_into()
        .map_err(|_| Error::Crypto("AES-GCM nonce must be 12 bytes".to_owned()))
}

pub struct ArkretMlsGroup {
    pub(super) identity: ArkretMlsIdentity,
    pub(super) group: MlsGroup,
    /// Per-epoch MLS exporter `history_secret[N]` retained for the
    /// `mls_exporter_aead_v1` content scheme. OpenMLS only evaluates
    /// `export_secret` against the *current* epoch, so a `history_secret`
    /// must be derived (via [`Self::derive_and_retain_history_secret`]) at
    /// the time the group is at epoch `N` and kept here so it can later be
    /// used to decrypt epoch-`N` content or be HPKE-sealed for a joiner.
    /// Empty by default; persisted across reload via [`OpenMlsStateSnapshot`].
    /// Values are [`Zeroizing`] so every retained secret is wiped from memory
    /// when the entry (or the whole group) is dropped.
    pub(super) history_secrets: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    /// Monotonic per-device AEAD nonce counter for the `mls_exporter_aead_v1`
    /// content scheme (`encoding §10.1`: `device_nonce_counter_be64`). Never
    /// reused within an epoch because the counter only ever advances, and
    /// carried through [`OpenMlsStateSnapshot`] because §10.1 makes persisting
    /// it mandatory: a device that cannot recover the counter for its epoch
    /// MUST commit to a new epoch rather than restart at 0.
    pub(super) content_nonce_counter: u64,
    /// Monotonic per-device AEAD nonce counter for the
    /// `ak.signal_exporter_aead.v1` Signal scheme (`encoding §10.1`). Kept
    /// separate from [`Self::content_nonce_counter`] because `purpose` is part
    /// of the nonce-derivation tuple: the two domains have disjoint nonce
    /// spaces, and sharing one counter would only waste range. Persisted with
    /// the group snapshot — see [`crate::signal`] for the reuse contract.
    pub(super) signal_nonce_counter: u64,
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
    pub removed_principals: Vec<DidCoreId>,
}

// NOTE: `MlsRemoveMemberResult` / `MlsAddMemberResult` / `MlsAddMembersResult`
// no longer carry `commit_operation` / `welcome_device_message_target`
// projections. The envelope -> local scheduler draft and envelope ->
// `DeviceMessageTarget` bindings live in `arkret-event-draft`
// (`MlsEnvelopeOperationExt`, `MlsWelcomeTargetExt`) so this OpenMLS-isolation
// layer never depends on the drafting / collaboration crates.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OpenMlsStateSnapshot {
    context: String,
    group_id: String,
    epoch: u64,
    principal_id: DidCoreId,
    device_id: DeviceId,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
    /// Retained per-epoch `history_secret[N]` (decimal epoch → base64url
    /// secret bytes). Defaults to empty for snapshots written before the
    /// `mls_exporter_aead_v1` content scheme existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    history_secrets: BTreeMap<String, String>,
    /// Persisted monotonic content AEAD nonce counter so a reloaded group
    /// never re-emits a counter in the same sender scope. Defaults to 0
    /// for snapshots written before the content scheme existed.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    content_nonce_counter: u64,
    /// Persisted monotonic Signal AEAD nonce counter. `encoding.md` §10.1
    /// makes persistence mandatory: a device that cannot recover its counter
    /// for an epoch MUST advance the epoch rather than restart at 0. The
    /// counter only ever reaches this snapshot from an in-memory value that
    /// has already been advanced past every nonce this device emitted, so a
    /// missing field can only mean "never sealed a Signal", i.e. 0.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    signal_nonce_counter: u64,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
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

    /// Exact RFC 9420 MLSMessage(GroupInfo) and external ratchet-tree bytes
    /// for a content-addressed `ak.mls.genesis` publication.
    pub fn public_group_state_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let group_info = self
            .group
            .export_group_info(
                self.identity.provider.crypto(),
                &self.identity.signer,
                false,
            )
            .map_err(mls_error)?
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let ratchet_tree = self
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        Ok((group_info, ratchet_tree))
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
        Ok(self
            .governance_binding_extension()
            .map(|extension| extension.decode_payload())
            .transpose()?)
    }

    pub fn verify_current_governance_binding(
        &self,
        expected: &MlsGovernanceBindingValidationContext<'_>,
    ) -> Result<MlsGovernanceBindingPayload> {
        let extension = self.governance_binding_extension();
        Ok(verify_mls_governance_binding_extension(
            extension.as_ref(),
            expected,
        )?)
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
    /// the `key_schedule_hash` field in `ak.component.mls.key_schedule.v1` cell
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
    /// e.g. the reaction routing root (`encryption-and-audit.md` §2.9, label
    /// `ak.reaction-routing-root-v1`, canonical effective-scope context) and SFrame media
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

    /// Derive the current epoch's reaction routing tag from the protocol's
    /// complete routing context. The returned value is the 32-byte HMAC output
    /// encoded as 43-character base64url without padding.
    pub fn reaction_routing_tag(
        &mut self,
        realm_id: &str,
        scheme: EncryptedPayloadScheme,
        effective_scope: &ScopeRef,
        target_ref: &EventId,
        routing_window: u64,
        canonical_emoji: &str,
    ) -> Result<String> {
        let routing_root = match scheme {
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                self.derive_and_retain_history_secret(realm_id)?
            }
            EncryptedPayloadScheme::MlsRfc9420 => self.export_secret(
                REACTION_ROUTING_ROOT_LABEL,
                &effective_scope.canonical_effective_scope_key_bytes()?,
                32,
            )?,
        };
        reaction_routing_tag_from_root(
            &routing_root,
            effective_scope,
            target_ref,
            routing_window,
            canonical_emoji,
        )
    }

    // ── `mls_exporter_aead_v1` history-shareable content scheme ──────────────
    //
    // The content key for epoch `N` is derived purely from the MLS exporter at
    // that epoch:
    //   history_secret[N] = MLS-Exporter("ak.history-v1", realm_id, KDF.Nh)
    //   K_content[N,S]    = ExpandWithLabel(history_secret[N], "ak.content-v1", S, AEAD.Nk)
    // `AEAD` is the one the group negotiated ([`ExporterAeadSuite`]) — §2.10.1
    // takes its lengths and §2.10.2 its `aead_profile` from the MLS ciphersuite
    // registry, never from a locally chosen algorithm. Content is sealed over
    // (nonce, aad, plaintext) with the §10.1 nonce
    // `I2OSP(durable_sender_counter, AEAD.Nn)`. Because `history_secret[N]`
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
        let secret = self.derive_history_secret(realm_id)?;
        self.history_secrets.insert(self.epoch(), secret.clone());
        Ok(secret)
    }

    /// Derive `history_secret[N]` for the current epoch **without** retaining
    /// it.
    ///
    /// Retention exists so a late joiner can be granted readable history; an
    /// ephemeral domain (the Signal rail) must not cause an epoch to be
    /// retained as shareable history just because a typing indicator was sent
    /// in it. Callers that do want the sharing side effect use
    /// [`Self::derive_and_retain_history_secret`].
    pub(crate) fn derive_history_secret(&self, realm_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.export_secret(HISTORY_SECRET_LABEL, realm_id.as_bytes(), 32)
    }

    /// Encrypt `plaintext` for the current epoch under the `mls_exporter_aead_v1`
    /// content scheme, returning the durable counter and ciphertext. The nonce
    /// is `I2OSP(counter, AEAD.Nn)` and is never duplicated on wire.
    ///
    /// Side effects: derives + retains `history_secret[epoch]` (so the sender can
    /// later re-decrypt or share it) and advances the device nonce counter.
    /// The caller supplies the already reconstructed closed pre-encryption
    /// header. The ordinary-profile sender domain is derived internally from
    /// the local identity and exact active LeafNode and must match the header.
    pub fn encrypt_content_exporter_aead(
        &mut self,
        realm_id: &str,
        header: &EventContentPreEncryptionHeader,
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        let sender_domain = self.verified_local_content_sender_domain(&header.sender_domain)?;
        header.validate()?;
        if header.scheme != EncryptedPayloadScheme::MlsExporterAeadV1
            || header.mls_group_id != self.group_id()
            || header.epoch != self.epoch()
            || header.sender_domain.as_bytes() != sender_domain
        {
            return Err(Error::Protocol(
                "exporter content header does not match the active MLS sender state".to_owned(),
            ));
        }
        // Resolved before any secret is derived: an unregistered or non-active
        // ciphersuite must fail closed rather than produce ciphertext under an
        // algorithm no receiver is allowed to accept.
        let suite = self.content_suite()?;
        let history_secret = self.derive_and_retain_history_secret(realm_id)?;
        let content_key = derive_content_key_from_history_secret(
            &history_secret,
            &sender_domain,
            suite.key_len(),
        )?;

        let epoch = self.epoch();
        let counter = self.content_nonce_counter;
        if header.counter != Some(counter) {
            return Err(Error::Protocol(
                "exporter content header counter was not reserved from the active sender state"
                    .to_owned(),
            ));
        }
        let nonce = self.content_aead_nonce(&sender_domain, epoch, suite, counter)?;

        let aead_aad = header.canonical_bytes()?;
        let ciphertext = suite.seal(&content_key, &nonce, &aead_aad, plaintext)?;

        self.content_nonce_counter = self
            .content_nonce_counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("content nonce counter overflow".to_owned()))?;

        Ok((counter, ciphertext))
    }

    /// Decrypt content produced by [`Self::encrypt_content_exporter_aead`] using
    /// a supplied `history_secret` (e.g. one retained locally for the sender's
    /// own epoch, or opened from a history-key carrier). `nonce_and_ct` is the
    /// `nonce || ciphertext` blob; `key_ref`, `epoch` and `aad` MUST be the
    /// verified envelope values. Takes `&self` — it does not touch ratchet state.
    ///
    /// The AEAD comes from the ciphersuite *this group* negotiated rather than
    /// from a caller-declared `aead_profile`: §10.1 makes the group at
    /// `key_ref.group_state_ref` the authority, so a caller holding the group
    /// has nothing left to declare. The group-free
    /// [`decrypt_content_exporter_aead_standalone`] is the path that must be
    /// told.
    pub fn decrypt_content_exporter_aead(
        &self,
        history_secret: &[u8],
        verified_sender_domain: &[u8],
        header: &EventContentPreEncryptionHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt_content_exporter_aead_standalone(
            history_secret,
            verified_sender_domain,
            header,
            self.group_ciphersuite_canonical_id()?,
            ciphertext,
        )
    }

    /// Return the retained `history_secret[from_epoch..=to_epoch]` subset a
    /// provider seals into a history-key carrier. Epochs outside the retained
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

    /// Export one retained epoch secret as a `local_authoritative` record.
    ///
    /// This is the only constructor of that record class in the SDK, and it
    /// takes the secret from **this** group rather than from an argument:
    /// `key-management.md:864-866` admits a secret as `local_authoritative`
    /// only when the endpoint exported it from an MLS state it fully verified
    /// and actually applied, and holding an [`ArkretMlsGroup`] at that epoch is
    /// exactly that evidence. Material from a history response, an
    /// organization-recovery archive or a portable backup can never reach this
    /// path, so it stays an `external_candidate` by construction.
    ///
    /// The caller supplies only the coordinates it alone knows: the durable
    /// local post-state handle and the exact `ak.component.mls.epoch.v1` winner
    /// tuple (`history-visibility.md:501-503`). All three transition fields are
    /// required, because the record's whole purpose is to make the post-state
    /// the secret came from checkable later.
    pub fn export_local_authoritative_history_secret(
        &self,
        effective_scope: &HistoryEffectiveScope,
        epoch: u64,
        local_state_ref: &str,
        transition_ref: &EventId,
        transition_event_digest: &Hash,
        mls_transition_digest: &Hash,
    ) -> Result<LocalAuthoritativeHistorySecret> {
        let mls_group_id = effective_scope.canonical_mls_group_id()?;
        if mls_group_id != self.group_id() {
            return Err(Error::Protocol(
                "effective scope does not derive this MLS group id".to_owned(),
            ));
        }
        let secret = self.history_secrets.get(&epoch).ok_or_else(|| {
            Error::Protocol(format!(
                "no locally derived history secret is retained for epoch {epoch}"
            ))
        })?;
        let record = LocalAuthoritativeHistorySecret {
            effective_scope: effective_scope.clone(),
            mls_group_id,
            epoch,
            mls_ciphersuite: self.group_ciphersuite_canonical_id()?.to_owned(),
            local_state_ref: local_state_ref.to_owned(),
            transition_ref: transition_ref.clone(),
            transition_event_digest: transition_event_digest.clone(),
            mls_transition_digest: mls_transition_digest.clone(),
            secret_b64u: base64url_encode(secret.as_slice()),
        };
        record.validate()?;
        Ok(record)
    }

    /// The AEAD suite this group negotiated, resolved through
    /// `mls-ciphersuite-registry.json`.
    fn content_suite(&self) -> Result<ExporterAeadSuite> {
        ExporterAeadSuite::resolve(self.group_ciphersuite_canonical_id()?)
    }

    /// `canonical_id` of the ciphersuite this group negotiated.
    ///
    /// The wire value comes from the registry constant, never from the
    /// third-party `Ciphersuite` `Debug` form; the OpenMLS value is only
    /// compared, so an unexpected suite fails closed instead of being
    /// stringified onto the wire.
    pub fn group_ciphersuite_canonical_id(&self) -> Result<&'static str> {
        if self.group.ciphersuite() == ARKRET_MLS_CIPHERSUITE {
            Ok(ARKRET_MLS_CIPHERSUITE_CANONICAL_ID)
        } else {
            Err(Error::Protocol(format!(
                "{}: MLS group negotiated a ciphersuite with no registered canonical_id",
                ReasonCode::UNSUPPORTED_AEAD_PROFILE
            )))
        }
    }

    /// Compose the §10.1 full-width content counter nonce.
    fn content_aead_nonce(
        &self,
        verified_sender_domain: &[u8],
        epoch: u64,
        suite: ExporterAeadSuite,
        counter: u64,
    ) -> Result<Vec<u8>> {
        self.content_nonce_context(verified_sender_domain, epoch)?;
        Ok(arkret_crypto::compose_aead_nonce(
            counter,
            suite.nonce_len(),
        )?)
    }

    /// Counter that must be frozen into the next exporter content header
    /// before encryption. The subsequent seal consumes exactly this value.
    pub fn next_content_counter(&self) -> u64 {
        self.content_nonce_counter
    }

    /// Return the sender-domain string derived from the unique active local
    /// BasicCredential leaf. Callers use this value when freezing the
    /// pre-encryption header; they must not infer it from UI profile state.
    pub fn local_content_sender_domain(&self) -> Result<String> {
        let mut own_leaves = self
            .group
            .members()
            .filter(|member| member.signature_key.as_slice() == self.identity.signer.public());
        let own_leaf = own_leaves.next().ok_or_else(|| {
            Error::Protocol("local MLS sender has no active leaf in this group".to_owned())
        })?;
        if own_leaves.next().is_some() {
            return Err(Error::Protocol(
                "local MLS signer matches multiple active leaves".to_owned(),
            ));
        }
        if own_leaf.credential.credential_type() != openmls::prelude::CredentialType::Basic {
            return Err(Error::Protocol(
                "local MLS sender leaf is not a BasicCredential".to_owned(),
            ));
        }
        let actual_identity = own_leaf.credential.serialized_content();
        let identity = std::str::from_utf8(actual_identity).map_err(|_| {
            Error::Protocol("active local MLS leaf identity is not canonical UTF-8".to_owned())
        })?;
        let derived_sender_domain = identity
            .rsplit_once('#')
            .map(|(_, device)| device)
            .unwrap_or(identity);
        Ok(derived_sender_domain.to_owned())
    }

    fn verified_local_content_sender_domain(&self, declared: &str) -> Result<Vec<u8>> {
        let derived_sender_domain = self.local_content_sender_domain()?;
        if derived_sender_domain != declared {
            return Err(Error::Protocol(
                "pre-encryption sender domain does not match the active local MLS leaf".to_owned(),
            ));
        }
        Ok(derived_sender_domain.into_bytes())
    }

    fn content_nonce_context(
        &self,
        verified_sender_domain: &[u8],
        epoch: u64,
    ) -> Result<arkret_crypto::AeadNonceContext> {
        let verified_sender_domain = std::str::from_utf8(verified_sender_domain).map_err(|_| {
            Error::Protocol("verified sender domain must be canonical UTF-8".to_owned())
        })?;
        Ok(arkret_crypto::AeadNonceContext {
            mls_group_id: self.group_id(),
            epoch,
            sender_domain: verified_sender_domain.to_owned(),
        })
    }

    /// Snapshot the current MLS group's member principals as canonical IDs.
    /// Iterates the OpenMLS `members()` view, parses each leaf's credential
    /// content as a UTF-8 DID string, and folds the results into a stable
    /// (deduplicated, BTreeSet-sorted) `Vec<DidCoreId>`. Useful for `ak.audit.
    /// ryw_receipt.delivered_to_devices` and for downstream auditors that
    /// want to know "which principals does this commit reach".
    ///
    /// Credentials that don't parse as a [`DidCoreId`] (e.g. opaque BasicCredential
    /// payloads) are silently skipped — the caller can
    /// detect this case by comparing `member_principal_ids().len()` against
    /// the group's true member count if it cares.
    pub fn member_principal_ids(&self) -> Vec<DidCoreId> {
        let mut seen = std::collections::BTreeSet::new();
        for member in self.group.members() {
            if let Ok((did, _)) = decode_leaf_credential(member.credential.serialized_content()) {
                seen.insert(did);
            }
        }
        seen.into_iter().collect()
    }

    /// Snapshot the group's active leaves for minimal-metadata author
    /// verification (encryption-and-audit.md §2.10.3). Unlike
    /// [`Self::member_principal_ids`] this does NOT dedupe — duplicate
    /// credential identities must stay visible so
    /// [`crate::verify_minimal_metadata_author`] can reject them.
    pub fn active_author_leaves(&self) -> Vec<crate::AuthorLeaf> {
        self.group
            .members()
            .map(|member| {
                let leaf_node_canonical_bytes = self
                    .group
                    .public_group()
                    .leaf(member.index)
                    .expect("member iterator only yields occupied LeafNodes")
                    .tls_serialize_detached()
                    .expect("verified RFC 9420 LeafNode serializes canonically");
                let credential = if member.credential.credential_type()
                    == openmls::prelude::CredentialType::Basic
                {
                    crate::AuthorLeafCredential::Basic {
                        // Author verification is byte-exact. Never project an
                        // ordinary `principal#device` credential down to the
                        // principal: doing so could masquerade as a valid
                        // minimal-metadata actor credential.
                        identity: member.credential.serialized_content().to_vec(),
                    }
                } else {
                    crate::AuthorLeafCredential::Other {
                        credential_type: format!("{:?}", member.credential.credential_type()),
                    }
                };
                crate::AuthorLeaf {
                    leaf_index: member.index.u32(),
                    credential,
                    signature_key: member.signature_key,
                    leaf_node_canonical_bytes,
                }
            })
            .collect()
    }

    /// Canonical current leaf set for MLS security-frontier projection.
    pub fn security_frontier_leaves(
        &self,
    ) -> Result<Vec<arkret_models_crypto::MlsSecurityFrontierLeaf>> {
        let mut leaves = self
            .group
            .members()
            .map(|member| {
                let (principal_id, credential_ref) =
                    decode_leaf_credential(member.credential.serialized_content())?;
                Ok(arkret_models_crypto::MlsSecurityFrontierLeaf {
                    leaf_index: member.index.u32(),
                    principal_id,
                    credential_ref,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        leaves.sort_by_key(|leaf| leaf.leaf_index);
        Ok(leaves)
    }

    /// Build the [`crate::AuthorGroupStateView`] for this group's current
    /// state. The caller supplies the `group_state_ref` it has verified as
    /// the winning group state for this epoch (accepted genesis / winning
    /// commit event id).
    pub fn author_group_state_view(&self, group_state_ref: &str) -> crate::AuthorGroupStateView {
        crate::AuthorGroupStateView {
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
            signal_nonce_counter: self.signal_nonce_counter,
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

    pub fn persist_state(&self, store: &mut impl MlsGroupStateSink) -> Result<MlsGroupStateRecord> {
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
            credential: BasicCredential::new(leaf_credential_bytes(
                &record.principal_id,
                &record.device_id,
            ))
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
            signal_nonce_counter: snapshot.signal_nonce_counter,
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
        let mut keypackages = Vec::with_capacity(member_key_packages.len());
        for member_key_package in member_key_packages {
            if !member_key_package.is_usable() {
                return Err(Error::Protocol(
                    "refusing to add revoked MLS KeyPackage".to_owned(),
                ));
            }
            keypackages.push(decode_key_package(
                &self.identity.provider,
                member_key_package,
            )?);
        }
        let governance_extensions = governance_binding
            .map(|binding| self.governance_extensions_for_next_epoch(binding))
            .transpose()?;
        let mut builder = self.group.commit_builder().propose_adds(keypackages);
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
                recipient: member_key_package.endpoint.clone(),
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
    pub fn remove_member_by_principal(
        &mut self,
        target: &DidCoreId,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_principal_with_optional_governance_binding(
            std::slice::from_ref(target),
            None,
        )
    }

    pub fn remove_member_by_principal_with_governance_binding(
        &mut self,
        target: &DidCoreId,
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_principal_with_optional_governance_binding(
            std::slice::from_ref(target),
            Some(governance_binding),
        )
    }

    /// Remove every leaf owned by any principal in `targets` in one MLS
    /// Commit. Each removed leaf produces a durable Remove proposal and the
    /// single Commit consumes all of them by reference.
    ///
    /// Errors when `targets` is empty or any target principal has no leaf in
    /// the group. This keeps a membership-transition rotation fail-closed:
    /// callers cannot accidentally commit only a subset of the required
    /// removals.
    pub fn remove_members_by_principal(
        &mut self,
        targets: &[DidCoreId],
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_principal_with_optional_governance_binding(targets, None)
    }

    pub fn remove_members_by_principal_with_governance_binding(
        &mut self,
        targets: &[DidCoreId],
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_principal_with_optional_governance_binding(
            targets,
            Some(governance_binding),
        )
    }

    fn remove_members_by_principal_with_optional_governance_binding(
        &mut self,
        targets: &[DidCoreId],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
        if targets.is_empty() {
            return Err(Error::Protocol(
                "remove_members_by_principal requires at least one target".to_owned(),
            ));
        }

        let mut canonical_targets: Vec<&str> = targets.iter().map(DidCoreId::as_str).collect();
        canonical_targets.sort_unstable();
        canonical_targets.dedup();
        let leaves: Vec<LeafNodeIndex> = self
            .group
            .members()
            .filter_map(|member| {
                let principal_id = decode_leaf_credential(member.credential.serialized_content())
                    .ok()
                    .map(|(principal_id, _)| principal_id)?;
                if canonical_targets
                    .iter()
                    .any(|target| principal_id.as_str() == *target)
                {
                    Some(member.index)
                } else {
                    None
                }
            })
            .collect();

        for target in canonical_targets {
            if !self
                .group
                .members()
                .filter_map(|member| {
                    decode_leaf_credential(member.credential.serialized_content())
                        .ok()
                        .map(|(principal_id, _)| principal_id)
                })
                .any(|principal_id| principal_id.as_str() == target)
            {
                return Err(Error::Protocol(format!(
                    "principal {target} has no leaf in group {}",
                    self.group_id()
                )));
            }
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

    fn remove_leaves(
        &mut self,
        leaves: &[LeafNodeIndex],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
        // Capture the decoded principal before commit so we can report
        // which principal each removed leaf belonged to even after the leaf
        // is gone from the post-commit group state.
        let pre_commit: Vec<(LeafNodeIndex, DidCoreId)> = self
            .group
            .members()
            .filter(|member| leaves.contains(&member.index))
            .map(|member| {
                let (principal_id, _) =
                    decode_leaf_credential(member.credential.serialized_content())?;
                Ok((member.index, principal_id))
            })
            .collect::<Result<Vec<_>>>()?;

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
        let mut removed_principals: Vec<DidCoreId> = Vec::with_capacity(pre_commit.len());
        for (idx, principal) in pre_commit {
            removed_leaves.push(idx.u32());
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
            },
            removed_leaves,
            removed_principals,
        })
    }

    pub fn join_from_welcome(
        identity: ArkretMlsIdentity,
        envelope: &MlsWelcomeEnvelope,
    ) -> Result<Self> {
        if envelope.recipient
            != MlsEndpointIdentity::human_device(
                identity.principal_id.clone(),
                identity.device_id.clone(),
            )
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
            signal_nonce_counter: 0,
        })
    }

    pub fn encrypt_payload(
        &mut self,
        header: EventContentPreEncryptionHeader,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        header.validate()?;
        self.verified_local_content_sender_domain(&header.sender_domain)?;
        if header.scheme != EncryptedPayloadScheme::MlsRfc9420
            || header.mls_group_id != self.group_id()
            || header.epoch != self.epoch()
        {
            return Err(Error::Protocol(
                "standard MLS content header does not match the active sender state".to_owned(),
            ));
        }
        let authenticated_data = header.canonical_bytes()?;
        self.group.set_aad(authenticated_data);
        let message = self
            .group
            .create_message(&self.identity.provider, &self.identity.signer, plaintext)
            .map_err(mls_error)?;
        let message_bytes = message.tls_serialize_detached().map_err(mls_error)?;
        let epoch = self.epoch();
        let ciphertext = encode(&message_bytes);
        let payload_digest =
            EncryptedPayload::payload_digest_for_header(&header, ciphertext.clone())?;
        Ok(EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: self.group_id(),
            epoch,
            content_type: header.content_type.clone(),
            ciphertext,
            counter: None,
            pre_encryption_header: header,
            payload_digest,
        })
    }

    /// Encrypt `plaintext` under the §2.10 `mls_exporter_aead_v1` content scheme
    /// and return the full [`EncryptedPayload`] (scheme / key_ref / digest set),
    /// so a late joiner granted the epoch's `history_secret` can decrypt it.
    ///
    /// `header` is the exact authenticated pre-encryption object. Side effect:
    /// derives + retains this
    /// epoch's `history_secret` (so the author can re-decrypt and later share it).
    pub fn encrypt_payload_exporter_aead(
        &mut self,
        realm_id: &str,
        header: EventContentPreEncryptionHeader,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        let (counter, ciphertext) =
            self.encrypt_content_exporter_aead(realm_id, &header, plaintext)?;
        let epoch = self.epoch();
        let ciphertext = encode(&ciphertext);
        let payload_digest =
            EncryptedPayload::payload_digest_for_header(&header, ciphertext.clone())?;
        Ok(EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsExporterAeadV1,
            group_id: self.group_id(),
            epoch,
            content_type: header.content_type.clone(),
            ciphertext,
            counter: Some(counter),
            pre_encryption_header: header,
            payload_digest,
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

        payload.verify_payload_digest()?;
        let message_bytes = decode(&payload.ciphertext)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(message_bytes.as_slice()).map_err(mls_error)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Protocol("MLS message is not a protocol message".to_owned()))?;
        let processed = self
            .group
            .process_message(&self.identity.provider, protocol_message)
            .map_err(mls_error)?;

        if processed.aad() != payload.pre_encryption_header.canonical_bytes()? {
            return Err(Error::Protocol(
                "standard MLS authenticated data does not match the reconstructed header"
                    .to_owned(),
            ));
        }

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(_) => Err(Error::Protocol(
                "expected MLS application message, got commit; apply it through apply_commit"
                    .to_owned(),
            )),
            _ => Err(Error::Protocol(
                "expected MLS application message".to_owned(),
            )),
        }
    }

    pub fn apply_commit(&mut self, envelope: &MlsCommitEnvelope) -> Result<u64> {
        if envelope.group_id != self.group_id() {
            return Err(Error::Protocol(
                "MLS Commit group_id does not match the local group".to_owned(),
            ));
        }
        let expected_epoch = self
            .epoch()
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("MLS epoch overflow".to_owned()))?;
        if envelope.epoch != expected_epoch {
            return Err(Error::Protocol(format!(
                "MLS Commit epoch {} is not the next local epoch {expected_epoch}",
                envelope.epoch
            )));
        }
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
                let applied_epoch = self.epoch();
                if applied_epoch != envelope.epoch {
                    return Err(Error::Protocol(format!(
                        "MLS Commit entered epoch {applied_epoch}, envelope declared {}",
                        envelope.epoch
                    )));
                }
                Ok(applied_epoch)
            }
            _ => Err(Error::Protocol("expected MLS Commit".to_owned())),
        }
    }

    /// Stage an incoming by-reference MLS proposal so a subsequent
    /// `apply_commit` that references it (e.g. a Remove commit produced by
    /// `remove_member_by_principal`) can resolve `MissingProposal`.
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
        let pending = validate_commit_backfill(&self.group_id(), self.epoch(), &sorted)?;
        for envelope in pending {
            self.apply_commit(envelope)?;
        }
        Ok(self.epoch())
    }

    /// Apply one strictly-next Commit and immediately retain the entered
    /// epoch's history secret before the caller exports a durable snapshot.
    ///
    /// Callers MUST persist the resulting group snapshot and retention marker
    /// as one recovery unit. This method deliberately takes the Realm context
    /// explicitly so Circle and Sidecar group identifiers are never mistaken
    /// for the MLS exporter context.
    pub fn apply_commit_and_retain_history_secret(
        &mut self,
        envelope: &MlsCommitEnvelope,
        realm_id: &str,
    ) -> Result<u64> {
        let epoch = self.apply_commit(envelope)?;
        self.derive_and_retain_history_secret(realm_id)?;
        Ok(epoch)
    }

    /// Apply a contiguous Commit range, retaining history material on every
    /// entered epoch instead of retaining only the final one.
    pub fn apply_commits_and_retain_history_secrets(
        &mut self,
        envelopes: &[MlsCommitEnvelope],
        realm_id: &str,
    ) -> Result<u64> {
        let mut sorted = envelopes.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|envelope| envelope.epoch);
        let pending = validate_commit_backfill(&self.group_id(), self.epoch(), &sorted)?;
        for envelope in pending {
            self.apply_commit_and_retain_history_secret(envelope, realm_id)?;
        }
        Ok(self.epoch())
    }
}

/// Derive the registered reaction routing tag from a replay-verified epoch
/// routing root. This is the group-free counterpart used by KAT runners and
/// history receivers that already verified the exact epoch state.
pub fn reaction_routing_tag_from_root(
    routing_root: &[u8],
    effective_scope: &ScopeRef,
    target_ref: &EventId,
    routing_window: u64,
    canonical_emoji: &str,
) -> Result<String> {
    #[derive(Serialize)]
    struct RoutingContext<'a> {
        effective_scope: &'a ScopeRef,
        target_ref: &'a EventId,
        routing_window: u64,
    }

    let normalized: String = canonical_emoji.nfc().collect();
    if normalized.is_empty() {
        return Err(Error::Protocol(
            "reaction routing emoji must not be empty".to_owned(),
        ));
    }
    let context = canonical::canonical_json_bytes(&RoutingContext {
        effective_scope,
        target_ref,
        routing_window,
    })?;
    let routing_key = arkret_crypto::mls_exporter::mls_expand_with_label(
        routing_root,
        REACTION_ROUTING_LABEL,
        &context,
        32,
    )
    .map_err(|error| Error::Crypto(error.to_string()))?;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&routing_key)
        .map_err(|_| Error::Crypto("reaction routing HMAC key is invalid".to_owned()))?;
    mac.update(normalized.as_bytes());
    Ok(base64url_encode(mac.finalize().into_bytes()))
}

fn validate_commit_backfill<'a>(
    expected_group_id: &str,
    current_epoch: u64,
    sorted: &[&'a MlsCommitEnvelope],
) -> Result<Vec<&'a MlsCommitEnvelope>> {
    if sorted.windows(2).any(|pair| pair[0].epoch == pair[1].epoch) {
        return Err(Error::Protocol(
            "MLS Commit backfill contains more than one candidate for an epoch".to_owned(),
        ));
    }
    if sorted
        .iter()
        .any(|envelope| envelope.group_id != expected_group_id)
    {
        return Err(Error::Protocol(
            "MLS Commit backfill contains a foreign group_id".to_owned(),
        ));
    }
    let pending = sorted
        .iter()
        .copied()
        .filter(|envelope| envelope.epoch > current_epoch)
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(pending);
    }
    let mut expected_epoch = current_epoch
        .checked_add(1)
        .ok_or_else(|| Error::Protocol("MLS epoch overflow".to_owned()))?;
    for envelope in &pending {
        if envelope.epoch != expected_epoch {
            return Err(Error::Protocol(format!(
                "MLS Commit backfill omits epoch {expected_epoch}"
            )));
        }
        expected_epoch = expected_epoch
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("MLS epoch overflow".to_owned()))?;
    }
    Ok(pending)
}

/// Standalone (group-free) variant of
/// [`ArkretMlsGroup::decrypt_content_exporter_aead`]. A device that holds a
/// granted `history_secret` but has **no** local MLS group snapshot for the
/// Realm (e.g. a member granted history before processing its own Welcome) can
/// decrypt `mls_exporter_aead_v1` content with this. `header` MUST be
/// reconstructed from the verified outer Event and exact winning group state.
///
/// `aead_profile` is a parameter here because this path has no group to ask.
/// It MUST come from the exact verified historical group state; the minimal
/// encrypted-envelope wire does not carry an algorithm selector.
pub fn decrypt_content_exporter_aead_standalone(
    history_secret: &[u8],
    verified_sender_domain: &[u8],
    header: &EventContentPreEncryptionHeader,
    aead_profile: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    header.validate()?;
    if header.scheme != EncryptedPayloadScheme::MlsExporterAeadV1
        || header.sender_domain.as_bytes() != verified_sender_domain
    {
        return Err(Error::Protocol(
            "exporter content header does not match the verified sender domain".to_owned(),
        ));
    }
    let suite = ExporterAeadSuite::resolve(aead_profile)?;
    if ciphertext.is_empty() {
        return Err(Error::Protocol(
            "exporter-aead ciphertext must not be empty".to_owned(),
        ));
    }
    let counter = header.counter.ok_or_else(|| {
        Error::Protocol("exporter content header is missing its counter".to_owned())
    })?;
    let nonce = arkret_crypto::aead_nonce::compose_aead_nonce(counter, suite.nonce_len())
        .map_err(|error| Error::Crypto(error.to_string()))?;
    if verified_sender_domain.is_empty() {
        return Err(Error::Protocol(
            "verified sender domain must not be empty".to_owned(),
        ));
    }
    let content_key = derive_content_key_from_history_secret(
        history_secret,
        verified_sender_domain,
        suite.key_len(),
    )?;
    let aead_aad = header.canonical_bytes()?;
    suite.open(&content_key, &nonce, &aead_aad, ciphertext)
}

/// What trying one exact received candidate against one exact accepted Event
/// established.
///
/// The AEAD result has exactly two carriers and no third one: a single
/// `EventCandidateBinding` row, and — only on success — the plaintext. Nothing
/// here promotes the candidate or the epoch, and the type deliberately has no
/// field that could
/// (`history-visibility.md:140`, `:437-440`).
#[derive(Clone, Debug)]
#[must_use = "the binding must be recorded whether the attempt succeeded or failed"]
pub struct EventCandidateAttempt {
    pub binding: EventCandidateBinding,
    pub plaintext: Option<Vec<u8>>,
}

/// Try one received history-secret candidate against one exact accepted Event
/// and return the Event→candidate binding it establishes.
///
/// This is the only place the `mls_exporter_aead_v1` open result is turned into
/// a store decision. `history-visibility.md:436-440` requires the caller to
/// have verified the outer Event proof, the scope/group/epoch, the sender
/// domain and the reconstructed AAD before a candidate is tried; the
/// consistency half of that (candidate coordinates, binding key and
/// pre-encryption header all naming the same scope/group/epoch/sender) is
/// enforced here so no caller can bind a plaintext to the wrong Event.
///
/// `mls_ciphersuite` MUST come from the exact verified historical group state,
/// not from the envelope: an unregistered suite is a hard error rather than a
/// failure binding, because it would otherwise turn a configuration fault into
/// "every candidate failed".
pub fn bind_event_candidate(
    candidate: &HistoryCandidateMaterialRecord,
    event_binding_key: &EventCandidateBindingKey,
    header: &EventContentPreEncryptionHeader,
    mls_ciphersuite: &str,
    ciphertext: &[u8],
    first_observed_at: chrono::DateTime<Utc>,
) -> Result<EventCandidateAttempt> {
    candidate.validate()?;
    event_binding_key.validate()?;
    header.validate()?;
    let _ = ExporterAeadSuite::resolve(mls_ciphersuite)?;
    if candidate.material_key.effective_scope != event_binding_key.effective_scope
        || candidate.material_key.mls_group_id != event_binding_key.mls_group_id
        || candidate.material_key.epoch != event_binding_key.epoch
    {
        return Err(Error::Protocol(
            "history candidate coordinates differ from the Event binding key".to_owned(),
        ));
    }
    if header.mls_group_id != event_binding_key.mls_group_id
        || header.epoch != event_binding_key.epoch
        || header.sender_domain != event_binding_key.verified_sender_domain
        || header.effective_scope != ScopeRef::from(event_binding_key.effective_scope.clone())
    {
        return Err(Error::Protocol(
            "exporter content header differs from the Event binding key".to_owned(),
        ));
    }
    let secret = base64url_decode(candidate.secret_b64u.as_bytes())
        .map_err(|error| Error::Protocol(format!("invalid history candidate bytes: {error}")))?;
    let plaintext = decrypt_content_exporter_aead_standalone(
        &secret,
        event_binding_key.verified_sender_domain.as_bytes(),
        header,
        mls_ciphersuite,
        ciphertext,
    )
    .ok();
    let outcome = if plaintext.is_some() {
        EventCandidateBindingOutcome::Success
    } else {
        EventCandidateBindingOutcome::Failure
    };
    Ok(EventCandidateAttempt {
        binding: EventCandidateBinding::new(
            event_binding_key.clone(),
            candidate.material_key.candidate_digest.clone(),
            outcome,
            first_observed_at,
        )?,
        plaintext,
    })
}

/// `K_content[N,S] = ExpandWithLabel(history_secret[N], "ak.content-v1", S, AEAD.Nk)`
/// (§2.10.1), where `S` is the already-verified sender domain. For the ordinary
/// profile it is the canonical `device_id` UTF-8 bytes; for minimal metadata it
/// is the exact active LeafNode credential identity bytes. Callers MUST verify
/// that identity before invoking this function.
///
/// `key_len` is the negotiated suite's `AEAD.Nk` and is encoded into
/// the `ExpandWithLabel` info, so two suites never derive a shared prefix.
///
/// Expand-only, no Extract: the `history_secret` is an MLS exporter output and
/// already has full entropy, which is what `ExpandWithLabel` assumes of its
/// Secret input.
pub fn derive_content_key_from_history_secret(
    history_secret: &[u8],
    verified_sender_domain: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if verified_sender_domain.is_empty() {
        return Err(Error::Protocol(
            "verified sender domain must not be empty".to_owned(),
        ));
    }
    if key_len == 0 {
        return Err(Error::Protocol(
            "content key length must be the positive AEAD.Nk of the active ciphersuite".to_owned(),
        ));
    }
    let hkdf = Hkdf::<Sha256>::from_prk(history_secret)
        .map_err(|_| Error::Crypto("history_secret too short for HKDF PRK".to_owned()))?;
    let info = mls_kdf_label(key_len, CONTENT_KEY_LABEL, verified_sender_domain)?;
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| Error::Crypto("content key derivation failed".to_owned()))?;
    Ok(key)
}

/// RFC 9420 §8.1 `KDFLabel` encoding used by `ExpandWithLabel`. Shared with
/// the Signal domain ([`crate::signal`]), which derives its per-epoch key from
/// the same `history_secret` under a different registered label.
pub(crate) fn mls_kdf_label(length: usize, label: &str, context: &[u8]) -> Result<Vec<u8>> {
    arkret_crypto::mls_exporter::mls_kdf_label(length, label, context)
        .map_err(|error| Error::Crypto(error.to_string()))
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

/// A live Arkret MLS group is the only authorized source for SFrame media
/// frame / recording / transcript keys (`arkret_crypto::sframe`). The bound
/// makes a non-MLS provenance unrepresentable at the type level.
impl arkret_crypto::sframe::MlsExporterSource for ArkretMlsGroup {
    fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> arkret_crypto::Result<Zeroizing<Vec<u8>>> {
        // Bridge the MLS behavior-layer error into the crypto-boundary error.
        ArkretMlsGroup::export_secret(self, label, context, length)
            .map_err(|error| arkret_crypto::Error::Crypto(error.to_string()))
    }
}

#[cfg(test)]
mod content_scheme_anchor_tests {
    use arkret_crypto::compose_aead_nonce;

    use super::*;
    use crate::identity::ArkretMlsIdentity;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const REALM: &str = "ak:realm:AWaw3_J06Ml7_fh-rnNBMJ3WJ6cLKzz1DvKyRhPSuJs0";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000007";

    fn founder() -> ArkretMlsGroup {
        ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DeviceId::new(DEVICE.to_owned()).unwrap(),
        )
        .unwrap()
        .create_group(REALM.as_bytes())
        .unwrap()
    }

    fn commit_stub(group_id: &str, epoch: u64, digest_byte: char) -> MlsCommitEnvelope {
        MlsCommitEnvelope {
            group_id: group_id.to_owned(),
            epoch,
            commit: "AA".to_owned(),
            commit_digest: Hash::new(format!("sha256:{}", digest_byte.to_string().repeat(64)))
                .unwrap(),
            ratchet_tree: None,
        }
    }

    #[test]
    fn commit_backfill_rejects_gaps_duplicates_and_foreign_groups_before_apply() {
        let first = commit_stub("group", 4, '1');
        let duplicate = commit_stub("group", 4, '2');
        assert!(validate_commit_backfill("group", 3, &[&first, &duplicate]).is_err());

        let gap = commit_stub("group", 5, '3');
        assert!(validate_commit_backfill("group", 3, &[&gap]).is_err());

        let foreign = commit_stub("other", 4, '4');
        assert!(validate_commit_backfill("group", 3, &[&foreign]).is_err());
        assert_eq!(
            validate_commit_backfill("group", 3, &[&first])
                .unwrap()
                .len(),
            1
        );
    }

    /// Every wire-breaking AEAD parameter of the content scheme, checked
    /// against the registry rather than against this module.
    ///
    /// `encryption-and-audit.md` §2.10.2 makes `aead_profile` the active
    /// ciphersuite `canonical_id` of the group at `key_ref.group_state_ref`,
    /// from `mls-ciphersuite-registry.json`, and forbids an HPKE suite name or
    /// any local alias; §2.10.1 then takes `AEAD.Nk` and the nonce length from
    /// that suite. The registry's only active row is AES-128-GCM, so the
    /// content scheme is 16-byte keys and 12-byte nonces — no registered MLS
    /// ciphersuite uses XChaCha20-Poly1305 at all.
    #[test]
    fn content_aead_parameters_come_from_the_mls_ciphersuite_registry() {
        let group = founder();
        let profile = group.group_ciphersuite_canonical_id().unwrap();
        assert_eq!(profile, "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519");
        assert_eq!(
            group
                .content_nonce_context(group.identity.device_id.as_str().as_bytes(), 3,)
                .unwrap()
                .mls_group_id,
            group.group_id()
        );

        let suite = group.content_suite().unwrap();
        assert_eq!(suite, ExporterAeadSuite::Aes128Gcm);
        assert_eq!(suite.key_len(), 16);
        assert_eq!(suite.nonce_len(), 12);
        assert_eq!(suite.nonce_prefix_len(), 4);

        // The pre-fix local aliases are not registered MLS ciphersuites and
        // MUST fail closed rather than select an algorithm.
        for alias in [
            "mls_exporter_aead_xchacha20poly1305",
            "mls_exporter_aead_aes_256_gcm",
            "ak.hpke_x25519_aead_chacha20poly1305.v1",
            "",
        ] {
            let error = ExporterAeadSuite::resolve(alias).unwrap_err().to_string();
            assert!(error.contains("unsupported_aead_profile"), "{error}");
        }
        // A registered-but-reserved row is equally forbidden on the wire.
        let error =
            ExporterAeadSuite::resolve("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519")
                .unwrap_err()
                .to_string();
        assert!(error.contains("reserved"), "{error}");
    }

    /// Pins the byte-exact `mls_exporter_aead_v1` content-scheme chain from a
    /// fixed history_secret — RFC 9420 ExpandWithLabel content key, canonical
    /// AAD construction, and the AEAD ciphertext itself. Any silent change to
    /// a label, key length, AAD shape or nonce composition breaks these bytes.
    /// The sender nonce prefix is not anchored here: it comes from a live MLS
    /// exporter, which has no fixed value outside a group (see
    /// `content_nonce_prefix_is_the_exporter_over_the_canonical_context_alone`).
    #[test]
    fn exporter_aead_content_scheme_regression_anchor() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| {
                case["vector_id"].as_str()
                    == Some("ak.vector.mls_exporter_aead.seal_open_transcript.v1")
            })
            .unwrap();
        let history_secret =
            hex::decode(case["input"]["history_secret_hex"].as_str().unwrap()).unwrap();
        let verified_sender_domain = case["input"]["verified_sender_domain"]
            .as_str()
            .unwrap()
            .as_bytes();
        let suite = ExporterAeadSuite::Aes128Gcm;
        let profile = ARKRET_MLS_CIPHERSUITE_CANONICAL_ID;
        let content_key = derive_content_key_from_history_secret(
            &history_secret,
            verified_sender_domain,
            suite.key_len(),
        )
        .unwrap();
        let other_sender_key = derive_content_key_from_history_secret(
            &history_secret,
            b"ak:device:01904100-0000-7000-8000-000000000008",
            suite.key_len(),
        )
        .unwrap();
        assert_ne!(content_key.as_slice(), other_sender_key.as_slice());

        let nonce = compose_aead_nonce(7, suite.nonce_len()).unwrap();
        assert_eq!(nonce.len(), suite.nonce_len());
        assert_eq!(&nonce[4..], 7u64.to_be_bytes(), "counter suffix drifted");

        let header: EventContentPreEncryptionHeader =
            serde_json::from_value(case["expected"]["reconstructed_pre_encryption_header"].clone())
                .unwrap();
        let aad = header.canonical_bytes().unwrap();
        assert_eq!(
            std::str::from_utf8(&aad).unwrap(),
            case["expected"]["aead_aad_canonical_json"]
                .as_str()
                .unwrap(),
            "canonical content AAD drifted"
        );

        let plaintext = hex::decode(case["input"]["plaintext_hex"].as_str().unwrap()).unwrap();
        let ciphertext = suite.seal(&content_key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(
            hex(&ciphertext),
            case["expected"]["ciphertext_with_tag_hex"]
                .as_str()
                .unwrap(),
            "exporter-aead ciphertext drifted"
        );

        let recovered = decrypt_content_exporter_aead_standalone(
            &history_secret,
            verified_sender_domain,
            &header,
            profile,
            &ciphertext,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);

        // Tamper negative: a flipped ciphertext byte must fail the tag check.
        let mut tampered = ciphertext;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            decrypt_content_exporter_aead_standalone(
                &history_secret,
                verified_sender_domain,
                &header,
                profile,
                &tampered,
            )
            .is_err()
        );
    }

    /// Reproduces the registered vector
    /// `ak.vector.mls_exporter_aead.content_key_derivation.v1` verbatim.
    ///
    /// The vector used to declare `aead_nk: 32` under the case name
    /// `..._sha256_aes256gcm`, which no registered MLS ciphersuite provides —
    /// §2.10.1 takes the content key length from the negotiated suite's
    /// `AEAD.Nk` and §2.10.2 forces `aead_profile` to an active
    /// `mls-ciphersuite-registry.json` row, whose only active entry is
    /// AES-128-GCM. arkret-spec `cb637541` moved the vector to that suite, so
    /// the live path and the vector now agree and this asserts equality rather
    /// than recording a disagreement.
    ///
    /// The length is bound into the `ExpandWithLabel` info, so this is a real
    /// check: a key derived at any other length is not a prefix of this one.
    #[test]
    fn content_key_matches_registered_spec_vector() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        let case = &fixture["cases"][0];
        let history_secret =
            hex::decode(case["expected"]["history_secret_hex"].as_str().unwrap()).unwrap();
        let vector_key_len = usize::try_from(case["input"]["aead_nk"].as_u64().unwrap()).unwrap();

        // The vector's declared length must be the one the live path derives,
        // not merely a length the derivation happens to accept.
        assert_eq!(vector_key_len, ExporterAeadSuite::Aes128Gcm.key_len());
        assert_eq!(
            case["input"]["aead_profile"].as_str().unwrap(),
            ARKRET_MLS_CIPHERSUITE_CANONICAL_ID,
        );

        let sender_domain = case["input"]["verified_sender_domain_utf8"]
            .as_str()
            .expect("content key vector must bind a verified sender domain")
            .as_bytes();
        assert_eq!(
            hex(&mls_kdf_label(
                vector_key_len,
                arkret_wire::ExporterLabelId::CONTENT_V1,
                sender_domain
            )
            .unwrap()),
            case["expected"]["content_expand_with_label_info_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex(derive_content_key_from_history_secret(
                &history_secret,
                sender_domain,
                vector_key_len
            )
            .unwrap()
            .as_ref()),
            case["expected"]["content_key_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn reaction_routing_tag_matches_registered_spec_vector() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| {
                case["vector_id"].as_str() == Some("ak.vector.reaction.routing_hmac_kat.v1")
            })
            .unwrap();
        let routing_root = hex::decode(case["input"]["routing_root_hex"].as_str().unwrap())
            .expect("routing root hex");
        let effective_scope: ScopeRef =
            serde_json::from_value(case["input"]["effective_scope"].clone()).unwrap();
        let target_ref =
            EventId::new(case["input"]["target_ref"].as_str().unwrap().to_owned()).unwrap();
        let routing_window = case["input"]["routing_window"].as_u64().unwrap();
        let emoji = ["e\u{301}", "é", "👍🏽"];
        let expected = case["expected"]["tags_hex"].as_array().unwrap();

        for (emoji, expected) in emoji.into_iter().zip(expected) {
            let tag = reaction_routing_tag_from_root(
                &routing_root,
                &effective_scope,
                &target_ref,
                routing_window,
                emoji,
            )
            .unwrap();
            assert_eq!(
                hex(&base64url_decode(tag.as_bytes()).unwrap()),
                expected.as_str().unwrap()
            );
        }
    }
}
