use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_models_crypto::{
    EncryptedPayload, EventContentPreEncryptionHeader, MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
    MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE, MlsCommitEnvelope, MlsCommitPayload,
    MlsEndpointIdentity, MlsGovernanceBindingPayload, MlsGroupStateRecord, MlsGroupStateSink,
    MlsKeyPackageRecord, MlsProposalEnvelope, REQUIRED_ARKRET_GROUP_CAPABILITIES,
    decode_keypackage_capability_extension, encode_keypackage_capability_extension,
    validate_required_keypackage_capabilities,
};
use arkret_wire::{
    ActorId, Base64UrlString, CommitStreamRef, DidCoreId, EncryptedPayloadScheme, EventId,
    EventKind, Hash, KeypackageClaimId, MLS_CIPHERSUITES, MlsGroupId, MlsWelcomeDelivery,
    MlsWelcomeRecipientEndpoint, ReasonCode, ScopeRef, StreamRow, canonical,
};
use chrono::Utc;
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, Extension, ExtensionType, Extensions,
    GroupContext, GroupId, LeafNode, LeafNodeIndex, LeafNodeParameters, MlsGroup,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProcessedMessageContent,
    RequiredCapabilitiesExtension, StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
use zeroize::Zeroizing;

use crate::identity::{
    ARKRET_MLS_CIPHERSUITE, ARKRET_MLS_CIPHERSUITE_CANONICAL_ID, ArkretMlsIdentity,
    ArkretMlsIdentityProfile, decode_key_package,
};
use crate::{MlsError as Error, Result};

const ARKRET_OPENMLS_STATE_SNAPSHOT: &str = "arkret-openmls-provider-state-v1";

/// Realm and Circle groups carry handshakes as `PublicMessage`; a Sidecar group
/// keeps its own policy and encrypts them.
///
/// This takes the scope, never a `group_id`. Before the 2218 ruling the policy
/// was recovered by parsing the `group_id` bytes back into a `RealmId` or
/// `CircleId`, which only worked because those bytes *were* the scope id in
/// clear. Since `group_id` is now a SHA-256 digest, that parse can only ever
/// fail — it would have silently downgraded every Realm and Circle group to
/// `PURE_CIPHERTEXT` instead of failing loudly. The scope is therefore threaded
/// down from the caller and persisted with the group.
pub(super) fn handshake_policy(scope: &ScopeRef) -> Result<openmls::prelude::WireFormatPolicy> {
    Ok(if scope.requires_public_mls_handshake()? {
        openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY
    } else {
        openmls::prelude::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY
    })
}

/// AEAD parameters fixed by the MLS ciphersuite for the live Signal rail.
///
/// `encoding.md` §10.1 splits the `aead_profile` vocabulary by how the key was
/// obtained, not by which envelope carries it: application-layer HPKE encryption
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

    pub(crate) fn encrypt(
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

    pub(crate) fn decrypt(
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
    /// The effective security scope this group serves.
    ///
    /// Held explicitly because the `group_id` is a one-way digest of it: after
    /// the 2218 ruling nothing can recover the scope from the group, so the
    /// only way to keep knowing it is to carry it. It also pins the handshake
    /// wire-format policy, which used to be re-derived from the `group_id`
    /// bytes.
    pub(super) scope: ScopeRef,
    /// The scope's derived `group_id`, in its wire spelling.
    ///
    /// Held rather than recomputed per call so the accessor stays infallible.
    /// Every constructor checks it against the raw bytes the OpenMLS group
    /// actually carries, so the two can never disagree.
    pub(super) group_id: MlsGroupId,
    /// Accepted-transition-derived member attribution. It is persisted inside
    /// the same opaque T3 snapshot as the RFC 9420 state and is never inferred
    /// from BasicCredential bytes alone.
    pub(super) leaf_bindings: BTreeMap<u32, MlsVerifiedLeafBinding>,
    /// Monotonic per-device AEAD nonce counter for the
    /// `ak.signal_exporter_aead.v1` Signal scheme. Persisted with the group
    /// snapshot so a device never repeats a nonce within one MLS epoch.
    pub(super) signal_nonce_counter: u64,
}

#[derive(Clone, Debug)]
pub struct MlsAddMemberResult {
    pub proposals: Vec<MlsProposalEnvelope>,
    pub commit: MlsCommitEnvelope,
    pub welcome: MlsWelcomeDraft,
}

#[derive(Clone, Debug)]
pub struct MlsAddMembersResult {
    pub proposals: Vec<MlsProposalEnvelope>,
    pub commit: MlsCommitEnvelope,
    pub welcomes: Vec<MlsWelcomeDraft>,
}

/// Member-side bytes that the producer signs and places in the authority's
/// recipient queue as an [`MlsWelcomeDelivery`]. It is not a shared Event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeDraft {
    pub recipient: MlsEndpointIdentity,
    pub keypackage_claim_ref: KeypackageClaimId,
    pub ciphertext_b64: Base64UrlString,
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
    /// The complete actor identities whose leaves were removed (one per leaf, may
    /// contain duplicates if the actor had multiple leaves / devices in
    /// the same group). Includes Station identity for downstream membership authorization.
    pub removed_actors: Vec<ActorId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsVerifiedLeafBinding {
    pub leaf_index: u32,
    /// Full accepted member identity; the endpoint is only signing evidence.
    pub actor_id: ActorId,
    pub endpoint: MlsEndpointIdentity,
    pub signature_key: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
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
    group_id: MlsGroupId,
    /// The effective security scope, persisted because the `group_id` above is
    /// a one-way digest of it. Without this the restored group could not tell
    /// whether its own handshakes are public, and no amount of parsing the
    /// `group_id` would bring it back.
    scope: ScopeRef,
    epoch: u64,
    actor_id: ActorId,
    endpoint: MlsEndpointIdentity,
    profile: ArkretMlsIdentityProfile,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
    leaf_bindings: BTreeMap<u32, MlsVerifiedLeafBinding>,
    /// Persisted monotonic Signal AEAD nonce counter. `encoding.md` §10.1
    /// makes persistence mandatory: a device that cannot recover its counter
    /// for an epoch MUST advance the epoch rather than restart at 0. The
    /// counter only ever reaches this snapshot from an in-memory value that
    /// has already been advanced past every nonce this device emitted, so a
    /// missing field can only mean "never encrypted a Signal", i.e. 0.
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

    /// Install the complete binding map derived from the accepted Genesis or
    /// winning Add/Commit transition. The map must cover every occupied leaf
    /// exactly once and match the RFC 9420 credential and signature key byte
    /// for byte before it can enter the durable T3 snapshot.
    pub fn install_verified_leaf_bindings(
        &mut self,
        bindings: Vec<MlsVerifiedLeafBinding>,
    ) -> Result<()> {
        let members = self
            .group
            .members()
            .map(|member| (member.index.u32(), member))
            .collect::<BTreeMap<_, _>>();
        if bindings.len() != members.len() {
            return Err(Error::Protocol(
                "verified MLS leaf bindings do not cover every occupied leaf".to_owned(),
            ));
        }
        let mut installed = BTreeMap::new();
        for binding in bindings {
            let member = members.get(&binding.leaf_index).ok_or_else(|| {
                Error::Protocol("verified MLS binding names an empty leaf".to_owned())
            })?;
            if installed.contains_key(&binding.leaf_index) {
                return Err(Error::Protocol(
                    "duplicate verified MLS leaf binding".to_owned(),
                ));
            }
            binding.actor_id.validate()?;
            if binding.endpoint.principal_id() != binding.actor_id.signing_principal_id() {
                return Err(Error::Protocol(
                    "verified MLS binding principal differs from endpoint actor".to_owned(),
                ));
            }
            match &binding.endpoint {
                MlsEndpointIdentity::HumanDevice { .. } => {
                    if binding.device_authorize_event_id.is_none() {
                        return Err(Error::Protocol(
                            "ordinary MLS leaf binding omits device authorization Event".to_owned(),
                        ));
                    }
                }
                MlsEndpointIdentity::AgentRuntime { .. } => {}
                MlsEndpointIdentity::MinimalMetadataPairwise {
                    pairwise_actor_id, ..
                } if matches!(&binding.actor_id, ActorId::Service { service_id } if service_id == pairwise_actor_id) =>
                    {}
                MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
                    return Err(Error::Protocol(
                        "pairwise MLS endpoint requires the exact service ActorId".to_owned(),
                    ));
                }
            }
            let expected_credential =
                arkret_models_crypto::mls_basic_credential_identity(&binding.actor_id)?;
            if member.credential.serialized_content() != expected_credential.as_slice() {
                return Err(Error::Protocol(
                    "verified MLS binding credential differs from the occupied leaf".to_owned(),
                ));
            }
            let signature_key = base64url_decode(binding.signature_key.as_str())?;
            if signature_key.as_slice() != member.signature_key.as_slice() {
                return Err(Error::Protocol(
                    "verified MLS binding signature key differs from the occupied leaf".to_owned(),
                ));
            }
            installed.insert(binding.leaf_index, binding);
        }
        self.leaf_bindings = installed;
        Ok(())
    }

    pub fn install_local_creator_binding(
        &mut self,
        actor_id: ActorId,
        device_authorize_event_id: Option<EventId>,
    ) -> Result<()> {
        let members = self.group.members().collect::<Vec<_>>();
        if members.len() != 1 || members[0].index.u32() != 0 {
            return Err(Error::Protocol(
                "local creator binding requires the unique epoch-0 leaf".to_owned(),
            ));
        }
        let member = &members[0];
        let credential_actor_id = arkret_models_crypto::decode_mls_basic_credential_identity(
            member.credential.serialized_content(),
        )?;
        if credential_actor_id != actor_id {
            return Err(Error::Protocol(
                "creator BasicCredential differs from the supplied ActorId".to_owned(),
            ));
        }
        let signature_key = Base64UrlString::new(base64url_encode(member.signature_key.as_slice()))
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        self.install_verified_leaf_bindings(vec![MlsVerifiedLeafBinding {
            leaf_index: 0,
            actor_id,
            endpoint: self.identity.endpoint.clone(),
            signature_key,
            device_authorize_event_id,
        }])
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn install_test_leaf_bindings(
        &mut self,
        endpoints: Vec<MlsEndpointIdentity>,
    ) -> Result<()> {
        let mut remaining = endpoints;
        let mut bindings = Vec::new();
        for leaf in self.active_author_leaves() {
            let crate::AuthorLeafCredential::Basic { identity } = leaf.credential else {
                return Err(Error::Protocol(
                    "test MLS leaf is not BasicCredential".to_owned(),
                ));
            };
            let actor_id = arkret_models_crypto::decode_mls_basic_credential_identity(&identity)?;
            let position = remaining
                .iter()
                .position(|endpoint| match endpoint {
                    MlsEndpointIdentity::HumanDevice { principal_id, .. } => {
                        actor_id.signing_principal_id() == principal_id
                    }
                    MlsEndpointIdentity::AgentRuntime { agent_id, .. } => {
                        actor_id.signing_principal_id() == agent_id
                    }
                    MlsEndpointIdentity::MinimalMetadataPairwise {
                        pairwise_actor_id, ..
                    } => matches!(&actor_id, ActorId::Service { service_id } if service_id == pairwise_actor_id),
                })
                .ok_or_else(|| {
                    Error::Protocol("test MLS endpoint does not match a leaf".to_owned())
                })?;
            let endpoint = remaining.remove(position);
            let device_authorize_event_id =
                matches!(endpoint, MlsEndpointIdentity::HumanDevice { .. }).then(|| {
                    EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned())
                        .expect("fixed test Event id is valid")
                });
            bindings.push(MlsVerifiedLeafBinding {
                leaf_index: leaf.leaf_index,
                actor_id,
                endpoint,
                signature_key: Base64UrlString::new(base64url_encode(&leaf.signature_key))
                    .map_err(|error| Error::Protocol(error.to_owned()))?,
                device_authorize_event_id,
            });
        }
        if !remaining.is_empty() {
            return Err(Error::Protocol(
                "test MLS endpoints leave phantom members".to_owned(),
            ));
        }
        self.install_verified_leaf_bindings(bindings)
    }

    pub fn verified_leaf_bindings(&self) -> Result<Vec<MlsVerifiedLeafBinding>> {
        self.require_complete_leaf_bindings()?;
        Ok(self.leaf_bindings.values().cloned().collect())
    }

    /// Return the previously verified bindings that still match occupied
    /// leaves after staging a membership transition. A newly added leaf is
    /// deliberately absent until the caller supplies its independently
    /// verified authority evidence and installs the complete post-transition
    /// map with [`Self::install_verified_leaf_bindings`].
    pub fn retained_verified_leaf_bindings(&self) -> Result<Vec<MlsVerifiedLeafBinding>> {
        let members = self
            .group
            .members()
            .map(|member| (member.index.u32(), member))
            .collect::<BTreeMap<_, _>>();
        let mut retained = Vec::with_capacity(self.leaf_bindings.len());
        for binding in self.leaf_bindings.values() {
            let Some(member) = members.get(&binding.leaf_index) else {
                continue;
            };
            if member.credential.serialized_content()
                != arkret_models_crypto::mls_basic_credential_identity(&binding.actor_id)?
                    .as_slice()
                || member.signature_key.as_slice()
                    != base64url_decode(binding.signature_key.as_str())?.as_slice()
            {
                return Err(Error::Protocol(
                    "retained MLS leaf binding differs from the occupied leaf".to_owned(),
                ));
            }
            retained.push(binding.clone());
        }
        Ok(retained)
    }

    fn require_complete_leaf_bindings(&self) -> Result<()> {
        let occupied = self
            .group
            .members()
            .map(|member| member.index.u32())
            .collect::<Vec<_>>();
        if occupied.len() != self.leaf_bindings.len()
            || occupied
                .iter()
                .any(|index| !self.leaf_bindings.contains_key(index))
        {
            return Err(Error::Protocol(
                "MLS member attribution is unavailable until accepted transition bindings are installed"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The effective security scope this group serves.
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }

    /// The RFC 9420 `group_id` in its wire spelling, always 43 characters.
    ///
    /// Equal by construction to `self.scope().canonical_mls_group_id()` and to
    /// the raw bytes the OpenMLS group carries; every constructor checks that
    /// before handing out an `ArkretMlsGroup`.
    pub fn group_id(&self) -> MlsGroupId {
        self.group_id.clone()
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

    pub fn required_keypackage_capabilities(&self) -> Result<Vec<String>> {
        let extension = self
            .group
            .extensions()
            .unknown(MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE)
            .ok_or_else(|| {
                Error::Protocol(
                    "required_keypackage_capabilities GroupContext extension is missing".to_owned(),
                )
            })?;
        decode_keypackage_capability_extension(&extension.0)
            .map_err(|error| Error::Protocol(error.to_string()))
    }

    fn validate_governance_binding_for_next_epoch(
        &self,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<()> {
        binding.validate()?;
        if binding.mls_group_id()? != self.group_id() {
            return Err(Error::Protocol(
                "mls_governance_binding.mls_group_id does not match current MLS group".to_owned(),
            ));
        }
        if binding.previous_epoch() != self.epoch() || binding.next_epoch() != self.epoch() + 1 {
            return Err(Error::Protocol(
                "mls_governance_binding epoch does not match current MLS group".to_owned(),
            ));
        }

        Ok(())
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
    /// Counter that must be frozen into the next exporter content header
    /// before encryption. The subsequent encryption consumes exactly this value.
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

    /// Snapshot complete member identities from the accepted binding map.
    /// Same-principal identities at different Stations remain distinct.
    pub fn member_actor_ids(&self) -> Result<Vec<ActorId>> {
        self.require_complete_leaf_bindings()?;
        Ok(self
            .leaf_bindings
            .values()
            .map(|binding| binding.actor_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    /// Signing-principal projection for cryptographic lookup only. This loses
    /// Station identity and MUST NOT be used for membership or roster authority.
    pub fn member_principal_ids(&self) -> Result<Vec<DidCoreId>> {
        self.require_complete_leaf_bindings()?;
        Ok(self
            .leaf_bindings
            .values()
            .map(|binding| binding.actor_id.signing_principal_id().clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect())
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
                        // Author verification is byte-exact. Principal
                        // ownership comes from the verified group-local leaf
                        // binding, not from reinterpretation of these bytes.
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
        self.require_complete_leaf_bindings()?;
        let snapshot = OpenMlsStateSnapshot {
            context: ARKRET_OPENMLS_STATE_SNAPSHOT.to_owned(),
            group_id: self.group_id.clone(),
            scope: self.scope.clone(),
            epoch: self.epoch(),
            actor_id: self.identity.actor_id.clone(),
            endpoint: self.identity.endpoint.clone(),
            profile: self.identity.profile().clone(),
            signer_public_key: encode(self.identity.signer.public()),
            storage_entries: snapshot_provider_storage(&self.identity.provider)?,
            leaf_bindings: self.leaf_bindings.clone(),
            signal_nonce_counter: self.signal_nonce_counter,
        };
        Ok(MlsGroupStateRecord {
            group_id: snapshot.group_id.clone(),
            actor_id: snapshot.actor_id.clone(),
            endpoint: snapshot.endpoint.clone(),
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
            || snapshot.actor_id != record.actor_id
            || snapshot.endpoint != record.endpoint
        {
            return Err(Error::Protocol(
                "OpenMLS state snapshot metadata mismatch".to_owned(),
            ));
        }
        // The persisted scope is what decides the handshake policy below, so a
        // snapshot whose scope does not derive its own group_id is rejected
        // here rather than quietly serving the wrong policy.
        let group_id = snapshot.scope.canonical_mls_group_id()?;
        if group_id != snapshot.group_id {
            return Err(Error::Protocol(
                "OpenMLS state snapshot scope does not derive its own group_id".to_owned(),
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
        snapshot.profile.validate_signer(signer.public())?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(snapshot.profile.credential_bytes(&record.actor_id)?)
                .into(),
            signature_key: signer.public().into(),
        };
        let raw_group_id = GroupId::from_slice(&decode(record.group_id.as_str())?);
        let group = MlsGroup::load(provider.storage(), &raw_group_id)
            .map_err(mls_error)?
            .ok_or_else(|| Error::Protocol("OpenMLS group state is missing".to_owned()))?;
        if group.configuration().wire_format_policy() != handshake_policy(&snapshot.scope)? {
            return Err(Error::Protocol(
                "OpenMLS snapshot does not enforce the handshake wire-format policy its scope requires"
                    .to_owned(),
            ));
        }
        if group.epoch().as_u64() != record.epoch {
            return Err(Error::Protocol(
                "OpenMLS restored epoch mismatch".to_owned(),
            ));
        }

        let bindings = snapshot.leaf_bindings;
        let mut restored = Self {
            identity: ArkretMlsIdentity {
                actor_id: record.actor_id.clone(),
                endpoint: record.endpoint.clone(),
                profile: snapshot.profile,
                provider,
                signer,
                credential,
            },
            group,
            scope: snapshot.scope,
            group_id,
            leaf_bindings: BTreeMap::new(),
            signal_nonce_counter: snapshot.signal_nonce_counter,
        };
        restored.install_verified_leaf_bindings(bindings.into_values().collect())?;
        Ok(restored)
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
    /// The resulting commit remains staged. It is installed only by
    /// [`Self::install_accepted_commit`] after the governance Station has
    /// committed the Event to this scope's independent stream.
    pub fn self_update_commit(&mut self) -> Result<MlsCommitEnvelope> {
        let bundle = self
            .group
            .self_update(
                &self.identity.provider,
                &self.identity.signer,
                LeafNodeParameters::default(),
            )
            .map_err(mls_error)?;
        let commit_bytes = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);
        Ok(MlsCommitEnvelope {
            group_id: self.group_id(),
            epoch: self
                .epoch()
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("MLS epoch overflow".to_owned()))?,
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
            &[],
        )?;
        let welcome = result
            .welcomes
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("MLS add_member returned no Welcome".to_owned()))?;
        Ok(MlsAddMemberResult {
            proposals: result.proposals,
            commit: result.commit,
            welcome,
        })
    }

    pub fn add_members(
        &mut self,
        member_key_packages: &[MlsKeyPackageRecord],
    ) -> Result<MlsAddMembersResult> {
        self.add_members_with_optional_governance_binding(member_key_packages, None, &[])
    }

    pub fn replace_member_endpoint(
        &mut self,
        package: &MlsKeyPackageRecord,
        actor: &ActorId,
        binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsAddMemberResult> {
        if !self
            .leaf_bindings
            .values()
            .any(|leaf| leaf.actor_id == *actor && leaf.endpoint == package.endpoint)
        {
            return Err(Error::Protocol(
                "endpoint replacement requires the exact current Account ActorId".to_owned(),
            ));
        }
        let result = self.add_members_with_optional_governance_binding(
            std::slice::from_ref(package),
            binding,
            std::slice::from_ref(actor),
        )?;
        Ok(MlsAddMemberResult {
            proposals: result.proposals,
            commit: result.commit,
            welcome: result.welcomes.into_iter().next().ok_or_else(|| {
                Error::Protocol("endpoint replacement produced no Welcome".to_owned())
            })?,
        })
    }

    pub(crate) fn add_members_with_optional_governance_binding(
        &mut self,
        member_key_packages: &[MlsKeyPackageRecord],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
        replace_actors: &[ActorId],
    ) -> Result<MlsAddMembersResult> {
        if member_key_packages.is_empty() {
            return Err(Error::Protocol(
                "refusing to add an empty MLS KeyPackage batch".to_owned(),
            ));
        }
        let mut keypackages = Vec::with_capacity(member_key_packages.len());
        let required_capabilities = self.required_keypackage_capabilities()?;
        for member_key_package in member_key_packages {
            if member_key_package.state != arkret_models_crypto::MlsKeyPackageState::Claimed {
                return Err(Error::Protocol(
                    "MLS Add requires an authority-claimed KeyPackage".to_owned(),
                ));
            }
            let claim_id = member_key_package.claim_id.as_deref().ok_or_else(|| {
                Error::Protocol("claimed MLS KeyPackage omits claim_id".to_owned())
            })?;
            KeypackageClaimId::new(claim_id.to_owned())?;
            let keypackage = decode_key_package(&self.identity.provider, member_key_package)?;
            validate_keypackage_capability_binding(
                member_key_package,
                &keypackage,
                &required_capabilities,
            )?;
            keypackages.push(keypackage);
        }
        let base_epoch = self.epoch();
        let ratchet_tree = Some(self.ratchet_tree()?);
        let mut proposals = Vec::with_capacity(keypackages.len());
        // A fresh package for an existing endpoint repairs that endpoint in
        // the same winning Commit. Keeping both leaves would give one device
        // two incarnations and leave the abandoned package active.
        let replacements: Vec<_> = self
            .leaf_bindings
            .values()
            .filter(|binding| {
                replace_actors.contains(&binding.actor_id)
                    && member_key_packages
                        .iter()
                        .any(|record| record.endpoint == binding.endpoint)
            })
            .map(|binding| LeafNodeIndex::new(binding.leaf_index))
            .collect();
        if replacements.contains(&self.group.own_leaf_index()) {
            return Err(Error::Protocol(
                "an MLS sender cannot replace its own endpoint via Add".to_owned(),
            ));
        }
        for leaf in replacements {
            let (message, _) = self
                .group
                .propose_remove_member(&self.identity.provider, &self.identity.signer, leaf)
                .map_err(mls_error)?;
            let bytes = message.tls_serialize_detached().map_err(mls_error)?;
            proposals.push(MlsProposalEnvelope {
                group_id: self.group_id(),
                epoch: base_epoch,
                proposal_type: "remove".to_owned(),
                proposal: encode(&bytes),
                proposal_digest: Hash::new(canonical::sha256_digest(&bytes))?,
                ratchet_tree: ratchet_tree.clone(),
            });
        }
        for key_package in &keypackages {
            let (proposal_message, _proposal_ref) = self
                .group
                .propose_add_member(&self.identity.provider, &self.identity.signer, key_package)
                .map_err(mls_error)?;
            let proposal_bytes = proposal_message
                .tls_serialize_detached()
                .map_err(mls_error)?;
            proposals.push(MlsProposalEnvelope {
                group_id: self.group_id(),
                epoch: base_epoch,
                proposal_type: "add".to_owned(),
                proposal: encode(&proposal_bytes),
                proposal_digest: Hash::new(canonical::sha256_digest(&proposal_bytes))?,
                ratchet_tree: ratchet_tree.clone(),
            });
        }
        if let Some(binding) = governance_binding {
            self.validate_governance_binding_for_next_epoch(binding)?;
        }
        let bundle = self
            .group
            .commit_builder()
            .consume_proposal_store(true)
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

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let welcome_bytes = welcome.tls_serialize_detached().map_err(mls_error)?;
        let commit_digest = Hash::new(canonical::sha256_digest(&commit_bytes))?;
        let group_id = self.group_id();
        let epoch = base_epoch
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("MLS epoch overflow".to_owned()))?;
        let welcomes = member_key_packages
            .iter()
            .map(|member_key_package| {
                Ok(MlsWelcomeDraft {
                    recipient: member_key_package.endpoint.clone(),
                    keypackage_claim_ref: KeypackageClaimId::new(
                        member_key_package
                            .claim_id
                            .clone()
                            .expect("claimed package was validated"),
                    )?,
                    ciphertext_b64: Base64UrlString::new(encode(&welcome_bytes))
                        .map_err(|error| Error::Protocol(error.to_owned()))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(MlsAddMembersResult {
            proposals,
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

    /// Remove every leaf owned by any complete actor in `targets` in one MLS
    /// Commit. Each removed leaf produces a durable Remove proposal and the
    /// single Commit consumes all of them by reference.
    ///
    /// Errors when `targets` is empty or any target actor has no leaf in
    /// the group. This keeps a membership-transition rotation fail-closed:
    /// callers cannot accidentally commit only a subset of the required
    /// removals.
    pub fn remove_members_by_actor(
        &mut self,
        targets: &[ActorId],
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_actor_with_optional_governance_binding(targets, None)
    }

    pub fn remove_members_by_actor_with_governance_binding(
        &mut self,
        targets: &[ActorId],
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_actor_with_optional_governance_binding(
            targets,
            Some(governance_binding),
        )
    }

    fn remove_members_by_actor_with_optional_governance_binding(
        &mut self,
        targets: &[ActorId],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
        if targets.is_empty() {
            return Err(Error::Protocol(
                "remove_members_by_actor requires at least one target".to_owned(),
            ));
        }
        self.require_complete_leaf_bindings()?;

        let mut canonical_targets: Vec<&ActorId> = targets.iter().collect();
        canonical_targets.sort_unstable();
        canonical_targets.dedup();
        let leaves: Vec<LeafNodeIndex> = self
            .group
            .members()
            .filter(|member| {
                self.leaf_bindings
                    .get(&member.index.u32())
                    .is_some_and(|binding| canonical_targets.contains(&&binding.actor_id))
            })
            .map(|member| member.index)
            .collect();

        for target in canonical_targets {
            if !self
                .leaf_bindings
                .values()
                .any(|binding| &binding.actor_id == target)
            {
                return Err(Error::Protocol(format!(
                    "actor {target} has no leaf in group {}",
                    self.group_id()
                )));
            }
        }

        self.remove_leaves(&leaves, governance_binding)
    }

    /// Remove exactly the selected occupied leaves, preserving other endpoints
    /// even when they belong to the same Actor.
    pub fn remove_members_by_leaf_indices_with_governance_binding(
        &mut self,
        leaf_indices: &[u32],
        governance_binding: &MlsGovernanceBindingPayload,
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_leaf_indices_internal(leaf_indices, Some(governance_binding))
    }

    pub fn remove_members_by_leaf_indices(
        &mut self,
        leaf_indices: &[u32],
    ) -> Result<MlsRemoveMemberResult> {
        self.remove_members_by_leaf_indices_internal(leaf_indices, None)
    }

    fn remove_members_by_leaf_indices_internal(
        &mut self,
        leaf_indices: &[u32],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
        if leaf_indices.is_empty()
            || leaf_indices.len() > 65_536
            || leaf_indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Protocol(
                "MLS removal indices must be nonempty, bounded and strictly increasing".to_owned(),
            ));
        }
        self.require_complete_leaf_bindings()?;
        let leaves = leaf_indices
            .iter()
            .copied()
            .map(LeafNodeIndex::new)
            .collect::<Vec<_>>();
        self.remove_leaves(&leaves, governance_binding)
    }

    fn remove_leaves(
        &mut self,
        leaves: &[LeafNodeIndex],
        governance_binding: Option<&MlsGovernanceBindingPayload>,
    ) -> Result<MlsRemoveMemberResult> {
        // Capture the complete actor before commit so we can report
        // which Station-bound member owned each removed leaf even after it
        // is gone from the post-commit group state.
        let pre_commit: Vec<(LeafNodeIndex, ActorId)> = self
            .group
            .members()
            .filter(|member| leaves.contains(&member.index))
            .map(|member| {
                let binding = self.leaf_bindings.get(&member.index.u32()).ok_or_else(|| {
                    Error::Protocol("removed MLS leaf has no verified binding".to_owned())
                })?;
                Ok((member.index, binding.actor_id.clone()))
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

        if let Some(binding) = governance_binding {
            self.validate_governance_binding_for_next_epoch(binding)?;
        }
        let (commit, _welcome_opt, _) = self
            .group
            .commit_builder()
            .consume_proposal_store(true)
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

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;

        let mut removed_leaves: Vec<u32> = Vec::with_capacity(pre_commit.len());
        let mut removed_actors: Vec<ActorId> = Vec::with_capacity(pre_commit.len());
        for (idx, principal) in pre_commit {
            removed_leaves.push(idx.u32());
            removed_actors.push(principal);
        }

        Ok(MlsRemoveMemberResult {
            proposals,
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: base_epoch
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("MLS epoch overflow".to_owned()))?,
                commit: encode(&commit_bytes),
                commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
                ratchet_tree,
            },
            removed_leaves,
            removed_actors,
        })
    }

    /// Consume an authority-queued Welcome only after resolving the exact
    /// accepted Commit Event it names. Producer-proof verification is a
    /// prerequisite performed by the caller against the accepted producer
    /// identity; this method validates every MLS and stream binding.
    pub fn join_from_verified_welcome_delivery(
        identity: ArkretMlsIdentity,
        delivery: &MlsWelcomeDelivery,
        accepted_commit: &StreamRow,
    ) -> Result<Self> {
        delivery.validate_shape()?;
        accepted_commit.validate_shape()?;
        if accepted_commit.event.kind != EventKind::MlsCommit
            || delivery.commit_event_ref != accepted_commit.event.event_id
            || delivery.realm_id != accepted_commit.event.realm_id
            || delivery.effective_scope != accepted_commit.event.scope_ref
        {
            return Err(Error::Protocol(
                "MLS Welcome does not name the exact accepted Commit Event".to_owned(),
            ));
        }
        let expected_stream = CommitStreamRef::from_scope(&delivery.effective_scope, None)?;
        if accepted_commit.commit.stream_ref != expected_stream {
            return Err(Error::Protocol(
                "MLS Welcome Commit is in a different independent stream".to_owned(),
            ));
        }
        let commit_payload = serde_json::from_value::<MlsCommitPayload>(
            serde_json::Value::Object(accepted_commit.event.payload.clone().into_iter().collect()),
        )?;
        commit_payload.validate()?;
        if commit_payload.governance_binding().effective_scope() != &delivery.effective_scope {
            return Err(Error::Protocol(
                "MLS Welcome scope differs from the accepted Commit payload".to_owned(),
            ));
        }
        let recipient_matches = match (&identity.endpoint, &delivery.recipient_endpoint) {
            (
                MlsEndpointIdentity::HumanDevice {
                    principal_id,
                    device_id,
                },
                MlsWelcomeRecipientEndpoint::Device {
                    device_id: delivered_device,
                },
            ) => {
                device_id == delivered_device
                    && delivery.recipient_actor_id.signing_principal_id() == principal_id
            }
            (
                MlsEndpointIdentity::AgentRuntime {
                    agent_id,
                    verification_method,
                    ..
                },
                MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method: delivered_method,
                },
            ) => {
                verification_method == delivered_method
                    && delivery.recipient_actor_id.signing_principal_id() == agent_id
            }
            _ => false,
        };
        if !recipient_matches {
            return Err(Error::Protocol(
                "MLS Welcome recipient does not match this endpoint".to_owned(),
            ));
        }

        let welcome_bytes = decode(delivery.ciphertext_b64.as_str())?;
        let message =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice()).map_err(mls_error)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::Protocol(
                "MLS delivery does not contain a Welcome".to_owned(),
            ));
        };
        let staged_welcome = StagedWelcome::new_from_welcome(
            &identity.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )
        .map_err(mls_error)?;
        let context = staged_welcome.group_context();
        if encode(context.group_id().as_slice()) != commit_payload.mls_group_id()?.as_str()
            || context.epoch().as_u64() != commit_payload.next_epoch()
        {
            return Err(Error::Protocol(
                "MLS Welcome authenticated group state differs from the accepted Commit".to_owned(),
            ));
        }
        Self::join_staged_welcome(identity, &delivery.effective_scope, staged_welcome)
    }

    fn join_staged_welcome(
        identity: ArkretMlsIdentity,
        scope: &ScopeRef,
        staged_welcome: StagedWelcome,
    ) -> Result<Self> {
        let context = staged_welcome.group_context();
        // The joiner is told which scope it is joining; it cannot read that
        // back out of the authenticated group_id, so it checks the two agree
        // instead. A Welcome whose group_id is not this scope's derivation is
        // a Welcome into a different group.
        let group_id = scope.canonical_mls_group_id()?;
        if encode(context.group_id().as_slice()) != group_id.as_str() {
            return Err(Error::Protocol(
                "MLS Welcome group_id is not the derivation of the named effective scope"
                    .to_owned(),
            ));
        }
        let join_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(handshake_policy(scope)?)
            .build();
        let required_extension = context
            .extensions()
            .unknown(MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE)
            .ok_or_else(|| {
                Error::Protocol(
                    "required_keypackage_capabilities GroupContext extension is missing".to_owned(),
                )
            })?;
        let required = decode_keypackage_capability_extension(&required_extension.0)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let required_refs = required.iter().map(String::as_str).collect::<Vec<_>>();
        validate_required_keypackage_capabilities(
            &required_refs,
            crate::identity::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES,
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;

        let mut group = staged_welcome
            .into_group(&identity.provider)
            .map_err(mls_error)?;
        group
            .set_configuration(identity.provider.storage(), &join_config)
            .map_err(mls_error)?;
        if let Err(error) = validate_group_capability_floor(&group, &required) {
            group
                .delete(identity.provider.storage())
                .map_err(mls_error)?;
            return Err(error);
        }
        Ok(Self {
            identity,
            group,
            scope: scope.clone(),
            group_id,
            leaf_bindings: BTreeMap::new(),
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

    /// Install an MLS Commit only after the containing Event has an accepted
    /// `RealmCommit` in the same independent Realm/Circle/Sidecar stream.
    pub fn install_accepted_commit(&mut self, item: &StreamRow) -> Result<u64> {
        item.validate_shape()?;
        if item.event.kind != EventKind::MlsCommit {
            return Err(Error::Protocol(
                "accepted MLS transition must contain ak.mls.commit".to_owned(),
            ));
        }
        let payload = serde_json::from_value::<MlsCommitPayload>(serde_json::Value::Object(
            item.event.payload.clone().into_iter().collect(),
        ))?;
        payload.validate()?;
        if payload.governance_binding().effective_scope() != &item.event.scope_ref
            || payload
                .governance_binding()
                .effective_scope()
                .realm_id_opt()
                != Some(&item.event.realm_id)
        {
            return Err(Error::Protocol(
                "accepted MLS Commit payload differs from its independent Event stream".to_owned(),
            ));
        }
        self.merge_accepted_commit_envelope(&payload.commit_envelope()?)
    }

    fn merge_accepted_commit_envelope(&mut self, envelope: &MlsCommitEnvelope) -> Result<u64> {
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
            ProcessedMessageContent::OwnPendingCommit => {
                // OpenMLS authenticated the echoed Commit and matched its
                // confirmation tag against the exact locally staged commit.
                self.group
                    .merge_pending_commit(&self.identity.provider)
                    .map_err(mls_error)?;
                let applied_epoch = self.epoch();
                if applied_epoch != envelope.epoch {
                    return Err(Error::Protocol(
                        "pending MLS Commit epoch mismatch".to_owned(),
                    ));
                }
                self.leaf_bindings.clear();
                Ok(applied_epoch)
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                validate_staged_commit_capability_floor(
                    &self.group,
                    &self.identity.provider,
                    &commit,
                )?;
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
                // A transition may add, remove, or replace occupied leaves.
                // The old map is never a valid compatibility fallback; the
                // caller must install the every-and-only accepted-transition
                // binding before any roster API can succeed.
                self.leaf_bindings.clear();
                Ok(applied_epoch)
            }
            _ => Err(Error::Protocol("expected MLS Commit".to_owned())),
        }
    }

    /// Stage an incoming by-reference MLS proposal so a subsequent
    /// `apply_commit` that references it can resolve `MissingProposal`.
    ///
    /// Add and Remove commits carry their proposals out-of-band. Existing
    /// members MUST apply each proposal through this method before applying
    /// the referencing commit; new Add recipients join from the Welcome.
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

#[cfg(test)]
mod tests {
    use arkret_wire::DeviceId;

    use super::*;

    fn identity() -> ArkretMlsIdentity {
        ArkretMlsIdentity::new_test_human_device(
            ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:mls.example").unwrap(),
                DidCoreId::new("ak:did_core:web:mls-fixture-station.example").unwrap(),
            )),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000071").unwrap(),
        )
        .unwrap()
    }

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
            )
            .unwrap(),
        }
    }

    #[test]
    fn keypackage_fixture_credentials_decode_to_the_exact_actor() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/mls-keypackage-endpoint-kat-fixture.json",
        )
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let keypackage =
                base64url_decode(case["keypackage"].as_str().unwrap().as_bytes()).unwrap();
            let leaf = crate::identity::author_leaf_from_key_package_bytes(&keypackage, 0).unwrap();
            let crate::AuthorLeafCredential::Basic { identity } = leaf.credential else {
                panic!("fixture KeyPackage must carry BasicCredential");
            };
            let actor: ActorId =
                serde_json::from_value(case["endpoint"]["actor_id"].clone()).unwrap();
            assert_eq!(
                arkret_models_crypto::decode_mls_basic_credential_identity(&identity).unwrap(),
                actor
            );
            assert_eq!(
                identity,
                base64url_decode(case["leaf_credential"].as_str().unwrap().as_bytes()).unwrap()
            );
            assert_eq!(
                std::str::from_utf8(&identity).unwrap(),
                case["leaf_credential_jcs"].as_str().unwrap()
            );
        }
    }

    /// The policy follows the scope kind, which is what the group is created
    /// and restored with. It is no longer recoverable from the `group_id`, and
    /// the point of this test is that nothing tries.
    #[test]
    fn scope_groups_keep_independent_handshake_policies() {
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV")
                .unwrap();
        for scope in [
            realm_scope(),
            ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: arkret_wire::CircleId::new(
                    "ak:circle:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
                )
                .unwrap(),
            },
        ] {
            assert_eq!(
                handshake_policy(&scope).unwrap(),
                openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY
            );
        }

        let sidecar = ScopeRef::Sidecar {
            realm_id,
            sidecar_id: arkret_wire::SidecarId::new(
                "ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
            )
            .unwrap(),
        };
        assert_eq!(
            handshake_policy(&sidecar).unwrap(),
            openmls::prelude::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY
        );
        assert!(handshake_policy(&ScopeRef::RealmGenesis).is_err());
    }

    /// The group is seeded with the scope's digest, never with scope bytes, so
    /// the 43-character wire id is what `group_id()` reports.
    #[test]
    fn group_is_created_under_the_scope_derived_group_id() {
        let scope = realm_scope();
        let group = identity().create_group(&scope).unwrap();
        assert_eq!(group.group_id(), scope.canonical_mls_group_id().unwrap());
        assert_eq!(group.group_id().as_str().len(), 43);
        assert_eq!(group.scope(), &scope);
    }

    #[test]
    fn outbound_commit_stays_pending_until_authority_acceptance() {
        let mut group = identity().create_group(&realm_scope()).unwrap();
        let base_epoch = group.epoch();

        let commit = group.self_update_commit().unwrap();

        assert_eq!(group.epoch(), base_epoch);
        assert_eq!(commit.epoch, base_epoch + 1);
    }
}

pub(super) fn encode(bytes: &[u8]) -> String {
    base64url_encode(bytes)
}

pub(super) fn decode(value: &str) -> Result<Vec<u8>> {
    Ok(base64url_decode(value)?)
}

pub(super) fn arkret_required_capabilities_extension() -> Extension {
    Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[
            ExtensionType::Unknown(MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE),
            ExtensionType::Unknown(MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE),
        ],
        &[],
        &[],
    ))
}

pub(super) fn arkret_openmls_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![
            ExtensionType::Unknown(MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE),
            ExtensionType::Unknown(MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE),
        ])
        .build()
}

pub(super) fn keypackage_capabilities_leaf_extensions() -> Result<Extensions<LeafNode>> {
    let extension_data = encode_keypackage_capability_extension(
        crate::identity::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES,
    )
    .map_err(|error| Error::Protocol(error.to_string()))?;
    Extensions::from_vec(vec![Extension::Unknown(
        MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
        UnknownExtension(extension_data),
    )])
    .map_err(mls_error)
}

fn required_keypackage_capabilities_group_context_extension() -> Result<Extension> {
    let extension_data = encode_keypackage_capability_extension(REQUIRED_ARKRET_GROUP_CAPABILITIES)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(Extension::Unknown(
        MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
        UnknownExtension(extension_data),
    ))
}

pub(super) fn arkret_group_context_extensions() -> Result<Extensions<GroupContext>> {
    Extensions::from_vec(vec![
        arkret_required_capabilities_extension(),
        required_keypackage_capabilities_group_context_extension()?,
    ])
    .map_err(mls_error)
}

fn validate_keypackage_capability_binding(
    record: &MlsKeyPackageRecord,
    keypackage: &openmls::prelude::KeyPackage,
    required: &[String],
) -> Result<()> {
    let extension = keypackage
        .leaf_node()
        .extensions()
        .unknown(MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE)
        .ok_or_else(|| {
            Error::Protocol("KeyPackage LeafNode keypackage_capabilities is missing".to_owned())
        })?;
    let signed = decode_keypackage_capability_extension(&extension.0)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if signed != record.capabilities {
        return Err(Error::Protocol(
            "outer KeyPackage capabilities do not match signed LeafNode capabilities".to_owned(),
        ));
    }
    let required = required.iter().map(String::as_str).collect::<Vec<_>>();
    let signed = signed.iter().map(String::as_str).collect::<Vec<_>>();
    validate_required_keypackage_capabilities(&required, &signed)
        .map_err(|error| Error::Protocol(error.to_string()))
}

fn validate_leaf_capability_floor(leaf: &LeafNode, required: &[String]) -> Result<()> {
    let extension = leaf
        .extensions()
        .unknown(MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE)
        .ok_or_else(|| Error::Protocol("LeafNode keypackage_capabilities is missing".to_owned()))?;
    let advertised = decode_keypackage_capability_extension(&extension.0)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let required = required.iter().map(String::as_str).collect::<Vec<_>>();
    let advertised = advertised.iter().map(String::as_str).collect::<Vec<_>>();
    validate_required_keypackage_capabilities(&required, &advertised)
        .map_err(|error| Error::Protocol(error.to_string()))
}

fn validate_group_capability_floor(group: &MlsGroup, required: &[String]) -> Result<()> {
    for leaf in group.export_ratchet_tree().leaves() {
        validate_leaf_capability_floor(leaf, required)?;
    }
    Ok(())
}

fn validate_staged_commit_capability_floor(
    current_group: &MlsGroup,
    provider: &OpenMlsRustCrypto,
    staged: &openmls::prelude::StagedCommit,
) -> Result<()> {
    let extension = staged
        .group_context()
        .extensions()
        .unknown(MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE)
        .ok_or_else(|| {
            Error::Protocol(
                "required_keypackage_capabilities GroupContext extension is missing".to_owned(),
            )
        })?;
    let required = decode_keypackage_capability_extension(&extension.0)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    // OpenMLS keeps only public state when this authenticated Commit removes
    // the local member. There is no prospective member tree to inspect; merge
    // the removal so subsequent content operations observe an inactive group.
    if staged.self_removed() {
        return Ok(());
    }
    let original_tree = current_group.export_ratchet_tree();
    let prospective_tree = staged
        .export_ratchet_tree(provider.crypto(), original_tree)
        .map_err(mls_error)?
        .ok_or_else(|| Error::Protocol("staged member Commit has no ratchet tree".to_owned()))?;
    for leaf in prospective_tree.leaves() {
        validate_leaf_capability_floor(leaf, &required)?;
    }
    Ok(())
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
