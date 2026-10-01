//! Client-local creator intent constrained by the normative bootstrap registry.
//! This record is never a wire request or a shared current-state value.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ActorId, DeviceId, DidUrl, Event, EventId, EventKind, MlsGroupId, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::authority_commit::SelfAuthoritySubmitRequest;
use crate::events_payloads::MlsGenesisBindingProposalCarrier;
use crate::internal_prelude::{Result, WireError};
use crate::sync_frames::account_subscribe::RealmDetailBaseline;
use crate::sync_frames::current_results::AccountCurrentResult;

crate::string_marker!(MlsCreatorBootstrapOperation, MlsGenesis, "mls_genesis");

/// The whole closed creation intent. Hosts atomically persist it before any
/// create submission or selector-dependent MLS randomness, and retain it
/// unchanged after Realm acceptance. The signer is not part of its logical key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapIntent {
    owner_actor_id: ActorId,
    effective_scope: ScopeRef,
    operation: MlsCreatorBootstrapOperation,
    creator_device_id: DeviceId,
    creator_signer_method: DidUrl,
    creator_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
    mls_group_id: MlsGroupId,
    proposed_group_genesis_binding: MlsGenesisBindingProposalCarrier,
    signed_scope_create_unit: SelfAuthoritySubmitRequest,
    scope_create_event_id: EventId,
}

impl MlsCreatorBootstrapIntent {
    pub fn new(
        owner_actor_id: ActorId,
        effective_scope: ScopeRef,
        creator_device_id: DeviceId,
        creator_signer_method: DidUrl,
        proposed_group_genesis_binding: MlsGovernanceBindingPayload,
        signed_scope_create_unit: SelfAuthoritySubmitRequest,
    ) -> Result<Self> {
        let endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: creator_device_id.clone(),
        };
        Self::new_with_endpoint(
            owner_actor_id,
            effective_scope,
            creator_device_id,
            creator_signer_method,
            endpoint,
            proposed_group_genesis_binding,
            signed_scope_create_unit,
        )
    }

    /// Preserve the explicit endpoint slot for human, Agent or service authoring.
    /// The authoring device remains immutable vault metadata, not the Actor class.
    pub fn new_with_endpoint(
        owner_actor_id: ActorId,
        effective_scope: ScopeRef,
        creator_device_id: DeviceId,
        creator_signer_method: DidUrl,
        creator_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
        proposed_group_genesis_binding: MlsGovernanceBindingPayload,
        signed_scope_create_unit: SelfAuthoritySubmitRequest,
    ) -> Result<Self> {
        let create = scope_create_event(&signed_scope_create_unit)?;
        let value = Self {
            owner_actor_id: owner_actor_id.clone(),
            effective_scope: effective_scope.clone(),
            operation: MlsCreatorBootstrapOperation::MlsGenesis,
            creator_device_id,
            creator_signer_method,
            creator_endpoint,
            mls_group_id: effective_scope.canonical_mls_group_id()?,
            proposed_group_genesis_binding: MlsGenesisBindingProposalCarrier::new(
                owner_actor_id,
                effective_scope,
                proposed_group_genesis_binding,
            ),
            scope_create_event_id: create.event_id.clone(),
            signed_scope_create_unit,
        };
        value.validate()?;
        Ok(value)
    }

    /// Check local consistency, not producer signatures or current authority.
    /// Evidence verification and the durable CAS remain mandatory host duties.
    pub fn validate(&self) -> Result<()> {
        self.signed_scope_create_unit.validate()?;
        let create = scope_create_event(&self.signed_scope_create_unit)?;
        let proof = create.producer_proof.as_ref().ok_or_else(|| {
            WireError::Protocol("creator intent requires the exact signed create unit".into())
        })?;
        let device_producer = create.human_device_producer()?;
        let endpoint_matches = match &self.creator_endpoint {
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => {
                device_id == &self.creator_device_id && device_producer.is_some()
            }
            arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => verification_method == &self.creator_signer_method && device_producer.is_none(),
        };
        if proof.verification_method != self.creator_signer_method
            || !endpoint_matches
            || device_producer.is_some_and(|producer| {
                producer.device_id != self.creator_device_id
                    || self
                        .owner_actor_id
                        .as_account_id()
                        .is_some_and(|owner| owner != &producer.account_id)
            })
        {
            return Err(WireError::Protocol(
                "creator intent changed its authoring device or signer".into(),
            ));
        }
        let proposal = &self.proposed_group_genesis_binding;
        let binding = proposal.proposed_group_genesis_binding();
        binding.validate()?;
        if create.actor_id != self.owner_actor_id
            || create.event_id != self.scope_create_event_id
            || proposal.sender_actor_id() != &self.owner_actor_id
            || proposal.target_scope() != &self.effective_scope
            || proposal.event_kind() != &EventKind::MlsGenesis
            || proposal.proposal_kind() != MlsGenesisBindingProposalCarrier::PROPOSAL_KIND
            || binding.effective_scope() != &self.effective_scope
            || binding.base_group_state_ref().is_some()
            || binding.previous_epoch() != 0
            || binding.next_epoch() != 0
            || binding.key_access_revision() != 0
            || binding.mls_group_id()? != self.mls_group_id
        {
            return Err(WireError::Protocol(
                "creator intent changed its closed proposal or create identity".into(),
            ));
        }
        match &self.effective_scope {
            ScopeRef::Realm { realm_id }
                if create.kind == EventKind::RealmCreate
                    && &create.realm_id == realm_id
                    && *realm_id == arkret_wire::RealmId::from_event_id(&create.event_id) => {}
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } if create.kind == EventKind::CircleCreate
                && &create.realm_id == realm_id
                && *circle_id == arkret_wire::CircleId::from_event_id(&create.event_id) => {}
            _ => return Err(WireError::Protocol(
                "creator intent requires its own exact Realm or Circle create; Sidecar is excluded"
                    .into(),
            )),
        }
        Ok(())
    }

    pub fn owner_actor_id(&self) -> &ActorId {
        &self.owner_actor_id
    }
    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }
    pub fn creator_device_id(&self) -> &DeviceId {
        &self.creator_device_id
    }
    pub fn creator_signer_method(&self) -> &DidUrl {
        &self.creator_signer_method
    }
    pub fn creator_endpoint(&self) -> &arkret_wire::MlsWelcomeRecipientEndpoint {
        &self.creator_endpoint
    }
    pub fn mls_group_id(&self) -> &MlsGroupId {
        &self.mls_group_id
    }
    pub fn proposal(&self) -> &MlsGenesisBindingProposalCarrier {
        &self.proposed_group_genesis_binding
    }
    pub fn signed_scope_create_unit(&self) -> &SelfAuthoritySubmitRequest {
        &self.signed_scope_create_unit
    }
    pub fn scope_create_event_id(&self) -> &EventId {
        &self.scope_create_event_id
    }
}

/// A complete authorized current cut retained with pinned creator evidence.
/// These existing carriers provide coverage and current values together;
/// neither a missing projection nor an empty incomplete result proves absence.
/// Signature, authority-chain and source authentication remain host duties.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapCurrentCut {
    baseline: RealmDetailBaseline,
    current: AccountCurrentResult,
}

impl MlsCreatorBootstrapCurrentCut {
    pub fn new(baseline: RealmDetailBaseline, current: AccountCurrentResult) -> Self {
        Self { baseline, current }
    }

    /// Check byte-local coverage and exact-scope absence against the independently
    /// verified authority coordinates of this cut. This is not authentication.
    pub fn validate_absence_binding(
        &self,
        scope: &ScopeRef,
        governance_generation: u64,
        realm_head: &arkret_wire::CommitStreamHead,
    ) -> Result<()> {
        use arkret_wire::{CommitStreamRef, CurrentSelector};

        let stream = match scope {
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. } => {
                CommitStreamRef::from_scope(scope, None)?
            }
            _ => {
                return Err(WireError::Protocol(
                    "creator current cut requires a Realm or Circle scope".into(),
                ));
            }
        };
        self.baseline.validate()?;
        self.current.validate()?;
        let coverage = &self.baseline.coverage;
        if !self.baseline.complete
            || !coverage.complete_for_authorized_streams
            || coverage.realm_id != *stream.realm_id()
            || self.current.realm_id != coverage.realm_id
            || self.current.governance_generation != governance_generation
            || realm_head.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: coverage.realm_id.clone(),
                })
            || !coverage.stream_heads.contains(realm_head)
            || !coverage
                .stream_heads
                .iter()
                .any(|head| head.stream_ref == stream)
            || coverage.stream_heads.len() != self.current.stream_heads.len()
            || coverage.stream_heads.iter().any(|head| {
                head.stream_ref.realm_id() != &coverage.realm_id
                    || !self.current.stream_heads.contains(head)
            })
            || self
                .current
                .entry(&CurrentSelector::MlsGroup {
                    scope_ref: scope.clone(),
                })
                .is_some()
        {
            return Err(WireError::Protocol(
                "creator current cut does not bind complete exact-scope Genesis absence".into(),
            ));
        }
        Ok(())
    }

    pub fn baseline(&self) -> &RealmDetailBaseline {
        &self.baseline
    }

    pub fn current(&self) -> &AccountCurrentResult {
        &self.current
    }
}

/// Exact accepted creation and its authority-root resolution retained by the
/// transaction. Shape checks cannot replace producer/Commit/route verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapAcceptedCreate {
    accepted_event: Event,
    covering_commit: arkret_wire::RealmCommit,
    digest_suite: arkret_canonical::DigestSuite,
    accepted_bytes_digest: arkret_wire::Hash,
    authority_root: arkret_wire::RealmAuthorityBundle,
}

/// Local retention of one exact row from the authenticated own-Station self
/// keys/query surface. It is not portable origin evidence and must never be
/// exposed to a peer as an attestation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapDeviceAuthority {
    account_id: arkret_wire::AccountId,
    device_id: DeviceId,
    signer_evidence_ref: arkret_wire::SignerEvidenceRef,
    projection: arkret_models_crypto::VerifiedDeviceProjection,
    generation: arkret_models_crypto::DeviceGenerationState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    verified_at: chrono::DateTime<chrono::Utc>,
}

impl MlsCreatorBootstrapDeviceAuthority {
    pub fn from_self_keys_query(
        intent: &MlsCreatorBootstrapIntent,
        outcome: &arkret_models_crypto::KeysQueryOutcome,
        verified_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        outcome.validate()?;
        let account_id = intent.owner_actor_id().as_account_id().ok_or_else(|| {
            WireError::Protocol("Device creator needs an exact Account ActorId".into())
        })?;
        let row = outcome
            .devices_for(account_id)
            .and_then(|rows| rows.get(intent.creator_device_id()))
            .ok_or_else(|| {
                WireError::Protocol("creator Device authorization unavailable".into())
            })?;
        row.validate_projection()?;
        let generation = outcome
            .generation_for(account_id)
            .ok_or_else(|| WireError::Protocol("creator Device generation unavailable".into()))?;
        let value = Self {
            account_id: account_id.clone(),
            device_id: intent.creator_device_id().clone(),
            signer_evidence_ref: row.signer_evidence_ref.clone(),
            projection: row.device_projection.clone(),
            generation: generation.clone(),
            verified_at: arkret_canonical::normalize_timestamp_canonical(verified_at),
        };
        value.validate_binding(intent)?;
        Ok(value)
    }

    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        let window = &self.projection.authorization_window;
        self.signer_evidence_ref.content_digest()?;
        if intent.owner_actor_id().as_account_id() != Some(&self.account_id)
            || intent.creator_device_id() != &self.device_id
            || intent.creator_endpoint()
                != &(arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: self.device_id.clone(),
                })
            || self.projection.device_status != arkret_models_crypto::DeviceStatus::Active
            || self.projection.authorized_generation_ref
                != self.generation.current_device_generation_ref
            || self.projection.attested_at > self.verified_at
            || self.verified_at >= self.projection.expires_at
            || self.verified_at < window.not_before
            || window.expires_at.is_some_and(|at| self.verified_at >= at)
        {
            return Err(WireError::Protocol("creator Device evidence does not bind the exact current endpoint at the verified cut".into()));
        }
        Ok(())
    }

    pub fn projection(&self) -> &arkret_models_crypto::VerifiedDeviceProjection {
        &self.projection
    }
}

/// One immutable local pin of independently verified authority/current data
/// and the exact original proposal. Cryptographic and authenticated transport
/// verification are host duties, before the atomic pin commit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapGovernanceEvidence {
    accepted_create: MlsCreatorBootstrapAcceptedCreate,
    genesis_absence: arkret_wire::RealmStateSnapshot,
    creator_device_authority: MlsCreatorBootstrapDeviceAuthority,
    canonical_proposal_bytes: Vec<u8>,
    proposal_digest: arkret_wire::Hash,
    governance_binding: MlsGovernanceBindingPayload,
}

impl MlsCreatorBootstrapGovernanceEvidence {
    pub fn new_device(
        intent: &MlsCreatorBootstrapIntent,
        accepted_create: MlsCreatorBootstrapAcceptedCreate,
        genesis_absence: arkret_wire::RealmStateSnapshot,
        creator_device_authority: MlsCreatorBootstrapDeviceAuthority,
    ) -> Result<Self> {
        let canonical_proposal_bytes = arkret_canonical::canonical_json_bytes(intent.proposal())?;
        let proposal_digest = arkret_wire::Hash::new(arkret_canonical::canonical::digest(
            accepted_create.digest_suite(),
            &canonical_proposal_bytes,
        ))?;
        let value = Self {
            accepted_create,
            genesis_absence,
            creator_device_authority,
            canonical_proposal_bytes,
            proposal_digest,
            governance_binding: intent.proposal().proposed_group_genesis_binding().clone(),
        };
        value.validate_binding(intent)?;
        Ok(value)
    }

    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        self.accepted_create.validate_binding(intent)?;
        validate_creator_genesis_absence_snapshot(
            intent,
            &self.accepted_create,
            &self.genesis_absence,
        )?;
        self.creator_device_authority.validate_binding(intent)?;
        let verified_at = self.creator_device_authority.verified_at;
        let authority = self.accepted_create.authority_root();
        if verified_at < authority.bundle_issued_at
            || verified_at >= authority.current_assertion.expires_at
            || self.genesis_absence.created_at > verified_at
        {
            return Err(WireError::Protocol("creator pin does not bind fresh authority and current evidence at the verified cut".into()));
        }
        if self.canonical_proposal_bytes
            != arkret_canonical::canonical_json_bytes(intent.proposal())?
            || self.proposal_digest.as_str()
                != arkret_canonical::canonical::digest(
                    self.accepted_create.digest_suite(),
                    &self.canonical_proposal_bytes,
                )
            || &self.governance_binding != intent.proposal().proposed_group_genesis_binding()
        {
            return Err(WireError::Protocol(
                "pinned creator proposal or binding changed".into(),
            ));
        }
        Ok(())
    }

    pub fn accepted_create(&self) -> &MlsCreatorBootstrapAcceptedCreate {
        &self.accepted_create
    }
    pub fn governance_binding(&self) -> &MlsGovernanceBindingPayload {
        &self.governance_binding
    }
    pub fn creator_device_authority(&self) -> &MlsCreatorBootstrapDeviceAuthority {
        &self.creator_device_authority
    }
}

/// One immutable epoch-zero recovery unit. The private bytes are an opaque
/// device-secret envelope; the host decrypts and restores them to verify the
/// MLS engine output against both exact public byte strings before use.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapEpochZero {
    encrypted_private_state: Vec<u8>,
    group_info_bytes: Vec<u8>,
    ratchet_tree_bytes: Vec<u8>,
    unsigned_genesis: arkret_wire::AuthoredEvent,
}

impl MlsCreatorBootstrapEpochZero {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        evidence: &MlsCreatorBootstrapGovernanceEvidence,
        encrypted_private_state: Vec<u8>,
        group_info_bytes: Vec<u8>,
        ratchet_tree_bytes: Vec<u8>,
        unsigned_genesis: arkret_wire::AuthoredEvent,
    ) -> Result<Self> {
        let value = Self {
            encrypted_private_state,
            group_info_bytes,
            ratchet_tree_bytes,
            unsigned_genesis,
        };
        value.validate_binding(intent, evidence)?;
        Ok(value)
    }

    pub fn validate_binding(
        &self,
        intent: &MlsCreatorBootstrapIntent,
        evidence: &MlsCreatorBootstrapGovernanceEvidence,
    ) -> Result<()> {
        evidence.validate_binding(intent)?;
        let event = self.unsigned_genesis.event();
        self.unsigned_genesis.verify_identity()?;
        let payload = self.payload()?;
        payload.validate()?;
        let blob_ref = |bytes: &[u8]| {
            format!(
                "ak:blob:{}",
                arkret_canonical::canonical::digest(arkret_canonical::DigestSuite::Sha256, bytes)
            )
        };
        if self.encrypted_private_state.is_empty()
            || self.group_info_bytes.is_empty()
            || self.ratchet_tree_bytes.is_empty()
            || event.producer_proof.is_some()
            || event.kind != EventKind::MlsGenesis
            || &event.actor_id != intent.owner_actor_id()
            || &event.scope_ref != intent.effective_scope()
            || Some(&event.realm_id) != intent.effective_scope().realm_id_opt()
            || self.unsigned_genesis.digest_suite() != evidence.accepted_create.digest_suite()
            || event.created_at != payload.created_at
            || payload.governance_binding != evidence.governance_binding
            || !arkret_wire::generated::security_strings::MLS_CIPHERSUITES
                .iter()
                .any(|suite| {
                    suite.canonical_id == payload.cipher_suite.as_str()
                        && suite.status == "active"
                        && suite.profile_gate.is_none()
                })
            || &payload.creator_leaf_authority.endpoint != intent.creator_endpoint()
            || payload.creator_leaf_authority.authorization_event_ref
                != evidence
                    .creator_device_authority
                    .projection
                    .device_authorize_event_id
            || payload.group_info_ref.as_str() != blob_ref(&self.group_info_bytes)
            || payload.ratchet_tree_ref.as_str() != blob_ref(&self.ratchet_tree_bytes)
        {
            return Err(WireError::Protocol("creator epoch-zero unit changed its scope, author, binding, public material or unsigned core".into()));
        }
        Ok(())
    }

    pub fn payload(&self) -> Result<crate::events_payloads::MlsGenesisPayload> {
        serde_json::from_value(serde_json::Value::Object(
            self.unsigned_genesis.payload.clone().into_iter().collect(),
        ))
        .map_err(|error| {
            WireError::Protocol(format!("invalid creator unsigned Genesis payload: {error}"))
        })
    }
    pub fn encrypted_private_state(&self) -> &[u8] {
        &self.encrypted_private_state
    }
    pub fn group_info_bytes(&self) -> &[u8] {
        &self.group_info_bytes
    }
    pub fn ratchet_tree_bytes(&self) -> &[u8] {
        &self.ratchet_tree_bytes
    }
    pub fn unsigned_genesis(&self) -> &arkret_wire::AuthoredEvent {
        &self.unsigned_genesis
    }
}

/// The one signed original associated with its queue ledger by Event id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapQueuedGenesis {
    signed_genesis: arkret_wire::AuthoredEvent,
    canonical_signed_bytes: Vec<u8>,
    canonical_bytes_digest: arkret_wire::Hash,
    outbound_queue_item_id: EventId,
}

impl MlsCreatorBootstrapQueuedGenesis {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        epoch_zero: &MlsCreatorBootstrapEpochZero,
        signed_genesis: arkret_wire::AuthoredEvent,
    ) -> Result<Self> {
        let bytes = arkret_canonical::canonical_json_bytes(signed_genesis.event())?;
        let value = Self {
            outbound_queue_item_id: signed_genesis.event_id().clone(),
            canonical_bytes_digest: arkret_wire::Hash::new(arkret_canonical::canonical::digest(
                signed_genesis.digest_suite(),
                &bytes,
            ))?,
            canonical_signed_bytes: bytes,
            signed_genesis,
        };
        value.validate_binding(intent, epoch_zero)?;
        Ok(value)
    }
    pub fn validate_binding(
        &self,
        intent: &MlsCreatorBootstrapIntent,
        epoch_zero: &MlsCreatorBootstrapEpochZero,
    ) -> Result<()> {
        self.signed_genesis.verify_identity()?;
        let event = self.signed_genesis.event();
        event.validate_proof_bindings_with_digest_suite(self.signed_genesis.digest_suite())?;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| WireError::Protocol("creator queue requires a signed Genesis".into()))?;
        let mut unsigned = self.signed_genesis.clone();
        unsigned.clear_producer_proof();
        if &unsigned != epoch_zero.unsigned_genesis()
            || proof.verification_method != *intent.creator_signer_method()
            || self.outbound_queue_item_id != event.event_id
            || self.canonical_signed_bytes != arkret_canonical::canonical_json_bytes(event)?
            || self.canonical_bytes_digest.as_str()
                != arkret_canonical::canonical::digest(
                    self.signed_genesis.digest_suite(),
                    &self.canonical_signed_bytes,
                )
        {
            return Err(WireError::Protocol(
                "creator queue changed the frozen unsigned core, original signer or signed bytes"
                    .into(),
            ));
        }
        Ok(())
    }
    pub fn signed_genesis(&self) -> &arkret_wire::AuthoredEvent {
        &self.signed_genesis
    }
    pub fn outbound_queue_item_id(&self) -> &EventId {
        &self.outbound_queue_item_id
    }
}

/// Exact accepted Genesis and the independently verified authority root.
/// Hosts authenticate the complete stream before constructing this carrier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapAcceptedGenesis {
    accepted: arkret_wire::CommittedEventFullView,
    canonical_accepted_bytes: Vec<u8>,
    accepted_bytes_digest: arkret_wire::Hash,
    authority_root: arkret_wire::RealmAuthorityBundle,
}

impl MlsCreatorBootstrapAcceptedGenesis {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        queued: &MlsCreatorBootstrapQueuedGenesis,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: arkret_wire::RealmAuthorityBundle,
    ) -> Result<Self> {
        let bytes = arkret_canonical::canonical_json_bytes(&accepted.event)?;
        let value = Self {
            accepted_bytes_digest: arkret_wire::Hash::new(arkret_canonical::canonical::digest(
                queued.signed_genesis.digest_suite(),
                &bytes,
            ))?,
            canonical_accepted_bytes: bytes,
            accepted,
            authority_root,
        };
        value.validate_binding(intent, queued)?;
        Ok(value)
    }
    pub fn validate_binding(
        &self,
        intent: &MlsCreatorBootstrapIntent,
        queued: &MlsCreatorBootstrapQueuedGenesis,
    ) -> Result<()> {
        self.accepted.validate_shape()?;
        self.authority_root.validate_shape()?;
        let suite = queued.signed_genesis.digest_suite();
        self.accepted
            .event
            .verify_event_id_matches_content_with_digest_suite(suite)?;
        self.accepted
            .event
            .validate_proof_bindings_with_digest_suite(suite)?;
        if self.accepted.event != *queued.signed_genesis.event()
            || self.canonical_accepted_bytes != queued.canonical_signed_bytes
            || self.canonical_accepted_bytes
                != arkret_canonical::canonical_json_bytes(&self.accepted.event)?
            || self.accepted_bytes_digest != queued.canonical_bytes_digest
            || self.authority_root.realm_id != *intent.effective_scope().realm_id()
            || self.accepted.commit.governance_generation > self.authority_root.current_generation
        {
            return Err(WireError::Protocol(
                "accepted Genesis does not bind the exact frozen signed bytes and authority".into(),
            ));
        }
        Ok(())
    }
    pub fn accepted(&self) -> &arkret_wire::CommittedEventFullView {
        &self.accepted
    }
    pub fn accepted_bytes_digest(&self) -> &arkret_wire::Hash {
        &self.accepted_bytes_digest
    }
}

/// A distinct accepted slot winner. The host authenticates its covering
/// Commit, full authority chain and exact current cut before construction.
/// This carrier never licenses adoption of the losing private state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapWinner {
    accepted: arkret_wire::CommittedEventFullView,
    canonical_accepted_bytes: Vec<u8>,
    accepted_bytes_digest: arkret_wire::Hash,
    digest_suite: arkret_canonical::DigestSuite,
    immutable_genesis_binding: MlsGovernanceBindingPayload,
    authority_root: arkret_wire::RealmAuthorityBundle,
}

impl MlsCreatorBootstrapWinner {
    pub fn new(
        record: &MlsCreatorBootstrapRecord,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: arkret_wire::RealmAuthorityBundle,
    ) -> Result<Self> {
        let suite = record
            .accepted_create()
            .ok_or_else(|| {
                WireError::Protocol("creator winner requires accepted scope create".into())
            })?
            .digest_suite();
        let value = Self::from_accepted(record.intent(), suite, accepted, authority_root)?;
        value.validate_binding(record)?;
        Ok(value)
    }

    fn from_accepted(
        intent: &MlsCreatorBootstrapIntent,
        suite: arkret_canonical::DigestSuite,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: arkret_wire::RealmAuthorityBundle,
    ) -> Result<Self> {
        let payload: crate::events_payloads::MlsGenesisPayload = serde_json::from_value(
            serde_json::Value::Object(accepted.event.payload.clone().into_iter().collect()),
        )
        .map_err(|error| {
            WireError::Protocol(format!("invalid winning Genesis payload: {error}"))
        })?;
        let bytes = arkret_canonical::canonical_json_bytes(&accepted.event)?;
        let value = Self {
            accepted_bytes_digest: arkret_wire::Hash::new(arkret_canonical::canonical::digest(
                suite, &bytes,
            ))?,
            canonical_accepted_bytes: bytes,
            digest_suite: suite,
            accepted,
            immutable_genesis_binding: payload.governance_binding,
            authority_root,
        };
        value.validate_scope_binding(intent, suite)?;
        Ok(value)
    }
    fn validate_scope_binding(
        &self,
        intent: &MlsCreatorBootstrapIntent,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.accepted.validate_shape()?;
        self.authority_root.validate_shape()?;
        self.accepted
            .event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        self.accepted
            .event
            .validate_proof_bindings_with_digest_suite(self.digest_suite)?;
        let payload: crate::events_payloads::MlsGenesisPayload = serde_json::from_value(
            serde_json::Value::Object(self.accepted.event.payload.clone().into_iter().collect()),
        )
        .map_err(|error| {
            WireError::Protocol(format!("invalid winning Genesis payload: {error}"))
        })?;
        payload.validate()?;
        let producer = self.accepted.event.human_device_producer()?;
        let endpoint_matches = match &payload.creator_leaf_authority.endpoint {
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => {
                producer.is_some_and(|producer| &producer.device_id == device_id)
            }
            arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => {
                producer.is_none()
                    && self
                        .accepted
                        .event
                        .producer_proof
                        .as_ref()
                        .is_some_and(|proof| &proof.verification_method == verification_method)
            }
        };
        if self.digest_suite != suite
            || self.accepted.event.producer_proof.is_none()
            || !endpoint_matches
            || !arkret_wire::generated::security_strings::MLS_CIPHERSUITES
                .iter()
                .any(|suite| {
                    suite.canonical_id == payload.cipher_suite.as_str()
                        && suite.status == "active"
                        && suite.profile_gate.is_none()
                })
            || self.accepted.event.kind != EventKind::MlsGenesis
            || &self.accepted.event.scope_ref != intent.effective_scope()
            || self.accepted.commit.stream_ref
                != arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None)?
            || &self.authority_root.realm_id != intent.effective_scope().realm_id()
            || self.accepted.commit.governance_generation > self.authority_root.current_generation
            || payload.governance_binding != self.immutable_genesis_binding
            || self.immutable_genesis_binding.effective_scope() != intent.effective_scope()
            || self.immutable_genesis_binding.mls_group_id()? != *intent.mls_group_id()
            || payload.created_at != self.accepted.event.created_at
            || self.canonical_accepted_bytes
                != arkret_canonical::canonical_json_bytes(&self.accepted.event)?
            || self.accepted_bytes_digest.as_str()
                != arkret_canonical::canonical::digest(
                    self.digest_suite,
                    &self.canonical_accepted_bytes,
                )
        {
            return Err(WireError::Protocol(
                "creator winner is not a distinct exact-scope accepted Genesis".into(),
            ));
        }
        Ok(())
    }
    pub fn validate_binding(&self, record: &MlsCreatorBootstrapRecord) -> Result<()> {
        let suite = record
            .accepted_create()
            .ok_or_else(|| {
                WireError::Protocol("creator winner lost scope-create authority".into())
            })?
            .digest_suite();
        self.validate_scope_binding(record.intent(), suite)?;
        let original = match record {
            MlsCreatorBootstrapRecord::Superseded { loser_record, .. } => loser_record.as_ref(),
            _ => record,
        };
        if original.diagnostic_queued_genesis().is_some_and(|queued| {
            queued.signed_genesis().event_id() == &self.accepted.event.event_id
        }) || record
            .closed_attempts()
            .iter()
            .any(|closed| closed.event_id() == &self.accepted.event.event_id)
        {
            return Err(WireError::Protocol(
                "creator winner is not a distinct exact-scope accepted Genesis".into(),
            ));
        }
        Ok(())
    }
    pub fn accepted(&self) -> &arkret_wire::CommittedEventFullView {
        &self.accepted
    }
    pub fn immutable_genesis_binding(&self) -> &MlsGovernanceBindingPayload {
        &self.immutable_genesis_binding
    }
}

/// Complete observations made by restoring the original private MLS state.
/// Hosts obtain these from the engine, never from a UI or an emitted flag.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapArtifactChecks {
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub cipher_suite: String,
    pub creator_leaf_authority: crate::events_payloads::MlsGenesisCreatorLeafAuthority,
    pub group_info_bytes: Vec<u8>,
    pub ratchet_tree_bytes: Vec<u8>,
}

/// One installed winning epoch, bound to the retained exact recovery unit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapArtifacts {
    accepted_artifact_ref: EventId,
    private_state_binding: arkret_wire::Hash,
    public_material_binding: (arkret_wire::BlobRef, arkret_wire::BlobRef),
    consistency_checks: MlsCreatorBootstrapArtifactChecks,
}

impl MlsCreatorBootstrapArtifacts {
    pub fn new(
        record: &MlsCreatorBootstrapRecord,
        checks: MlsCreatorBootstrapArtifactChecks,
    ) -> Result<Self> {
        let unit = record
            .epoch_zero()
            .ok_or_else(|| WireError::Protocol("creator artifact lost private unit".into()))?;
        let accepted = record.accepted_genesis().ok_or_else(|| {
            WireError::Protocol("creator artifact requires exact acceptance".into())
        })?;
        let payload = unit.payload()?;
        let value = Self {
            accepted_artifact_ref: accepted.accepted().event.event_id.clone(),
            private_state_binding: arkret_wire::Hash::new(arkret_canonical::canonical::digest(
                unit.unsigned_genesis().digest_suite(),
                unit.encrypted_private_state(),
            ))?,
            public_material_binding: (payload.group_info_ref, payload.ratchet_tree_ref),
            consistency_checks: checks,
        };
        value.validate_binding(record)?;
        Ok(value)
    }
    pub fn validate_binding(&self, record: &MlsCreatorBootstrapRecord) -> Result<()> {
        let unit = record
            .epoch_zero()
            .ok_or_else(|| WireError::Protocol("creator artifact lost private unit".into()))?;
        let accepted = record
            .accepted_genesis()
            .ok_or_else(|| WireError::Protocol("creator artifact lost exact acceptance".into()))?;
        let payload = unit.payload()?;
        let checks = &self.consistency_checks;
        if self.accepted_artifact_ref != accepted.accepted().event.event_id
            || self.private_state_binding.as_str()
                != arkret_canonical::canonical::digest(
                    unit.unsigned_genesis().digest_suite(),
                    unit.encrypted_private_state(),
                )
            || self.public_material_binding != (payload.group_info_ref, payload.ratchet_tree_ref)
            || &checks.effective_scope != record.intent().effective_scope()
            || &checks.mls_group_id != record.intent().mls_group_id()
            || checks.epoch != 0
            || checks.cipher_suite != payload.cipher_suite.as_str()
            || checks.creator_leaf_authority != payload.creator_leaf_authority
            || checks.group_info_bytes != unit.group_info_bytes()
            || checks.ratchet_tree_bytes != unit.ratchet_tree_bytes()
        {
            return Err(WireError::Protocol(
                "creator accepted artifact differs from its private/public winning epoch".into(),
            ));
        }
        Ok(())
    }
    pub fn accepted_artifact_ref(&self) -> &EventId {
        &self.accepted_artifact_ref
    }
}

/// Local terminal receipt; its position names the atomic vault commit that
/// publishes both this receipt and the send-gate index. It has no wire weight.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapReadyReceipt {
    owner_actor_id: ActorId,
    effective_scope: ScopeRef,
    operation: MlsCreatorBootstrapOperation,
    accepted_genesis_event_id: EventId,
    accepted_genesis_digest: arkret_wire::Hash,
    immutable_genesis_binding: MlsGovernanceBindingPayload,
    accepted_artifact_ref: EventId,
    ready_commit_position: u64,
}

impl MlsCreatorBootstrapReadyReceipt {
    pub fn new(record: &MlsCreatorBootstrapRecord, ready_commit_position: u64) -> Result<Self> {
        let accepted = record
            .accepted_genesis()
            .ok_or_else(|| WireError::Protocol("creator readiness lost exact acceptance".into()))?;
        let artifacts = record.artifacts().ok_or_else(|| {
            WireError::Protocol("creator readiness lost installed artifacts".into())
        })?;
        let value = Self {
            owner_actor_id: record.intent().owner_actor_id().clone(),
            effective_scope: record.intent().effective_scope().clone(),
            operation: MlsCreatorBootstrapOperation::MlsGenesis,
            accepted_genesis_event_id: accepted.accepted().event.event_id.clone(),
            accepted_genesis_digest: accepted.accepted_bytes_digest().clone(),
            immutable_genesis_binding: record
                .intent()
                .proposal()
                .proposed_group_genesis_binding()
                .clone(),
            accepted_artifact_ref: artifacts.accepted_artifact_ref().clone(),
            ready_commit_position,
        };
        value.validate_binding(record)?;
        Ok(value)
    }
    pub fn validate_binding(&self, record: &MlsCreatorBootstrapRecord) -> Result<()> {
        let accepted = record
            .accepted_genesis()
            .ok_or_else(|| WireError::Protocol("creator readiness lost acceptance".into()))?;
        let artifacts = record
            .artifacts()
            .ok_or_else(|| WireError::Protocol("creator readiness lost artifacts".into()))?;
        artifacts.validate_binding(record)?;
        if &self.owner_actor_id != record.intent().owner_actor_id()
            || &self.effective_scope != record.intent().effective_scope()
            || self.accepted_genesis_event_id != accepted.accepted().event.event_id
            || self.accepted_genesis_digest != *accepted.accepted_bytes_digest()
            || &self.immutable_genesis_binding
                != record.intent().proposal().proposed_group_genesis_binding()
            || &self.accepted_artifact_ref != artifacts.accepted_artifact_ref()
            || self.ready_commit_position == 0
        {
            return Err(WireError::Protocol(
                "creator readiness receipt changed its winning epoch or commit position".into(),
            ));
        }
        Ok(())
    }
    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }
    pub fn accepted_genesis_event_id(&self) -> &EventId {
        &self.accepted_genesis_event_id
    }
    pub fn ready_commit_position(&self) -> u64 {
        self.ready_commit_position
    }
}

/// An independently authenticated exact absence decision. Hosts verify the
/// current authority and snapshot signatures before constructing this carrier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapVerifiedAbsence {
    accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
    current_snapshot: Box<arkret_wire::RealmStateSnapshot>,
}

impl MlsCreatorBootstrapVerifiedAbsence {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        accepted_create: MlsCreatorBootstrapAcceptedCreate,
        current_snapshot: arkret_wire::RealmStateSnapshot,
    ) -> Result<Self> {
        let value = Self {
            accepted_create: Box::new(accepted_create),
            current_snapshot: Box::new(current_snapshot),
        };
        value.validate_binding(intent)?;
        Ok(value)
    }
    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        self.accepted_create.validate_binding(intent)?;
        validate_creator_genesis_absence_snapshot(
            intent,
            &self.accepted_create,
            &self.current_snapshot,
        )
    }
    pub fn accepted_create(&self) -> &MlsCreatorBootstrapAcceptedCreate {
        &self.accepted_create
    }
    pub fn current_snapshot(&self) -> &arkret_wire::RealmStateSnapshot {
        &self.current_snapshot
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsCreatorBootstrapRejectionStage {
    AuthoritySubmit,
}

/// The terminal diagnostic doubles as the closed-attempt tombstone. It keeps
/// the original reason rather than a UI error or a locally synthesized refusal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapRejection {
    intent: MlsCreatorBootstrapIntent,
    event_id: EventId,
    canonical_bytes_digest: arkret_wire::Hash,
    signed_genesis: Box<arkret_wire::AuthoredEvent>,
    reason_code: String,
    stage: MlsCreatorBootstrapRejectionStage,
    last_verified: MlsCreatorBootstrapVerifiedAbsence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority_problem: Option<Box<arkret_wire::Problem>>,
}

impl MlsCreatorBootstrapRejection {
    pub fn new(
        record: &MlsCreatorBootstrapRecord,
        reason_code: String,
        last_verified: MlsCreatorBootstrapVerifiedAbsence,
    ) -> Result<Self> {
        let queued = record.queued_genesis().ok_or_else(|| {
            WireError::Protocol("creator rejection requires the exact signed original".into())
        })?;
        let value = Self {
            intent: record.intent().clone(),
            event_id: queued.signed_genesis().event_id().clone(),
            canonical_bytes_digest: queued.canonical_bytes_digest.clone(),
            signed_genesis: Box::new(queued.signed_genesis().clone()),
            reason_code,
            stage: MlsCreatorBootstrapRejectionStage::AuthoritySubmit,
            last_verified,
            authority_problem: None,
        };
        value.validate_original(record)?;
        Ok(value)
    }
    /// Only a definite Event-admission refusal closes this attempt. Session,
    /// availability, routing and HTTP precondition failures do not qualify.
    pub fn terminal_problem_reason(problem: &arkret_wire::Problem) -> Option<&str> {
        let admitted = matches!(
            problem.code(),
            "capability_denied"
                | "device_revoked"
                | "device_revocation_pending"
                | "device_generation_fenced"
                | "device_unauthorized"
                | "signature_invalid"
                | "schema_violation"
                | "digest_mismatch"
                | "event_id_digest_mismatch"
                | "duplicate_conflict"
                | "failed_precondition"
                | "unsupported_event_kind"
        );
        if !admitted || !matches!(problem.status, 400 | 403 | 409 | 422) {
            return None;
        }
        Some(
            problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                .filter(|reason| arkret_wire::ReasonCode::is_registered(reason))
                .unwrap_or_else(|| problem.code()),
        )
    }
    pub fn from_problem(
        record: &MlsCreatorBootstrapRecord,
        problem: arkret_wire::Problem,
        last_verified: MlsCreatorBootstrapVerifiedAbsence,
    ) -> Result<Self> {
        let reason = Self::terminal_problem_reason(&problem).ok_or_else(|| {
            WireError::Protocol("authority Problem is not a definite Genesis rejection".into())
        })?;
        let mut value = Self::new(record, reason.to_owned(), last_verified)?;
        value.authority_problem = Some(Box::new(problem));
        value.validate_original(record)?;
        Ok(value)
    }
    pub fn authority_problem(&self) -> Option<&arkret_wire::Problem> {
        self.authority_problem.as_deref()
    }
    fn validate_tombstone(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        self.last_verified.validate_binding(intent)?;
        self.signed_genesis.verify_identity()?;
        let event = self.signed_genesis.event();
        event.validate_proof_bindings_with_digest_suite(self.signed_genesis.digest_suite())?;
        if self.signed_genesis.event_id() != &self.event_id
            || event.kind != EventKind::MlsGenesis
            || &event.actor_id != intent.owner_actor_id()
            || &event.scope_ref != intent.effective_scope()
            || event
                .producer_proof
                .as_ref()
                .is_none_or(|proof| &proof.verification_method != intent.creator_signer_method())
            || self.canonical_bytes_digest.as_str()
                != arkret_canonical::canonical::digest(
                    self.signed_genesis.digest_suite(),
                    &arkret_canonical::canonical_json_bytes(event)?,
                )
        {
            return Err(WireError::Protocol(
                "creator rejection changed its original signed evidence".into(),
            ));
        }
        if self.authority_problem.as_deref().is_some_and(|problem| {
            Self::terminal_problem_reason(problem) != Some(self.reason_code.as_str())
        }) {
            return Err(WireError::Protocol(
                "creator rejection changed its authority Problem".into(),
            ));
        }
        if &self.intent != intent
            || self.reason_code.is_empty()
            || self.canonical_bytes_digest.digest_suite()?
                != self.last_verified.accepted_create.digest_suite()
            || self.event_id.digest_suite_code().digest_suite()
                != self.last_verified.accepted_create.digest_suite()
        {
            return Err(WireError::Protocol(
                "creator rejection lost its original diagnostic".into(),
            ));
        }
        Ok(())
    }
    fn validate_original(&self, record: &MlsCreatorBootstrapRecord) -> Result<()> {
        self.validate_tombstone(record.intent())?;
        let queued = record.queued_genesis().ok_or_else(|| {
            WireError::Protocol("creator rejection lost its exact signed original".into())
        })?;
        if &self.event_id != queued.signed_genesis().event_id()
            || self.canonical_bytes_digest != queued.canonical_bytes_digest
            || self.signed_genesis.as_ref() != queued.signed_genesis()
        {
            return Err(WireError::Protocol(
                "creator rejection changed the rejected bytes".into(),
            ));
        }
        Ok(())
    }
    /// Retain public signed evidence after erasing a closed attempt's private
    /// unit, so a host can identify its derived unaccepted epoch-zero cache.
    pub fn matches_epoch_zero_public_material(
        &self,
        group_info: &[u8],
        tree: &[u8],
    ) -> Result<bool> {
        self.validate_tombstone(&self.intent)?;
        let payload: crate::events_payloads::MlsGenesisPayload =
            serde_json::from_value(serde_json::Value::Object(
                self.signed_genesis
                    .event()
                    .payload
                    .clone()
                    .into_iter()
                    .collect(),
            ))?;
        payload.validate()?;
        let matches = |reference: &arkret_wire::BlobRef, bytes: &[u8]| -> Result<bool> {
            let digest = crate::mls_group_state_material::material_digest_from_ref(reference)?;
            Ok(digest.as_str()
                == arkret_canonical::canonical::digest(digest.digest_suite()?, bytes))
        };
        Ok(matches(&payload.group_info_ref, group_info)?
            && matches(&payload.ratchet_tree_ref, tree)?)
    }
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
    pub fn canonical_bytes_digest(&self) -> &arkret_wire::Hash {
        &self.canonical_bytes_digest
    }
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }
}

/// The local invariant that stopped an authenticated creator recovery unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsCreatorBootstrapInvariant {
    RecordBinding,
    QueueBinding,
    PrivateMaterial,
    PublicMaterial,
    SignedBytes,
    AcceptedResult,
    ReadyIndex,
}

impl MlsCreatorBootstrapInvariant {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::RecordBinding => "creator_record_binding_mismatch",
            Self::QueueBinding => "creator_queue_binding_mismatch",
            Self::PrivateMaterial => "creator_private_material_mismatch",
            Self::PublicMaterial => "creator_public_material_mismatch",
            Self::SignedBytes => "creator_signed_bytes_mismatch",
            Self::AcceptedResult => "creator_accepted_result_mismatch",
            Self::ReadyIndex => "creator_ready_index_mismatch",
        }
    }
}

/// Exact accepted evidence already verified by the host, retained only for
/// quarantine diagnosis. Neither branch permits a private install or send.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsCreatorBootstrapKnownGenesis {
    Original {
        acceptance: Box<MlsCreatorBootstrapAcceptedGenesis>,
    },
    Winner {
        winner: Box<MlsCreatorBootstrapWinner>,
    },
}

impl MlsCreatorBootstrapKnownGenesis {
    /// Hosts independently authenticate this accepted row and authority root.
    /// A closed/original Event is retained as a contradiction, never adopted.
    pub fn authenticated_winner(
        record: &MlsCreatorBootstrapRecord,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: arkret_wire::RealmAuthorityBundle,
    ) -> Result<Self> {
        let suite = record
            .accepted_create()
            .ok_or_else(|| {
                WireError::Protocol("known creator winner lost scope-create authority".into())
            })?
            .digest_suite();
        Ok(Self::Winner {
            winner: Box::new(MlsCreatorBootstrapWinner::from_accepted(
                record.intent(),
                suite,
                accepted,
                authority_root,
            )?),
        })
    }
}

/// A local terminal diagnostic, retaining the authenticated original even if
/// its corrupt recovery unit cannot deserialize into the active record DTO.
/// Hosts authenticate the vault and independently verify any known winner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapQuarantine {
    last_state: arkret_wire::MlsCreatorBootstrapState,
    invariant: MlsCreatorBootstrapInvariant,
    invariant_detail: String,
    event_id: Option<EventId>,
    canonical_bytes_digest: Option<arkret_wire::Hash>,
    outbound_queue_item_id: Option<EventId>,
    accepted_winner: Option<Box<MlsCreatorBootstrapKnownGenesis>>,
    reason_code: String,
    detected_at: chrono::DateTime<chrono::Utc>,
    recovery_record: Box<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    related_recovery_records: Vec<serde_json::Value>,
    recovery_queue_items: Vec<serde_json::Value>,
}

impl MlsCreatorBootstrapQuarantine {
    fn original_attempt(mut raw: &serde_json::Value) -> &serde_json::Value {
        while let Some(inner) = raw
            .get("rejected_record")
            .or_else(|| raw.get("loser_record"))
        {
            raw = inner;
        }
        raw
    }
    fn signed_coordinates(
        raw: &serde_json::Value,
    ) -> (Option<EventId>, Option<arkret_wire::Hash>, Option<EventId>) {
        let queued = Self::original_attempt(raw).get("queued_genesis");
        let typed = |value: Option<&serde_json::Value>| {
            value
                .cloned()
                .and_then(|value| serde_json::from_value::<EventId>(value).ok())
        };
        (
            typed(queued.and_then(|queued| queued.pointer("/signed_genesis/event/event_id"))),
            queued
                .and_then(|queued| queued.get("canonical_bytes_digest"))
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok()),
            typed(queued.and_then(|queued| queued.get("outbound_queue_item_id"))),
        )
    }
    fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        let original_intent: MlsCreatorBootstrapIntent =
            serde_json::from_value(self.recovery_record.get("intent").cloned().ok_or_else(
                || WireError::Protocol("quarantine lost its original intent".into()),
            )?)?;
        let coordinates = Self::signed_coordinates(&self.recovery_record);
        if &original_intent != intent
            || self
                .recovery_record
                .get("state")
                .and_then(serde_json::Value::as_str)
                != Some(self.last_state.as_str())
            || self.last_state.failure_disposition()
                != arkret_wire::MlsCreatorBootstrapFailureDisposition::Quarantined
            || self.invariant_detail.trim().is_empty()
            || self.reason_code != self.invariant.reason_code()
            || self.detected_at != arkret_canonical::normalize_timestamp_canonical(self.detected_at)
            || (
                &self.event_id,
                &self.canonical_bytes_digest,
                &self.outbound_queue_item_id,
            ) != (&coordinates.0, &coordinates.1, &coordinates.2)
        {
            return Err(WireError::Protocol(
                "creator quarantine changed its original diagnostic or logical key".into(),
            ));
        }
        for raw in &self.related_recovery_records {
            let related: MlsCreatorBootstrapIntent = serde_json::from_value(
                raw.get("intent")
                    .cloned()
                    .ok_or_else(|| WireError::Protocol("related recovery lost intent".into()))?,
            )?;
            related.validate()?;
            let state = raw
                .get("state")
                .and_then(serde_json::Value::as_str)
                .and_then(arkret_wire::MlsCreatorBootstrapState::from_wire)
                .ok_or_else(|| {
                    WireError::Protocol("related recovery lost its last state".into())
                })?;
            if related.owner_actor_id() != intent.owner_actor_id()
                || related.effective_scope() != intent.effective_scope()
                || state.failure_disposition()
                    != arkret_wire::MlsCreatorBootstrapFailureDisposition::Quarantined
            {
                return Err(WireError::Protocol(
                    "related quarantine material changed its logical key or terminal state".into(),
                ));
            }
        }
        if let Some(known) = &self.accepted_winner {
            match known.as_ref() {
                MlsCreatorBootstrapKnownGenesis::Original { acceptance } => {
                    let queued: MlsCreatorBootstrapQueuedGenesis = serde_json::from_value(
                        Self::original_attempt(&self.recovery_record)
                            .get("queued_genesis")
                            .cloned()
                            .ok_or_else(|| {
                                WireError::Protocol(
                                    "quarantine accepted original lost its signed bytes".into(),
                                )
                            })?,
                    )?;
                    acceptance.validate_binding(intent, &queued)?;
                }
                MlsCreatorBootstrapKnownGenesis::Winner { winner } => {
                    winner.validate_scope_binding(
                        intent,
                        intent
                            .scope_create_event_id()
                            .digest_suite_code()
                            .digest_suite(),
                    )?;
                }
            }
        }
        Ok(())
    }
    pub fn last_state(&self) -> arkret_wire::MlsCreatorBootstrapState {
        self.last_state
    }
    pub fn invariant(&self) -> MlsCreatorBootstrapInvariant {
        self.invariant
    }
    pub fn event_id(&self) -> Option<&EventId> {
        self.event_id.as_ref()
    }
    pub fn outbound_queue_item_id(&self) -> Option<&EventId> {
        self.outbound_queue_item_id.as_ref()
    }
    pub fn recovery_record(&self) -> &serde_json::Value {
        &self.recovery_record
    }
    pub fn related_recovery_records(&self) -> &[serde_json::Value] {
        &self.related_recovery_records
    }
    pub fn recovery_queue_items(&self) -> &[serde_json::Value] {
        &self.recovery_queue_items
    }
    pub fn accepted_winner(&self) -> Option<&MlsCreatorBootstrapKnownGenesis> {
        self.accepted_winner.as_deref()
    }
}

/// Durable recovery units of the normative creator transaction.
/// Hosts authenticate evidence before committing a transition;
/// the checks here bind the saved bytes, not their signatures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsCreatorBootstrapRecord {
    GenesisIntentPersisted {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
    },
    RealmAccepted {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
    },
    GovernanceResultPinned {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
        governance_evidence: Box<MlsCreatorBootstrapGovernanceEvidence>,
    },
    Epoch0StatePersisted {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
        governance_evidence: Box<MlsCreatorBootstrapGovernanceEvidence>,
        epoch_zero: Box<MlsCreatorBootstrapEpochZero>,
    },
    GenesisQueued {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
        governance_evidence: Box<MlsCreatorBootstrapGovernanceEvidence>,
        epoch_zero: Box<MlsCreatorBootstrapEpochZero>,
        queued_genesis: Box<MlsCreatorBootstrapQueuedGenesis>,
    },
    GenesisAccepted {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
        governance_evidence: Box<MlsCreatorBootstrapGovernanceEvidence>,
        epoch_zero: Box<MlsCreatorBootstrapEpochZero>,
        queued_genesis: Box<MlsCreatorBootstrapQueuedGenesis>,
        accepted_genesis: Box<MlsCreatorBootstrapAcceptedGenesis>,
    },
    ArtifactsConverged {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
        governance_evidence: Box<MlsCreatorBootstrapGovernanceEvidence>,
        epoch_zero: Box<MlsCreatorBootstrapEpochZero>,
        queued_genesis: Box<MlsCreatorBootstrapQueuedGenesis>,
        accepted_genesis: Box<MlsCreatorBootstrapAcceptedGenesis>,
        artifacts: Box<MlsCreatorBootstrapArtifacts>,
    },
    Ready {
        intent: Box<MlsCreatorBootstrapIntent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        closed_attempts: Vec<MlsCreatorBootstrapRejection>,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
        governance_evidence: Box<MlsCreatorBootstrapGovernanceEvidence>,
        epoch_zero: Box<MlsCreatorBootstrapEpochZero>,
        queued_genesis: Box<MlsCreatorBootstrapQueuedGenesis>,
        accepted_genesis: Box<MlsCreatorBootstrapAcceptedGenesis>,
        artifacts: Box<MlsCreatorBootstrapArtifacts>,
        ready_receipt: Box<MlsCreatorBootstrapReadyReceipt>,
    },
    Rejected {
        intent: Box<MlsCreatorBootstrapIntent>,
        rejection: Box<MlsCreatorBootstrapRejection>,
        rejected_record: Box<MlsCreatorBootstrapRecord>,
    },
    Superseded {
        intent: Box<MlsCreatorBootstrapIntent>,
        winner: Box<MlsCreatorBootstrapWinner>,
        loser_genesis: Option<(EventId, arkret_wire::Hash)>,
        loser_record: Box<MlsCreatorBootstrapRecord>,
    },
    Quarantined {
        intent: Box<MlsCreatorBootstrapIntent>,
        diagnostic: Box<MlsCreatorBootstrapQuarantine>,
    },
}

impl MlsCreatorBootstrapRecord {
    pub fn new(intent: MlsCreatorBootstrapIntent) -> Result<Self> {
        intent.validate()?;
        Ok(Self::GenesisIntentPersisted {
            intent: Box::new(intent),
            closed_attempts: Vec::new(),
        })
    }

    pub fn intent(&self) -> &MlsCreatorBootstrapIntent {
        match self {
            Self::GenesisIntentPersisted { intent, .. }
            | Self::RealmAccepted { intent, .. }
            | Self::GovernanceResultPinned { intent, .. }
            | Self::Epoch0StatePersisted { intent, .. }
            | Self::GenesisQueued { intent, .. }
            | Self::GenesisAccepted { intent, .. }
            | Self::ArtifactsConverged { intent, .. }
            | Self::Ready { intent, .. }
            | Self::Rejected { intent, .. }
            | Self::Superseded { intent, .. }
            | Self::Quarantined { intent, .. } => intent,
        }
    }

    pub fn state(&self) -> arkret_wire::MlsCreatorBootstrapState {
        match self {
            Self::GenesisIntentPersisted { .. } => {
                arkret_wire::MlsCreatorBootstrapState::GenesisIntentPersisted
            }
            Self::RealmAccepted { .. } => arkret_wire::MlsCreatorBootstrapState::RealmAccepted,
            Self::GovernanceResultPinned { .. } => {
                arkret_wire::MlsCreatorBootstrapState::GovernanceResultPinned
            }
            Self::Epoch0StatePersisted { .. } => {
                arkret_wire::MlsCreatorBootstrapState::Epoch0StatePersisted
            }
            Self::GenesisQueued { .. } => arkret_wire::MlsCreatorBootstrapState::GenesisQueued,
            Self::GenesisAccepted { .. } => arkret_wire::MlsCreatorBootstrapState::GenesisAccepted,
            Self::ArtifactsConverged { .. } => {
                arkret_wire::MlsCreatorBootstrapState::ArtifactsConverged
            }
            Self::Ready { .. } => arkret_wire::MlsCreatorBootstrapState::Ready,
            Self::Rejected { .. } => arkret_wire::MlsCreatorBootstrapState::Rejected,
            Self::Superseded { .. } => arkret_wire::MlsCreatorBootstrapState::Superseded,
            Self::Quarantined { .. } => arkret_wire::MlsCreatorBootstrapState::Quarantined,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.intent().validate()?;
        if let Self::Quarantined { diagnostic, .. } = self {
            return diagnostic.validate_binding(self.intent());
        }
        if self.state() == arkret_wire::MlsCreatorBootstrapState::GenesisIntentPersisted
            && !self.closed_attempts().is_empty()
        {
            return Err(WireError::Protocol(
                "a closed creator attempt cannot reopen at intent persistence".into(),
            ));
        }
        let mut closed_ids = std::collections::BTreeSet::new();
        for closed in self.closed_attempts() {
            closed.validate_tombstone(self.intent())?;
            if !closed_ids.insert(closed.event_id()) {
                return Err(WireError::Protocol(
                    "creator attempt tombstone was duplicated".into(),
                ));
            }
        }
        if self
            .diagnostic_queued_genesis()
            .is_some_and(|queued| closed_ids.contains(queued.signed_genesis().event_id()))
        {
            return Err(WireError::Protocol(
                "creator cannot reopen rejected signed bytes".into(),
            ));
        }
        if let Self::Rejected {
            intent,
            rejection,
            rejected_record,
        } = self
        {
            rejected_record.validate()?;
            if intent.as_ref() != rejected_record.intent()
                || rejected_record.state() != arkret_wire::MlsCreatorBootstrapState::GenesisQueued
                || !rejected_record
                    .state()
                    .allowed_exits()
                    .contains(&arkret_wire::MlsCreatorBootstrapState::Rejected)
            {
                return Err(WireError::Protocol(
                    "creator rejection changed the original attempt".into(),
                ));
            }
            rejection.validate_original(rejected_record)?;
            return Ok(());
        }
        if let Self::Superseded {
            intent,
            winner,
            loser_genesis,
            loser_record,
        } = self
        {
            loser_record.validate()?;
            if intent.as_ref() != loser_record.intent()
                || !loser_record
                    .state()
                    .allowed_exits()
                    .contains(&arkret_wire::MlsCreatorBootstrapState::Superseded)
                || *loser_genesis
                    != loser_record.diagnostic_queued_genesis().map(|queued| {
                        (
                            queued.signed_genesis().event_id().clone(),
                            queued.canonical_bytes_digest.clone(),
                        )
                    })
            {
                return Err(WireError::Protocol(
                    "superseded creator changed its immutable loser or terminal diagnostics".into(),
                ));
            }
            winner.validate_binding(loser_record)?;
            return Ok(());
        }
        if let Self::RealmAccepted {
            intent,
            accepted_create,
            genesis_absence,
            ..
        }
        | Self::GovernanceResultPinned {
            intent,
            accepted_create,
            genesis_absence,
            ..
        }
        | Self::Epoch0StatePersisted {
            intent,
            accepted_create,
            genesis_absence,
            ..
        }
        | Self::GenesisQueued {
            intent,
            accepted_create,
            genesis_absence,
            ..
        }
        | Self::GenesisAccepted {
            intent,
            accepted_create,
            genesis_absence,
            ..
        }
        | Self::ArtifactsConverged {
            intent,
            accepted_create,
            genesis_absence,
            ..
        }
        | Self::Ready {
            intent,
            accepted_create,
            genesis_absence,
            ..
        } = self
        {
            accepted_create.validate_binding(intent)?;
            validate_creator_genesis_absence_snapshot(intent, accepted_create, genesis_absence)?;
        }
        if let Some(evidence) = self.governance_evidence() {
            evidence.validate_binding(self.intent())?;
        }
        if let Some(epoch_zero) = self.epoch_zero() {
            epoch_zero.validate_binding(
                self.intent(),
                self.governance_evidence()
                    .ok_or_else(|| WireError::Protocol("creator epoch zero lost its pin".into()))?,
            )?;
        }
        if let Some(queued) = self.queued_genesis() {
            queued.validate_binding(
                self.intent(),
                self.epoch_zero()
                    .ok_or_else(|| WireError::Protocol("creator queue lost epoch zero".into()))?,
            )?;
        }
        if let Some(accepted) = self.accepted_genesis() {
            accepted.validate_binding(
                self.intent(),
                self.queued_genesis().ok_or_else(|| {
                    WireError::Protocol("accepted Genesis lost its signed original".into())
                })?,
            )?;
        }
        if let Some(artifacts) = self.artifacts() {
            artifacts.validate_binding(self)?;
        }
        if let Some(receipt) = self.ready_receipt() {
            receipt.validate_binding(self)?;
        }
        Ok(())
    }

    /// Convert only an authenticated local record with a valid immutable
    /// intent. This is not a repair: all active getters become unavailable and
    /// the entire original recovery material remains inside the protected vault.
    pub fn quarantine_authenticated_record(
        recovery_record: serde_json::Value,
        recovery_queue_items: Vec<serde_json::Value>,
        invariant: MlsCreatorBootstrapInvariant,
        invariant_detail: String,
        accepted_winner: Option<MlsCreatorBootstrapKnownGenesis>,
        detected_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        Self::quarantine_authenticated_records(
            vec![recovery_record],
            recovery_queue_items,
            invariant,
            invariant_detail,
            accepted_winner,
            detected_at,
        )
    }

    /// Collapse conflicting authenticated records for one logical key while
    /// retaining every original. Terminal diagnostics cannot be amended.
    pub fn quarantine_authenticated_records(
        mut recovery_records: Vec<serde_json::Value>,
        recovery_queue_items: Vec<serde_json::Value>,
        invariant: MlsCreatorBootstrapInvariant,
        invariant_detail: String,
        accepted_winner: Option<MlsCreatorBootstrapKnownGenesis>,
        detected_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        if recovery_records.is_empty() {
            return Err(WireError::Protocol(
                "quarantine requires original recovery material".into(),
            ));
        }
        let recovery_record = recovery_records.remove(0);
        let intent: MlsCreatorBootstrapIntent =
            serde_json::from_value(recovery_record.get("intent").cloned().ok_or_else(|| {
                WireError::Protocol(
                    "cannot quarantine a record without its authenticated intent".into(),
                )
            })?)?;
        intent.validate()?;
        let last_state = recovery_record
            .get("state")
            .and_then(serde_json::Value::as_str)
            .and_then(arkret_wire::MlsCreatorBootstrapState::from_wire)
            .ok_or_else(|| {
                WireError::Protocol("cannot quarantine an unknown creator state".into())
            })?;
        let (event_id, canonical_bytes_digest, outbound_queue_item_id) =
            MlsCreatorBootstrapQuarantine::signed_coordinates(&recovery_record);
        let diagnostic = MlsCreatorBootstrapQuarantine {
            last_state,
            invariant,
            invariant_detail,
            event_id,
            canonical_bytes_digest,
            outbound_queue_item_id,
            accepted_winner: accepted_winner.map(Box::new),
            reason_code: invariant.reason_code().to_owned(),
            detected_at: arkret_canonical::normalize_timestamp_canonical(detected_at),
            recovery_record: Box::new(recovery_record),
            related_recovery_records: recovery_records,
            recovery_queue_items,
        };
        let next = Self::Quarantined {
            intent: Box::new(intent),
            diagnostic: Box::new(diagnostic),
        };
        next.validate()?;
        Ok(next)
    }
    pub fn quarantine_diagnostic(&self) -> Option<&MlsCreatorBootstrapQuarantine> {
        match self {
            Self::Quarantined { diagnostic, .. } => Some(diagnostic),
            _ => None,
        }
    }

    pub fn accepted_create(&self) -> Option<&MlsCreatorBootstrapAcceptedCreate> {
        match self {
            Self::RealmAccepted {
                accepted_create, ..
            }
            | Self::GovernanceResultPinned {
                accepted_create, ..
            }
            | Self::Epoch0StatePersisted {
                accepted_create, ..
            }
            | Self::GenesisQueued {
                accepted_create, ..
            }
            | Self::GenesisAccepted {
                accepted_create, ..
            }
            | Self::ArtifactsConverged {
                accepted_create, ..
            }
            | Self::Ready {
                accepted_create, ..
            } => Some(accepted_create),
            Self::Superseded { loser_record, .. } => loser_record.accepted_create(),
            Self::Rejected {
                rejected_record, ..
            } => rejected_record.accepted_create(),
            _ => None,
        }
    }
    pub fn closed_attempts(&self) -> &[MlsCreatorBootstrapRejection] {
        match self {
            Self::GenesisIntentPersisted {
                closed_attempts, ..
            }
            | Self::RealmAccepted {
                closed_attempts, ..
            }
            | Self::GovernanceResultPinned {
                closed_attempts, ..
            }
            | Self::Epoch0StatePersisted {
                closed_attempts, ..
            }
            | Self::GenesisQueued {
                closed_attempts, ..
            }
            | Self::GenesisAccepted {
                closed_attempts, ..
            }
            | Self::ArtifactsConverged {
                closed_attempts, ..
            }
            | Self::Ready {
                closed_attempts, ..
            } => closed_attempts,
            Self::Superseded { loser_record, .. } => loser_record.closed_attempts(),
            Self::Rejected {
                rejected_record, ..
            } => rejected_record.closed_attempts(),
            Self::Quarantined { .. } => &[],
        }
    }
    fn diagnostic_queued_genesis(&self) -> Option<&MlsCreatorBootstrapQueuedGenesis> {
        match self {
            Self::Rejected {
                rejected_record, ..
            } => rejected_record.diagnostic_queued_genesis(),
            Self::Superseded { loser_record, .. } => loser_record.diagnostic_queued_genesis(),
            _ => self.queued_genesis(),
        }
    }
    pub fn rejection(&self) -> Option<&MlsCreatorBootstrapRejection> {
        match self {
            Self::Rejected { rejection, .. } => Some(rejection),
            _ => None,
        }
    }
    pub fn reject(&mut self, rejection: MlsCreatorBootstrapRejection) -> Result<()> {
        if let Some(existing) = self.rejection() {
            return if existing == &rejection {
                self.validate()
            } else {
                Err(WireError::Protocol(
                    "cannot replace the original creator rejection".into(),
                ))
            };
        }
        rejection.validate_original(self)?;
        let next = Self::Rejected {
            intent: Box::new(self.intent().clone()),
            rejection: Box::new(rejection),
            rejected_record: Box::new(self.clone()),
        };
        next.validate()?;
        *self = next;
        Ok(())
    }
    /// Close the old attempt and carry its tombstone into the next generation
    /// under the same key. Hosts commit this whole replacement atomically.
    pub fn reopen_rejected(&mut self, absence: MlsCreatorBootstrapVerifiedAbsence) -> Result<()> {
        self.validate()?;
        let Self::Rejected {
            intent,
            rejection,
            rejected_record,
        } = self
        else {
            return Err(WireError::Protocol(
                "only a rejected creator attempt may reopen".into(),
            ));
        };
        absence.validate_binding(intent)?;
        if absence
            .accepted_create
            .authority_root()
            .current_assertion
            .nonce
            == rejection
                .last_verified
                .accepted_create
                .authority_root()
                .current_assertion
                .nonce
        {
            return Err(WireError::Protocol(
                "reopening requires a new independently verified absence query".into(),
            ));
        }
        let mut closed_attempts = rejected_record.closed_attempts().to_vec();
        closed_attempts.push((**rejection).clone());
        let next = Self::RealmAccepted {
            intent: intent.clone(),
            closed_attempts,
            accepted_create: absence.accepted_create,
            genesis_absence: absence.current_snapshot,
        };
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn superseded_winner(&self) -> Option<&MlsCreatorBootstrapWinner> {
        match self {
            Self::Superseded { winner, .. } => Some(winner),
            _ => None,
        }
    }
    pub fn supersede(&mut self, winner: MlsCreatorBootstrapWinner) -> Result<()> {
        if let Some(existing) = self.superseded_winner() {
            return if existing == &winner {
                self.validate()
            } else {
                Err(WireError::Protocol(
                    "cannot replace terminal creator winner".into(),
                ))
            };
        }
        if !self
            .state()
            .allowed_exits()
            .contains(&arkret_wire::MlsCreatorBootstrapState::Superseded)
        {
            return Err(WireError::Protocol(
                "creator state has no registered superseded exit".into(),
            ));
        }
        winner.validate_binding(self)?;
        let next = Self::Superseded {
            intent: Box::new(self.intent().clone()),
            loser_genesis: self.diagnostic_queued_genesis().map(|queued| {
                (
                    queued.signed_genesis().event_id().clone(),
                    queued.canonical_bytes_digest.clone(),
                )
            }),
            loser_record: Box::new(self.clone()),
            winner: Box::new(winner),
        };
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn governance_evidence(&self) -> Option<&MlsCreatorBootstrapGovernanceEvidence> {
        match self {
            Self::GovernanceResultPinned {
                governance_evidence,
                ..
            }
            | Self::Epoch0StatePersisted {
                governance_evidence,
                ..
            }
            | Self::GenesisQueued {
                governance_evidence,
                ..
            }
            | Self::GenesisAccepted {
                governance_evidence,
                ..
            }
            | Self::ArtifactsConverged {
                governance_evidence,
                ..
            }
            | Self::Ready {
                governance_evidence,
                ..
            } => Some(governance_evidence),
            _ => None,
        }
    }

    pub fn epoch_zero(&self) -> Option<&MlsCreatorBootstrapEpochZero> {
        match self {
            Self::Epoch0StatePersisted { epoch_zero, .. }
            | Self::GenesisQueued { epoch_zero, .. }
            | Self::GenesisAccepted { epoch_zero, .. }
            | Self::ArtifactsConverged { epoch_zero, .. }
            | Self::Ready { epoch_zero, .. } => Some(epoch_zero),
            _ => None,
        }
    }
    pub fn queued_genesis(&self) -> Option<&MlsCreatorBootstrapQueuedGenesis> {
        match self {
            Self::GenesisQueued { queued_genesis, .. }
            | Self::GenesisAccepted { queued_genesis, .. }
            | Self::ArtifactsConverged { queued_genesis, .. }
            | Self::Ready { queued_genesis, .. } => Some(queued_genesis),
            _ => None,
        }
    }
    pub fn accepted_genesis(&self) -> Option<&MlsCreatorBootstrapAcceptedGenesis> {
        match self {
            Self::GenesisAccepted {
                accepted_genesis, ..
            }
            | Self::ArtifactsConverged {
                accepted_genesis, ..
            }
            | Self::Ready {
                accepted_genesis, ..
            } => Some(accepted_genesis),
            _ => None,
        }
    }
    pub fn artifacts(&self) -> Option<&MlsCreatorBootstrapArtifacts> {
        match self {
            Self::ArtifactsConverged { artifacts, .. } | Self::Ready { artifacts, .. } => {
                Some(artifacts)
            }
            _ => None,
        }
    }
    pub fn ready_receipt(&self) -> Option<&MlsCreatorBootstrapReadyReceipt> {
        match self {
            Self::Ready { ready_receipt, .. } => Some(ready_receipt),
            _ => None,
        }
    }
    pub fn converge_artifacts(&mut self, artifacts: MlsCreatorBootstrapArtifacts) -> Result<()> {
        artifacts.validate_binding(self)?;
        if let Some(existing) = self.artifacts() {
            return if existing == &artifacts {
                Ok(())
            } else {
                Err(WireError::Protocol(
                    "cannot replace installed creator artifacts".into(),
                ))
            };
        }
        let Self::GenesisAccepted {
            intent,
            closed_attempts,
            accepted_create,
            genesis_absence,
            governance_evidence,
            epoch_zero,
            queued_genesis,
            accepted_genesis,
        } = self
        else {
            return Err(WireError::Protocol(
                "creator artifact install requires exact accepted Genesis".into(),
            ));
        };
        let next = Self::ArtifactsConverged {
            intent: intent.clone(),
            closed_attempts: closed_attempts.clone(),
            accepted_create: accepted_create.clone(),
            genesis_absence: genesis_absence.clone(),
            governance_evidence: governance_evidence.clone(),
            epoch_zero: epoch_zero.clone(),
            queued_genesis: queued_genesis.clone(),
            accepted_genesis: accepted_genesis.clone(),
            artifacts: Box::new(artifacts),
        };
        let arrow = arkret_wire::MlsCreatorBootstrapTransition::GenesisAcceptedToArtifactsConverged;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "invalid registered creator artifact arrow".into(),
            ));
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn publish_ready(&mut self, ready_receipt: MlsCreatorBootstrapReadyReceipt) -> Result<()> {
        ready_receipt.validate_binding(self)?;
        if let Some(existing) = self.ready_receipt() {
            return if existing == &ready_receipt {
                Ok(())
            } else {
                Err(WireError::Protocol(
                    "cannot replace creator ready receipt".into(),
                ))
            };
        }
        let Self::ArtifactsConverged {
            intent,
            closed_attempts,
            accepted_create,
            genesis_absence,
            governance_evidence,
            epoch_zero,
            queued_genesis,
            accepted_genesis,
            artifacts,
        } = self
        else {
            return Err(WireError::Protocol(
                "creator readiness requires durable artifacts".into(),
            ));
        };
        let next = Self::Ready {
            intent: intent.clone(),
            closed_attempts: closed_attempts.clone(),
            accepted_create: accepted_create.clone(),
            genesis_absence: genesis_absence.clone(),
            governance_evidence: governance_evidence.clone(),
            epoch_zero: epoch_zero.clone(),
            queued_genesis: queued_genesis.clone(),
            accepted_genesis: accepted_genesis.clone(),
            artifacts: artifacts.clone(),
            ready_receipt: Box::new(ready_receipt),
        };
        let arrow = arkret_wire::MlsCreatorBootstrapTransition::ArtifactsConvergedToReady;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "invalid registered creator ready arrow".into(),
            ));
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn accept_genesis(&mut self, accepted: MlsCreatorBootstrapAcceptedGenesis) -> Result<()> {
        if let Some(existing) = self.accepted_genesis() {
            return if existing == &accepted {
                Ok(())
            } else {
                Err(WireError::Protocol(
                    "cannot replace creator accepted Genesis evidence".into(),
                ))
            };
        }
        let Self::GenesisQueued {
            intent,
            closed_attempts,
            accepted_create,
            genesis_absence,
            governance_evidence,
            epoch_zero,
            queued_genesis,
        } = self
        else {
            return Err(WireError::Protocol(
                "creator acceptance requires durable signed original".into(),
            ));
        };
        let next = Self::GenesisAccepted {
            intent: intent.clone(),
            closed_attempts: closed_attempts.clone(),
            accepted_create: accepted_create.clone(),
            genesis_absence: genesis_absence.clone(),
            governance_evidence: governance_evidence.clone(),
            epoch_zero: epoch_zero.clone(),
            queued_genesis: queued_genesis.clone(),
            accepted_genesis: Box::new(accepted),
        };
        let arrow = arkret_wire::MlsCreatorBootstrapTransition::GenesisQueuedToGenesisAccepted;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "invalid registered creator acceptance arrow".into(),
            ));
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn persist_epoch_zero(&mut self, unit: MlsCreatorBootstrapEpochZero) -> Result<()> {
        if let Some(existing) = self.epoch_zero() {
            return if existing == &unit {
                Ok(())
            } else {
                Err(WireError::Protocol(
                    "cannot replace creator epoch-zero recovery material".into(),
                ))
            };
        }
        let Self::GovernanceResultPinned {
            intent,
            closed_attempts,
            accepted_create,
            genesis_absence,
            governance_evidence,
        } = self
        else {
            return Err(WireError::Protocol(
                "creator epoch zero requires durable governance pin".into(),
            ));
        };
        let next = Self::Epoch0StatePersisted {
            intent: intent.clone(),
            closed_attempts: closed_attempts.clone(),
            accepted_create: accepted_create.clone(),
            genesis_absence: genesis_absence.clone(),
            governance_evidence: governance_evidence.clone(),
            epoch_zero: Box::new(unit),
        };
        let arrow = arkret_wire::MlsCreatorBootstrapTransition::GovernanceResultPinnedToEpoch0StatePersisted;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "invalid registered creator epoch-zero arrow".into(),
            ));
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn queue_genesis(&mut self, signed: arkret_wire::AuthoredEvent) -> Result<()> {
        let unit = self.epoch_zero().ok_or_else(|| {
            WireError::Protocol("creator queue requires durable epoch zero".into())
        })?;
        let queued = MlsCreatorBootstrapQueuedGenesis::new(self.intent(), unit, signed)?;
        if let Some(existing) = self.queued_genesis() {
            return if existing == &queued {
                Ok(())
            } else {
                Err(WireError::Protocol(
                    "cannot replace creator signed original".into(),
                ))
            };
        }
        let Self::Epoch0StatePersisted {
            intent,
            closed_attempts,
            accepted_create,
            genesis_absence,
            governance_evidence,
            epoch_zero,
        } = self
        else {
            return Err(WireError::Protocol(
                "creator queue requires the registered epoch-zero state".into(),
            ));
        };
        let next = Self::GenesisQueued {
            intent: intent.clone(),
            closed_attempts: closed_attempts.clone(),
            accepted_create: accepted_create.clone(),
            genesis_absence: genesis_absence.clone(),
            governance_evidence: governance_evidence.clone(),
            epoch_zero: epoch_zero.clone(),
            queued_genesis: Box::new(queued),
        };
        let arrow = arkret_wire::MlsCreatorBootstrapTransition::Epoch0StatePersistedToGenesisQueued;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "invalid registered creator queue arrow".into(),
            ));
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn pin_governance(
        &mut self,
        evidence: MlsCreatorBootstrapGovernanceEvidence,
    ) -> Result<()> {
        evidence.validate_binding(self.intent())?;
        if let Some(existing) = self.governance_evidence() {
            return if existing == &evidence {
                Ok(())
            } else {
                Err(WireError::Protocol(
                    "cannot replace pinned creator governance evidence".into(),
                ))
            };
        }
        let Self::RealmAccepted {
            intent,
            closed_attempts,
            accepted_create,
            genesis_absence,
        } = self
        else {
            return Err(WireError::Protocol(
                "creator governance pin requires durable Realm acceptance".into(),
            ));
        };
        let next = Self::GovernanceResultPinned {
            intent: intent.clone(),
            closed_attempts: closed_attempts.clone(),
            accepted_create: accepted_create.clone(),
            genesis_absence: genesis_absence.clone(),
            governance_evidence: Box::new(evidence),
        };
        let arrow =
            arkret_wire::MlsCreatorBootstrapTransition::RealmAcceptedToGovernanceResultPinned;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "invalid registered creator governance pin arrow".into(),
            ));
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Advance exactly the registered acceptance arrow. Once accepted, retain
    /// the original cut; an idempotent replay cannot replace it with a new one.
    pub fn accept_realm(
        &mut self,
        accepted_create: MlsCreatorBootstrapAcceptedCreate,
        genesis_absence: arkret_wire::RealmStateSnapshot,
    ) -> Result<()> {
        let next = Self::RealmAccepted {
            intent: Box::new(self.intent().clone()),
            closed_attempts: self.closed_attempts().to_vec(),
            accepted_create: Box::new(accepted_create),
            genesis_absence: Box::new(genesis_absence),
        };
        next.validate()?;
        if *self == next {
            return Ok(());
        }
        let arrow =
            arkret_wire::MlsCreatorBootstrapTransition::GenesisIntentPersistedToRealmAccepted;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "creator acceptance cannot replace an immutable durable cut".into(),
            ));
        }
        *self = next;
        Ok(())
    }
}

/// Bind an independently authenticated complete snapshot to exact Genesis
/// absence. A signed current snapshot is an existing complete current carrier;
/// no fabricated Account baseline or empty projection is used as evidence.
pub fn validate_creator_genesis_absence_snapshot(
    intent: &MlsCreatorBootstrapIntent,
    accepted: &MlsCreatorBootstrapAcceptedCreate,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> Result<()> {
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentResult};
    let stream = CommitStreamRef::from_scope(intent.effective_scope(), None)?;
    let root = accepted.authority_root();
    let create = accepted.covering_commit();
    let scope_head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream);
    let create_head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == create.stream_ref);
    let distinct: std::collections::BTreeSet<_> = snapshot
        .visible_stream_heads
        .iter()
        .map(|head| &head.stream_ref)
        .collect();
    if snapshot.realm_id != root.realm_id
        || snapshot.governance_generation != root.current_generation
        || distinct.len() != snapshot.visible_stream_heads.len()
        || snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref.realm_id() != &root.realm_id)
        || scope_head.is_none()
        || create_head.is_none_or(|head| {
            head.stream_position < create.stream_position
                || (head.stream_position == create.stream_position
                    && head.commit_id != create.commit_id)
        })
        || !snapshot
            .visible_stream_heads
            .contains(&root.realm_stream_head)
        || snapshot.current_state_entries.iter().any(|entry| {
            let selector = match entry {
                TypedCurrentResult::Value { selector, .. } => selector,
            };
            selector
                == &CurrentSelector::MlsGroup {
                    scope_ref: intent.effective_scope().clone(),
                }
        })
    {
        return Err(WireError::Protocol("creator snapshot does not prove complete exact-scope Genesis absence at the accepted authority cut".into()));
    }
    Ok(())
}

impl MlsCreatorBootstrapAcceptedCreate {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        accepted_event: Event,
        covering_commit: arkret_wire::RealmCommit,
        digest_suite: arkret_canonical::DigestSuite,
        authority_root: arkret_wire::RealmAuthorityBundle,
    ) -> Result<Self> {
        let bytes = arkret_canonical::canonical_json_bytes(&accepted_event)?;
        let value = Self {
            accepted_event,
            covering_commit,
            digest_suite,
            accepted_bytes_digest: arkret_wire::Hash::new(arkret_canonical::canonical::digest(
                digest_suite,
                &bytes,
            ))?,
            authority_root,
        };
        value.validate_binding(intent)?;
        Ok(value)
    }

    /// Require the unchanged signed creation, covering independent-stream
    /// Commit and the exact authority root. The host verifies all signatures
    /// and complete accepted history before advancing the transaction.
    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        intent.validate()?;
        self.covering_commit.validate_shape()?;
        self.authority_root.validate_shape()?;
        self.accepted_event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        self.accepted_event
            .validate_proof_bindings_with_digest_suite(self.digest_suite)?;
        self.authority_root
            .genesis_event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        let original = scope_create_event(intent.signed_scope_create_unit())?;
        let expected_stream = arkret_wire::CommitStreamRef::from_scope(
            &original.scope_ref,
            Some(original.realm_id.clone()),
        )?;
        let bytes = arkret_canonical::canonical_json_bytes(&self.accepted_event)?;
        if &self.accepted_event != original
            || self.accepted_bytes_digest.as_str()
                != arkret_canonical::canonical::digest(self.digest_suite, &bytes)
            || self.covering_commit.event_ref != original.event_id
            || self.covering_commit.realm_id != original.realm_id
            || self.covering_commit.stream_ref != expected_stream
            || self.authority_root.realm_id != original.realm_id
            || self.covering_commit.governance_generation > self.authority_root.current_generation
            || (original.kind == EventKind::RealmCreate
                && (self.authority_root.genesis_event != self.accepted_event
                    || self.authority_root.genesis_commit != self.covering_commit))
        {
            return Err(WireError::Protocol(
                "accepted creator evidence changed the exact creation, digest, stream, or root"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn accepted_event(&self) -> &Event {
        &self.accepted_event
    }

    pub fn covering_commit(&self) -> &arkret_wire::RealmCommit {
        &self.covering_commit
    }

    pub fn digest_suite(&self) -> arkret_canonical::DigestSuite {
        self.digest_suite
    }

    pub fn accepted_bytes_digest(&self) -> &arkret_wire::Hash {
        &self.accepted_bytes_digest
    }

    pub fn authority_root(&self) -> &arkret_wire::RealmAuthorityBundle {
        &self.authority_root
    }
}

fn scope_create_event(request: &SelfAuthoritySubmitRequest) -> Result<&Event> {
    match request {
        SelfAuthoritySubmitRequest::Event(submission) => Ok(&submission.event),
        SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit) => unit
            .events
            .first()
            .map(|submission| &submission.event)
            .ok_or_else(|| WireError::Protocol("creator intent has no signed create unit".into())),
        SelfAuthoritySubmitRequest::DirectConversationFounding(unit) => Ok(&unit.events[0].event),
        _ => Err(WireError::Protocol(
            "creator intent is not a scope creation unit".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, DidCoreId, Hash, ProducerEventProof};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    const DEVICE: &str = "ak:device:0198ff00-0000-7000-8000-000000000001";

    fn fixture_intent(circle: bool) -> MlsCreatorBootstrapIntent {
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let parent = if circle {
            scope_create_event(fixture_intent(false).signed_scope_create_unit())
                .unwrap()
                .realm_id
                .clone()
        } else {
            arkret_wire::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap()
        };
        let timestamp = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let mut create = arkret_wire::test_support::raw_event_for_actor_at(
            if circle {
                "ak.circle.create"
            } else {
                "ak.realm.create"
            },
            if circle {
                ScopeRef::Realm {
                    realm_id: parent.clone(),
                }
            } else {
                ScopeRef::RealmGenesis
            },
            actor.clone(),
            json!({}),
            timestamp,
        )
        .unwrap();
        let method = DidUrl::new(format!("did:web:alice.example#{DEVICE}")).unwrap();
        let digest = Hash::new(
            create
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        // This fixture checks durable DTO bindings, not signature verification.
        create.producer_proof = Some(ProducerEventProof {
            kind: "detached_jws".into(),
            verification_method: method.clone(),
            event_digest: digest.clone(),
            created_at: timestamp,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
        });
        let scope = if circle {
            ScopeRef::Circle {
                realm_id: parent,
                circle_id: arkret_wire::CircleId::from_event_id(&create.event_id),
            }
        } else {
            ScopeRef::Realm {
                realm_id: create.realm_id.clone(),
            }
        };
        MlsCreatorBootstrapIntent::new(
            actor,
            scope.clone(),
            DeviceId::new(DEVICE).unwrap(),
            method,
            MlsGovernanceBindingPayload::new(scope, None, 0, 0, 0).unwrap(),
            SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(create)),
        )
        .unwrap()
    }

    #[test]
    fn realm_and_circle_intents_retain_exact_create_bytes_and_derived_group() {
        for circle in [false, true] {
            let original = fixture_intent(circle);
            let bytes = arkret_canonical::canonical_json_bytes(&original).unwrap();
            let restored: MlsCreatorBootstrapIntent = serde_json::from_slice(&bytes).unwrap();
            restored.validate().unwrap();
            assert_eq!(original, restored);
            assert_eq!(
                restored.mls_group_id(),
                &restored.effective_scope().canonical_mls_group_id().unwrap()
            );
        }
    }

    #[test]
    fn creator_intent_rejects_foreign_station_device_signer_and_create_identity() {
        let original = fixture_intent(false);
        let mut altered = original.clone();
        altered.owner_actor_id = ActorId::account(AccountId::new(
            original
                .owner_actor_id
                .as_account_id()
                .unwrap()
                .principal_id
                .clone(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        assert!(altered.validate().is_err());
        altered = original.clone();
        altered.creator_device_id =
            DeviceId::new("ak:device:0198ff00-0000-7000-8000-000000000002").unwrap();
        assert!(altered.validate().is_err());
        altered = original.clone();
        altered.creator_signer_method = DidUrl::new("did:web:other.example#key").unwrap();
        assert!(altered.validate().is_err());
        altered = original.clone();
        altered.scope_create_event_id = fixture_intent(true).scope_create_event_id;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn intent_cannot_borrow_another_scope_or_serialize_an_open_or_partial_record() {
        let original = fixture_intent(false);
        let mut altered = original.clone();
        altered.effective_scope = fixture_intent(true).effective_scope;
        assert!(altered.validate().is_err());
        let value = serde_json::to_value(original).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut partial = value.clone();
            partial.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<MlsCreatorBootstrapIntent>(partial).is_err(),
                "missing {field}"
            );
        }
        let mut open = value;
        open["proof_outcome"] = json!({});
        assert!(serde_json::from_value::<MlsCreatorBootstrapIntent>(open).is_err());
    }

    #[test]
    fn deserialized_intent_cannot_rebind_genesis_coordinates_or_its_derived_group() {
        let original = fixture_intent(false);
        for field in ["previous_epoch", "next_epoch", "key_access_revision"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value["proposed_group_genesis_binding"]["proposed_group_genesis_binding"][field] =
                json!(1);
            let altered: MlsCreatorBootstrapIntent = serde_json::from_value(value).unwrap();
            assert!(altered.validate().is_err(), "changed {field}");
        }
        let mut altered = original;
        altered.mls_group_id = fixture_intent(true).mls_group_id;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn human_creator_cannot_replace_the_device_proof_with_a_generic_account_key() {
        let mut altered = fixture_intent(false);
        let method = DidUrl::new("did:web:alice.example#key").unwrap();
        altered.creator_signer_method = method.clone();
        let SelfAuthoritySubmitRequest::Event(event) = &mut altered.signed_scope_create_unit else {
            panic!("fixture must be an Event");
        };
        event
            .event
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method = method;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn runtime_endpoint_does_not_classify_an_agent_account_as_a_human_device() {
        let mut original = fixture_intent(false);
        let method = DidUrl::new("did:web:alice.example#agent-key").unwrap();
        let SelfAuthoritySubmitRequest::Event(event) = &mut original.signed_scope_create_unit
        else {
            panic!("fixture must be an Event");
        };
        event
            .event
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method = method.clone();
        let endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: method.clone(),
        };
        let mut runtime = MlsCreatorBootstrapIntent::new_with_endpoint(
            original.owner_actor_id.clone(),
            original.effective_scope.clone(),
            original.creator_device_id.clone(),
            method,
            endpoint,
            original.proposal().proposed_group_genesis_binding().clone(),
            original.signed_scope_create_unit.clone(),
        )
        .unwrap();
        runtime.validate().unwrap();
        runtime.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: runtime.creator_device_id.clone(),
        };
        assert!(runtime.validate().is_err());
        let mut device = fixture_intent(false);
        device.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: device.creator_signer_method.clone(),
        };
        assert!(device.validate().is_err());
    }

    fn current_cut(
        circle: bool,
    ) -> (
        ScopeRef,
        arkret_wire::CommitStreamHead,
        MlsCreatorBootstrapCurrentCut,
    ) {
        use arkret_wire::{CommitStreamHead, CommitStreamRef, RealmCommitId};

        use crate::sync_frames::current_results::AccountCurrentCoverage;

        let scope = fixture_intent(circle).effective_scope;
        let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
        let realm_id = stream.realm_id().clone();
        let realm_head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: 7,
            commit_id: RealmCommitId::new(
                "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            )
            .unwrap(),
        };
        let mut heads = vec![realm_head.clone()];
        if circle {
            heads.push(CommitStreamHead {
                stream_ref: stream,
                stream_position: 2,
                commit_id: RealmCommitId::new(
                    "ak:realm_commit:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            });
        }
        let cut = MlsCreatorBootstrapCurrentCut::new(
            RealmDetailBaseline {
                snapshot_cursor: "ak:cursor:creator_cut".into(),
                cut_revision: 11,
                coverage: AccountCurrentCoverage {
                    realm_id: realm_id.clone(),
                    stream_heads: heads.clone(),
                    complete_for_authorized_streams: true,
                },
                complete: true,
            },
            AccountCurrentResult {
                realm_id,
                governance_generation: 3,
                stream_heads: heads,
                entries: vec![],
            },
        );
        (scope, realm_head, cut)
    }

    #[test]
    fn complete_realm_and_circle_cuts_preserve_independent_heads_across_reload() {
        for circle in [false, true] {
            let (scope, head, cut) = current_cut(circle);
            let bytes = arkret_canonical::canonical_json_bytes(&cut).unwrap();
            let mut restored: MlsCreatorBootstrapCurrentCut =
                serde_json::from_slice(&bytes).unwrap();
            restored.current.stream_heads.reverse();
            restored.validate_absence_binding(&scope, 3, &head).unwrap();
        }
    }

    #[test]
    fn empty_incomplete_or_uncovered_cuts_never_prove_genesis_absence() {
        let (scope, head, cut) = current_cut(true);
        let mut altered = cut.clone();
        altered.baseline.complete = false;
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        altered.baseline.coverage.complete_for_authorized_streams = false;
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        altered.baseline.coverage.stream_heads.pop();
        altered.current.stream_heads.pop();
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut;
        altered.baseline.coverage.stream_heads.clear();
        altered.current.stream_heads.clear();
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    }

    #[test]
    fn creator_cut_cannot_mix_generations_heads_realms_or_duplicate_coverage() {
        let (scope, head, cut) = current_cut(true);
        assert!(cut.validate_absence_binding(&scope, 4, &head).is_err());
        let mut altered = cut.clone();
        altered.current.stream_heads[1].stream_position += 1;
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        altered.baseline.coverage.stream_heads.push(head.clone());
        altered.current.stream_heads.push(head.clone());
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        let mut other = current_cut(false).1;
        other.stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        };
        altered.baseline.coverage.stream_heads.push(other.clone());
        altered.current.stream_heads.push(other);
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        let mut advanced_head = head;
        advanced_head.stream_position += 1;
        assert!(
            cut.validate_absence_binding(&scope, 3, &advanced_head)
                .is_err()
        );
    }

    #[test]
    fn an_exact_scope_mls_current_entry_is_a_winner_even_if_its_value_is_empty() {
        let (scope, head, mut cut) = current_cut(true);
        let entry = arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::MlsGroup {
                scope_ref: scope.clone(),
            },
            source_stream_ref: cut.current.stream_heads[1].stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: cut.current.stream_heads[1].commit_id.clone(),
                stream_position: 2,
            },
            value: json!({}),
        };
        cut.current.entries.push(entry);
        assert!(cut.validate_absence_binding(&scope, 3, &head).is_err());
    }

    fn accepted_create(
        circle: bool,
    ) -> (MlsCreatorBootstrapIntent, MlsCreatorBootstrapAcceptedCreate) {
        use arkret_wire::{
            Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedObjectSignature,
            DetachedSignatureAlgorithm, DetachedSignatureContext, RealmAuthorityBundle,
            RealmAuthorityCurrentAssertion, RealmCommit, RealmCommitAuthorityRef, RealmCommitId,
        };

        let intent = fixture_intent(circle);
        let root_event = scope_create_event(fixture_intent(false).signed_scope_create_unit())
            .unwrap()
            .clone();
        let realm_id = root_event.realm_id.clone();
        let service = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let timestamp = root_event.created_at;
        // These detached signatures exercise shape bindings only. No test
        // claims independently verified acceptance from this synthetic bundle.
        let signature = |context| DetachedObjectSignature {
            context,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:web:station.example#key").unwrap(),
            signed_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            created_at: timestamp,
            sig: Base64UrlString::new("AA").unwrap(),
        };
        let root_commit = RealmCommit {
            commit_id: RealmCommitId::new(
                "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            )
            .unwrap(),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: root_event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                root_event.event_id.clone(),
            ),
            committed_at: timestamp,
            signature: signature(DetachedSignatureContext::RealmCommit),
        };
        let head = CommitStreamHead {
            stream_ref: root_commit.stream_ref.clone(),
            stream_position: 0,
            commit_id: root_commit.commit_id.clone(),
        };
        let root = RealmAuthorityBundle {
            realm_id: realm_id.clone(),
            genesis_event: root_event,
            genesis_commit: root_commit.clone(),
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: service.clone(),
            current_route_record: json!({}),
            realm_stream_head: head.clone(),
            bundle_issued_at: timestamp,
            current_assertion: RealmAuthorityCurrentAssertion {
                realm_id,
                current_generation: 0,
                current_service_id: service,
                last_handoff_ref: None,
                realm_stream_head: head,
                nonce: Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
                expires_at: timestamp + chrono::TimeDelta::minutes(5),
                signature: signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
            },
        };
        let event = scope_create_event(intent.signed_scope_create_unit())
            .unwrap()
            .clone();
        let mut commit = root_commit;
        if circle {
            commit.previous_commit_ref = Some(commit.commit_id.clone());
            commit.commit_id =
                RealmCommitId::new("ak:realm_commit:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap();
            commit.stream_position = 1;
            commit.event_ref = event.event_id.clone();
        }
        let accepted = MlsCreatorBootstrapAcceptedCreate::new(
            &intent,
            event,
            commit,
            arkret_canonical::DigestSuite::Sha256,
            root,
        )
        .unwrap();
        (intent, accepted)
    }

    fn absence_snapshot(
        accepted: &MlsCreatorBootstrapAcceptedCreate,
    ) -> arkret_wire::RealmStateSnapshot {
        let root = accepted.authority_root();
        let head = root.realm_stream_head.clone();
        let mut signature = root.current_assertion.signature.clone();
        signature.context = arkret_wire::DetachedSignatureContext::RealmSnapshot;
        // Structural fixture only; the host must authenticate this carrier.
        arkret_wire::RealmStateSnapshot {
            snapshot_id: arkret_wire::RealmSnapshotId::from_digest([3; 32]),
            realm_id: root.realm_id.clone(),
            governance_generation: root.current_generation,
            visible_stream_heads: vec![head.clone()],
            current_state_entries: vec![],
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: head.stream_ref,
                    oldest_position: 0,
                }],
            },
            created_at: root.bundle_issued_at,
            signature,
        }
    }

    fn device_query_fixture(
        intent: &MlsCreatorBootstrapIntent,
    ) -> arkret_models_crypto::KeysQueryOutcome {
        let now = scope_create_event(intent.signed_scope_create_unit())
            .unwrap()
            .created_at;
        // Shape-only local evidence fixture, never an authenticated Station response.
        serde_json::from_value(json!({
            "device_keys": [{"account_id": intent.owner_actor_id().as_account_id().unwrap(), "device_keys": {
                intent.creator_device_id().as_str(): {
                    "signer_evidence_ref": "ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "algorithms": {}, "trust_algorithms": [],
                    "device_projection": {
                        "device_signing_key_did": "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
                        "hpke_key": "hpke-test", "device_authorize_event_id": intent.scope_create_event_id(),
                        "authorized_generation_ref": 7, "device_status": "active",
                        "attested_at": arkret_canonical::format_timestamp_canonical(now), "expires_at": arkret_canonical::format_timestamp_canonical(now + chrono::TimeDelta::minutes(5)),
                        "authorization_window": {"not_before": arkret_canonical::format_timestamp_canonical(now), "expires_at": null}
                    }
                }
            }}],
            "failures": [],
            "device_generations": [{"account_id": intent.owner_actor_id().as_account_id().unwrap(),
                "generation_state": {"current_device_generation_ref": 7}}]
        })).unwrap()
    }

    fn pinned_fixture(
        intent: &MlsCreatorBootstrapIntent,
        accepted: &MlsCreatorBootstrapAcceptedCreate,
    ) -> MlsCreatorBootstrapGovernanceEvidence {
        let device = MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
            intent,
            &device_query_fixture(intent),
            accepted.authority_root().bundle_issued_at,
        )
        .unwrap();
        MlsCreatorBootstrapGovernanceEvidence::new_device(
            intent,
            accepted.clone(),
            absence_snapshot(accepted),
            device,
        )
        .unwrap()
    }

    fn epoch_zero_fixture(
        intent: &MlsCreatorBootstrapIntent,
        evidence: &MlsCreatorBootstrapGovernanceEvidence,
    ) -> MlsCreatorBootstrapEpochZero {
        let public = b"shape-only-group-info".to_vec();
        let tree = b"shape-only-tree".to_vec();
        let blob = |bytes: &[u8]| {
            arkret_wire::BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::canonical::digest(arkret_canonical::DigestSuite::Sha256, bytes)
            ))
            .unwrap()
        };
        let at = evidence.creator_device_authority.verified_at;
        let payload = crate::events_payloads::MlsGenesisPayload {
            cipher_suite: arkret_wire::NonEmptyString::new(
                arkret_wire::generated::security_strings::MLS_CIPHERSUITES
                    .iter()
                    .find(|suite| suite.status == "active" && suite.profile_gate.is_none())
                    .unwrap()
                    .canonical_id,
            )
            .unwrap(),
            group_info_ref: blob(&public),
            ratchet_tree_ref: blob(&tree),
            creator_leaf_authority: crate::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url::base64url_encode(&[3; 32]),
                )
                .unwrap(),
                endpoint: intent.creator_endpoint().clone(),
                authorization_event_ref: evidence
                    .creator_device_authority
                    .projection
                    .device_authorize_event_id
                    .clone(),
            },
            governance_binding: evidence.governance_binding.clone(),
            created_at: at,
        };
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.mls.genesis",
            intent.effective_scope().clone(),
            intent.owner_actor_id().clone(),
            serde_json::to_value(payload).unwrap(),
            at,
        )
        .unwrap();
        MlsCreatorBootstrapEpochZero::new(
            intent,
            evidence,
            b"opaque-device-envelope-fixture".to_vec(),
            public,
            tree,
            arkret_wire::AuthoredEvent::finalize_with_digest_suite(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn sign_epoch_zero_fixture(
        intent: &MlsCreatorBootstrapIntent,
        unit: &MlsCreatorBootstrapEpochZero,
    ) -> arkret_wire::AuthoredEvent {
        let mut event = unit.unsigned_genesis().clone();
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(event.digest_suite())
                .unwrap(),
        )
        .unwrap();
        // Structural proof only. These tests do not authenticate acceptance.
        event.attach_proof(ProducerEventProof {
            kind: "detached_jws".into(),
            verification_method: intent.creator_signer_method().clone(),
            event_digest: digest.clone(),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
        });
        event
    }

    #[test]
    fn creator_epoch_zero_and_signed_original_roundtrip_without_replacement() {
        let (intent, accepted) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &accepted);
        let unit = epoch_zero_fixture(&intent, &evidence);
        let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        assert!(record.persist_epoch_zero(unit.clone()).is_err());
        record
            .accept_realm(accepted.clone(), absence_snapshot(&accepted))
            .unwrap();
        record.pin_governance(evidence).unwrap();
        record.persist_epoch_zero(unit.clone()).unwrap();
        assert_eq!(
            record.state(),
            arkret_wire::MlsCreatorBootstrapState::Epoch0StatePersisted
        );
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        reopened.validate().unwrap();
        record.persist_epoch_zero(unit.clone()).unwrap();
        let mut different = unit.clone();
        different.encrypted_private_state.push(1);
        assert!(record.persist_epoch_zero(different).is_err());
        assert_eq!(record, reopened);
        let signed = sign_epoch_zero_fixture(&intent, &unit);
        record.queue_genesis(signed.clone()).unwrap();
        assert_eq!(
            record.state(),
            arkret_wire::MlsCreatorBootstrapState::GenesisQueued
        );
        record.queue_genesis(signed.clone()).unwrap();
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        reopened.validate().unwrap();
        let mut changed = signed;
        let mut proof = changed.producer_proof.clone().unwrap();
        proof.created_at += chrono::TimeDelta::milliseconds(1);
        changed.attach_proof(proof);
        assert!(record.queue_genesis(changed).is_err());
        assert_eq!(record, reopened);
    }

    #[test]
    fn creator_new_query_cut_keeps_the_original_governance_pin_immutable() {
        let (intent, create) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &create);
        let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        record
            .accept_realm(create.clone(), absence_snapshot(&create))
            .unwrap();
        record.pin_governance(evidence.clone()).unwrap();
        let frozen = record.clone();
        // Shape-only later cut. Its real signatures are verified by the host.
        let mut root = create.authority_root().clone();
        root.realm_stream_head.stream_position += 1;
        root.realm_stream_head.commit_id = arkret_wire::RealmCommitId::from_digest([23; 32]);
        root.current_assertion.realm_stream_head = root.realm_stream_head.clone();
        let current = MlsCreatorBootstrapAcceptedCreate::new(
            &intent,
            create.accepted_event().clone(),
            create.covering_commit().clone(),
            create.digest_suite(),
            root,
        )
        .unwrap();
        let later = absence_snapshot(&current);
        assert!(validate_creator_genesis_absence_snapshot(&intent, &create, &later).is_err());
        validate_creator_genesis_absence_snapshot(&intent, &current, &later).unwrap();
        assert_eq!(record, frozen);
        assert_eq!(record.governance_evidence(), Some(&evidence));
    }

    #[test]
    fn creator_exact_accepted_genesis_retains_bytes_commit_and_original_unit() {
        let (intent, create) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &create);
        let unit = epoch_zero_fixture(&intent, &evidence);
        let signed = sign_epoch_zero_fixture(&intent, &unit);
        let queued = MlsCreatorBootstrapQueuedGenesis::new(&intent, &unit, signed.clone()).unwrap();
        // Synthetic Commit exercises structure only, not authority signatures.
        let mut commit = create.covering_commit().clone();
        commit.stream_position += 1;
        commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
        commit.event_ref = signed.event_id().clone();
        let row = arkret_wire::CommittedEventFullView {
            event: signed.event().clone(),
            commit,
        };
        let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
            &intent,
            &queued,
            row.clone(),
            create.authority_root().clone(),
        )
        .unwrap();
        let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        assert!(record.accept_genesis(accepted.clone()).is_err());
        record
            .accept_realm(create.clone(), absence_snapshot(&create))
            .unwrap();
        record.pin_governance(evidence).unwrap();
        record.persist_epoch_zero(unit.clone()).unwrap();
        assert!(record.accept_genesis(accepted.clone()).is_err());
        record.queue_genesis(signed.clone()).unwrap();
        record.accept_genesis(accepted.clone()).unwrap();
        record.accept_genesis(accepted.clone()).unwrap();
        assert_eq!(
            record.state(),
            arkret_wire::MlsCreatorBootstrapState::GenesisAccepted
        );
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        reopened.validate().unwrap();
        assert_eq!(reopened.epoch_zero(), Some(&unit));
        let mut changed = accepted.clone();
        changed.accepted.commit.committed_at += chrono::TimeDelta::milliseconds(1);
        assert!(record.accept_genesis(changed).is_err());
        assert_eq!(record, reopened);
        let mut changed = row.clone();
        changed.event.producer_proof.as_mut().unwrap().created_at +=
            chrono::TimeDelta::milliseconds(1);
        assert!(
            MlsCreatorBootstrapAcceptedGenesis::new(
                &intent,
                &queued,
                changed,
                create.authority_root().clone()
            )
            .is_err()
        );
        let mut changed = row.clone();
        changed.commit.event_ref = intent.scope_create_event_id().clone();
        assert!(
            MlsCreatorBootstrapAcceptedGenesis::new(
                &intent,
                &queued,
                changed,
                create.authority_root().clone()
            )
            .is_err()
        );
        let mut changed = accepted;
        changed.canonical_accepted_bytes.push(0);
        assert!(changed.validate_binding(&intent, &queued).is_err());
    }

    #[test]
    fn creator_terminal_rejection_reopens_only_from_a_new_verified_absence_and_keeps_tombstones() {
        let (intent, create) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &create);
        let unit = epoch_zero_fixture(&intent, &evidence);
        let signed = sign_epoch_zero_fixture(&intent, &unit);
        let mut original = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        original
            .accept_realm(create.clone(), absence_snapshot(&create))
            .unwrap();
        original.pin_governance(evidence).unwrap();
        original.persist_epoch_zero(unit.clone()).unwrap();
        original.queue_genesis(signed.clone()).unwrap();
        let last_verified = MlsCreatorBootstrapVerifiedAbsence::new(
            &intent,
            create.clone(),
            absence_snapshot(&create),
        )
        .unwrap();
        assert!(
            MlsCreatorBootstrapRejection::new(&original, String::new(), last_verified.clone())
                .is_err()
        );
        for (code, status) in [
            ("failed_precondition", 412),
            ("unauthorized", 401),
            ("not_found", 404),
            ("rate_limited", 429),
            ("internal_error", 500),
            ("failed_precondition", 503),
        ] {
            assert!(
                MlsCreatorBootstrapRejection::from_problem(
                    &original,
                    arkret_wire::Problem::new(code, status, "not a definite admission decision"),
                    last_verified.clone()
                )
                .is_err()
            );
        }
        let problem = arkret_wire::Problem::new("failed_precondition", 409, "admission refused")
            .with_extension(
                "reason_code",
                serde_json::json!("governance_binding_mismatch"),
            );
        let rejection = MlsCreatorBootstrapRejection::from_problem(
            &original,
            problem.clone(),
            last_verified.clone(),
        )
        .unwrap();
        assert_eq!(rejection.reason_code(), "governance_binding_mismatch");
        assert_eq!(rejection.authority_problem(), Some(&problem));
        let irreversible =
            arkret_wire::Problem::new("failed_precondition", 409, "already accepted")
                .with_extension(
                    "reason_code",
                    serde_json::json!("mls_activation_irreversible"),
                );
        assert_eq!(
            MlsCreatorBootstrapRejection::terminal_problem_reason(&irreversible),
            Some("mls_activation_irreversible")
        );
        assert_eq!(
            MlsCreatorBootstrapRejection::terminal_problem_reason(&arkret_wire::Problem::new(
                "digest_mismatch",
                400,
                "Genesis public material digest mismatch"
            )),
            Some("digest_mismatch")
        );
        let rejection = MlsCreatorBootstrapRejection::new(
            &original,
            "capability_denied".into(),
            last_verified.clone(),
        )
        .unwrap();
        let mut record = original.clone();
        record.reject(rejection.clone()).unwrap();
        record.reject(rejection.clone()).unwrap();
        assert_eq!(
            record.state(),
            arkret_wire::MlsCreatorBootstrapState::Rejected
        );
        assert_eq!(record.rejection().unwrap().event_id(), signed.event_id());
        assert_eq!(
            record.rejection().unwrap().reason_code(),
            "capability_denied"
        );
        assert!(record.epoch_zero().is_none());
        assert!(record.queued_genesis().is_none());
        let mut contradiction_commit = create.covering_commit().clone();
        contradiction_commit.stream_position += 1;
        contradiction_commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
        contradiction_commit.event_ref = signed.event_id().clone();
        let contradiction = arkret_wire::CommittedEventFullView {
            event: signed.event().clone(),
            commit: contradiction_commit,
        };
        assert!(
            MlsCreatorBootstrapWinner::new(
                &record,
                contradiction.clone(),
                create.authority_root().clone()
            )
            .is_err()
        );
        let known = MlsCreatorBootstrapKnownGenesis::authenticated_winner(
            &record,
            contradiction.clone(),
            create.authority_root().clone(),
        )
        .unwrap();
        let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
            serde_json::to_value(&record).unwrap(),
            vec![],
            MlsCreatorBootstrapInvariant::AcceptedResult,
            "definitely rejected original is independently proved accepted".into(),
            Some(known.clone()),
            create.authority_root().bundle_issued_at,
        )
        .unwrap();
        assert_eq!(
            quarantined.quarantine_diagnostic().unwrap().last_state(),
            arkret_wire::MlsCreatorBootstrapState::Rejected
        );
        assert_eq!(
            quarantined
                .quarantine_diagnostic()
                .unwrap()
                .accepted_winner(),
            Some(&known)
        );
        assert!(quarantined.epoch_zero().is_none());
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        reopened.validate().unwrap();
        assert!(record.reopen_rejected(last_verified.clone()).is_err());
        assert_eq!(record, reopened);
        let mut changed = rejection.clone();
        changed.reason_code = "different_reason".into();
        assert!(record.reject(changed).is_err());
        assert_eq!(record, reopened);
        let mut fresh_create = create.clone();
        fresh_create.authority_root.current_assertion.nonce =
            arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let fresh = MlsCreatorBootstrapVerifiedAbsence::new(
            &intent,
            fresh_create.clone(),
            absence_snapshot(&fresh_create),
        )
        .unwrap();
        let mut incomplete = fresh.clone();
        incomplete.current_snapshot.visible_stream_heads.clear();
        assert!(record.reopen_rejected(incomplete).is_err());
        assert_eq!(record, reopened);
        record.reopen_rejected(fresh).unwrap();
        assert!(
            MlsCreatorBootstrapWinner::new(
                &record,
                contradiction.clone(),
                create.authority_root().clone()
            )
            .is_err()
        );
        let known = MlsCreatorBootstrapKnownGenesis::authenticated_winner(
            &record,
            contradiction,
            create.authority_root().clone(),
        )
        .unwrap();
        let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
            serde_json::to_value(&record).unwrap(),
            vec![],
            MlsCreatorBootstrapInvariant::AcceptedResult,
            "closed original is independently proved accepted".into(),
            Some(known),
            create.authority_root().bundle_issued_at,
        )
        .unwrap();
        assert_eq!(
            quarantined.quarantine_diagnostic().unwrap().last_state(),
            arkret_wire::MlsCreatorBootstrapState::RealmAccepted
        );
        assert_eq!(
            record.state(),
            arkret_wire::MlsCreatorBootstrapState::RealmAccepted
        );
        assert_eq!(record.intent(), &intent);
        assert_eq!(record.closed_attempts(), &[rejection]);
        assert!(
            record.closed_attempts()[0]
                .matches_epoch_zero_public_material(
                    unit.group_info_bytes(),
                    unit.ratchet_tree_bytes()
                )
                .unwrap()
        );
        assert!(
            !record.closed_attempts()[0]
                .matches_epoch_zero_public_material(
                    b"unrelated public bytes",
                    unit.ratchet_tree_bytes()
                )
                .unwrap()
        );
        assert!(record.epoch_zero().is_none());
        assert!(record.queued_genesis().is_none());
        record
            .pin_governance(pinned_fixture(&intent, &fresh_create))
            .unwrap();
        record.persist_epoch_zero(unit).unwrap();
        let before = record.clone();
        assert!(record.queue_genesis(signed).is_err());
        assert_eq!(record, before);
        assert_eq!(record.closed_attempts().len(), 1);
    }

    #[test]
    fn creator_distinct_winner_stops_the_original_attempt_without_adopting_its_private_unit() {
        let (intent, create) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &create);
        let unit = epoch_zero_fixture(&intent, &evidence);
        let signed = sign_epoch_zero_fixture(&intent, &unit);
        let mut original = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        original
            .accept_realm(create.clone(), absence_snapshot(&create))
            .unwrap();
        original.pin_governance(evidence).unwrap();
        original.persist_epoch_zero(unit.clone()).unwrap();
        original.queue_genesis(signed.clone()).unwrap();
        // A distinct structural winner, not an authenticated Station fixture.
        let mut foreign_unit = unit.clone();
        let mut event = unit.unsigned_genesis().event().clone();
        event.created_at += chrono::TimeDelta::milliseconds(1);
        event.payload.insert(
            "created_at".into(),
            serde_json::Value::String(arkret_canonical::format_timestamp_canonical(
                event.created_at,
            )),
        );
        foreign_unit.unsigned_genesis =
            arkret_wire::AuthoredEvent::finalize_with_digest_suite(event, signed.digest_suite())
                .unwrap();
        let foreign = sign_epoch_zero_fixture(&intent, &foreign_unit);
        let mut commit = create.covering_commit().clone();
        commit.stream_position += 1;
        commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
        commit.event_ref = foreign.event_id().clone();
        let row = arkret_wire::CommittedEventFullView {
            event: foreign.event().clone(),
            commit,
        };
        let winner =
            MlsCreatorBootstrapWinner::new(&original, row.clone(), create.authority_root().clone())
                .unwrap();
        // The accepted slot is scope-wide, not restricted to the loser's Actor.
        // Producer authentication and roster validation remain host obligations.
        let mut other_event = row.event.clone();
        other_event.actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        other_event.producer_proof = None;
        let mut other_signed = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            other_event,
            signed.digest_suite(),
        )
        .unwrap();
        let digest = Hash::new(
            other_signed
                .event_digest_with_digest_suite(signed.digest_suite())
                .unwrap(),
        )
        .unwrap();
        other_signed.attach_proof(ProducerEventProof {
            kind: "detached_jws".into(),
            verification_method: DidUrl::new(format!("did:web:bob.example#{DEVICE}")).unwrap(),
            event_digest: digest.clone(),
            created_at: other_signed.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
        });
        let mut other_row = row.clone();
        other_row.event = other_signed.event().clone();
        other_row.commit.event_ref = other_signed.event_id().clone();
        let other_winner =
            MlsCreatorBootstrapWinner::new(&original, other_row, create.authority_root().clone())
                .unwrap();
        let mut other_terminal = original.clone();
        other_terminal.supersede(other_winner).unwrap();
        assert_eq!(other_terminal.intent(), &intent);
        let mut terminal = original.clone();
        terminal.supersede(winner.clone()).unwrap();
        terminal.supersede(winner.clone()).unwrap();
        assert_eq!(
            terminal.state(),
            arkret_wire::MlsCreatorBootstrapState::Superseded
        );
        assert_eq!(terminal.intent(), &intent);
        assert!(terminal.epoch_zero().is_none());
        assert!(terminal.queued_genesis().is_none());
        assert!(terminal.accepted_genesis().is_none());
        assert!(terminal.ready_receipt().is_none());
        assert!(terminal.persist_epoch_zero(unit.clone()).is_err());
        assert!(terminal.queue_genesis(signed.clone()).is_err());
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&terminal).unwrap()).unwrap();
        reopened.validate().unwrap();
        let saved_record = &reopened;
        if let MlsCreatorBootstrapRecord::Superseded {
            loser_genesis,
            loser_record,
            ..
        } = saved_record
        {
            assert_eq!(loser_record.as_ref(), &original);
            assert_eq!(loser_record.epoch_zero(), Some(&unit));
            assert_eq!(loser_genesis.as_ref().unwrap().0, *signed.event_id());
        } else {
            panic!("terminal state lost");
        }
        let mut different = winner.clone();
        different.authority_root.bundle_issued_at += chrono::TimeDelta::milliseconds(1);
        assert!(terminal.supersede(different).is_err());
        assert_eq!(terminal, reopened);
        let mut original_row = row.clone();
        original_row.event = signed.event().clone();
        original_row.commit.event_ref = signed.event_id().clone();
        assert!(
            MlsCreatorBootstrapWinner::new(
                &original,
                original_row.clone(),
                create.authority_root().clone()
            )
            .is_err()
        );
        let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
            &intent,
            original.queued_genesis().unwrap(),
            original_row,
            create.authority_root().clone(),
        )
        .unwrap();
        original.accept_genesis(accepted).unwrap();
        assert!(original.supersede(winner).is_err());
        let mut changed = row;
        changed.commit.event_ref = intent.scope_create_event_id().clone();
        assert!(
            MlsCreatorBootstrapWinner::new(&reopened, changed, create.authority_root().clone())
                .is_err()
        );
    }

    #[test]
    fn creator_quarantine_retains_undecodable_recovery_material_without_an_active_exit() {
        let (intent, create) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &create);
        let unit = epoch_zero_fixture(&intent, &evidence);
        let signed = sign_epoch_zero_fixture(&intent, &unit);
        let mut original = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        original
            .accept_realm(create.clone(), absence_snapshot(&create))
            .unwrap();
        original.pin_governance(evidence).unwrap();
        original.persist_epoch_zero(unit).unwrap();
        original.queue_genesis(signed.clone()).unwrap();
        let mut raw = serde_json::to_value(&original).unwrap();
        raw["epoch_zero"]["encrypted_private_state"] =
            serde_json::json!({"damaged_bytes": [1, 2, 3]});
        assert!(serde_json::from_value::<MlsCreatorBootstrapRecord>(raw.clone()).is_err());
        // Opaque local queue corruption is retained, never accepted as sendable.
        let queues = vec![serde_json::json!({"undecodable_queue_bytes": [7, 8, 9]})];
        let mut quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
            raw.clone(),
            queues.clone(),
            MlsCreatorBootstrapInvariant::PrivateMaterial,
            "undecodable encrypted_private_state".into(),
            None,
            create.authority_root().bundle_issued_at,
        )
        .unwrap();
        quarantined.validate().unwrap();
        let diagnostic = quarantined.quarantine_diagnostic().unwrap();
        assert_eq!(
            diagnostic.last_state(),
            arkret_wire::MlsCreatorBootstrapState::GenesisQueued
        );
        assert_eq!(diagnostic.event_id(), Some(signed.event_id()));
        assert_eq!(diagnostic.outbound_queue_item_id(), Some(signed.event_id()));
        assert_eq!(diagnostic.recovery_record(), &raw);
        assert_eq!(diagnostic.recovery_queue_items(), queues);
        assert!(quarantined.epoch_zero().is_none());
        assert!(quarantined.queued_genesis().is_none());
        assert!(quarantined.accepted_genesis().is_none());
        assert!(quarantined.ready_receipt().is_none());
        assert!(quarantined.queue_genesis(signed).is_err());
        assert!(
            quarantined
                .accept_realm(create.clone(), absence_snapshot(&create))
                .is_err()
        );
        let mut next_root = create.authority_root().clone();
        next_root.current_assertion.nonce =
            arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let next_create = MlsCreatorBootstrapAcceptedCreate::new(
            &intent,
            create.accepted_event().clone(),
            create.covering_commit().clone(),
            create.digest_suite(),
            next_root,
        )
        .unwrap();
        let absence = MlsCreatorBootstrapVerifiedAbsence::new(
            &intent,
            next_create,
            absence_snapshot(&create),
        )
        .unwrap();
        assert!(quarantined.reopen_rejected(absence).is_err());
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&quarantined).unwrap()).unwrap();
        reopened.validate().unwrap();
        assert_eq!(reopened, quarantined);
        for field in ["reason_code", "event_id", "last_state"] {
            let mut bad = serde_json::to_value(&quarantined).unwrap();
            bad["diagnostic"][field] = match field {
                "last_state" => serde_json::json!("realm_accepted"),
                "event_id" => serde_json::json!(EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [91; 32]
                )),
                _ => serde_json::json!("cleared"),
            };
            let bad: MlsCreatorBootstrapRecord = serde_json::from_value(bad).unwrap();
            assert!(bad.validate().is_err(), "{field}");
        }
        for state in ["superseded", "quarantined", "unknown"] {
            let mut forbidden = raw.clone();
            forbidden["state"] = serde_json::json!(state);
            assert!(
                MlsCreatorBootstrapRecord::quarantine_authenticated_record(
                    forbidden,
                    vec![],
                    MlsCreatorBootstrapInvariant::RecordBinding,
                    "forbidden original state".into(),
                    None,
                    create.authority_root().bundle_issued_at
                )
                .is_err()
            );
        }
        let mut untrusted = raw;
        untrusted.as_object_mut().unwrap().remove("intent");
        assert!(
            MlsCreatorBootstrapRecord::quarantine_authenticated_record(
                untrusted,
                vec![],
                MlsCreatorBootstrapInvariant::RecordBinding,
                "original record binding mismatch".into(),
                None,
                create.authority_root().bundle_issued_at
            )
            .is_err()
        );
    }

    #[test]
    fn creator_ready_and_rejected_failure_dispositions_come_from_the_registry() {
        use arkret_wire::{
            MlsCreatorBootstrapFailureDisposition as Disposition, MlsCreatorBootstrapState as State,
        };
        assert_eq!(State::ALL.len(), 11);
        for state in State::ALL {
            assert_eq!(
                state.failure_disposition(),
                if matches!(state, State::Superseded | State::Quarantined) {
                    Disposition::Terminal
                } else {
                    Disposition::Quarantined
                }
            );
        }
        assert!(State::Ready.allowed_exits().is_empty());
        assert!(
            !State::Rejected
                .allowed_exits()
                .contains(&State::Quarantined)
        );
        assert_eq!(State::Ready.failure_disposition(), Disposition::Quarantined);
        assert_eq!(
            State::Rejected.failure_disposition(),
            Disposition::Quarantined
        );
    }

    #[test]
    fn creator_artifact_and_ready_receipt_bind_the_whole_original_winning_epoch() {
        let (intent, create) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &create);
        let unit = epoch_zero_fixture(&intent, &evidence);
        let signed = sign_epoch_zero_fixture(&intent, &unit);
        let queued = MlsCreatorBootstrapQueuedGenesis::new(&intent, &unit, signed.clone()).unwrap();
        let mut commit = create.covering_commit().clone();
        commit.stream_position += 1;
        commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
        commit.event_ref = signed.event_id().clone();
        let accepted = MlsCreatorBootstrapAcceptedGenesis::new(
            &intent,
            &queued,
            arkret_wire::CommittedEventFullView {
                event: signed.event().clone(),
                commit,
            },
            create.authority_root().clone(),
        )
        .unwrap();
        let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        record
            .accept_realm(create.clone(), absence_snapshot(&create))
            .unwrap();
        record.pin_governance(evidence).unwrap();
        record.persist_epoch_zero(unit.clone()).unwrap();
        record.queue_genesis(signed).unwrap();
        let payload = unit.payload().unwrap();
        let checks = MlsCreatorBootstrapArtifactChecks {
            effective_scope: intent.effective_scope().clone(),
            mls_group_id: intent.mls_group_id().clone(),
            epoch: 0,
            cipher_suite: payload.cipher_suite.to_string(),
            creator_leaf_authority: payload.creator_leaf_authority,
            group_info_bytes: unit.group_info_bytes().to_vec(),
            ratchet_tree_bytes: unit.ratchet_tree_bytes().to_vec(),
        };
        assert!(MlsCreatorBootstrapArtifacts::new(&record, checks.clone()).is_err());
        record.accept_genesis(accepted).unwrap();
        assert!(MlsCreatorBootstrapReadyReceipt::new(&record, 1).is_err());
        let artifacts = MlsCreatorBootstrapArtifacts::new(&record, checks.clone()).unwrap();
        for field in ["epoch", "scope", "suite", "leaf", "info", "tree"] {
            let mut bad = checks.clone();
            match field {
                "epoch" => bad.epoch = 1,
                "scope" => {
                    bad.effective_scope = ScopeRef::Realm {
                        realm_id: arkret_wire::RealmId::from_event_id(
                            intent.scope_create_event_id(),
                        ),
                    }
                }
                "suite" => bad.cipher_suite.push('x'),
                "leaf" => {
                    bad.creator_leaf_authority.authorization_event_ref =
                        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [43; 32])
                }
                "info" => bad.group_info_bytes.push(0),
                _ => bad.ratchet_tree_bytes.clear(),
            }
            if field == "scope" {
                bad.effective_scope = ScopeRef::Realm {
                    realm_id: arkret_wire::RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [42; 32],
                    )),
                };
            }
            assert!(
                MlsCreatorBootstrapArtifacts::new(&record, bad).is_err(),
                "{field}"
            );
        }
        record.converge_artifacts(artifacts.clone()).unwrap();
        record.converge_artifacts(artifacts.clone()).unwrap();
        assert!(MlsCreatorBootstrapReadyReceipt::new(&record, 0).is_err());
        let receipt = MlsCreatorBootstrapReadyReceipt::new(&record, 7).unwrap();
        record.publish_ready(receipt.clone()).unwrap();
        let frozen = record.clone();
        let known = MlsCreatorBootstrapKnownGenesis::Original {
            acceptance: Box::new(record.accepted_genesis().unwrap().clone()),
        };
        let quarantined = MlsCreatorBootstrapRecord::quarantine_authenticated_record(
            serde_json::to_value(&record).unwrap(),
            vec![],
            MlsCreatorBootstrapInvariant::PrivateMaterial,
            "restored private state disagrees with accepted public bytes".into(),
            Some(known.clone()),
            create.authority_root().bundle_issued_at,
        )
        .unwrap();
        assert_eq!(
            quarantined.state(),
            arkret_wire::MlsCreatorBootstrapState::Quarantined
        );
        let diagnostic = quarantined.quarantine_diagnostic().unwrap();
        assert_eq!(
            diagnostic.last_state(),
            arkret_wire::MlsCreatorBootstrapState::Ready
        );
        assert_eq!(diagnostic.accepted_winner(), Some(&known));
        assert_eq!(
            diagnostic.recovery_record(),
            &serde_json::to_value(&record).unwrap()
        );
        assert!(quarantined.ready_receipt().is_none());
        assert!(quarantined.artifacts().is_none());
        assert_eq!(
            serde_json::from_value::<MlsCreatorBootstrapRecord>(
                serde_json::to_value(&quarantined).unwrap()
            )
            .unwrap(),
            quarantined
        );
        record.publish_ready(receipt.clone()).unwrap();
        let mut changed = receipt;
        changed.ready_commit_position += 1;
        assert!(record.publish_ready(changed).is_err());
        assert_eq!(record, frozen);
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        reopened.validate().unwrap();
        assert_eq!(
            reopened.state(),
            arkret_wire::MlsCreatorBootstrapState::Ready
        );
        assert_eq!(reopened.epoch_zero(), Some(&unit));
        let mut bad = artifacts;
        bad.private_state_binding = arkret_wire::Hash::new(arkret_canonical::canonical::digest(
            arkret_canonical::DigestSuite::Sha256,
            b"different",
        ))
        .unwrap();
        assert!(record.converge_artifacts(bad).is_err());
        let mut changed = serde_json::to_value(&reopened).unwrap();
        changed["artifacts"]["consistency_checks"]["epoch"] = serde_json::json!(1);
        let changed: MlsCreatorBootstrapRecord = serde_json::from_value(changed).unwrap();
        assert!(changed.validate().is_err());
    }

    #[test]
    fn creator_epoch_zero_rejects_public_refs_unsigned_core_leaf_and_private_omissions() {
        let (intent, accepted) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &accepted);
        let original = epoch_zero_fixture(&intent, &evidence);
        let mut bad = vec![];
        let mut unit = original.clone();
        unit.encrypted_private_state.clear();
        bad.push(unit);
        let mut unit = original.clone();
        unit.group_info_bytes.push(0);
        bad.push(unit);
        let mut unit = original.clone();
        unit.ratchet_tree_bytes.clear();
        bad.push(unit);
        let mut unit = original.clone();
        unit.unsigned_genesis = sign_epoch_zero_fixture(&intent, &unit);
        bad.push(unit);
        for change in ["time", "leaf", "scope"] {
            let mut event = original.unsigned_genesis.event().clone();
            match change {
                "time" => event.created_at += chrono::TimeDelta::milliseconds(1),
                "leaf" => {
                    event.payload.get_mut("creator_leaf_authority").unwrap()["endpoint"]["device_id"] =
                        json!("ak:device:0198ff00-0000-7000-8000-000000000002");
                }
                _ => event.scope_ref = fixture_intent(true).effective_scope().clone(),
            }
            let mut unit = original.clone();
            unit.unsigned_genesis = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
            bad.push(unit);
        }
        for invalid in bad {
            assert!(invalid.validate_binding(&intent, &evidence).is_err());
        }
    }

    #[test]
    fn creator_pin_requires_acceptance_and_retains_the_exact_immutable_evidence() {
        let (intent, accepted) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &accepted);
        let mut record = MlsCreatorBootstrapRecord::new(intent).unwrap();
        let initial = record.clone();
        assert!(record.pin_governance(evidence.clone()).is_err());
        assert_eq!(record, initial);
        record
            .accept_realm(accepted.clone(), absence_snapshot(&accepted))
            .unwrap();
        record.pin_governance(evidence.clone()).unwrap();
        assert_eq!(
            record.state(),
            arkret_wire::MlsCreatorBootstrapState::GovernanceResultPinned
        );
        let reopened: MlsCreatorBootstrapRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        reopened.validate().unwrap();
        assert_eq!(reopened, record);
        record.pin_governance(evidence.clone()).unwrap();
        let mut changed = evidence;
        changed.creator_device_authority.verified_at += chrono::TimeDelta::milliseconds(1);
        assert!(record.pin_governance(changed).is_err());
        assert_eq!(record, reopened);
    }

    #[test]
    fn creator_pin_rejects_wrong_device_station_generation_and_expired_authority() {
        let (intent, accepted) = accepted_create(false);
        let evidence = pinned_fixture(&intent, &accepted);
        let mut bad = Vec::new();
        let mut changed = evidence.clone();
        changed.creator_device_authority.account_id.station_id =
            DidCoreId::new("ak:did_core:web:other.example").unwrap();
        bad.push(changed);
        let mut changed = evidence.clone();
        changed.creator_device_authority.device_id =
            DeviceId::new("ak:device:0198ff00-0000-7000-8000-000000000002").unwrap();
        bad.push(changed);
        let mut changed = evidence.clone();
        changed
            .creator_device_authority
            .generation
            .current_device_generation_ref += 1;
        bad.push(changed);
        let mut changed = evidence.clone();
        changed.creator_device_authority.verified_at =
            changed.creator_device_authority.projection.expires_at;
        bad.push(changed);
        let mut changed = evidence.clone();
        changed
            .creator_device_authority
            .projection
            .authorization_window
            .expires_at = Some(changed.creator_device_authority.verified_at);
        bad.push(changed);
        let mut changed = evidence.clone();
        changed.canonical_proposal_bytes.push(0);
        bad.push(changed);
        let mut changed = evidence.clone();
        changed
            .accepted_create
            .authority_root
            .current_assertion
            .expires_at = changed.creator_device_authority.verified_at;
        bad.push(changed);
        let mut changed = evidence.clone();
        changed.genesis_absence.visible_stream_heads.clear();
        bad.push(changed);
        let mut record = MlsCreatorBootstrapRecord::new(intent.clone()).unwrap();
        record
            .accept_realm(accepted.clone(), absence_snapshot(&accepted))
            .unwrap();
        let original = record.clone();
        for invalid in bad {
            assert!(record.pin_governance(invalid).is_err());
            assert_eq!(record, original);
        }
        let mut missing = device_query_fixture(&intent);
        missing.device_keys.clear();
        assert!(
            MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
                &intent,
                &missing,
                evidence.creator_device_authority.verified_at
            )
            .is_err()
        );
    }

    #[test]
    fn creator_record_acceptance_roundtrips_without_replacing_its_cut() {
        let (intent, accepted) = accepted_create(false);
        let snapshot = absence_snapshot(&accepted);
        let mut record = MlsCreatorBootstrapRecord::new(intent).unwrap();
        record
            .accept_realm(accepted.clone(), snapshot.clone())
            .unwrap();
        record
            .accept_realm(accepted.clone(), snapshot.clone())
            .unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        let restored: MlsCreatorBootstrapRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, record);
        restored.validate().unwrap();
        let mut changed = snapshot;
        changed.created_at += chrono::TimeDelta::seconds(1);
        assert!(record.accept_realm(accepted, changed).is_err());
        assert_eq!(record, restored);
    }

    #[test]
    fn creator_record_unknown_or_incomplete_acceptance_keeps_intent_unchanged() {
        let (intent, accepted) = accepted_create(false);
        let snapshot = absence_snapshot(&accepted);
        let original = MlsCreatorBootstrapRecord::new(intent).unwrap();
        let mut missing = snapshot.clone();
        missing.visible_stream_heads.clear();
        let mut stale = snapshot.clone();
        stale.governance_generation += 1;
        let mut duplicate = snapshot.clone();
        duplicate
            .visible_stream_heads
            .push(duplicate.visible_stream_heads[0].clone());
        for invalid in [missing, stale, duplicate] {
            let mut record = original.clone();
            assert!(record.accept_realm(accepted.clone(), invalid).is_err());
            assert_eq!(record, original);
        }
        let mut changed = serde_json::to_value(&original).unwrap();
        changed["state"] = serde_json::json!("ready");
        assert!(serde_json::from_value::<MlsCreatorBootstrapRecord>(changed).is_err());
    }

    #[test]
    fn creator_circle_absence_cannot_borrow_its_parent_realm_head() {
        let (intent, accepted) = accepted_create(true);
        let parent_only = absence_snapshot(&accepted);
        assert!(
            validate_creator_genesis_absence_snapshot(&intent, &accepted, &parent_only).is_err()
        );
    }

    #[test]
    fn accepted_creation_keeps_its_exact_signed_event_and_parent_authorization_stream() {
        for circle in [false, true] {
            let (intent, accepted) = accepted_create(circle);
            let bytes = arkret_canonical::canonical_json_bytes(&accepted).unwrap();
            let restored: MlsCreatorBootstrapAcceptedCreate =
                serde_json::from_slice(&bytes).unwrap();
            restored.validate_binding(&intent).unwrap();
            assert_eq!(accepted, restored);
            if circle {
                assert_ne!(
                    restored.covering_commit.stream_ref,
                    arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None)
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn accepted_creation_cannot_rebind_proof_commit_scope_or_digest_suite() {
        let (intent, accepted) = accepted_create(true);
        assert!(
            MlsCreatorBootstrapAcceptedCreate::new(
                &intent,
                accepted.accepted_event.clone(),
                accepted.covering_commit.clone(),
                arkret_canonical::DigestSuite::Blake3,
                accepted.authority_root.clone()
            )
            .is_err()
        );
        let mut altered = accepted.clone();
        altered
            .accepted_event
            .producer_proof
            .as_mut()
            .unwrap()
            .jws
            .push('x');
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted.clone();
        altered.covering_commit.stream_ref =
            arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None).unwrap();
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted.clone();
        altered.digest_suite = arkret_canonical::DigestSuite::Blake3;
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted.clone();
        altered.covering_commit.event_ref = fixture_intent(false).scope_create_event_id;
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted;
        altered.covering_commit.governance_generation = 1;
        assert!(altered.validate_binding(&intent).is_err());
    }
}
