//! Client-local creator intent constrained by the normative bootstrap registry.
//! This record is never a wire request or a shared current-state value.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ActorId, DeviceId, DidUrl, Event, EventId, EventKind, MlsGroupId, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::authority_commit::SelfAuthoritySubmitRequest;
use crate::events_payloads::MlsGenesisBindingProposalCarrier;
use crate::internal_prelude::{Result, WireError};
use crate::sync_frames::account_subscribe::RealmDetailBaseline;
use crate::sync_frames::current_results::AccountCurrentView;

mod endpoint_authority;
pub use endpoint_authority::{
    MlsCreatorBootstrapAgentAuthority, MlsCreatorBootstrapEndpointAuthority,
};

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
        let device_producer = create.account_device_producer()?;
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
    current: AccountCurrentView,
}

impl MlsCreatorBootstrapCurrentCut {
    pub fn new(baseline: RealmDetailBaseline, current: AccountCurrentView) -> Self {
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

    pub fn current(&self) -> &AccountCurrentView {
        &self.current
    }
}

/// Client-local role evidence. Own-Station originals are retained only after
/// the host consumes a live authenticated bound response. They do not claim
/// independent Station/auditor authority verification and are never wire data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
pub enum MlsCreatorBootstrapAuthority {
    NativeAudit(arkret_wire::RealmAuthorityBundle),
    OwnStation(MlsCreatorBootstrapOwnStationCut),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapOwnStationCut {
    snapshot: arkret_wire::RealmStateSnapshot,
    realm_genesis: crate::events_payloads::RealmGenesis,
    account_id: arkret_wire::AccountId,
    session_grant_id: arkret_wire::SessionGrantId,
    session_epoch: u64,
    request_sequence: u64,
}

impl PartialEq for MlsCreatorBootstrapOwnStationCut {
    fn eq(&self, other: &Self) -> bool {
        self.snapshot == other.snapshot
            && self.account_id == other.account_id
            && self.session_grant_id == other.session_grant_id
            && self.session_epoch == other.session_epoch
            && self.request_sequence == other.request_sequence
            && match (
                arkret_canonical::canonical_json_bytes(&self.realm_genesis),
                arkret_canonical::canonical_json_bytes(&other.realm_genesis),
            ) {
                (Ok(left), Ok(right)) => left == right,
                _ => false,
            }
    }
}

fn validate_creator_own_snapshot(snapshot: &arkret_wire::RealmStateSnapshot) -> Result<()> {
    if snapshot.visible_stream_heads.is_empty()
        || !snapshot
            .visible_stream_heads
            .windows(2)
            .all(|p| p[0].stream_ref < p[1].stream_ref)
        || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
    {
        return Err(WireError::Protocol(
            "creator own-Station snapshot has invalid independent stream shape".into(),
        ));
    }
    let mut floors = std::collections::BTreeMap::new();
    for floor in &snapshot.retention_and_history_floor.stream_floors {
        if floor.stream_ref.realm_id() != &snapshot.realm_id
            || floors
                .insert(&floor.stream_ref, floor.oldest_position)
                .is_some()
        {
            return Err(WireError::Protocol(
                "creator snapshot has foreign or duplicate floors".into(),
            ));
        }
    }
    if floors.len() != snapshot.visible_stream_heads.len()
        || snapshot.visible_stream_heads.iter().any(|h| {
            h.stream_ref.realm_id() != &snapshot.realm_id
                || floors
                    .get(&h.stream_ref)
                    .is_none_or(|p| *p > h.stream_position)
        })
    {
        return Err(WireError::Protocol(
            "creator snapshot floors do not cover the exact visible heads".into(),
        ));
    }
    let mut subjects = std::collections::BTreeSet::new();
    let mut commits = std::collections::BTreeMap::new();
    for row in &snapshot.current_state_entries {
        let arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            ..
        } = row;
        if source_stream_ref.realm_id() != &snapshot.realm_id
            || snapshot
                .visible_stream_heads
                .iter()
                .find(|h| &h.stream_ref == source_stream_ref)
                .is_none_or(|h| {
                    revision.stream_position > h.stream_position
                        || (revision.stream_position == h.stream_position
                            && revision.commit_id != h.commit_id)
                })
            || !subjects.insert(arkret_canonical::canonical_json_bytes(selector)?)
        {
            return Err(WireError::Protocol(
                "creator snapshot current has no exact covering head or repeats a selector".into(),
            ));
        }
        if let Some(old) = commits.insert(
            (source_stream_ref, revision.stream_position),
            &revision.commit_id,
        ) && old != &revision.commit_id
        {
            return Err(WireError::Protocol(
                "creator snapshot forks a typed current coordinate".into(),
            ));
        }
    }
    let mut body = serde_json::to_value(snapshot)?;
    let object = body
        .as_object_mut()
        .ok_or_else(|| WireError::Protocol("creator snapshot is not an object".into()))?;
    object.remove("snapshot_id");
    object.remove("signature");
    let digest = arkret_canonical::sha256_bytes(&arkret_canonical::canonical_json_bytes(&body)?);
    if snapshot.snapshot_id != arkret_wire::RealmSnapshotId::from_digest(digest) {
        return Err(WireError::Protocol(
            "creator own-Station snapshot content address changed".into(),
        ));
    }
    Ok(())
}

impl From<arkret_wire::RealmAuthorityBundle> for MlsCreatorBootstrapAuthority {
    fn from(bundle: arkret_wire::RealmAuthorityBundle) -> Self {
        Self::NativeAudit(bundle)
    }
}
impl MlsCreatorBootstrapAuthority {
    /// The host must check the original Bound response immediately before and
    /// after construction; these local coordinates cannot mint source trust.
    pub fn own_station(
        snapshot: arkret_wire::RealmStateSnapshot,
        realm_genesis: crate::events_payloads::RealmGenesis,
        account_id: arkret_wire::AccountId,
        session_grant_id: arkret_wire::SessionGrantId,
        session_epoch: u64,
        request_sequence: u64,
    ) -> Result<Self> {
        let value = Self::OwnStation(MlsCreatorBootstrapOwnStationCut {
            snapshot,
            realm_genesis,
            account_id,
            session_grant_id,
            session_epoch,
            request_sequence,
        });
        value.validate_shape()?;
        Ok(value)
    }
    fn validate_shape(&self) -> Result<()> {
        match self {
            Self::NativeAudit(bundle) => bundle.validate_shape(),
            Self::OwnStation(cut) => {
                cut.realm_genesis.validate()?;
                validate_creator_own_snapshot(&cut.snapshot)?;
                let realm_stream = arkret_wire::CommitStreamRef::Realm {
                    realm_id: cut.snapshot.realm_id.clone(),
                };
                let distinct: std::collections::BTreeSet<_> = cut
                    .snapshot
                    .visible_stream_heads
                    .iter()
                    .map(|h| &h.stream_ref)
                    .collect();
                let genesis = cut
                    .snapshot
                    .current_state_entries
                    .iter()
                    .filter_map(|row| match row {
                        arkret_wire::TypedCurrentRow::Value {
                            source_stream_ref: stream_ref,
                            selector: arkret_wire::CurrentSelector::RealmGenesis,
                            value,
                            revision,
                            ..
                        } if stream_ref == &realm_stream => Some((value, revision)),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if cut.request_sequence == 0
                    || distinct.len() != cut.snapshot.visible_stream_heads.len()
                    || !cut
                        .snapshot
                        .visible_stream_heads
                        .iter()
                        .any(|h| h.stream_ref == realm_stream)
                    || cut
                        .snapshot
                        .visible_stream_heads
                        .iter()
                        .any(|h| h.stream_ref.realm_id() != &cut.snapshot.realm_id)
                    || genesis.len() != 1
                    || genesis[0].1.stream_position != 0
                    || genesis[0].0 != &serde_json::to_value(&cut.realm_genesis)?
                {
                    return Err(WireError::Protocol(
                        "creator own-Station cut is not the exact complete typed Realm origin"
                            .into(),
                    ));
                }
                Ok(())
            }
        }
    }
    pub fn native_bundle(&self) -> Result<&arkret_wire::RealmAuthorityBundle> {
        match self {
            Self::NativeAudit(bundle) => Ok(bundle),
            Self::OwnStation(_) => Err(WireError::Protocol(
                "ordinary creator evidence is not a native audit Bundle".into(),
            )),
        }
    }
    #[cfg(test)]
    fn native_bundle_mut(&mut self) -> &mut arkret_wire::RealmAuthorityBundle {
        match self {
            Self::NativeAudit(bundle) => bundle,
            Self::OwnStation(_) => panic!("native audit fixture required"),
        }
    }
    fn realm_id(&self) -> &arkret_wire::RealmId {
        match self {
            Self::NativeAudit(b) => &b.realm_id,
            Self::OwnStation(c) => &c.snapshot.realm_id,
        }
    }
    fn generation(&self) -> u64 {
        match self {
            Self::NativeAudit(b) => b.current_generation,
            Self::OwnStation(c) => c.snapshot.governance_generation,
        }
    }
    fn realm_head(&self) -> Result<&arkret_wire::CommitStreamHead> {
        match self {
            Self::NativeAudit(b) => Ok(&b.realm_stream_head),
            Self::OwnStation(c) => c
                .snapshot
                .visible_stream_heads
                .iter()
                .find(|h| matches!(&h.stream_ref, arkret_wire::CommitStreamRef::Realm { .. }))
                .ok_or_else(|| WireError::Protocol("own-Station cut lacks Realm head".into())),
        }
    }
    fn validate_accepted_commit(&self, commit: &arkret_wire::RealmCommit) -> Result<()> {
        if let Self::OwnStation(cut) = self {
            let head = cut
                .snapshot
                .visible_stream_heads
                .iter()
                .find(|h| h.stream_ref == commit.stream_ref);
            if commit.realm_id != cut.snapshot.realm_id
                || commit.governance_generation > cut.snapshot.governance_generation
                || head.is_none_or(|h| {
                    h.stream_position < commit.stream_position
                        || (h.stream_position == commit.stream_position
                            && h.commit_id != commit.commit_id)
                })
            {
                return Err(WireError::Protocol(
                    "creator accepted original is not covered by its exact own-Station current cut"
                        .into(),
                ));
            }
        }
        Ok(())
    }
    fn validate_holder(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        if let Self::OwnStation(cut) = self
            && intent.owner_actor_id().as_account_id() != Some(&cut.account_id)
        {
            return Err(WireError::Protocol(
                "creator own-Station consumer is not the complete holder Account".into(),
            ));
        }
        Ok(())
    }
    fn validate_fresh_at(&self, at: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let valid = match self {
            Self::NativeAudit(b) => at >= b.bundle_issued_at && at < b.current_assertion.expires_at,
            Self::OwnStation(c) => at >= c.snapshot.created_at,
        };
        if !valid {
            return Err(WireError::Protocol(
                "creator cut is not fresh at the device evidence observation".into(),
            ));
        }
        Ok(())
    }
    fn same_read(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NativeAudit(a), Self::NativeAudit(b)) => {
                a.current_assertion.nonce == b.current_assertion.nonce
            }
            (Self::OwnStation(a), Self::OwnStation(b)) => {
                a.account_id == b.account_id
                    && a.session_grant_id == b.session_grant_id
                    && a.session_epoch == b.session_epoch
                    && a.request_sequence == b.request_sequence
            }
            _ => false,
        }
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
    authority_root: MlsCreatorBootstrapAuthority,
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
    creator_authority: MlsCreatorBootstrapEndpointAuthority,
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
        Self::new_with_endpoint_authority(
            intent,
            accepted_create,
            genesis_absence,
            MlsCreatorBootstrapEndpointAuthority::Device(creator_device_authority),
        )
    }

    pub fn new_with_endpoint_authority(
        intent: &MlsCreatorBootstrapIntent,
        accepted_create: MlsCreatorBootstrapAcceptedCreate,
        genesis_absence: arkret_wire::RealmStateSnapshot,
        creator_authority: MlsCreatorBootstrapEndpointAuthority,
    ) -> Result<Self> {
        let canonical_proposal_bytes = arkret_canonical::canonical_json_bytes(intent.proposal())?;
        let proposal_digest = arkret_wire::Hash::new(arkret_canonical::canonical::digest(
            accepted_create.digest_suite(),
            &canonical_proposal_bytes,
        ))?;
        let value = Self {
            accepted_create,
            genesis_absence,
            creator_authority,
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
        self.creator_authority.validate_binding(intent)?;
        let verified_at = self.creator_authority.verified_at();
        self.accepted_create
            .authority_root
            .validate_fresh_at(verified_at)?;
        if self.genesis_absence.created_at > verified_at {
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
    #[cfg(test)]
    fn device_authority_mut(&mut self) -> &mut MlsCreatorBootstrapDeviceAuthority {
        match &mut self.creator_authority {
            MlsCreatorBootstrapEndpointAuthority::Device(value) => value,
            _ => panic!("Device fixture required"),
        }
    }

    pub fn creator_authority(&self) -> &MlsCreatorBootstrapEndpointAuthority {
        &self.creator_authority
    }
    pub fn creator_device_authority(&self) -> Result<&MlsCreatorBootstrapDeviceAuthority> {
        match &self.creator_authority {
            MlsCreatorBootstrapEndpointAuthority::Device(value) => Ok(value),
            _ => Err(WireError::Protocol(
                "creator endpoint is not a Device".into(),
            )),
        }
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
                != *evidence.creator_authority.authorization_event_ref()
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
    authority_root: MlsCreatorBootstrapAuthority,
}

impl MlsCreatorBootstrapAcceptedGenesis {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        queued: &MlsCreatorBootstrapQueuedGenesis,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: impl Into<MlsCreatorBootstrapAuthority>,
    ) -> Result<Self> {
        let authority_root = authority_root.into();
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
        self.authority_root
            .validate_accepted_commit(&self.accepted.commit)?;
        self.authority_root.validate_holder(intent)?;
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
            || *self.authority_root.realm_id() != *intent.effective_scope().realm_id()
            || self.accepted.commit.governance_generation > self.authority_root.generation()
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
    accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
    accepted: arkret_wire::CommittedEventFullView,
    canonical_accepted_bytes: Vec<u8>,
    accepted_bytes_digest: arkret_wire::Hash,
    digest_suite: arkret_canonical::DigestSuite,
    immutable_genesis_binding: MlsGovernanceBindingPayload,
    authority_root: MlsCreatorBootstrapAuthority,
}

impl MlsCreatorBootstrapWinner {
    pub fn new(
        record: &MlsCreatorBootstrapRecord,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: impl Into<MlsCreatorBootstrapAuthority>,
    ) -> Result<Self> {
        let authority_root = authority_root.into();
        let create = record.accepted_create().ok_or_else(|| {
            WireError::Protocol("creator winner requires accepted scope create".into())
        })?;
        let value = Self::from_accepted(record.intent(), create.clone(), accepted, authority_root)?;
        value.validate_binding(record)?;
        Ok(value)
    }

    /// A winner may precede the local accepted-create checkpoint. The host
    /// authenticates both originals without ever inventing an absent result.
    pub fn from_accepted(
        intent: &MlsCreatorBootstrapIntent,
        accepted_create: MlsCreatorBootstrapAcceptedCreate,
        accepted: arkret_wire::CommittedEventFullView,
        authority_root: impl Into<MlsCreatorBootstrapAuthority>,
    ) -> Result<Self> {
        let authority_root = authority_root.into();
        accepted_create.validate_binding(intent)?;
        let suite = accepted_create.digest_suite();
        let payload: crate::events_payloads::MlsGenesisPayload = serde_json::from_value(
            serde_json::Value::Object(accepted.event.payload.clone().into_iter().collect()),
        )
        .map_err(|error| {
            WireError::Protocol(format!("invalid winning Genesis payload: {error}"))
        })?;
        let bytes = arkret_canonical::canonical_json_bytes(&accepted.event)?;
        let value = Self {
            accepted_create: Box::new(accepted_create),
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
        self.accepted_create.validate_binding(intent)?;
        if self.accepted_create.digest_suite() != suite {
            return Err(WireError::Protocol(
                "creator winner changed original create digest suite".into(),
            ));
        }
        self.accepted.validate_shape()?;
        self.authority_root.validate_shape()?;
        self.authority_root
            .validate_accepted_commit(&self.accepted.commit)?;
        self.authority_root.validate_holder(intent)?;
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
        let producer = self.accepted.event.account_device_producer()?;
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
            || self.authority_root.realm_id() != intent.effective_scope().realm_id()
            || self.accepted.commit.governance_generation > self.authority_root.generation()
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
            .unwrap_or(&self.accepted_create)
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
        authority_root: impl Into<MlsCreatorBootstrapAuthority>,
    ) -> Result<Self> {
        let authority_root = authority_root.into();
        let create = record.accepted_create().ok_or_else(|| {
            WireError::Protocol("known creator winner lost scope-create authority".into())
        })?;
        Ok(Self::Winner {
            winner: Box::new(MlsCreatorBootstrapWinner::from_accepted(
                record.intent(),
                create.clone(),
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
            Self::Superseded {
                loser_record,
                winner,
                ..
            } => loser_record
                .accepted_create()
                .or(Some(&winner.accepted_create)),
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
            .authority_root
            .same_read(&rejection.last_verified.accepted_create.authority_root)
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
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentRow};
    let stream = CommitStreamRef::from_scope(intent.effective_scope(), None)?;
    accepted.validate_binding(intent)?;
    let root = &accepted.authority_root;
    if let MlsCreatorBootstrapAuthority::OwnStation(cut) = root
        && &cut.snapshot != snapshot
    {
        return Err(WireError::Protocol(
            "creator absence changed the original own-Station current result".into(),
        ));
    }
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
    if snapshot.realm_id != *root.realm_id()
        || snapshot.governance_generation != root.generation()
        || distinct.len() != snapshot.visible_stream_heads.len()
        || snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref.realm_id() != root.realm_id())
        || scope_head.is_none()
        || create_head.is_none_or(|head| {
            head.stream_position < create.stream_position
                || (head.stream_position == create.stream_position
                    && head.commit_id != create.commit_id)
        })
        || !snapshot.visible_stream_heads.contains(root.realm_head()?)
        || snapshot.current_state_entries.iter().any(|entry| {
            let selector = match entry {
                TypedCurrentRow::Value { selector, .. } => selector,
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
        authority_root: impl Into<MlsCreatorBootstrapAuthority>,
    ) -> Result<Self> {
        let authority_root = authority_root.into();
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
        self.authority_root
            .validate_accepted_commit(&self.covering_commit)?;
        self.authority_root.validate_holder(intent)?;
        self.accepted_event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        self.accepted_event
            .validate_proof_bindings_with_digest_suite(self.digest_suite)?;
        self.authority_root.validate_holder(intent)?;
        if let MlsCreatorBootstrapAuthority::NativeAudit(bundle) = &self.authority_root {
            bundle
                .genesis_event
                .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        }
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
            || *self.authority_root.realm_id() != original.realm_id
            || self.covering_commit.governance_generation > self.authority_root.generation()
            || (original.kind == EventKind::RealmCreate
                && match &self.authority_root {
                    MlsCreatorBootstrapAuthority::NativeAudit(bundle) => {
                        bundle.genesis_event != self.accepted_event
                            || bundle.genesis_commit != self.covering_commit
                    }
                    MlsCreatorBootstrapAuthority::OwnStation(cut) => {
                        let payload: crate::events_payloads::RealmCreatePayload =
                            serde_json::from_value(serde_json::to_value(
                                &self.accepted_event.payload,
                            )?)?;
                        payload.object.validate()?;
                        arkret_canonical::canonical_json_bytes(&payload.object)?
                            != arkret_canonical::canonical_json_bytes(&cut.realm_genesis)?
                            || arkret_wire::RealmId::from_event_id(&self.accepted_event.event_id)
                                != cut.snapshot.realm_id
                    }
                })
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

    pub fn authority_root(&self) -> Result<&arkret_wire::RealmAuthorityBundle> {
        self.authority_root.native_bundle()
    }
    pub fn authority_evidence(&self) -> &MlsCreatorBootstrapAuthority {
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
#[path = "mls_creator_bootstrap/tests.rs"]
mod tests;
