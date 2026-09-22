//! Production verification of the Arkret MLS governance binding.

pub use arkret_models_collaboration::events_payloads::MlsGenesisBindingProposalCarrier;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ErrorCode, EventId, EventKind, MlsGroupId, ReasonCode, ScopeRef};

/// Stable rejection produced after a carrier has passed structural decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlsGovernanceBindingRejection {
    GovernanceBindingMismatch,
    EpochUpdateRequired,
    MlsGenesisBindingProposalMismatch,
}

impl MlsGovernanceBindingRejection {
    pub const fn code(self) -> &'static str {
        match self {
            Self::GovernanceBindingMismatch => ReasonCode::GOVERNANCE_BINDING_MISMATCH,
            Self::EpochUpdateRequired => ReasonCode::EPOCH_UPDATE_REQUIRED,
            Self::MlsGenesisBindingProposalMismatch => {
                ErrorCode::MLS_GENESIS_BINDING_PROPOSAL_MISMATCH
            }
        }
    }
}

/// Which production gate issued a verified governance-binding effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifiedMlsGovernanceBindingUse {
    Transition,
    NextEpoch,
    PublicStateAndPayload,
    HistoricalReplay,
    CurrentSend,
    GenesisProposal,
}

/// Opaque success effect issued only after the selected production gate has
/// verified all of its typed inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceBinding {
    binding: MlsGovernanceBindingPayload,
    verified_use: VerifiedMlsGovernanceBindingUse,
}

impl VerifiedMlsGovernanceBinding {
    pub fn binding(&self) -> &MlsGovernanceBindingPayload {
        &self.binding
    }

    pub const fn verified_use(&self) -> VerifiedMlsGovernanceBindingUse {
        self.verified_use
    }
}

/// Exact Station public coordinates against which a next-epoch binding and
/// its Event payload are compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsGovernanceBindingPublicState {
    effective_scope: ScopeRef,
    base_group_state_ref: Option<EventId>,
    current_epoch: u64,
    current_key_access_revision: u64,
}

impl MlsGovernanceBindingPublicState {
    pub const fn new(
        effective_scope: ScopeRef,
        base_group_state_ref: Option<EventId>,
        current_epoch: u64,
        current_key_access_revision: u64,
    ) -> Self {
        Self {
            effective_scope,
            base_group_state_ref,
            current_epoch,
            current_key_access_revision,
        }
    }
}

/// Exact current public coordinates needed by the application-message send
/// gate. Historical verification never constructs this value implicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCurrentSendState {
    effective_scope: ScopeRef,
    current_epoch: u64,
    current_key_access_revision: u64,
}

impl MlsCurrentSendState {
    pub const fn new(
        effective_scope: ScopeRef,
        current_epoch: u64,
        current_key_access_revision: u64,
    ) -> Self {
        Self {
            effective_scope,
            current_epoch,
            current_key_access_revision,
        }
    }
}

/// Verify the binding-local epoch transition and monotonic key-access
/// revision. Exact equality with current public state is enforced by
/// [`verify_governance_binding_against_public_state_and_payload`].
pub fn verify_governance_binding_transition(
    binding: &MlsGovernanceBindingPayload,
    current_key_access_revision: u64,
) -> Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection> {
    binding
        .validate()
        .map_err(|_| MlsGovernanceBindingRejection::GovernanceBindingMismatch)?;
    if binding.key_access_revision() < current_key_access_revision {
        return Err(MlsGovernanceBindingRejection::GovernanceBindingMismatch);
    }
    Ok(verified(
        binding,
        VerifiedMlsGovernanceBindingUse::Transition,
    ))
}

/// Shared coordinate gate used by the live [`crate::ArkretMlsGroup`] commit
/// path and by typed conformance consumers.
pub fn verify_next_epoch_governance_binding(
    current_group_id: &MlsGroupId,
    current_epoch: u64,
    binding: &MlsGovernanceBindingPayload,
) -> Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection> {
    binding
        .validate()
        .map_err(|_| MlsGovernanceBindingRejection::GovernanceBindingMismatch)?;
    let next_epoch = current_epoch
        .checked_add(1)
        .ok_or(MlsGovernanceBindingRejection::GovernanceBindingMismatch)?;
    if binding
        .mls_group_id()
        .map_err(|_| MlsGovernanceBindingRejection::GovernanceBindingMismatch)?
        != *current_group_id
        || binding.previous_epoch() != current_epoch
        || binding.next_epoch() != next_epoch
    {
        return Err(MlsGovernanceBindingRejection::GovernanceBindingMismatch);
    }
    Ok(verified(
        binding,
        VerifiedMlsGovernanceBindingUse::NextEpoch,
    ))
}

/// Verify that the GroupContext extension, accepted Station public state and
/// Event payload name the same next-epoch transition field for field.
pub fn verify_governance_binding_against_public_state_and_payload(
    binding: &MlsGovernanceBindingPayload,
    public_state: &MlsGovernanceBindingPublicState,
    event_payload_binding: &MlsGovernanceBindingPayload,
) -> Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection> {
    let group_id = public_state
        .effective_scope
        .canonical_mls_group_id()
        .map_err(|_| MlsGovernanceBindingRejection::GovernanceBindingMismatch)?;
    verify_next_epoch_governance_binding(&group_id, public_state.current_epoch, binding)?;
    if binding != event_payload_binding
        || binding.effective_scope() != &public_state.effective_scope
        || binding.base_group_state_ref() != public_state.base_group_state_ref.as_ref()
        || binding.key_access_revision() != public_state.current_key_access_revision
    {
        return Err(MlsGovernanceBindingRejection::GovernanceBindingMismatch);
    }
    Ok(verified(
        binding,
        VerifiedMlsGovernanceBindingUse::PublicStateAndPayload,
    ))
}

/// Verify historical material only against the immutable binding accepted
/// with that historical Event.
pub fn verify_historical_governance_binding(
    binding: &MlsGovernanceBindingPayload,
    accepted_historical_binding: &MlsGovernanceBindingPayload,
) -> Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection> {
    binding
        .validate()
        .map_err(|_| MlsGovernanceBindingRejection::GovernanceBindingMismatch)?;
    accepted_historical_binding
        .validate()
        .map_err(|_| MlsGovernanceBindingRejection::GovernanceBindingMismatch)?;
    if binding != accepted_historical_binding {
        return Err(MlsGovernanceBindingRejection::GovernanceBindingMismatch);
    }
    Ok(verified(
        binding,
        VerifiedMlsGovernanceBindingUse::HistoricalReplay,
    ))
}

/// Verify that a binding grants application-message authority at the exact
/// current scope, epoch and key-access revision.
pub fn verify_current_send_governance_binding(
    binding: &MlsGovernanceBindingPayload,
    current: &MlsCurrentSendState,
) -> Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection> {
    binding
        .validate()
        .map_err(|_| MlsGovernanceBindingRejection::EpochUpdateRequired)?;
    if binding.effective_scope() != &current.effective_scope
        || binding.next_epoch() != current.current_epoch
        || binding.key_access_revision() != current.current_key_access_revision
    {
        return Err(MlsGovernanceBindingRejection::EpochUpdateRequired);
    }
    Ok(verified(
        binding,
        VerifiedMlsGovernanceBindingUse::CurrentSend,
    ))
}

/// Verify a structurally decoded, complete pre-Genesis proposal carrier.
pub fn verify_mls_genesis_binding_proposal(
    carrier: &MlsGenesisBindingProposalCarrier,
) -> Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection> {
    let binding = carrier.proposed_group_genesis_binding();
    binding
        .validate()
        .map_err(|_| MlsGovernanceBindingRejection::MlsGenesisBindingProposalMismatch)?;
    if carrier.event_kind() != &EventKind::MlsGenesis
        || carrier.proposal_kind() != MlsGenesisBindingProposalCarrier::PROPOSAL_KIND
        || carrier.target_scope() != binding.effective_scope()
        || binding.base_group_state_ref().is_some()
        || binding.previous_epoch() != 0
        || binding.next_epoch() != 0
        || binding.key_access_revision() != 0
    {
        return Err(MlsGovernanceBindingRejection::MlsGenesisBindingProposalMismatch);
    }
    Ok(verified(
        binding,
        VerifiedMlsGovernanceBindingUse::GenesisProposal,
    ))
}

fn verified(
    binding: &MlsGovernanceBindingPayload,
    verified_use: VerifiedMlsGovernanceBindingUse,
) -> VerifiedMlsGovernanceBinding {
    VerifiedMlsGovernanceBinding {
        binding: binding.clone(),
        verified_use,
    }
}
