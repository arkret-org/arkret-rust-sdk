use arkret_state::state::MemoryCellStateRegistry;
use arkret_state::state_model::StateModelKind;
use arkret_wire::{EventCellExecution, EventCellValueShape};

use super::contract_registry::{ContractRegistryError, canonical_transition_contracts};
use super::generated::SPEC_STATE_MODEL_BINDINGS;
use super::impls::*;
use super::registry::*;

/// Build the typed registry used for subject derivation and event-kind dispatch.
///
/// The complete executable family/state-model/bottom mapping is generated
/// directly from `event-kind-registry.json`; see [`SPEC_STATE_MODEL_BINDINGS`].
/// Registrations below are ordered alphabetically on purpose: grouping them by
/// state model would restate a binding that only the generated table owns,
/// and such a grouping silently rots the moment a family's algebra changes.
pub fn default_cell_family_registry() -> CellFamilyRegistry {
    let mut registry = CellFamilyRegistry::new();

    registry.register(AgentKey);
    registry.register(AgentSelectorClaim);
    registry.register(AgentStatus);
    registry.register(AppletRegistration);
    registry.register(AuditBinding);
    registry.register(AuditBindingState);
    registry.register(AuditRelease);
    registry.register(AuditSession);
    registry.register(CallFocus);
    registry.register(CallModeration);
    registry.register(CallMuteOverride);
    registry.register(CallRecording);
    registry.register(CallRecordingResult);
    registry.register(CallRoster);
    registry.register(CallState);
    registry.register(CallSummary);
    registry.register(CallTranscript);
    registry.register(CallTranscriptResult);
    registry.register(CapabilityDerived);
    registry.register(CapabilityGrant);
    registry.register(CircleCreate);
    registry.register(CircleHistoryAccess);
    registry.register(CircleMember);
    registry.register(CircleTombstone);
    registry.register(ConsentGrant);
    registry.register(ContactFactLog);
    registry.register(DeviceAuthorized);
    registry.register(DeviceListUpdate);
    registry.register(DirectConversationBinding);
    registry.register(IdentityAccountability);
    registry.register(InviteLifecycle);
    registry.register(KeyBackupActiveSeries);
    registry.register(MemberIdentity);
    registry.register(MemberState);
    registry.register(MimiRoomBinding);
    registry.register(MlsEpoch);
    registry.register(ModerationState);
    registry.register(MorphStage);
    registry.register(NotaryCell);
    registry.register(PolicyDefinition);
    registry.register(PolicyRule);
    registry.register(ProfileCreate);
    registry.register(RealmAlias);
    registry.register(RealmArchive);
    registry.register(RealmAssetPrivacyPolicy);
    registry.register(RealmCreate);
    registry.register(RealmDestroy);
    registry.register(RealmDiscovery);
    registry.register(RealmFreeze);
    registry.register(RealmGenesis);
    registry.register(RealmHistoryAccess);
    registry.register(RealmInheritancePolicy);
    registry.register(RealmJoinRule);
    registry.register(RealmLink);
    registry.register(RealmMediaService);
    registry.register(RealmOrganization);
    registry.register(RealmPlaintextVisibleServices);
    registry.register(RealmPolicy);
    registry.register(RealmPolicyBundle);
    registry.register(RealmPreviewPolicy);
    registry.register(RealmProfile);
    registry.register(RealmReadReceiptPolicy);
    registry.register(RealmReducerProfile);
    registry.register(RealmSchema);
    registry.register(RealmSearchPolicy);
    registry.register(RealmTombstone);
    registry.register(SidecarCreate);
    registry.register(SpaceParent);
    registry.register(StrandObject);
    registry.register(StrandPosition);
    registry.register(StrandStage);
    registry.register(StrandWatch);
    registry.register(View);

    registry
}

/// One-shot list of `(cell_family, execution, state_model, value_shape)`
/// generated from every active cell contract.
pub fn state_model_bindings_for_sdk_registry() -> Vec<(
    &'static str,
    EventCellExecution,
    StateModelKind,
    EventCellValueShape,
)> {
    SPEC_STATE_MODEL_BINDINGS.to_vec()
}

/// Build the shared Realm cell registry from generated canonical descriptors.
///
/// This convenience wrapper is appropriate when an invalid generated contract
/// is a process invariant violation. Servers that need a recoverable startup
/// error should call [`try_build_sdk_state_registry`] and fail closed.
pub fn build_sdk_state_registry() -> MemoryCellStateRegistry {
    try_build_sdk_state_registry().expect("generated canonical cell contract must resolve")
}

pub fn try_build_sdk_state_registry() -> Result<MemoryCellStateRegistry, ContractRegistryError> {
    let mut sdk_registry = MemoryCellStateRegistry::empty();
    for (family, execution, state_model, value_shape) in state_model_bindings_for_sdk_registry() {
        if family.starts_with("ak.private.") {
            return Err(ContractRegistryError::Invalid(format!(
                "actor-private family {family} leaked into the shared registry"
            )));
        }
        sdk_registry.register(family, execution, state_model, value_shape);
    }
    for contract in canonical_transition_contracts()? {
        sdk_registry
            .register_domain_transition(
                &contract.cell_family,
                contract.runtime_initial_state,
                contract.runtime_transitions,
            )
            .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
    }
    Ok(sdk_registry)
}
