use arkret_state::lattice::LatticeKind as SdkLatticeKind;
use arkret_state::state::{EventCellBottom, MemoryCellRegistry};

use super::contract_registry::{ContractRegistryError, canonical_fsm_contracts};
use super::generated::SPEC_LATTICE_BINDINGS;
use super::impls::*;
use super::registry::*;

/// Build the typed registry used for subject derivation and event-kind dispatch.
///
/// The complete executable family/lattice/bottom mapping is generated directly
/// from `event-kind-registry.json`; see [`lattice_bindings_for_sdk_registry`].
/// Registrations below are ordered alphabetically on purpose: grouping them by
/// lattice algebra would restate a binding that only the generated table owns,
/// and such a grouping silently rots the moment a family's algebra changes.
pub fn default_lattice_registry() -> LatticeRegistry {
    let mut registry = LatticeRegistry::new();

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
    registry.register(MemberIdentityLattice);
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

/// One-shot list of `(cell_family, sdk_lattice_kind, sdk_bottom_mode)`
/// generated from every active cell contract in `event-kind-registry.json`.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, EventCellBottom)> {
    SPEC_LATTICE_BINDINGS.to_vec()
}

/// Build the shared Realm cell registry from generated canonical descriptors.
///
/// This convenience wrapper is appropriate when an invalid generated contract
/// is a process invariant violation. Servers that need a recoverable startup
/// error should call [`try_build_sdk_cell_registry`] and fail closed.
pub fn build_sdk_cell_registry() -> MemoryCellRegistry {
    try_build_sdk_cell_registry().expect("generated canonical cell contract must resolve")
}

pub fn try_build_sdk_cell_registry() -> Result<MemoryCellRegistry, ContractRegistryError> {
    let mut sdk_registry = MemoryCellRegistry::empty();
    for (family, kind, bottom_mode) in lattice_bindings_for_sdk_registry() {
        if matches!(kind, SdkLatticeKind::Fsm) {
            continue;
        }
        if family.starts_with("ak.private.") {
            return Err(ContractRegistryError::Invalid(format!(
                "actor-private family {family} leaked into the shared registry"
            )));
        }
        sdk_registry.register(family, kind, bottom_mode);
    }
    for contract in canonical_fsm_contracts()? {
        sdk_registry.register_fsm(
            &contract.cell_family,
            contract.runtime_initial_state,
            contract.runtime_transitions,
            EventCellBottom::Reject,
        );
    }
    Ok(sdk_registry)
}
