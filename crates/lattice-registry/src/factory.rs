use arkret_state::lattice::LatticeKind as SdkLatticeKind;
use arkret_state::state::{BottomMode, MemoryCellRegistry};

use super::contract_registry::{ContractRegistryError, canonical_fsm_contracts};
use super::generated::SPEC_LATTICE_BINDINGS;
use super::impls::*;
use super::registry::*;

/// Build the typed registry used for subject derivation and event-kind dispatch.
///
/// The complete executable family/lattice/bottom mapping is generated directly
/// from `event-kind-registry.json`; see [`lattice_bindings_for_sdk_registry`].
pub fn default_lattice_registry() -> LatticeRegistry {
    let mut registry = LatticeRegistry::new();

    // OrSet
    registry.register(ConsentGrant);
    registry.register(ModerationState);
    registry.register(CapabilityGrant);
    registry.register(CapabilityDerived);
    registry.register(SessionGrant);
    registry.register(DeviceAuthorized);
    registry.register(DeviceListUpdate);
    registry.register(AgentKey);
    registry.register(KeyBackupActiveSeries);
    registry.register(CallModeration);
    registry.register(CallRoster);

    // CasRegister
    registry.register(AppletRegistration);
    registry.register(CircleTombstone);
    registry.register(CircleMember);
    registry.register(StrandPosition);
    registry.register(StrandStage);
    registry.register(MorphStage);
    registry.register(StrandWatch);
    registry.register(CrossSigningPublish);
    registry.register(NotaryCell);
    registry.register(IdentityAccountability);
    registry.register(MlsEpoch);
    registry.register(CallSummary);
    registry.register(CallFocus);
    registry.register(CallRecordingResult);
    registry.register(CallTranscriptResult);
    registry.register(CallMuteOverride);
    registry.register(PolicyDefinition);

    // Fsm
    registry.register(MemberState);
    registry.register(InviteLifecycle);
    registry.register(AgentStatus);
    registry.register(AuditBinding);
    registry.register(AuditSession);
    registry.register(CallState);
    registry.register(CallRecording);
    registry.register(CallTranscript);
    registry.register(RealmLink);

    // OrderedLog
    registry.register(AuditRelease);
    registry.register(CircleCreate);
    registry.register(SidecarCreate);
    registry.register(SpaceParent);
    registry.register(AccountStatus);
    registry.register(PolicyRule);
    registry.register(CrossSigningReset);
    registry.register(MemberIdentityLattice);
    registry.register(ContactFactLog);
    registry.register(DirectConversationBinding);

    // MvRegister
    registry.register(ProfileCreate);
    registry.register(AgentSelectorClaim);
    registry.register(ViewCreate);
    registry.register(ViewUpdate);
    registry.register(ViewReconcile);
    registry.register(MimiRoomBinding);

    registry.register(RealmPolicy);
    registry.register(RealmMetadata);
    registry.register(RealmReadReceiptPolicy);
    registry.register(RealmHistoryVisibility);
    registry.register(RealmJoinRule);
    registry.register(RealmDiscovery);
    registry.register(RealmOrganization);
    registry.register(RealmArchive);
    registry.register(RealmFreeze);
    registry.register(RealmTombstone);
    registry.register(RealmDestroy);
    registry.register(RealmModerationPolicy);
    registry.register(RealmHistorySharingPolicy);
    registry.register(RealmPreviewPolicy);
    registry.register(RealmAssetPrivacyPolicy);
    registry.register(RealmPolicyBundle);
    registry.register(RealmPolicyServer);
    registry.register(RealmAlias);
    registry.register(RealmPlaintextVisibleServices);
    registry.register(RealmMediaService);
    registry.register(RealmSchema);
    registry.register(RealmDeliveryBindingPolicy);
    registry.register(RealmDisappearingPolicy);
    registry.register(RealmSearchPolicy);
    registry.register(RealmInheritancePolicy);
    registry.register(RealmUpgrade);
    registry.register(RealmCreate);
    registry.register(StrandObject);
    registry.register(StrandMetadata);
    registry.register(StrandTracks);

    registry
}

/// One-shot list of `(cell_family, sdk_lattice_kind, sdk_bottom_mode)`
/// generated from every active cell contract in `event-kind-registry.json`.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, BottomMode)> {
    SPEC_LATTICE_BINDINGS.to_vec()
}

/// Build the shared Realm cell registry from the embedded canonical contract.
///
/// This convenience wrapper is appropriate when an invalid embedded artifact
/// is a process invariant violation. Servers that need a recoverable startup
/// error should call [`try_build_sdk_cell_registry`] and fail closed.
pub fn build_sdk_cell_registry() -> MemoryCellRegistry {
    try_build_sdk_cell_registry().expect("embedded canonical cell contract must resolve")
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
            BottomMode::Reject,
        );
    }
    Ok(sdk_registry)
}
