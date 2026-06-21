use super::impls::*;
use super::registry::*;
use crate::lattice::LatticeKind as SdkLatticeKind;
use crate::state_res::{BottomMode, MemoryCellRegistry};

/// Build a [`LatticeRegistry`] pre-populated with every spec-normative
/// cell family covered by this module. Downstream Move/Seal receive
/// pipelines call this once at boot. Lifted from soland so all
/// consumers (soland, yougen Move pre-check, cotest fixtures) share
/// one canonical registry.
///
/// Coverage target: all spec-declared cell families in
/// `event-kind-registry.json`.
pub fn default_lattice_registry() -> LatticeRegistry {
    let mut registry = LatticeRegistry::new();

    // OrSet
    registry.register(ConsentGrant);
    registry.register(CapabilityGrant);
    registry.register(CapabilityDelegate);
    registry.register(CapabilityDerived);
    registry.register(SessionGrant);
    registry.register(DeviceAuthorized);
    registry.register(DeviceListUpdate);
    registry.register(DevicePushRoute);
    registry.register(AgentKey);
    registry.register(CoveredSeals);
    registry.register(KeyBackupActiveSeries);

    // CasRegister
    registry.register(CircleTombstone);
    registry.register(CircleMember);
    registry.register(StrandPosition);
    registry.register(StrandStage);
    registry.register(MorphStage);
    registry.register(StrandWatch);
    registry.register(CrossSigningPublish);
    registry.register(NotaryCell);
    registry.register(MlsEpoch);
    registry.register(CallSummary);

    // Fsm
    registry.register(MemberState);
    registry.register(AgentStatus);
    registry.register(CallState);

    // OrderedLog
    registry.register(CircleCreate);
    registry.register(SpaceParent);
    registry.register(AccountStatus);
    registry.register(PolicyRule);
    registry.register(CrossSigningReset);
    registry.register(MemberIdentityLattice);
    registry.register(ContactFactLog);
    registry.register(DirectConversationBinding);

    // MvRegister
    registry.register(ProfileCreate);
    registry.register(ViewCreate);
    registry.register(ViewUpdate);
    registry.register(ViewReconcile);
    registry.register(MimiRoomBinding);

    registry.register(RealmPolicy);
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
    registry.register(RealmPolicyComponents);
    registry.register(RealmPolicyServer);
    registry.register(RealmPlaintextVisibleServices);
    registry.register(RealmMediaService);
    registry.register(RealmSchema);
    registry.register(RealmDeliveryBindingPolicy);
    registry.register(RealmDisappearingPolicy);
    registry.register(RealmSearchPolicy);
    registry.register(RealmInheritancePolicy);
    registry.register(RealmUpgrade);
    registry.register(RealmCreate);
    registry.register(RealmLink);
    registry.register(StrandMetadata);
    registry.register(StrandTracks);

    registry
}

/// One-shot list of `(cell_family, sdk_lattice_kind, sdk_bottom_mode)`
/// used to bulk-register the SDK's [`MemoryCellRegistry`] so the
/// Move/Seal receive pipeline (`apply_seal` / `verify_move`)
/// resolves every spec-declared cell family correctly. The list mirrors
/// [`default_lattice_registry`] one-to-one.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, BottomMode)> {
    let registry = default_lattice_registry();
    const FAMILIES: &[&str] = &[
        // OrSet
        "ck.component.consent.grant.v1",
        "ck.component.capability.grant.v1",
        "ck.component.capability.delegate.v1",
        "ck.component.capability.derived.v1",
        "ck.component.session.grant.v1",
        "ck.component.device.authorization.v1",
        "ck.component.device.list_update.v1",
        "ck.component.device.push_route.v1",
        "ck.component.agent.key.v1",
        "ck.component.covered_seals.v1",
        "ck.component.key_backup.active_series.v1",
        // CasRegister
        "ck.component.circle.tombstone.v1",
        "ck.component.circle.member.v1",
        "ck.component.strand.position.v1",
        "ck.component.strand.stage.v1",
        "ck.component.morph.stage.v1",
        "ck.component.strand.watch.v1",
        "ck.component.cross_signing.publish.v1",
        "ck.component.notary.v1",
        "ck.component.mls.epoch.v1",
        "ck.component.call.summary.v1",
        // Fsm
        "ck.component.member.state.v1",
        "ck.component.agent.status.v1",
        "ck.component.call.state.v1",
        // OrderedLog
        "ck.component.circle.create.v1",
        "ck.component.space.parent.v1",
        "ck.component.account.status.v1",
        "ck.component.policy.rule.v1",
        "ck.component.cross_signing.reset.v1",
        "ck.component.member.identity.v1",
        "ck.component.contact.fact_log.v1",
        "ck.component.direct_conversation.binding.v1",
        // MvRegister
        "ck.component.profile.create.v1",
        "ck.component.view.create.v1",
        "ck.component.view.update.v1",
        "ck.component.view.reconcile.v1",
        "ck.component.mimi.room_binding.v1",
        // Realm + spec-new strand facet families.
        "ck.component.realm.policy.v1",
        "ck.component.realm.read_receipt_policy.v1",
        "ck.component.realm.history_visibility.v1",
        "ck.component.realm.join_rule.v1",
        "ck.component.realm.discovery.v1",
        "ck.component.realm.organization.v1",
        "ck.component.realm.archive.v1",
        "ck.component.realm.freeze.v1",
        "ck.component.realm.tombstone.v1",
        "ck.component.realm.destroy.v1",
        "ck.component.realm.moderation_policy.v1",
        "ck.component.realm.history_sharing_policy.v1",
        "ck.component.realm.preview_policy.v1",
        "ck.component.realm.asset_privacy_policy.v1",
        "ck.component.realm.policy_components.v1",
        "ck.component.realm.policy_server.v1",
        "ck.component.realm.plaintext_visible_services.v1",
        "ck.component.realm.media_service.v1",
        "ck.component.realm.schema.v1",
        "ck.component.realm.delivery_binding_policy.v1",
        "ck.component.realm.disappearing_policy.v1",
        "ck.component.realm.search_policy.v1",
        "ck.component.realm.inheritance_policy.v1",
        "ck.component.realm.upgrade.v1",
        "ck.component.realm.create.v1",
        "ck.component.realm.link.v1",
        "ck.component.strand.metadata.v1",
        "ck.component.strand.tracks.v1",
    ];
    FAMILIES
        .iter()
        .map(|family| {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("default_lattice_registry missing {family}"));
            (
                *family,
                kind.lattice(),
                kind.bottom_policy().to_sdk_bottom_mode(),
            )
        })
        .collect()
}

/// Build a fresh [`MemoryCellRegistry`] populated with every
/// spec-declared cell family. Move/Seal receive pipeline
/// (`verify_move` / `apply_seal`) uses this to resolve
/// `(family → Lattice)` for every effect.
///
/// FSM families need their transition tables set via `register_fsm`; the
/// spec-normative membership FSM table is encoded inline below.
pub fn build_sdk_cell_registry() -> MemoryCellRegistry {
    use serde_json::json;

    let mut sdk_registry = MemoryCellRegistry::new();
    for (family, kind, bottom_mode) in lattice_bindings_for_sdk_registry() {
        if matches!(kind, SdkLatticeKind::Fsm) {
            continue;
        }
        sdk_registry.register(family, kind, bottom_mode);
    }
    sdk_registry.register_fsm(
        "ck.component.member.state.v1",
        Some(json!("invite")),
        vec![
            (json!("invite"), json!("join")),
            (json!("invite"), json!("leave")),
            (json!("knock"), json!("join")),
            (json!("knock"), json!("leave")),
            (json!("join"), json!("leave")),
            (json!("join"), json!("ban")),
            (json!("leave"), json!("invite")),
            (json!("leave"), json!("knock")),
            (json!("ban"), json!("invite")),
            (json!("ban"), json!("knock")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ck.component.agent.status.v1",
        None,
        vec![
            (json!("active"), json!("paused")),
            (json!("paused"), json!("active")),
            (json!("pending_runtime_key"), json!("deactivated")),
            (json!("active"), json!("deactivated")),
            (json!("paused"), json!("deactivated")),
            (json!("pairing_expired"), json!("deactivated")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ck.component.call.state.v1",
        None,
        vec![
            (json!("scheduled"), json!("ringing")),
            (json!("scheduled"), json!("connecting")),
            (json!("scheduled"), json!("cancelled")),
            (json!("scheduled"), json!("missed")),
            (json!("scheduled"), json!("failed")),
            (json!("ringing"), json!("connecting")),
            (json!("ringing"), json!("active")),
            (json!("ringing"), json!("missed")),
            (json!("ringing"), json!("cancelled")),
            (json!("ringing"), json!("failed")),
            (json!("connecting"), json!("active")),
            (json!("connecting"), json!("failed")),
            (json!("connecting"), json!("ended")),
            (json!("active"), json!("ended")),
            (json!("active"), json!("failed")),
        ],
        BottomMode::Reject,
    );
    sdk_registry
}
