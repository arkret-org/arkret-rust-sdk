use arkret_models_collaboration::governance::realm_governance::REALM_LINK_ALLOWED_TRANSITIONS;
use arkret_state::lattice::LatticeKind as SdkLatticeKind;
use arkret_state::state::{BottomMode, MemoryCellRegistry};

use super::impls::*;
use super::registry::*;

/// Build a [`LatticeRegistry`] pre-populated with every spec-normative
/// cell family covered by this module. Downstream Move/Seal receive
/// pipelines call this once at boot. Lifted from soland so all
/// consumers (soland, inkson Move pre-check, cotest fixtures) share
/// one canonical registry.
///
/// Coverage target: all spec-declared cell families in
/// `event-kind-registry.json`.
pub fn default_lattice_registry() -> LatticeRegistry {
    let mut registry = LatticeRegistry::new();

    // OrSet
    registry.register(ConsentGrant);
    registry.register(ModerationState);
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
    registry.register(CallModeration);
    registry.register(CallRoster);

    // CasRegister
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
/// used to bulk-register the SDK's [`MemoryCellRegistry`] so the
/// Move/Seal receive pipeline (`apply_seal` / `verify_move`)
/// resolves every spec-declared cell family correctly. The list mirrors
/// [`default_lattice_registry`] one-to-one.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, BottomMode)> {
    let registry = default_lattice_registry();
    const FAMILIES: &[&str] = &[
        // OrSet
        "ak.component.consent.grant.v1",
        "ak.component.moderation_state.v1",
        "ak.component.capability.grant.v1",
        "ak.component.capability.delegate.v1",
        "ak.component.capability.derived.v1",
        "ak.component.session.grant.v1",
        "ak.component.device.authorization.v1",
        "ak.component.device.list_update.v1",
        "ak.component.device.push_route.v1",
        "ak.component.agent.key.v1",
        "ak.component.covered_seals.v1",
        "ak.component.key_backup.active_series.v1",
        "ak.component.call.moderation.v1",
        "ak.component.call.roster.v1",
        // CasRegister
        "ak.component.circle.tombstone.v1",
        "ak.component.circle.member.v1",
        "ak.component.strand.position.v1",
        "ak.component.strand.stage.v1",
        "ak.component.morph.stage.v1",
        "ak.component.strand.watch.v1",
        "ak.component.cross_signing.publish.v1",
        "ak.component.notary.v1",
        "ak.component.identity.accountability.v1",
        "ak.component.mls.epoch.v1",
        "ak.component.call.summary.v1",
        "ak.component.call.focus.v1",
        "ak.component.call.recording_result.v1",
        "ak.component.call.transcript_result.v1",
        "ak.component.call.mute_override.v1",
        "ak.component.policy.definition.v1",
        // Fsm
        "ak.component.member.state.v1",
        "ak.component.invite.lifecycle.v1",
        "ak.component.agent.status.v1",
        "ak.component.audit.binding.v1",
        "ak.component.audit.session.v1",
        "ak.component.call.state.v1",
        "ak.component.call.recording.v1",
        "ak.component.call.transcript.v1",
        "ak.component.realm.link.v1",
        // OrderedLog
        "ak.component.audit.release.v1",
        "ak.component.circle.create.v1",
        "ak.component.sidecar.create.v1",
        "ak.component.space.parent.v1",
        "ak.component.account.status.v1",
        "ak.component.policy.rule.v1",
        "ak.component.cross_signing.reset.v1",
        "ak.component.member.identity.v1",
        "ak.component.contact.fact_log.v1",
        "ak.component.direct_conversation.binding.v1",
        // MvRegister
        "ak.component.profile.create.v1",
        "ak.component.agent.selector_claim.v1",
        "ak.component.view.create.v1",
        "ak.component.view.update.v1",
        "ak.component.view.reconcile.v1",
        "ak.component.mimi.room_binding.v1",
        // Realm + spec-new strand facet families.
        "ak.component.realm.policy.v1",
        "ak.component.realm.read_receipt_policy.v1",
        "ak.component.realm.history_visibility.v1",
        "ak.component.realm.join_rule.v1",
        "ak.component.realm.discovery.v1",
        "ak.component.realm.organization.v1",
        "ak.component.realm.archive.v1",
        "ak.component.realm.freeze.v1",
        "ak.component.realm.tombstone.v1",
        "ak.component.realm.destroy.v1",
        "ak.component.realm.moderation_policy.v1",
        "ak.component.realm.history_sharing_policy.v1",
        "ak.component.realm.preview_policy.v1",
        "ak.component.realm.asset_privacy_policy.v1",
        "ak.component.realm.policy_bundle.v1",
        "ak.component.realm.policy_server.v1",
        "ak.component.realm.plaintext_visible_services.v1",
        "ak.component.realm.media_service.v1",
        "ak.component.realm.schema.v1",
        "ak.component.realm.delivery_binding_policy.v1",
        "ak.component.realm.disappearing_policy.v1",
        "ak.component.realm.search_policy.v1",
        "ak.component.realm.inheritance_policy.v1",
        "ak.component.realm.upgrade.v1",
        "ak.component.realm.create.v1",
        "ak.component.realm.metadata.v1",
        "ak.component.strand.object.v1",
        "ak.component.strand.metadata.v1",
        "ak.component.strand.tracks.v1",
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
        "ak.component.member.state.v1",
        Some(json!("leave")),
        vec![
            (json!("leave"), json!("invite")),
            (json!("leave"), json!("knock")),
            (json!("leave"), json!("join")),
            (json!("leave"), json!("ban")),
            (json!("invite"), json!("join")),
            (json!("invite"), json!("leave")),
            (json!("invite"), json!("ban")),
            (json!("knock"), json!("invite")),
            (json!("knock"), json!("join")),
            (json!("knock"), json!("leave")),
            (json!("knock"), json!("ban")),
            (json!("join"), json!("join")),
            (json!("join"), json!("leave")),
            (json!("join"), json!("ban")),
            (json!("ban"), json!("leave")),
            (json!("ban"), json!("invite")),
        ],
        BottomMode::Reject,
    );
    let invite_terminal_states = [
        "expired",
        "revoked",
        "revoked_by_capability_loss",
        "revoked_by_inviter_left",
        "invalidated_by_rate_limit",
    ];
    let mut invite_transitions = vec![
        (json!(null), json!("pending")),
        (json!("pending"), json!("accepted")),
        (json!("pending"), json!("rejected")),
        (json!("pending"), json!("claimed")),
        (json!("pending"), json!("send_failed")),
        (json!("claimed"), json!("accepted")),
        (json!("claimed"), json!("rejected")),
        (json!("send_failed"), json!("pending")),
    ];
    for from in ["pending", "claimed", "send_failed"] {
        invite_transitions.extend(
            invite_terminal_states
                .iter()
                .map(|to| (json!(from), json!(to))),
        );
    }
    sdk_registry.register_fsm(
        "ak.component.invite.lifecycle.v1",
        Some(json!(null)),
        invite_transitions,
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.agent.status.v1",
        None,
        vec![
            (json!("active"), json!("paused")),
            (json!("paused"), json!("active")),
            (json!("active"), json!("deactivated")),
            (json!("paused"), json!("deactivated")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.call.state.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("scheduled")),
            (json!(null), json!("ringing")),
            (json!(null), json!("connecting")),
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
    sdk_registry.register_fsm(
        "ak.component.call.recording.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("recording")),
            (json!("recording"), json!("stopped")),
            (json!("recording"), json!("ready")),
            (json!("recording"), json!("failed")),
            (json!("stopped"), json!("ready")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.call.transcript.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("transcribing")),
            (json!("transcribing"), json!("stopped")),
            (json!("transcribing"), json!("ready")),
            (json!("transcribing"), json!("failed")),
            (json!("stopped"), json!("ready")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.realm.link.v1",
        None,
        REALM_LINK_ALLOWED_TRANSITIONS
            .iter()
            .map(|(from, to)| (json!(from.as_str()), json!(to.as_str())))
            .collect(),
        BottomMode::Reject,
    );
    sdk_registry
}
