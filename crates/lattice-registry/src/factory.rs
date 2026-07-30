use arkret_models_collaboration::governance::realm_governance::REALM_LINK_ALLOWED_TRANSITIONS;
use arkret_state::lattice::LatticeKind as SdkLatticeKind;
use arkret_state::state::{BottomMode, MemoryCellRegistry};

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

/// Build a fresh [`MemoryCellRegistry`] populated with every
/// spec-declared cell family. Move/Seal receive pipeline
/// (`verify_move` / `apply_seal`) uses this to resolve
/// `(family → Lattice)` for every effect.
///
/// FSM families need their transition tables set via `register_fsm`; the
/// spec-normative membership FSM table is encoded inline below.
pub fn build_sdk_cell_registry() -> MemoryCellRegistry {
    use serde_json::json;

    let mut sdk_registry = MemoryCellRegistry::empty();
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
    sdk_registry.register_fsm(
        "ak.component.circle.member.v1",
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
        Some(json!("active")),
        vec![
            (json!("active"), json!("paused")),
            (json!("paused"), json!("active")),
            (json!("active"), json!("deactivated")),
            (json!("paused"), json!("deactivated")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.audit.binding.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("active")),
            (json!("active"), json!("suspended")),
            (json!("active"), json!("revoked")),
            (json!("suspended"), json!("active")),
            (json!("suspended"), json!("revoked")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.audit.session.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("request")),
            (json!("request"), json!("authorize")),
            (json!("authorize"), json!("notice")),
            (json!("request"), json!("close")),
            (json!("authorize"), json!("close")),
            (json!("notice"), json!("close")),
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
    for family in [
        "ak.component.circle.lifecycle.v1",
        "ak.component.morph.lifecycle.v1",
        "ak.component.strand.lifecycle.v1",
    ] {
        sdk_registry.register_fsm(
            family,
            Some(json!("active")),
            vec![
                (json!("active"), json!("archived")),
                (json!("archived"), json!("active")),
            ],
            BottomMode::Reject,
        );
    }
    sdk_registry.register_fsm(
        "ak.component.space.lifecycle.v1",
        Some(json!("active")),
        vec![
            (json!("active"), json!("archived")),
            (json!("archived"), json!("active")),
            (json!("active"), json!("tombstoned")),
            (json!("archived"), json!("tombstoned")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.relation.lifecycle.v1",
        Some(json!("active")),
        vec![(json!("active"), json!("tombstoned"))],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.moderation.appeal.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("submitted")),
            (json!("submitted"), json!("under_review")),
            (json!("under_review"), json!("decided")),
            (json!("submitted"), json!("closed")),
            (json!("under_review"), json!("closed")),
            (json!("decided"), json!("closed")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.mls.keypackage.v1",
        Some(json!(null)),
        vec![
            (json!(null), json!("published")),
            (json!("published"), json!("published")),
            (json!("published"), json!("claimed")),
            (json!("published"), json!("expired")),
            (json!("published"), json!("revoked")),
            (json!("claimed"), json!("consumed")),
            (json!("claimed"), json!("expired")),
            (json!("claimed"), json!("revoked")),
        ],
        BottomMode::Reject,
    );
    sdk_registry.register_fsm(
        "ak.component.realm.link.v1",
        Some(json!(null)),
        [
            (json!(null), json!("active")),
            (json!(null), json!("rejected")),
            (json!(null), json!("tombstoned")),
        ]
        .into_iter()
        .chain(
            REALM_LINK_ALLOWED_TRANSITIONS
                .iter()
                .map(|(from, to)| (json!(from.as_str()), json!(to.as_str()))),
        )
        .collect(),
        BottomMode::Reject,
    );
    sdk_registry
}
