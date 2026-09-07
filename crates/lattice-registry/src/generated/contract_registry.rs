//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-07.12;
//! sha256=bd9e9683c3f1f26f685426a3be20e8c877fdc33005fff707f127a384ac150d2b
//! Entries: actor_private_families=5, actor_private_writes=8, fsm_contracts=18

use arkret_wire::CellFamilyId;

use crate::contract_registry::{
    ActorPrivateEffectProjection, ActorPrivateMergeKind, ActorPrivateSubjectComponent,
    ActorPrivateSubjectRule, ActorPrivateTombstoneMode, GeneratedActorPrivateFamily,
    GeneratedActorPrivateFsm, GeneratedActorPrivateWrite, GeneratedFsmContract, GeneratedState,
};

pub(crate) const GENERATED_ACTOR_PRIVATE_FAMILIES: &[GeneratedActorPrivateFamily] = &[
    GeneratedActorPrivateFamily {
        cell_family: "ak.private.account.blocklist.v1",
        merge: ActorPrivateMergeKind::ServerRevisionCas,
        tombstone: Some(ActorPrivateTombstoneMode::ValueTombstone),
        bottom_reject: false,
        fsm: None,
    },
    GeneratedActorPrivateFamily {
        cell_family: "ak.private.account_data.v1",
        merge: ActorPrivateMergeKind::ServerRevisionCas,
        tombstone: Some(ActorPrivateTombstoneMode::VersionedTombstone),
        bottom_reject: false,
        fsm: None,
    },
    GeneratedActorPrivateFamily {
        cell_family: "ak.private.agent.draft.v1",
        merge: ActorPrivateMergeKind::FsmCas,
        tombstone: None,
        bottom_reject: true,
        fsm: Some(GeneratedActorPrivateFsm {
            initial_state: "proposed",
            states: &["proposed", "approved", "rejected", "published"],
            terminal_states: &["rejected", "published"],
            allowed_transitions: &[
                ("proposed", "approved"),
                ("proposed", "rejected"),
                ("approved", "published"),
            ],
        }),
    },
    GeneratedActorPrivateFamily {
        cell_family: "ak.private.device.push_route.v1",
        merge: ActorPrivateMergeKind::ServerRevisionCas,
        tombstone: Some(ActorPrivateTombstoneMode::VersionedTombstone),
        bottom_reject: false,
        fsm: None,
    },
    GeneratedActorPrivateFamily {
        cell_family: "ak.private.read_cursor.v1",
        merge: ActorPrivateMergeKind::CausalThenHlcThenDevice,
        tombstone: None,
        bottom_reject: false,
        fsm: None,
    },
];

pub(crate) const GENERATED_ACTOR_PRIVATE_WRITES: &[GeneratedActorPrivateWrite] = &[
    GeneratedActorPrivateWrite {
        event_kind: "ak.account.blocklist",
        cell_family: "ak.private.account.blocklist.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::CanonicalJson("envelope.actor_id"),
        ]),
        effect_projection: ActorPrivateEffectProjection::SetPayload,
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.account_data.set",
        cell_family: "ak.private.account_data.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::CanonicalJson("envelope.actor_id"),
            ActorPrivateSubjectComponent::Field("payload.key"),
        ]),
        effect_projection: ActorPrivateEffectProjection::SetPayload,
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.agent.action_approve",
        cell_family: "ak.private.agent.draft.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::Field("payload.agent_id"),
            ActorPrivateSubjectComponent::Field("payload.draft_id"),
        ]),
        effect_projection: ActorPrivateEffectProjection::Transition {
            from: Some("proposed"),
            to: "approved",
        },
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.agent.action_reject",
        cell_family: "ak.private.agent.draft.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::Field("payload.agent_id"),
            ActorPrivateSubjectComponent::Field("payload.draft_id"),
        ]),
        effect_projection: ActorPrivateEffectProjection::Transition {
            from: Some("proposed"),
            to: "rejected",
        },
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.agent.action_request",
        cell_family: "ak.private.agent.draft.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::Field("payload.agent_id"),
            ActorPrivateSubjectComponent::Field("payload.draft_id"),
        ]),
        effect_projection: ActorPrivateEffectProjection::Transition {
            from: None,
            to: "proposed",
        },
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.agent.draft.propose",
        cell_family: "ak.private.agent.draft.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::Field("payload.agent_id"),
            ActorPrivateSubjectComponent::Field("payload.draft_id"),
        ]),
        effect_projection: ActorPrivateEffectProjection::Transition {
            from: None,
            to: "proposed",
        },
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.device.push_route",
        cell_family: "ak.private.device.push_route.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::CanonicalJson("payload.account_id"),
            ActorPrivateSubjectComponent::Field("payload.device_id"),
            ActorPrivateSubjectComponent::Field("payload.push_route"),
        ]),
        effect_projection: ActorPrivateEffectProjection::SetPayload,
    },
    GeneratedActorPrivateWrite {
        event_kind: "ak.read_cursor.advance",
        cell_family: "ak.private.read_cursor.v1",
        cell_subject: ActorPrivateSubjectRule::Composite(&[
            ActorPrivateSubjectComponent::CanonicalJson("envelope.actor_id"),
            ActorPrivateSubjectComponent::Field("payload.realm_id"),
            ActorPrivateSubjectComponent::Field("payload.read_scope"),
        ]),
        effect_projection: ActorPrivateEffectProjection::MergePayload,
    },
];

pub(crate) const GENERATED_FSM_CONTRACTS: &[GeneratedFsmContract] = &[
    GeneratedFsmContract {
        cell_family: CellFamilyId::AGENT_STATUS_V1,
        axis: "status",
        states: &["uninitialized", "active", "paused", "deactivated"],
        terminal_states: &["deactivated"],
        initial_states: &["uninitialized"],
        allowed_transitions: &[
            ("uninitialized", "active"),
            ("active", "paused"),
            ("paused", "active"),
            ("active", "deactivated"),
            ("paused", "deactivated"),
        ],
        runtime_initial_state: GeneratedState::String("uninitialized"),
        runtime_transitions: &[
            (
                GeneratedState::String("uninitialized"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("paused"),
            ),
            (
                GeneratedState::String("paused"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("deactivated"),
            ),
            (
                GeneratedState::String("paused"),
                GeneratedState::String("deactivated"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::AUDIT_BINDING_STATE_V1,
        axis: "audit",
        states: &["active", "suspended", "revoked"],
        terminal_states: &["revoked"],
        initial_states: &["active"],
        allowed_transitions: &[
            ("active", "suspended"),
            ("active", "revoked"),
            ("suspended", "active"),
            ("suspended", "revoked"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("active")),
            (
                GeneratedState::String("active"),
                GeneratedState::String("suspended"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("revoked"),
            ),
            (
                GeneratedState::String("suspended"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("suspended"),
                GeneratedState::String("revoked"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::AUDIT_SESSION_V1,
        axis: "audit",
        states: &["request", "authorize", "notice", "close"],
        terminal_states: &["close"],
        initial_states: &["request"],
        allowed_transitions: &[
            ("request", "authorize"),
            ("authorize", "notice"),
            ("request", "close"),
            ("authorize", "close"),
            ("notice", "close"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("request")),
            (
                GeneratedState::String("request"),
                GeneratedState::String("authorize"),
            ),
            (
                GeneratedState::String("authorize"),
                GeneratedState::String("notice"),
            ),
            (
                GeneratedState::String("request"),
                GeneratedState::String("close"),
            ),
            (
                GeneratedState::String("authorize"),
                GeneratedState::String("close"),
            ),
            (
                GeneratedState::String("notice"),
                GeneratedState::String("close"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::CALL_RECORDING_V1,
        axis: "workflow",
        states: &["recording", "stopped", "ready", "failed"],
        terminal_states: &["ready", "failed"],
        initial_states: &["recording"],
        allowed_transitions: &[
            ("recording", "stopped"),
            ("recording", "ready"),
            ("recording", "failed"),
            ("stopped", "ready"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("recording")),
            (
                GeneratedState::String("recording"),
                GeneratedState::String("stopped"),
            ),
            (
                GeneratedState::String("recording"),
                GeneratedState::String("ready"),
            ),
            (
                GeneratedState::String("recording"),
                GeneratedState::String("failed"),
            ),
            (
                GeneratedState::String("stopped"),
                GeneratedState::String("ready"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::CALL_STATE_V1,
        axis: "workflow",
        states: &[
            "scheduled",
            "ringing",
            "connecting",
            "active",
            "ended",
            "missed",
            "failed",
            "cancelled",
        ],
        terminal_states: &["ended", "missed", "failed", "cancelled"],
        initial_states: &["scheduled", "ringing", "connecting"],
        allowed_transitions: &[
            ("scheduled", "ringing"),
            ("scheduled", "connecting"),
            ("scheduled", "cancelled"),
            ("scheduled", "missed"),
            ("scheduled", "failed"),
            ("ringing", "connecting"),
            ("ringing", "active"),
            ("ringing", "missed"),
            ("ringing", "cancelled"),
            ("ringing", "failed"),
            ("connecting", "active"),
            ("connecting", "failed"),
            ("connecting", "ended"),
            ("active", "ended"),
            ("active", "failed"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("scheduled")),
            (GeneratedState::Null, GeneratedState::String("ringing")),
            (GeneratedState::Null, GeneratedState::String("connecting")),
            (
                GeneratedState::String("scheduled"),
                GeneratedState::String("ringing"),
            ),
            (
                GeneratedState::String("scheduled"),
                GeneratedState::String("connecting"),
            ),
            (
                GeneratedState::String("scheduled"),
                GeneratedState::String("cancelled"),
            ),
            (
                GeneratedState::String("scheduled"),
                GeneratedState::String("missed"),
            ),
            (
                GeneratedState::String("scheduled"),
                GeneratedState::String("failed"),
            ),
            (
                GeneratedState::String("ringing"),
                GeneratedState::String("connecting"),
            ),
            (
                GeneratedState::String("ringing"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("ringing"),
                GeneratedState::String("missed"),
            ),
            (
                GeneratedState::String("ringing"),
                GeneratedState::String("cancelled"),
            ),
            (
                GeneratedState::String("ringing"),
                GeneratedState::String("failed"),
            ),
            (
                GeneratedState::String("connecting"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("connecting"),
                GeneratedState::String("failed"),
            ),
            (
                GeneratedState::String("connecting"),
                GeneratedState::String("ended"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("ended"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("failed"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::CALL_TRANSCRIPT_V1,
        axis: "workflow",
        states: &["transcribing", "stopped", "ready", "failed"],
        terminal_states: &["ready", "failed"],
        initial_states: &["transcribing"],
        allowed_transitions: &[
            ("transcribing", "stopped"),
            ("transcribing", "ready"),
            ("transcribing", "failed"),
            ("stopped", "ready"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("transcribing")),
            (
                GeneratedState::String("transcribing"),
                GeneratedState::String("stopped"),
            ),
            (
                GeneratedState::String("transcribing"),
                GeneratedState::String("ready"),
            ),
            (
                GeneratedState::String("transcribing"),
                GeneratedState::String("failed"),
            ),
            (
                GeneratedState::String("stopped"),
                GeneratedState::String("ready"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::CIRCLE_HISTORY_ACCESS_V1,
        axis: "history_access",
        states: &["since_join", "all_history_for_current_members"],
        terminal_states: &["since_join"],
        initial_states: &["since_join", "all_history_for_current_members"],
        allowed_transitions: &[("all_history_for_current_members", "since_join")],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (
                GeneratedState::Null,
                GeneratedState::String("all_history_for_current_members"),
            ),
            (GeneratedState::Null, GeneratedState::String("since_join")),
            (
                GeneratedState::String("all_history_for_current_members"),
                GeneratedState::String("since_join"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::CIRCLE_LIFECYCLE_V1,
        axis: "object_lifecycle",
        states: &["active", "archived"],
        terminal_states: &[],
        initial_states: &["active"],
        allowed_transitions: &[("active", "archived"), ("archived", "active")],
        runtime_initial_state: GeneratedState::String("active"),
        runtime_transitions: &[
            (
                GeneratedState::String("active"),
                GeneratedState::String("archived"),
            ),
            (
                GeneratedState::String("archived"),
                GeneratedState::String("active"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::CIRCLE_MEMBER_V1,
        axis: "membership",
        states: &["join", "knock", "leave", "ban"],
        terminal_states: &[],
        initial_states: &["leave"],
        allowed_transitions: &[
            ("leave", "knock"),
            ("leave", "join"),
            ("knock", "join"),
            ("knock", "leave"),
            ("join", "leave"),
            ("leave", "ban"),
            ("knock", "ban"),
            ("join", "ban"),
            ("ban", "leave"),
        ],
        runtime_initial_state: GeneratedState::String("leave"),
        runtime_transitions: &[
            (
                GeneratedState::String("leave"),
                GeneratedState::String("knock"),
            ),
            (
                GeneratedState::String("leave"),
                GeneratedState::String("join"),
            ),
            (
                GeneratedState::String("knock"),
                GeneratedState::String("join"),
            ),
            (
                GeneratedState::String("knock"),
                GeneratedState::String("leave"),
            ),
            (
                GeneratedState::String("join"),
                GeneratedState::String("leave"),
            ),
            (
                GeneratedState::String("leave"),
                GeneratedState::String("ban"),
            ),
            (
                GeneratedState::String("knock"),
                GeneratedState::String("ban"),
            ),
            (
                GeneratedState::String("join"),
                GeneratedState::String("ban"),
            ),
            (
                GeneratedState::String("ban"),
                GeneratedState::String("leave"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::INVITE_LIFECYCLE_V1,
        axis: "workflow",
        states: &[
            "pending",
            "accepted",
            "rejected",
            "revoked",
            "expired",
            "claimed",
            "send_failed",
            "revoked_by_capability_loss",
            "revoked_by_inviter_left",
            "invalidated_by_rate_limit",
        ],
        terminal_states: &[
            "accepted",
            "rejected",
            "revoked",
            "expired",
            "revoked_by_capability_loss",
            "revoked_by_inviter_left",
            "invalidated_by_rate_limit",
        ],
        initial_states: &["pending"],
        allowed_transitions: &[
            ("pending", "accepted"),
            ("pending", "rejected"),
            ("pending", "revoked"),
            ("pending", "expired"),
            ("pending", "claimed"),
            ("pending", "send_failed"),
            ("pending", "revoked_by_capability_loss"),
            ("pending", "revoked_by_inviter_left"),
            ("pending", "invalidated_by_rate_limit"),
            ("claimed", "accepted"),
            ("claimed", "rejected"),
            ("claimed", "revoked"),
            ("claimed", "expired"),
            ("claimed", "revoked_by_capability_loss"),
            ("claimed", "revoked_by_inviter_left"),
            ("claimed", "invalidated_by_rate_limit"),
            ("send_failed", "revoked"),
            ("send_failed", "expired"),
            ("send_failed", "revoked_by_capability_loss"),
            ("send_failed", "revoked_by_inviter_left"),
            ("send_failed", "invalidated_by_rate_limit"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("pending")),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("accepted"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("rejected"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("revoked"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("expired"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("claimed"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("send_failed"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("revoked_by_capability_loss"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("revoked_by_inviter_left"),
            ),
            (
                GeneratedState::String("pending"),
                GeneratedState::String("invalidated_by_rate_limit"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("accepted"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("rejected"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("revoked"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("expired"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("revoked_by_capability_loss"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("revoked_by_inviter_left"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("invalidated_by_rate_limit"),
            ),
            (
                GeneratedState::String("send_failed"),
                GeneratedState::String("revoked"),
            ),
            (
                GeneratedState::String("send_failed"),
                GeneratedState::String("expired"),
            ),
            (
                GeneratedState::String("send_failed"),
                GeneratedState::String("revoked_by_capability_loss"),
            ),
            (
                GeneratedState::String("send_failed"),
                GeneratedState::String("revoked_by_inviter_left"),
            ),
            (
                GeneratedState::String("send_failed"),
                GeneratedState::String("invalidated_by_rate_limit"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::MEMBER_STATE_V1,
        axis: "membership",
        states: &["join", "knock", "leave", "ban"],
        terminal_states: &[],
        initial_states: &["leave"],
        allowed_transitions: &[
            ("leave", "knock"),
            ("leave", "join"),
            ("knock", "join"),
            ("knock", "leave"),
            ("join", "leave"),
            ("leave", "ban"),
            ("knock", "ban"),
            ("join", "ban"),
            ("ban", "leave"),
        ],
        runtime_initial_state: GeneratedState::String("leave"),
        runtime_transitions: &[
            (
                GeneratedState::String("leave"),
                GeneratedState::String("knock"),
            ),
            (
                GeneratedState::String("leave"),
                GeneratedState::String("join"),
            ),
            (
                GeneratedState::String("knock"),
                GeneratedState::String("join"),
            ),
            (
                GeneratedState::String("knock"),
                GeneratedState::String("leave"),
            ),
            (
                GeneratedState::String("join"),
                GeneratedState::String("leave"),
            ),
            (
                GeneratedState::String("leave"),
                GeneratedState::String("ban"),
            ),
            (
                GeneratedState::String("knock"),
                GeneratedState::String("ban"),
            ),
            (
                GeneratedState::String("join"),
                GeneratedState::String("ban"),
            ),
            (
                GeneratedState::String("ban"),
                GeneratedState::String("leave"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::MLS_KEYPACKAGE_V1,
        axis: "key_material",
        states: &["published", "claimed", "consumed", "revoked", "retired"],
        terminal_states: &["consumed", "revoked", "retired"],
        initial_states: &["published"],
        allowed_transitions: &[
            ("published", "claimed"),
            ("published", "revoked"),
            ("published", "retired"),
            ("claimed", "consumed"),
            ("claimed", "revoked"),
        ],
        runtime_initial_state: GeneratedState::String("published"),
        runtime_transitions: &[
            (
                GeneratedState::String("published"),
                GeneratedState::String("claimed"),
            ),
            (
                GeneratedState::String("published"),
                GeneratedState::String("revoked"),
            ),
            (
                GeneratedState::String("published"),
                GeneratedState::String("retired"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("consumed"),
            ),
            (
                GeneratedState::String("claimed"),
                GeneratedState::String("revoked"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::MORPH_LIFECYCLE_V1,
        axis: "object_lifecycle",
        states: &["active", "archived"],
        terminal_states: &[],
        initial_states: &["active"],
        allowed_transitions: &[("active", "archived"), ("archived", "active")],
        runtime_initial_state: GeneratedState::String("active"),
        runtime_transitions: &[
            (
                GeneratedState::String("active"),
                GeneratedState::String("archived"),
            ),
            (
                GeneratedState::String("archived"),
                GeneratedState::String("active"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::REALM_HISTORY_ACCESS_V1,
        axis: "history_access",
        states: &["since_join", "all_history_for_current_members"],
        terminal_states: &["since_join"],
        initial_states: &["since_join", "all_history_for_current_members"],
        allowed_transitions: &[("all_history_for_current_members", "since_join")],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (
                GeneratedState::Null,
                GeneratedState::String("all_history_for_current_members"),
            ),
            (GeneratedState::Null, GeneratedState::String("since_join")),
            (
                GeneratedState::String("all_history_for_current_members"),
                GeneratedState::String("since_join"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::REALM_LINK_V1,
        axis: "relationship",
        states: &["active", "rejected", "tombstoned"],
        terminal_states: &["tombstoned"],
        initial_states: &["active", "rejected", "tombstoned"],
        allowed_transitions: &[
            ("active", "active"),
            ("active", "rejected"),
            ("active", "tombstoned"),
            ("rejected", "rejected"),
            ("rejected", "active"),
            ("rejected", "tombstoned"),
            ("tombstoned", "tombstoned"),
        ],
        runtime_initial_state: GeneratedState::Null,
        runtime_transitions: &[
            (GeneratedState::Null, GeneratedState::String("active")),
            (GeneratedState::Null, GeneratedState::String("rejected")),
            (GeneratedState::Null, GeneratedState::String("tombstoned")),
            (
                GeneratedState::String("active"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("rejected"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("tombstoned"),
            ),
            (
                GeneratedState::String("rejected"),
                GeneratedState::String("rejected"),
            ),
            (
                GeneratedState::String("rejected"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("rejected"),
                GeneratedState::String("tombstoned"),
            ),
            (
                GeneratedState::String("tombstoned"),
                GeneratedState::String("tombstoned"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::RELATION_LIFECYCLE_V1,
        axis: "object_lifecycle",
        states: &["active", "tombstoned"],
        terminal_states: &["tombstoned"],
        initial_states: &["active"],
        allowed_transitions: &[("active", "tombstoned")],
        runtime_initial_state: GeneratedState::String("active"),
        runtime_transitions: &[(
            GeneratedState::String("active"),
            GeneratedState::String("tombstoned"),
        )],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::SPACE_LIFECYCLE_V1,
        axis: "object_lifecycle",
        states: &["active", "archived", "tombstoned"],
        terminal_states: &["tombstoned"],
        initial_states: &["active"],
        allowed_transitions: &[
            ("active", "archived"),
            ("archived", "active"),
            ("active", "tombstoned"),
            ("archived", "tombstoned"),
        ],
        runtime_initial_state: GeneratedState::String("active"),
        runtime_transitions: &[
            (
                GeneratedState::String("active"),
                GeneratedState::String("archived"),
            ),
            (
                GeneratedState::String("archived"),
                GeneratedState::String("active"),
            ),
            (
                GeneratedState::String("active"),
                GeneratedState::String("tombstoned"),
            ),
            (
                GeneratedState::String("archived"),
                GeneratedState::String("tombstoned"),
            ),
        ],
    },
    GeneratedFsmContract {
        cell_family: CellFamilyId::STRAND_LIFECYCLE_V1,
        axis: "object_lifecycle",
        states: &["active", "archived"],
        terminal_states: &[],
        initial_states: &["active"],
        allowed_transitions: &[("active", "archived"), ("archived", "active")],
        runtime_initial_state: GeneratedState::String("active"),
        runtime_transitions: &[
            (
                GeneratedState::String("active"),
                GeneratedState::String("archived"),
            ),
            (
                GeneratedState::String("archived"),
                GeneratedState::String("active"),
            ),
        ],
    },
];
