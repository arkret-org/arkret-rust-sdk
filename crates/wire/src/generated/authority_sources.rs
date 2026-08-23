//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/authority-source-registry.json; version=2026-08-23.7;
//! sha256=8c7965a6d9adf75eaabb9c2b535f9a71a152baa50a1cdfeeb626d6d2a8ba2a27 Entries: registered=4

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum AuthoritySourceId {
    DirectConversationParticipantV1,
    DirectConversationRepairV1,
    MembershipCompensationV1,
    SidecarParentBootstrapV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthoritySourcePhaseDescriptor {
    pub phase: &'static str,
    pub actor_rule: &'static str,
    pub action_allowlist: &'static [&'static str],
    pub activation_checks: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthoritySourceDescriptor {
    pub authority_source_id: AuthoritySourceId,
    pub status: &'static str,
    pub profile: &'static str,
    pub wire_ref: &'static str,
    pub binding_event_kind: &'static str,
    pub binding_ref_role: &'static str,
    pub phases: &'static [AuthoritySourcePhaseDescriptor],
    pub phase_selection: Option<&'static str>,
    pub action_allowlist: &'static [&'static str],
    pub activation_checks: &'static [&'static str],
    pub forbidden_actions: &'static [&'static str],
    pub revocation_model: &'static str,
    pub authority_generation_independent: bool,
    pub grantable: bool,
    pub delegated_event_rule: &'static str,
    pub failure_mode: &'static str,
}

impl AuthoritySourceId {
    pub const ALL: &'static [Self] = &[
        Self::DirectConversationParticipantV1,
        Self::DirectConversationRepairV1,
        Self::MembershipCompensationV1,
        Self::SidecarParentBootstrapV1,
    ];

    pub const DIRECT_CONVERSATION_PARTICIPANT_V1: &'static str =
        "ak.authority.direct_conversation_participant.v1";
    pub const DIRECT_CONVERSATION_REPAIR_V1: &'static str =
        "ak.authority.direct_conversation_repair.v1";
    pub const MEMBERSHIP_COMPENSATION_V1: &'static str = "ak.authority.membership_compensation.v1";
    pub const SIDECAR_PARENT_BOOTSTRAP_V1: &'static str =
        "ak.authority.sidecar_parent_bootstrap.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectConversationParticipantV1 => Self::DIRECT_CONVERSATION_PARTICIPANT_V1,
            Self::DirectConversationRepairV1 => Self::DIRECT_CONVERSATION_REPAIR_V1,
            Self::MembershipCompensationV1 => Self::MEMBERSHIP_COMPENSATION_V1,
            Self::SidecarParentBootstrapV1 => Self::SIDECAR_PARENT_BOOTSTRAP_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::DIRECT_CONVERSATION_PARTICIPANT_V1 => Some(Self::DirectConversationParticipantV1),
            Self::DIRECT_CONVERSATION_REPAIR_V1 => Some(Self::DirectConversationRepairV1),
            Self::MEMBERSHIP_COMPENSATION_V1 => Some(Self::MembershipCompensationV1),
            Self::SIDECAR_PARENT_BOOTSTRAP_V1 => Some(Self::SidecarParentBootstrapV1),
            _ => None,
        }
    }

    pub const fn descriptor(self) -> &'static AuthoritySourceDescriptor {
        &REGISTERED_AUTHORITY_SOURCES[self as usize]
    }
}

impl std::fmt::Display for AuthoritySourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AuthoritySourceId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthoritySourceId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown authority source id: {raw}")))
    }
}

pub const REGISTERED_AUTHORITY_SOURCES: &[AuthoritySourceDescriptor] = &[
    AuthoritySourceDescriptor {
        authority_source_id: AuthoritySourceId::DirectConversationParticipantV1,
        status: "active",
        profile: "ak.profile.direct_conversation_realm.v1",
        wire_ref: "ak.authority.direct_conversation_participant.v1",
        binding_event_kind: "ak.direct_conversation.bound",
        binding_ref_role: "direct_conversation_binding",
        phases: &[],
        phase_selection: None,
        action_allowlist: &[
            "ak.call.join",
            "ak.call.screen_share",
            "ak.call.signal.send",
            "ak.member.leave.own",
            "ak.message.create",
            "ak.message.redact.own",
            "ak.message.revise.own",
            "ak.mls.commit",
            "ak.mls.proposal",
            "ak.mls.welcome.own_device",
            "ak.reaction.add",
            "ak.reaction.remove",
            "ak.read_cursor.advance",
            "ak.receipt.broadcast",
            "ak.strand.create",
            "ak.typing.broadcast",
        ],
        activation_checks: &[
            "realm_profile_and_discriminator_exact",
            "realm_create_critical_extension_present",
            "stable_binding_exact",
            "actor_is_one_of_exactly_two_stable_participants",
            "actor_membership_active_join",
            "realm_main_strand_and_target_scope_exact",
            "unique_scope_derived_group_state_cross_binding_exact",
            "realm_binding_and_target_strand_non_terminal_or_suspended",
            "resource_within_dm_realm_non_circle_discussion_scope",
            "current_signed_directional_contact_heads_gate_for_send_like_actions",
            "action_specific_self_device_mls_and_agent_gates",
        ],
        forbidden_actions: &[],
        revocation_model: "structural_profile_lifecycle",
        authority_generation_independent: true,
        grantable: false,
        delegated_event_rule: "conjunctive_with_executor_delegation",
        failure_mode: "fail_closed_or_dependency_pending",
    },
    AuthoritySourceDescriptor {
        authority_source_id: AuthoritySourceId::DirectConversationRepairV1,
        status: "active",
        profile: "ak.profile.direct_conversation_repair.v1",
        wire_ref: "ak.authority.direct_conversation_repair.v1",
        binding_event_kind: "ak.direct_conversation.bound",
        binding_ref_role: "direct_conversation_binding",
        phases: &[],
        phase_selection: None,
        action_allowlist: &["ak.member.rejoin.own"],
        activation_checks: &[
            "stable_binding_exact",
            "exact_two_participant_mask",
            "missing_member_branch_closed",
            "current_signed_directional_contact_heads_authorize_exact_pair",
            "current_human_or_owned_agent_authoring_proof",
            "new_realm_group_history_isolated",
        ],
        forbidden_actions: &[],
        revocation_model: "current_profile_predicates",
        authority_generation_independent: true,
        grantable: false,
        delegated_event_rule: "human_self_or_owned_agent_controller_closed_xor",
        failure_mode: "fail_closed_or_dependency_pending",
    },
    AuthoritySourceDescriptor {
        authority_source_id: AuthoritySourceId::MembershipCompensationV1,
        status: "active",
        profile: "ak.profile.membership_join_compensation.v1",
        wire_ref: "ak.authority.membership_compensation.v1",
        binding_event_kind: "ak.member.state",
        binding_ref_role: "membership_compensation_delegation",
        phases: &[],
        phase_selection: None,
        action_allowlist: &["ak.member.compensate.leave", "ak.member.compensate.remove"],
        activation_checks: &[
            "delegation_core_digest_exact",
            "actual_join_authoring_signer_exact",
            "admission_and_membership_incarnation_exact",
            "executor_did_and_proof_key_exact",
            "action_branch_closed",
            "destination_single_use_cas",
            "current_positive_provenance_is_original_j1_or_signed_no_write",
        ],
        forbidden_actions: &[],
        revocation_model: "accepted_at_single_use_until_signed_terminal_outcome",
        authority_generation_independent: true,
        grantable: false,
        delegated_event_rule: "fixed_join_actor_executed_by_registered_executor",
        failure_mode: "fail_closed_or_signed_no_write",
    },
    AuthoritySourceDescriptor {
        authority_source_id: AuthoritySourceId::SidecarParentBootstrapV1,
        status: "active",
        profile: "ak.profile.agent_sidecar.v1",
        wire_ref: "ak.authority.sidecar_parent_bootstrap.v1",
        binding_event_kind: "ak.sidecar.create",
        binding_ref_role: "sidecar_parent_realm",
        phases: &[],
        phase_selection: None,
        action_allowlist: &["ak.self.agent.sidecar.command.ensure"],
        activation_checks: &[
            "controller_current_and_exact",
            "parent_realm_current",
            "sidecar_create_minimal",
            "first_ensure_exact_create_then_context_attach",
            "native_sidecar_scope_reserved",
        ],
        forbidden_actions: &[],
        revocation_model: "one_shot_parent_realm_scoped_bootstrap",
        authority_generation_independent: false,
        grantable: false,
        delegated_event_rule: "none",
        failure_mode: "atomic_rollback",
    },
];
