//! Native Personal Agent Realm-membership cascade wire contracts.
//!
//! Canonical Agent membership transitions remain caller-signed Events.  The
//! registered cascade carrier only supplies the exact-set/atomic transaction
//! boundary; it never authorizes a service or reducer to synthesize an Event.

use std::collections::BTreeSet;

use arkret_wire::{
    CbaProofBundle, DidCoreId, Event, EventFederationSubmission, EventId, EventInitialSubmission,
    Hash, PrincipalAuthorityKey, RealmId, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event_sync::FederationServiceBindingRef;
use crate::governance::membership_invite::{MembershipPayload, MembershipPayloadState};

pub const MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS: usize = 256;
pub const MAX_AGENT_MEMBERSHIP_CASCADE_CBA_BUNDLES: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentMembershipCascadeUnitKind {
    #[default]
    AgentMembershipCascade,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipLifecycleCause {
    ControllerMembershipEnded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentControllerMembershipBinding {
    pub controller_authority: PrincipalAuthorityKey,
    pub controller_membership_generation_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_terminal_event_ref: Option<EventId>,
}

impl AgentControllerMembershipBinding {
    pub fn validate(&self) -> Result<()> {
        self.controller_authority.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentCleanupStatusView {
    Pending,
    Completed,
    Overdue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentMembershipCascadeSchema {
    #[serde(rename = "ak.schema.agent_membership_cascade.v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentCleanupRecord {
    pub schema: AgentMembershipCascadeSchema,
    pub realm_id: RealmId,
    pub controller_authority: PrincipalAuthorityKey,
    pub controller_membership_generation_ref: EventId,
    pub initiator_authority: PrincipalAuthorityKey,
    pub controller_terminal_event_id: EventId,
    pub controller_terminal_event_digest: Hash,
    pub expected_agent_ids: Vec<DidCoreId>,
    pub cleanup_intent_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub cleanup_due_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_wire::serde_helpers::optional_canonical_timestamp"
    )]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_transition_event_ids: Option<Vec<EventId>>,
}

impl AgentCleanupRecord {
    pub fn cleanup_status(&self, now: DateTime<Utc>) -> AgentCleanupStatusView {
        if self.completed_at.is_some() {
            AgentCleanupStatusView::Completed
        } else if self.cleanup_due_at <= now {
            AgentCleanupStatusView::Overdue
        } else {
            AgentCleanupStatusView::Pending
        }
    }

    pub fn expected_cleanup_intent_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct CleanupIntentPreimage<'a> {
            schema: AgentMembershipCascadeSchema,
            realm_id: &'a RealmId,
            controller_authority: &'a PrincipalAuthorityKey,
            controller_membership_generation_ref: &'a EventId,
            initiator_authority: &'a PrincipalAuthorityKey,
            controller_terminal_event_id: &'a EventId,
            controller_terminal_event_digest: &'a Hash,
            expected_agent_ids: &'a [DidCoreId],
        }

        Ok(Hash::new(arkret_canonical::canonical_sha256(
            &CleanupIntentPreimage {
                schema: self.schema,
                realm_id: &self.realm_id,
                controller_authority: &self.controller_authority,
                controller_membership_generation_ref: &self.controller_membership_generation_ref,
                initiator_authority: &self.initiator_authority,
                controller_terminal_event_id: &self.controller_terminal_event_id,
                controller_terminal_event_digest: &self.controller_terminal_event_digest,
                expected_agent_ids: &self.expected_agent_ids,
            },
        )?)?)
    }

    pub fn validate(&self) -> Result<()> {
        self.controller_authority.validate()?;
        self.initiator_authority.validate()?;
        validate_sorted_unique_agent_ids(&self.expected_agent_ids)?;
        if self.cleanup_due_at <= self.accepted_at {
            return Err(WireError::Protocol(
                "agent cleanup deadline must follow canonical acceptance".to_owned(),
            ));
        }
        if self.cleanup_intent_digest != self.expected_cleanup_intent_digest()? {
            return Err(WireError::Protocol(
                "agent cleanup intent digest does not bind the frozen record".to_owned(),
            ));
        }
        match (
            self.completed_at.as_ref(),
            self.agent_transition_event_ids.as_deref(),
        ) {
            (Some(_), Some(event_ids)) => {
                validate_unique_event_ids(event_ids)?;
                if event_ids.len() != self.expected_agent_ids.len() {
                    return Err(WireError::Protocol(
                        "completed agent cleanup transition count must equal the frozen Agent set"
                            .to_owned(),
                    ));
                }
            }
            (None, None) => {}
            _ => return Err(WireError::Protocol(
                "agent cleanup completion timestamp and transition Event ids must appear together"
                    .to_owned(),
            )),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentMembershipCascadeMode {
    AtomicSelfLeave,
    EmergencyTerminal,
    EmergencyCleanup,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentMembershipCascadeSubmission {
    pub unit_kind: AgentMembershipCascadeUnitKind,
    pub cascade_mode: AgentMembershipCascadeMode,
    pub controller_transition: EventInitialSubmission,
    pub agent_transitions: Vec<EventInitialSubmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_intent_digest: Option<Hash>,
}

impl AgentMembershipCascadeSubmission {
    pub fn validate(&self) -> Result<()> {
        validate_cascade(
            self.cascade_mode,
            &self.controller_transition.event,
            self.agent_transitions
                .iter()
                .map(|submission| &submission.event),
            self.cleanup_intent_digest.as_ref(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentMembershipCascadeFederationSubmission {
    pub unit_kind: AgentMembershipCascadeUnitKind,
    pub cascade_mode: AgentMembershipCascadeMode,
    pub service_binding_ref: FederationServiceBindingRef,
    pub controller_transition: EventFederationSubmission,
    pub agent_transitions: Vec<EventFederationSubmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_intent_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
}

impl AgentMembershipCascadeFederationSubmission {
    pub fn validate(&self) -> Result<()> {
        if self.cba_proof_bundles.len() > MAX_AGENT_MEMBERSHIP_CASCADE_CBA_BUNDLES {
            return Err(WireError::Protocol(
                "agent membership cascade exceeds 64 CBA proof bundles".to_owned(),
            ));
        }
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        if self.controller_transition.event.realm_id != self.service_binding_ref.realm_id
            || self
                .agent_transitions
                .iter()
                .any(|submission| submission.event.realm_id != self.service_binding_ref.realm_id)
        {
            return Err(WireError::Protocol(
                "federated agent membership cascade must bind one Realm".to_owned(),
            ));
        }
        validate_cascade(
            self.cascade_mode,
            &self.controller_transition.event,
            self.agent_transitions
                .iter()
                .map(|submission| &submission.event),
            self.cleanup_intent_digest.as_ref(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentMembershipCascadeOutcomeStatus {
    CleanupCompleted,
    TerminalAppliedCleanupPending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentMembershipCascadeOutcome {
    pub status: AgentMembershipCascadeOutcomeStatus,
    pub controller_transition_event_id: EventId,
    pub agent_transition_event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_intent_digest: Option<Hash>,
}

impl AgentMembershipCascadeOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_unique_event_ids(&self.agent_transition_event_ids)?;
        match self.status {
            AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending => {
                if !self.agent_transition_event_ids.is_empty()
                    || self.cleanup_intent_digest.is_none()
                {
                    return Err(WireError::Protocol(
                        "terminal-applied cleanup-pending outcome requires an intent digest and no Agent Event ids"
                            .to_owned(),
                    ));
                }
            }
            AgentMembershipCascadeOutcomeStatus::CleanupCompleted => {
                if self.agent_transition_event_ids.is_empty()
                    || self.cleanup_intent_digest.is_some()
                {
                    return Err(WireError::Protocol(
                        "completed agent cleanup requires Agent Event ids and forbids an intent digest"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_cascade<'a>(
    mode: AgentMembershipCascadeMode,
    controller: &Event,
    agents: impl IntoIterator<Item = &'a Event>,
    cleanup_intent_digest: Option<&Hash>,
) -> Result<()> {
    if controller.kind.as_str() != arkret_wire::event_kind_str::MEMBER_STATE {
        return Err(WireError::Protocol(
            "agent membership cascade controller transition must be ak.member.state".to_owned(),
        ));
    }
    let controller_payload = decode_membership_payload(controller)?;
    if controller_payload.actor_id.as_ref() != Some(&controller.actor_id) {
        return Err(WireError::Protocol(
            "agent membership cascade controller payload actor mismatch".to_owned(),
        ));
    }
    if !matches!(
        controller_payload.membership,
        MembershipPayloadState::Leave | MembershipPayloadState::Ban
    ) {
        return Err(WireError::Protocol(
            "agent membership cascade controller transition must be terminal".to_owned(),
        ));
    }
    let initiator = controller
        .executed_by
        .as_ref()
        .unwrap_or(&controller.actor_id);
    match mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            if initiator != &controller.actor_id
                || controller_payload.membership != MembershipPayloadState::Leave
                || cleanup_intent_digest.is_some()
            {
                return Err(WireError::Protocol(
                    "atomic self leave requires a self-authored leave and forbids cleanup_intent_digest"
                        .to_owned(),
                ));
            }
        }
        AgentMembershipCascadeMode::EmergencyTerminal
        | AgentMembershipCascadeMode::EmergencyCleanup => {
            if initiator == &controller.actor_id {
                return Err(WireError::Protocol(
                    "emergency agent membership cascade requires a third-party initiator"
                        .to_owned(),
                ));
            }
        }
    }

    let agents = agents.into_iter().collect::<Vec<_>>();
    if agents.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS {
        return Err(WireError::Protocol(
            "agent membership cascade exceeds 256 Agent transitions".to_owned(),
        ));
    }
    match mode {
        AgentMembershipCascadeMode::EmergencyTerminal => {
            if !agents.is_empty() || cleanup_intent_digest.is_some() {
                return Err(WireError::Protocol(
                    "emergency terminal requires an empty Agent set and forbids cleanup_intent_digest"
                        .to_owned(),
                ));
            }
        }
        AgentMembershipCascadeMode::EmergencyCleanup => {
            if agents.is_empty() || cleanup_intent_digest.is_none() {
                return Err(WireError::Protocol(
                    "emergency cleanup requires Agent transitions and cleanup_intent_digest"
                        .to_owned(),
                ));
            }
        }
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            if agents.is_empty() {
                return Err(WireError::Protocol(
                    "atomic self leave requires the non-empty frozen Agent set".to_owned(),
                ));
            }
        }
    }

    let controller_authority = PrincipalAuthorityKey {
        principal_id: controller.actor_id.clone(),
        principal_server_id: controller.principal_server_id.clone(),
    };
    let mut controller_generation = None;
    let mut event_ids = BTreeSet::new();
    let mut actor_ids = BTreeSet::new();
    for agent in agents {
        if !event_ids.insert(agent.event_id.clone()) || !actor_ids.insert(agent.actor_id.clone()) {
            return Err(WireError::Protocol(
                "agent membership cascade contains a duplicate Agent transition".to_owned(),
            ));
        }
        if agent.kind.as_str() != arkret_wire::event_kind_str::MEMBER_STATE
            || agent.realm_id != controller.realm_id
            || agent.actor_id == controller.actor_id
            || agent.executed_by.as_ref() != Some(initiator)
            || agent.principal_server_id != controller.principal_server_id
        {
            return Err(WireError::Protocol(
                "agent membership cascade Event authority or Realm binding mismatch".to_owned(),
            ));
        }
        let payload = decode_membership_payload(agent)?;
        let binding = payload.agent_controller_binding.as_ref().ok_or_else(|| {
            WireError::Protocol("agent cleanup membership is missing controller binding".to_owned())
        })?;
        if payload.membership != MembershipPayloadState::Leave
            || payload.membership_cause != Some(MembershipLifecycleCause::ControllerMembershipEnded)
            || payload.actor_id.as_ref() != Some(&agent.actor_id)
            || binding.controller_terminal_event_ref.as_ref() != Some(&controller.event_id)
        {
            return Err(WireError::Protocol(
                "agent cleanup membership payload does not bind the terminal controller Event"
                    .to_owned(),
            ));
        }
        binding.validate()?;
        if binding.controller_authority != controller_authority {
            return Err(WireError::Protocol(
                "agent cleanup membership controller authority mismatch".to_owned(),
            ));
        }
        match &controller_generation {
            Some(generation) if generation != &binding.controller_membership_generation_ref => {
                return Err(WireError::Protocol(
                    "agent cleanup membership controller generation mismatch".to_owned(),
                ));
            }
            None => {
                controller_generation = Some(binding.controller_membership_generation_ref.clone());
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn decode_membership_payload(event: &Event) -> Result<MembershipPayload> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
        WireError::Protocol(format!("membership payload conversion failed: {error}"))
    })?)
    .map_err(|error| WireError::Protocol(format!("membership payload decode failed: {error}")))
}

fn validate_sorted_unique_agent_ids(agent_ids: &[DidCoreId]) -> Result<()> {
    if agent_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS
        || agent_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(WireError::Protocol(
            "expected Agent ids must be strictly sorted, unique and bounded to 256".to_owned(),
        ));
    }
    Ok(())
}

fn validate_unique_event_ids(event_ids: &[EventId]) -> Result<()> {
    if event_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS
        || event_ids.iter().collect::<BTreeSet<_>>().len() != event_ids.len()
    {
        return Err(WireError::Protocol(
            "Agent transition Event ids must be unique and bounded to 256".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::membership_invite::MembershipPayload;

    fn event_id(seed: char) -> EventId {
        EventId::new(format!("ak:event:A{}", seed.to_string().repeat(43))).unwrap()
    }

    fn hash(seed: char) -> Hash {
        Hash::new(format!("sha256:{}", seed.to_string().repeat(64))).unwrap()
    }

    fn authority(principal: &str, server: &str) -> PrincipalAuthorityKey {
        PrincipalAuthorityKey {
            principal_id: DidCoreId::new(principal).unwrap(),
            principal_server_id: DidCoreId::new(server).unwrap(),
        }
    }

    #[test]
    fn membership_cause_requires_leave_and_terminal_binding() {
        let binding = AgentControllerMembershipBinding {
            controller_authority: authority(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:principal.example",
            ),
            controller_membership_generation_ref: event_id('a'),
            controller_terminal_event_ref: Some(event_id('b')),
        };
        MembershipPayload::transition(
            MembershipPayloadState::Leave,
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            "controller membership ended",
        )
        .with_controller_membership_ended(binding.clone())
        .to_value()
        .unwrap();
        assert!(
            MembershipPayload::transition(
                MembershipPayloadState::Ban,
                DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                "controller membership ended",
            )
            .with_controller_membership_ended(binding)
            .to_value()
            .is_err()
        );
    }

    #[test]
    fn cleanup_record_enforces_frozen_set_and_completion_shape() {
        let accepted_at = DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut record = AgentCleanupRecord {
            schema: AgentMembershipCascadeSchema::V1,
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            controller_authority: authority(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:principal.example",
            ),
            controller_membership_generation_ref: event_id('a'),
            initiator_authority: authority(
                "ak:did_core:web:bob.example",
                "ak:did_core:web:principal.example",
            ),
            controller_terminal_event_id: event_id('b'),
            controller_terminal_event_digest: hash('1'),
            expected_agent_ids: vec![
                DidCoreId::new("ak:did_core:web:agent-a.example").unwrap(),
                DidCoreId::new("ak:did_core:web:agent-b.example").unwrap(),
            ],
            cleanup_intent_digest: hash('2'),
            accepted_at,
            cleanup_due_at: accepted_at + chrono::Duration::hours(1),
            completed_at: None,
            agent_transition_event_ids: None,
        };
        record.cleanup_intent_digest = record.expected_cleanup_intent_digest().unwrap();
        record.validate().unwrap();
        assert_eq!(
            record.cleanup_status(accepted_at + chrono::Duration::minutes(30)),
            AgentCleanupStatusView::Pending
        );
        assert_eq!(
            record.cleanup_status(accepted_at + chrono::Duration::hours(2)),
            AgentCleanupStatusView::Overdue
        );
        record.completed_at = Some(accepted_at + chrono::Duration::minutes(1));
        assert!(record.validate().is_err());
        record.agent_transition_event_ids = Some(vec![event_id('c'), event_id('d')]);
        record.validate().unwrap();
        assert_eq!(
            record.cleanup_status(accepted_at + chrono::Duration::hours(2)),
            AgentCleanupStatusView::Completed
        );
    }

    #[test]
    fn cascade_outcome_distinguishes_pending_from_completed() {
        let mut outcome = AgentMembershipCascadeOutcome {
            status: AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending,
            controller_transition_event_id: event_id('a'),
            agent_transition_event_ids: Vec::new(),
            cleanup_intent_digest: Some(hash('1')),
        };
        outcome.validate().unwrap();
        outcome.status = AgentMembershipCascadeOutcomeStatus::CleanupCompleted;
        assert!(outcome.validate().is_err());
        outcome.cleanup_intent_digest = None;
        outcome.agent_transition_event_ids = vec![event_id('b')];
        outcome.validate().unwrap();
    }
}
