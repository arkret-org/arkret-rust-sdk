//! Agent Realm-membership cascade wire contracts.
//!
//! Canonical Agent membership transitions stay caller-signed Events. The
//! registered cascade unit only supplies the exact-set and atomic transaction
//! boundary; it never authorizes a service or a reducer to synthesize an Event
//! on an Agent's behalf (`zh/models/actor.md`, `zh/identity/account-lifecycle.md`).
//!
//! Effective Agent membership is the AND of the Agent member typed current
//! result, the exact controller membership generation, Agent lifecycle, and
//! provision/accountability validity. A controller rejoin mints a new join
//! Event id and can never revive an earlier binding.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, Event, EventAdmissionSubmission, EventId, Hash, RealmId, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::membership_invite::{MembershipPayload, MembershipPayloadState};

/// `agent-membership-cascade.schema.json#/$defs/agent_cleanup_record`
/// bounds both `expected_agent_ids` and `agent_transition_event_ids` at 256.
pub const MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentMembershipCascadeUnitKind {
    #[default]
    AgentMembershipCascade,
}

/// Closed audit-only lifecycle cause.
///
/// It classifies a transition for auditors and never supplies authorization or
/// proves reducer provenance: security provenance comes from the terminal
/// Event, the exact controller binding, the actual signer, the terminal
/// pre-state exact set and the atomic submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipLifecycleCause {
    ControllerMembershipEnded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// Field declaration order is byte-for-byte the `properties` order of
// `agent-membership-cascade.schema.json#/$defs/agent_controller_membership_binding`.
pub struct AgentControllerMembershipBinding {
    pub controller_account_id: AccountId,
    /// Exact controller `ak.member.state` join Event that establishes the bound
    /// membership generation. A later rejoin has another Event id and never
    /// revives this binding.
    pub controller_membership_generation_ref: EventId,
    /// Present only on an explicit controller-membership-ended cleanup Event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_terminal_event_ref: Option<EventId>,
}

impl AgentControllerMembershipBinding {
    pub fn validate(&self) -> Result<()> {
        self.controller_account_id.validate()
    }
}

/// Computed cleanup view. The durable record never stores it: `completed_at`
/// together with the complete `agent_transition_event_ids` means completed,
/// and an incomplete record is overdue only against an observation time.
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
// Field declaration order is byte-for-byte the `properties` order of
// `agent-membership-cascade.schema.json#/$defs/agent_cleanup_record`.
pub struct AgentCleanupRecord {
    pub schema: AgentMembershipCascadeSchema,
    pub realm_id: RealmId,
    pub controller_account_id: AccountId,
    pub controller_membership_generation_ref: EventId,
    pub initiator_actor_id: ActorId,
    pub controller_terminal_event_id: EventId,
    /// Exact set of active controlled Agent ActorIds frozen from the terminal
    /// pre-state, sorted by the unsigned UTF-8 bytes of each RFC 8785 ActorId.
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub expected_agent_ids: Vec<ActorId>,
    pub cleanup_intent_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    /// Governance alert deadline only. Crossing it changes pending to overdue
    /// and never restores controller or Agent authority.
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

    /// sha256 of the RFC 8785 canonical record fields through
    /// `expected_agent_ids`. It is the durable idempotency key for emergency
    /// cleanup: the same intent replays, a different one is rejected.
    pub fn expected_cleanup_intent_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct CleanupIntentPreimage<'a> {
            schema: AgentMembershipCascadeSchema,
            realm_id: &'a RealmId,
            controller_account_id: &'a AccountId,
            controller_membership_generation_ref: &'a EventId,
            initiator_actor_id: &'a ActorId,
            controller_terminal_event_id: &'a EventId,
            expected_agent_ids: &'a [ActorId],
        }

        Ok(Hash::new(arkret_canonical::canonical_sha256(
            &CleanupIntentPreimage {
                schema: self.schema,
                realm_id: &self.realm_id,
                controller_account_id: &self.controller_account_id,
                controller_membership_generation_ref: &self.controller_membership_generation_ref,
                initiator_actor_id: &self.initiator_actor_id,
                controller_terminal_event_id: &self.controller_terminal_event_id,
                expected_agent_ids: &self.expected_agent_ids,
            },
        )?)?)
    }

    pub fn validate(&self) -> Result<()> {
        self.controller_account_id.validate()?;
        self.initiator_actor_id.validate()?;
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
            _ => {
                return Err(WireError::Protocol(
                    "agent cleanup completion timestamp and transition Event ids must appear together"
                        .to_owned(),
                ));
            }
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

/// One registered `agent_membership_cascade` unit.
///
/// Every Event inside it is an ordinary caller-signed shared durable Event
/// submitted to the current governance Station as an [`EventAdmissionSubmission`].
/// The unit adds only the exact-set and all-or-nothing boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentMembershipCascadeSubmission {
    pub unit_kind: AgentMembershipCascadeUnitKind,
    pub cascade_mode: AgentMembershipCascadeMode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub controller_transition: EventAdmissionSubmission,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub agent_transitions: Vec<EventAdmissionSubmission>,
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
    if controller_payload.member_id != controller.actor_id {
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

    let controller_account_id = controller
        .actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| {
            WireError::Protocol("agent membership controller must be an account actor".to_owned())
        })?;
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
            || agent.actor_id.route_service_id() != controller.actor_id.route_service_id()
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
            || payload.member_id != agent.actor_id
            || binding.controller_terminal_event_ref.as_ref() != Some(&controller.event_id)
        {
            return Err(WireError::Protocol(
                "agent cleanup membership payload does not bind the terminal controller Event"
                    .to_owned(),
            ));
        }
        binding.validate()?;
        if binding.controller_account_id != controller_account_id {
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

fn validate_sorted_unique_agent_ids(agent_ids: &[ActorId]) -> Result<()> {
    arkret_wire::validate_identity_entries(agent_ids)?;
    if agent_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS {
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
    use arkret_wire::DidCoreId;
    use serde_json::json;

    use super::*;

    fn event_id(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    fn hash(seed: char) -> Hash {
        Hash::new(format!("sha256:{}", seed.to_string().repeat(64))).unwrap()
    }

    fn account(principal: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&event_id(0x10))
    }

    fn record() -> AgentCleanupRecord {
        let accepted_at = DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut record = AgentCleanupRecord {
            schema: AgentMembershipCascadeSchema::V1,
            realm_id: realm_id(),
            controller_account_id: account("ak:did_core:web:alice.example"),
            controller_membership_generation_ref: event_id(0xa1),
            initiator_actor_id: ActorId::account(account("ak:did_core:web:bob.example")),
            controller_terminal_event_id: event_id(0xb2),
            expected_agent_ids: vec![
                ActorId::account(account("ak:did_core:web:agent-a.example")),
                ActorId::account(account("ak:did_core:web:agent-b.example")),
            ],
            cleanup_intent_digest: hash('2'),
            accepted_at,
            cleanup_due_at: accepted_at + chrono::Duration::hours(1),
            completed_at: None,
            agent_transition_event_ids: None,
        };
        record.cleanup_intent_digest = record.expected_cleanup_intent_digest().unwrap();
        record
    }

    #[test]
    fn cleanup_record_round_trips_through_canonical_json() {
        let record = record();
        record.validate().unwrap();
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            value["schema"],
            json!("ak.schema.agent_membership_cascade.v1")
        );
        assert!(value.get("completed_at").is_none());
        assert!(value.get("agent_transition_event_ids").is_none());
        let decoded: AgentCleanupRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, record);
        decoded.validate().unwrap();
    }

    #[test]
    fn cleanup_record_rejects_a_member_outside_the_closed_field_set() {
        let mut value = serde_json::to_value(record()).unwrap();
        value["cleanup_status"] = json!("pending");
        assert!(serde_json::from_value::<AgentCleanupRecord>(value).is_err());
    }

    #[test]
    fn cleanup_record_rejects_an_omitted_required_member() {
        for member in [
            "schema",
            "realm_id",
            "controller_account_id",
            "controller_membership_generation_ref",
            "initiator_actor_id",
            "controller_terminal_event_id",
            "expected_agent_ids",
            "cleanup_intent_digest",
            "accepted_at",
            "cleanup_due_at",
        ] {
            let mut value = serde_json::to_value(record()).unwrap();
            value.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<AgentCleanupRecord>(value).is_err(),
                "{member} must be required"
            );
        }
    }

    #[test]
    fn cleanup_record_binds_its_frozen_set_through_the_intent_digest() {
        let record = record();
        let mut other_initiator = record.clone();
        other_initiator.initiator_actor_id =
            ActorId::account(account("ak:did_core:web:carol.example"));
        assert!(other_initiator.validate().is_err());
        assert_ne!(
            other_initiator.expected_cleanup_intent_digest().unwrap(),
            record.cleanup_intent_digest
        );
    }

    #[test]
    fn cleanup_status_is_computed_never_stored() {
        let mut record = record();
        assert_eq!(
            record.cleanup_status(record.accepted_at + chrono::Duration::minutes(30)),
            AgentCleanupStatusView::Pending
        );
        assert_eq!(
            record.cleanup_status(record.accepted_at + chrono::Duration::hours(2)),
            AgentCleanupStatusView::Overdue
        );
        record.completed_at = Some(record.accepted_at + chrono::Duration::minutes(1));
        assert!(
            record.validate().is_err(),
            "completion without the transition Event ids is not a completed cleanup"
        );
        record.agent_transition_event_ids = Some(vec![event_id(0xc3), event_id(0xd4)]);
        record.validate().unwrap();
        assert_eq!(
            record.cleanup_status(record.accepted_at + chrono::Duration::hours(2)),
            AgentCleanupStatusView::Completed
        );
    }

    #[test]
    fn completed_cleanup_must_cover_the_whole_frozen_set() {
        let mut record = record();
        record.completed_at = Some(record.accepted_at + chrono::Duration::minutes(1));
        record.agent_transition_event_ids = Some(vec![event_id(0xc3)]);
        assert!(record.validate().is_err());
    }

    #[test]
    fn controller_binding_round_trips_and_rejects_unknown_and_missing_members() {
        let binding = AgentControllerMembershipBinding {
            controller_account_id: account("ak:did_core:web:alice.example"),
            controller_membership_generation_ref: event_id(0xa1),
            controller_terminal_event_ref: Some(event_id(0xb2)),
        };
        binding.validate().unwrap();
        let value = serde_json::to_value(&binding).unwrap();
        assert_eq!(
            serde_json::from_value::<AgentControllerMembershipBinding>(value.clone()).unwrap(),
            binding
        );

        let mut unknown = value.clone();
        unknown["controller_station_id"] = json!("ak:did_core:web:station.example");
        assert!(serde_json::from_value::<AgentControllerMembershipBinding>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("controller_membership_generation_ref");
        assert!(serde_json::from_value::<AgentControllerMembershipBinding>(missing).is_err());
    }

    #[test]
    fn membership_cause_requires_a_leave_bound_to_the_terminal_controller_event() {
        let binding = AgentControllerMembershipBinding {
            controller_account_id: account("ak:did_core:web:alice.example"),
            controller_membership_generation_ref: event_id(0xa1),
            controller_terminal_event_ref: Some(event_id(0xb2)),
        };
        let agent = ActorId::account(account("ak:did_core:web:agent-a.example"));

        let mut leave = MembershipPayload::transition(
            MembershipPayloadState::Leave,
            agent.clone(),
            "controller membership ended",
        );
        leave.membership_cause = Some(MembershipLifecycleCause::ControllerMembershipEnded);
        leave.agent_controller_binding = Some(binding.clone());
        leave.to_value().unwrap();

        let mut ban = MembershipPayload::transition(
            MembershipPayloadState::Ban,
            agent.clone(),
            "controller membership ended",
        );
        ban.membership_cause = Some(MembershipLifecycleCause::ControllerMembershipEnded);
        ban.agent_controller_binding = Some(binding);
        assert!(ban.to_value().is_err());

        let mut unbound = MembershipPayload::transition(
            MembershipPayloadState::Leave,
            agent,
            "controller membership ended",
        );
        unbound.membership_cause = Some(MembershipLifecycleCause::ControllerMembershipEnded);
        assert!(unbound.to_value().is_err());
    }

    #[test]
    fn cascade_outcome_distinguishes_pending_from_completed() {
        let mut outcome = AgentMembershipCascadeOutcome {
            status: AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending,
            controller_transition_event_id: event_id(0xa1),
            agent_transition_event_ids: Vec::new(),
            cleanup_intent_digest: Some(hash('1')),
        };
        outcome.validate().unwrap();
        outcome.status = AgentMembershipCascadeOutcomeStatus::CleanupCompleted;
        assert!(outcome.validate().is_err());
        outcome.cleanup_intent_digest = None;
        outcome.agent_transition_event_ids = vec![event_id(0xb2)];
        outcome.validate().unwrap();

        let mut value = serde_json::to_value(&outcome).unwrap();
        let decoded: AgentMembershipCascadeOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded, outcome);
        value["cleanup_status"] = json!("completed");
        assert!(serde_json::from_value::<AgentMembershipCascadeOutcome>(value).is_err());

        let mut missing = serde_json::to_value(&outcome).unwrap();
        missing.as_object_mut().unwrap().remove("status");
        assert!(serde_json::from_value::<AgentMembershipCascadeOutcome>(missing).is_err());
    }
}
