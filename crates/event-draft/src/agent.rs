//! Agent Event materialization.

use arkret_models_collaboration::events_payloads::agent::{
    AgentDeactivatePayload, AgentKeyAuthorizePayload, AgentKeyRevokePayload, AgentPausePayload,
    AgentResumePayload,
};
use arkret_wire::{ActorId, DidUrl, ScopeRef, event_spec};
use chrono::{DateTime, Utc};

use crate::{EventIntent, EventSpec, Result, TypedEventDraft};

/// Local authoring state used to choose the legal source of a lifecycle
/// transition. It is not a shared Event payload or a replicated state record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentLifecycleState {
    Active,
    Paused,
    Deactivated,
}

/// Draft a controller-executed `ak.agent.key.authorize`. The current Station
/// assigns authority-stream position only after the producer Event is signed.
pub fn build_agent_key_authorize_intent(
    payload: &AgentKeyAuthorizePayload,
    scope_ref: ScopeRef,
    agent_actor_id: ActorId,
    controller_actor_id: ActorId,
    controller_authorization_ref: DidUrl,
    created_at: DateTime<Utc>,
) -> Result<EventIntent> {
    TypedEventDraft::<event_spec::AgentKeyAuthorize>::new(
        scope_ref,
        agent_actor_id,
        payload.clone(),
    )?
    .with_executed_by(controller_actor_id)
    .with_authorization_ref(controller_authorization_ref.into())
    .into_intent(created_at)
}

pub fn build_agent_key_revoke_intent(
    payload: &AgentKeyRevokePayload,
    scope_ref: ScopeRef,
    agent_actor_id: ActorId,
    controller_actor_id: ActorId,
    controller_authorization_ref: DidUrl,
    created_at: DateTime<Utc>,
) -> Result<EventIntent> {
    TypedEventDraft::<event_spec::AgentKeyRevoke>::new(scope_ref, agent_actor_id, payload.clone())?
        .with_executed_by(controller_actor_id)
        .with_authorization_ref(controller_authorization_ref.into())
        .into_intent(created_at)
}

struct AgentLifecycleEventInput<P> {
    payload: P,
    agent_actor_id: ActorId,
    controller_actor_id: ActorId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    status_changed_at: DateTime<Utc>,
}

fn build_agent_lifecycle_intent<K: EventSpec>(
    input: AgentLifecycleEventInput<K::Payload>,
) -> Result<EventIntent> {
    if input.agent_actor_id.as_account_id().is_none() {
        return Err(crate::EventDraftError::Protocol(
            "Agent lifecycle Events require a complete Account ActorId".to_owned(),
        ));
    }
    TypedEventDraft::<K>::new(
        input.principal_control_scope_ref,
        input.agent_actor_id,
        input.payload,
    )?
    .with_executed_by(input.controller_actor_id)
    .with_authorization_ref(input.controller_authorization_ref.into())
    .into_intent(input.status_changed_at)
}

pub fn build_agent_pause_intent(
    agent_actor_id: ActorId,
    controller_actor_id: ActorId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    reason: Option<arkret_wire::AuditReasonText>,
    status_changed_at: DateTime<Utc>,
) -> Result<EventIntent> {
    let payload = AgentPausePayload {
        transition: "pause".to_owned(),
        previous_status: "active".to_owned(),
        status_changed_at,
        reason,
    };
    build_agent_lifecycle_intent::<event_spec::SelfAgentPause>(AgentLifecycleEventInput {
        payload,
        agent_actor_id,
        controller_actor_id,
        principal_control_scope_ref,
        controller_authorization_ref,
        status_changed_at,
    })
}

pub fn build_agent_resume_intent(
    agent_actor_id: ActorId,
    controller_actor_id: ActorId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    status_changed_at: DateTime<Utc>,
) -> Result<EventIntent> {
    let payload = AgentResumePayload {
        transition: "resume".to_owned(),
        previous_status: "paused".to_owned(),
        status_changed_at,
        reason: None,
    };
    build_agent_lifecycle_intent::<event_spec::SelfAgentResume>(AgentLifecycleEventInput {
        payload,
        agent_actor_id,
        controller_actor_id,
        principal_control_scope_ref,
        controller_authorization_ref,
        status_changed_at,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_agent_deactivate_intent(
    agent_actor_id: ActorId,
    controller_actor_id: ActorId,
    principal_control_scope_ref: ScopeRef,
    controller_authorization_ref: DidUrl,
    previous_status: AgentLifecycleState,
    reason: Option<arkret_wire::AuditReasonText>,
    status_changed_at: DateTime<Utc>,
) -> Result<EventIntent> {
    let previous_status = match previous_status {
        AgentLifecycleState::Active => "active",
        AgentLifecycleState::Paused => "paused",
        AgentLifecycleState::Deactivated => {
            return Err(crate::EventDraftError::Protocol(
                "cannot author an Agent deactivation from terminal deactivated state".to_owned(),
            ));
        }
    };
    let payload = AgentDeactivatePayload {
        transition: "deactivate".to_owned(),
        previous_status: previous_status.to_owned(),
        status_changed_at,
        reason,
    };
    build_agent_lifecycle_intent::<event_spec::SelfAgentDeactivate>(AgentLifecycleEventInput {
        payload,
        agent_actor_id,
        controller_actor_id,
        principal_control_scope_ref,
        controller_authorization_ref,
        status_changed_at,
    })
}
