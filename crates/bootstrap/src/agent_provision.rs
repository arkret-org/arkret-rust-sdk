//! Controller-owned managed-agent provisioning Event authoring.

use arkret_models_collaboration::events_payloads::agent::{
    AgentProvisionAccountabilityScope, AgentProvisionPayload, AgentProvisionSchema,
};
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{
    Did, DidUrl, Event, EventId, EventKind, Hash, Hlc, ProfileRef, RealmId, Result, SchemaId,
    ScopeRef, SealBasis,
};
use chrono::{DateTime, Utc};

/// Envelope stamps supplied before the ordinary submit pipeline signs the
/// single controller-authored provision Event.
#[derive(Clone, Debug)]
pub struct AgentProvisionEventDraftOptions {
    pub created_at: DateTime<Utc>,
    pub actor_seq: u64,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    pub seal_basis: Option<SealBasis>,
}

/// Build the single closed `ak.agent.provision` Event draft registered by v1.
///
/// The payload carries no nested proof. Callers must attach the controller's
/// ordinary Event proof and publication evidence through the standard submit
/// pipeline.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_provision_event_draft(
    controller_id: &Did,
    controller_realm_id: &RealmId,
    agent_id: &Did,
    principal_control_realm_id: &RealmId,
    controller_authorization_ref: &DidUrl,
    agent_slug: &str,
    requested_scope_digest: &Hash,
    selector_visibility: HandleVisibility,
    selector_audience: Option<String>,
    options: AgentProvisionEventDraftOptions,
) -> Result<Event> {
    let created_at = arkret_canonical::normalize_timestamp_canonical(options.created_at);
    let payload = AgentProvisionPayload {
        schema: AgentProvisionSchema::V1,
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        principal_control_realm_id: principal_control_realm_id.clone(),
        controller_authorization_ref: controller_authorization_ref.clone(),
        agent_slug: agent_slug.to_owned(),
        accountability_scope: AgentProvisionAccountabilityScope::AgentOperator,
        requested_scope_digest: requested_scope_digest.clone(),
        selector_visibility,
        selector_audience,
        created_at,
    };
    payload.validate()?;
    let mut event = Event::new_at(
        EventKind::AgentProvision.to_string(),
        ScopeRef::Realm {
            realm_id: controller_realm_id.clone(),
        },
        controller_id.clone(),
        options.actor_seq,
        options.hlc,
        serde_json::to_value(payload)?,
        created_at,
    )?;
    event.prev_refs = options.prev_refs;
    event.seal_basis = options.seal_basis;
    event.requirements.schema_profile_refs =
        vec![ProfileRef::new(SchemaId::AGENT_PROVISION_V1).unwrap()];
    Ok(event)
}
