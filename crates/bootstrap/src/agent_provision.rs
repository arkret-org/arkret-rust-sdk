//! Controller-owned Agent provisioning Event authoring.

use arkret_models_collaboration::events_payloads::agent::{
    AgentProvisionAccountabilityScope, AgentProvisionPayload, AgentProvisionSchema,
};
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl, Hash, RealmId, ScopeRef, WireError};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct AgentProvisionIntentOptions {
    pub controller_station_id: DidCoreId,
    pub created_at: DateTime<Utc>,
}

/// Draft one producer Event. Its Realm-stream position is assigned only by the
/// current governance Station after validation.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_provision_intent(
    controller_principal_id: &DidCoreId,
    controller_realm_id: &RealmId,
    agent_id: &DidCoreId,
    principal_control_realm_id: &RealmId,
    controller_authorization_ref: &DidUrl,
    agent_slug: &str,
    requested_scope_digest: &Hash,
    selector_visibility: HandleVisibility,
    selector_audience: Option<String>,
    options: AgentProvisionIntentOptions,
) -> arkret_wire::Result<arkret_wire::AuthoredEvent> {
    let created_at = arkret_canonical::normalize_timestamp_canonical(options.created_at);
    let payload = AgentProvisionPayload {
        schema: AgentProvisionSchema::V1,
        agent_id: agent_id.clone(),
        controller_principal_id: controller_principal_id.clone(),
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
    crate::author_event::<arkret_wire::event_spec::AgentProvision>(
        ScopeRef::Realm {
            realm_id: controller_realm_id.clone(),
        },
        ActorId::account(AccountId::new(
            controller_principal_id.clone(),
            options.controller_station_id,
        )),
        None,
        Some(
            arkret_wire::AuthorizationRef::new(controller_authorization_ref.as_str())
                .map_err(|error| WireError::Protocol(error.to_owned()))?,
        ),
        created_at,
        Vec::new(),
        payload,
    )
}
