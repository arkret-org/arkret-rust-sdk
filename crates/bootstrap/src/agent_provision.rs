//! Controller-owned managed-agent provisioning Event authoring.

use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::agent::{
    AgentProvisionAccountabilityScope, AgentProvisionPayload, AgentProvisionSchema,
};
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{
    DidCoreId, DidUrl, Hash, ProfileRef, RealmId, Result, SchemaId, ScopeRef, SealBasis, WireError,
    event_spec,
};
use chrono::{DateTime, Utc};

/// Envelope facts supplied before the ordinary submit pipeline authors and
/// signs the single controller-authored provision Event.
///
/// The actor-chain position and HLC are deliberately absent: they belong to the
/// submit path that reads the accepted frontier, not to a builder.
#[derive(Clone, Debug)]
pub struct AgentProvisionIntentOptions {
    /// Principal Server for the controller authority pair that admits the
    /// provision Event. This is envelope identity, not the controller DID.
    pub controller_principal_server_id: DidCoreId,
    pub created_at: DateTime<Utc>,
    pub seal_basis: Option<SealBasis>,
}

/// Draft the single closed `ak.agent.provision` registered by v1.
///
/// The payload carries no nested proof. Callers author this intent and attach
/// the controller's ordinary Event proof and publication evidence through the
/// standard submit pipeline.
#[allow(clippy::too_many_arguments)]
pub fn build_agent_provision_intent(
    controller_id: &DidCoreId,
    controller_realm_id: &RealmId,
    agent_id: &DidCoreId,
    principal_control_realm_id: &RealmId,
    controller_authorization_ref: &DidUrl,
    agent_slug: &str,
    requested_scope_digest: &Hash,
    selector_visibility: HandleVisibility,
    selector_audience: Option<String>,
    options: AgentProvisionIntentOptions,
) -> Result<arkret_event_draft::EventIntent> {
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
    let mut draft = TypedEventDraft::<event_spec::AgentProvision>::new(
        ScopeRef::Realm {
            realm_id: controller_realm_id.clone(),
        },
        controller_id.clone(),
        options.controller_principal_server_id,
        payload,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?
    .with_schema_profile_ref(ProfileRef::new(SchemaId::AGENT_PROVISION_V1).unwrap());
    if let Some(seal_basis) = options.seal_basis {
        draft = draft.with_seal_basis(seal_basis);
    }
    draft
        .into_intent(created_at)
        .map_err(|error| WireError::Protocol(error.to_string()))
}
