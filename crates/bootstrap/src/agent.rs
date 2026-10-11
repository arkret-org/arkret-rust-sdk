//! Agent control-Realm bootstrap Event authoring.

use arkret_models_collaboration::events_payloads::{
    RealmCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_wire::{
    AccountId, ActorId, AuthorizationRef, DidCoreId, Discoverability, GenesisSalt, HistoryAccess,
    JoinRule, ScopeRef, SecurityClass, TrustDomainId, WireError, project_did_to_core_id,
};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct AgentPcrCreatePayloadInput {
    pub agent_id: DidCoreId,
    pub governance_station_id: DidCoreId,
    pub initial_resolution: ResolutionCommitment,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TrustDomainId,
    pub initial_join_rule: JoinRule,
    pub initial_history_access: HistoryAccess,
    pub initial_discoverability: Discoverability,
}

pub fn build_agent_pcr_create_payload(
    input: AgentPcrCreatePayloadInput,
) -> arkret_wire::Result<RealmCreatePayload> {
    if project_did_to_core_id(&input.initial_resolution.did)? != input.agent_id
        || input.initial_resolution.method_history_head.is_empty()
        || input.initial_resolution.version_id.is_empty()
    {
        return Err(WireError::Protocol(
            "Agent initial resolution does not match agent_id".to_owned(),
        ));
    }
    Ok(RealmCreatePayload::new(RealmGenesis::new(
        RealmPurpose::AgentControl,
        input.genesis_salt,
        input.trust_domain,
        SecurityClass::HighAssurance,
        input.governance_station_id,
        input.initial_join_rule,
        input.initial_history_access,
        input.initial_discoverability,
        None,
        Some(input.initial_resolution),
    )?))
}

/// Envelope inputs for an Agent control-Realm create.
#[derive(Clone, Debug)]
pub struct AgentPcrCreateEventInput {
    pub payload: AgentPcrCreatePayloadInput,
    pub executed_by: ActorId,
    pub authorization_ref: AuthorizationRef,
    pub created_at: DateTime<Utc>,
}

/// Build a content-bound Agent Realm-create Event ready for the controller's
/// proof.
///
/// `identity/key-management.md` section 4.1: the control facts belong to the
/// Agent's complete account ActorId, and the controller executes the Event
/// under the DID delegation. The Agent PCR is carried by its controller's
/// Station, so the Agent account takes the controller account's Station; a
/// `service` actor or a non-account executor is refused.
///
/// The Event has no predecessor. The governance Station later puts it at
/// position zero of that Realm's independent commit stream.
pub fn build_agent_pcr_create(
    input: AgentPcrCreateEventInput,
) -> arkret_wire::Result<arkret_wire::AuthoredEvent> {
    let controller = input.executed_by.as_account_id().ok_or_else(|| {
        WireError::Protocol("Agent PCR create executor must be the controller account".to_owned())
    })?;
    let agent = ActorId::account(AccountId::new(
        input.payload.agent_id.clone(),
        controller.station_id.clone(),
    ));
    let payload = build_agent_pcr_create_payload(input.payload)?;
    crate::author_event::<arkret_wire::event_spec::RealmCreate>(
        ScopeRef::RealmGenesis,
        agent,
        Some(input.executed_by),
        Some(input.authorization_ref),
        input.created_at,
        Vec::new(),
        payload,
    )
}
