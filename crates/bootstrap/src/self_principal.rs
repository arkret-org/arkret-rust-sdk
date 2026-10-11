//! Self-principal Realm bootstrap Event authoring.

use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, RealmCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_wire::{
    AccountId, ActorId, Did, DidCoreId, Discoverability, Event, EventKind, GenesisSalt,
    HistoryAccess, JoinRule, PcrGenesisUnit, ScopeRef, SecurityClass, SemanticRef, TrustDomainId,
    WireError, project_did_to_core_id,
};
use chrono::{DateTime, Utc};

use crate::DID_INCEPTION_REF_ROLE;

/// Producer-selected content for the self-principal Realm-create Event.
///
/// The Station assigns stream order only after accepting the producer-signed
/// Event; producer input contains no authority ordering coordinates.
#[derive(Clone, Debug)]
pub struct SelfPrincipalPcrCreateInput {
    pub principal_id: DidCoreId,
    pub governance_station_id: DidCoreId,
    pub principal_did: Did,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TrustDomainId,
    pub did_inception_ref: SemanticRef,
    pub initial_resolution: ResolutionCommitment,
    pub founding_device_descriptor: FoundingDeviceDescriptor,
    pub initial_join_rule: JoinRule,
    pub initial_history_access: HistoryAccess,
    pub initial_discoverability: Discoverability,
    pub created_at: DateTime<Utc>,
}

/// Build the unsigned, content-bound self-principal Realm-create Event.
///
/// The returned [`arkret_wire::AuthoredEvent`] is ready for the producer proof
/// to be attached. It is not committed or ordered by this crate.
pub fn build_self_principal_pcr_create(
    input: SelfPrincipalPcrCreateInput,
) -> arkret_wire::Result<arkret_wire::AuthoredEvent> {
    if project_did_to_core_id(&input.principal_did)? != input.principal_id
        || input.initial_resolution.did != input.principal_did
        || input.initial_resolution.method_history_head.is_empty()
        || input.initial_resolution.version_id.is_empty()
    {
        return Err(WireError::Protocol(
            "self-principal identity resolution does not match principal_id".to_owned(),
        ));
    }
    if input.did_inception_ref.role != DID_INCEPTION_REF_ROLE || !input.did_inception_ref.critical {
        return Err(WireError::Protocol(
            "self-principal bootstrap requires one critical did_inception reference".to_owned(),
        ));
    }

    let genesis = RealmGenesis::new(
        RealmPurpose::PrincipalControl,
        input.genesis_salt,
        input.trust_domain,
        SecurityClass::HighAssurance,
        input.governance_station_id.clone(),
        input.initial_join_rule,
        input.initial_history_access,
        input.initial_discoverability,
        Some(input.founding_device_descriptor),
        Some(input.initial_resolution),
    )?;
    let actor_id = ActorId::account(AccountId::new(
        input.principal_id,
        input.governance_station_id,
    ));
    let event = crate::author_event::<arkret_wire::event_spec::RealmCreate>(
        ScopeRef::RealmGenesis,
        actor_id,
        None,
        None,
        input.created_at,
        vec![input.did_inception_ref],
        RealmCreatePayload::new(genesis),
    )?;
    validate_self_principal_pcr_create(&event, false)?;
    Ok(event)
}

/// Validate the closed producer-owned portion of a self-principal create.
///
/// `require_proof` is used at the acceptance boundary. Commit ancestry is
/// intentionally not checked here: it belongs to the RealmCommit stream.
pub fn validate_self_principal_pcr_create(
    event: &Event,
    require_proof: bool,
) -> arkret_wire::Result<()> {
    if event.kind != EventKind::RealmCreate
        || event.scope_ref != ScopeRef::RealmGenesis
        || event.realm_id != arkret_wire::RealmId::from_event_id(&event.event_id)
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || event.external_ref.is_some()
        || event.semantic_refs.len() != 1
        || event.semantic_refs[0].role != DID_INCEPTION_REF_ROLE
        || !event.semantic_refs[0].critical
    {
        return Err(WireError::Protocol(
            "invalid self-principal Realm-create Event shape".to_owned(),
        ));
    }
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    if require_proof {
        event.validate_for_submit_structural()?;
        event.validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    } else if event.producer_proof.is_some() {
        return Err(WireError::Protocol(
            "self-principal Event builder must return an unsigned Event".to_owned(),
        ));
    }

    let payload: RealmCreatePayload = serde_json::from_value(serde_json::Value::Object(
        event.payload.clone().into_iter().collect(),
    ))?;
    payload.object.validate()?;
    let resolution_matches = payload
        .object
        .initial_resolution
        .as_ref()
        .is_some_and(|resolution| {
            project_did_to_core_id(&resolution.did)
                .is_ok_and(|principal_id| principal_id == *event.actor_id.signing_principal_id())
        });
    if payload.object.purpose != RealmPurpose::PrincipalControl
        || payload.object.governance_station_id != *event.actor_id.route_service_id()
        || !resolution_matches
    {
        return Err(WireError::Protocol(
            "self-principal Realm-create payload is inconsistent with its producer".to_owned(),
        ));
    }
    Ok(())
}

/// Package the two independently producer-signed identity creation Events as
/// the atomic PCR genesis unit.
///
/// The Account Authority submits the unit to the current governance Station in
/// this exact order, and the Station produces one RealmCommit for each Event in
/// the Realm stream. `principal-operations.schema.json#/$defs/pcr_genesis_unit`
/// is the single carrier for the pair, so there is no second Rust shape that
/// holds the same two Events under different member names.
pub fn build_pcr_genesis_unit(
    realm_create: Event,
    founding_device_authorize: Event,
) -> arkret_wire::Result<PcrGenesisUnit> {
    validate_self_principal_pcr_create(&realm_create, true)?;
    if founding_device_authorize.actor_id != realm_create.actor_id {
        return Err(WireError::Protocol(
            "founding device authorization must have the same producer as Realm creation"
                .to_owned(),
        ));
    }
    founding_device_authorize
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    founding_device_authorize
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    PcrGenesisUnit::new(realm_create, founding_device_authorize)
}
