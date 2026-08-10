//! The closed self-principal PCR bootstrap unit: the unsigned genesis builder,
//! the two-slot submit request, and the validators both sides run.

use std::collections::BTreeMap;

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    validate_root_anchored_authorize_payload_digest,
};
use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, RealmCreatePayload, RealmGenesis,
};
use arkret_models_collaboration::objects::realm::NotaryProfile;
use arkret_wire::{
    ActorId, CellRef, Did, EncryptionProfile, Error, Event, EventKind, EventRef, GenesisSalt, Hash,
    Hlc, NotaryValue, PcrGenesisUnit, ProfileId, Result, SchemaId, ScopeRef, SecurityClass,
    TypedTrustDomainId, composite_subject, event_spec, project_full_id_to_core_id, proof_kind,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::DID_INCEPTION_REF_ROLE;
use crate::projection::{CellWriteProjector, direct_projection, validate_realm_create_projection};

/// Public inputs required to construct the unsigned, root-anchored first
/// Event of a self-principal PCR bootstrap unit.
#[derive(Clone, Debug)]
pub struct SelfPrincipalPcrCreateInput {
    pub principal_id: Did,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TypedTrustDomainId,
    pub did_inception_ref: EventRef,
    pub founding_device_descriptor: FoundingDeviceDescriptor,
    /// Genesis capability-action registry basis copied into the Realm's
    /// authority-root cell (`models/realm-and-space.md` section 2.5).
    pub capability_action_registry_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
}

/// Construct the only unsigned `ak.realm.create` shape that an identity root
/// may sign. Signing material remains entirely with the caller.
pub fn build_self_principal_pcr_create(
    input: SelfPrincipalPcrCreateInput,
    project: CellWriteProjector<'_>,
) -> Result<Event> {
    let created_at = arkret_canonical::canonical::normalize_timestamp_canonical(input.created_at);
    let actor_id = ActorId::from(project_full_id_to_core_id(&input.principal_id)?);
    if input.did_inception_ref.role != DID_INCEPTION_REF_ROLE
        || !input.did_inception_ref.critical
        || input.did_inception_ref.proof.is_some()
    {
        return Err(Error::Protocol(
            "self principal PCR requires one direct critical did_inception ref".to_owned(),
        ));
    }

    let genesis = RealmGenesis::principal_control(
        input.genesis_salt,
        Some(input.founding_device_descriptor),
        input.trust_domain,
        vec![
            SchemaId::REALM_V1.to_owned(),
            ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_canonical::DigestSuite::Sha256,
        SecurityClass::HighAssurance,
        EncryptionProfile::MlsRfc9420,
        NotaryProfile::SingleDid,
        NotaryValue::single_did(input.principal_id.clone()),
        input.capability_action_registry_digest.clone(),
    )?;

    let payload = RealmCreatePayload::new(genesis);
    let event = arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::RealmCreate>::new(
        // zh/models/realm-and-space.md section 2.5.0: a Realm genesis scope
        // carries no realm_id. Every Realm id, including a PCR, is derived
        // from the authored create Event.
        ScopeRef::RealmGenesis,
        actor_id,
        payload,
    )
    .map_err(|error| Error::Protocol(error.to_string()))?
    .with_ref(input.did_inception_ref)
    .author(0, input.hlc, created_at)
    .map_err(|error| Error::Protocol(error.to_string()))?;
    validate_self_principal_pcr_create(&event, false, project)?;
    Ok(event)
}

/// Validate and package the closed two-slot self-principal PCR genesis unit.
/// Authorization leases do not exist before the PCR. The root proof on
/// `ak.realm.create`, the device-possession signature in
/// `ak.device.authorize`, and the descriptor's one-way payload commitment are
/// the complete genesis authorization chain.
pub fn build_self_principal_pcr_genesis_unit(
    create: Event,
    authorize: Event,
    project: CellWriteProjector<'_>,
) -> Result<PcrGenesisUnit> {
    validate_self_principal_pcr_genesis_unit(&create, &authorize, project)?;
    PcrGenesisUnit::new(create, authorize)
}

pub fn validate_self_principal_pcr_genesis_unit(
    create: &Event,
    authorize: &Event,
    project: CellWriteProjector<'_>,
) -> Result<()> {
    validate_self_principal_pcr_create(create, true, project)?;
    if authorize.kind != EventKind::DeviceAuthorize
        || authorize.realm_id != create.realm_id
        || authorize.actor_id != create.actor_id
        || authorize.actor_seq != 1
        || authorize.prev_refs != vec![create.event_id.clone()]
        || authorize.event_id == create.event_id
        || authorize.seal_ref.is_some()
        || authorize.auth_context.is_some()
        || authorize.seal_basis.is_some()
        || !authorize.preconditions.is_empty()
        || authorize.executed_by.is_some()
        || authorize.authorization_ref.is_some()
        || authorize.applet_id.is_some()
        || authorize.external_ref.is_some()
        || authorize.actor_kind.is_some()
        || !authorize.unsigned.is_empty()
        || authorize.refs.iter().any(|reference| {
            matches!(
                reference.role.as_str(),
                "did_inception" | "did_recovery_anchor" | "bootstrap_binding"
            )
        })
    {
        return Err(Error::Protocol(
            "second self principal bootstrap slot is not the closed device authorize shape"
                .to_owned(),
        ));
    }
    validate_event_proof_digests(authorize)?;
    let payload: DeviceAuthorizePayload =
        authorize.typed_payload::<event_spec::DeviceAuthorize>()?;
    if ActorId::from(project_full_id_to_core_id(&payload.principal_id)?) != create.actor_id
        || payload.authorization_binding_kind != DeviceAuthorizationBindingKind::RootAnchored
        || payload.recovery_session_id.is_some()
    {
        return Err(Error::Protocol(
            "founding device authorize must be root-anchored".to_owned(),
        ));
    }
    let authorized_by_matches = match &payload.authorized_by {
        DeviceOrPrincipalRef::Did(did) => {
            ActorId::from(project_full_id_to_core_id(did)?) == create.actor_id
        }
        DeviceOrPrincipalRef::DeviceId(_) => false,
    };
    let create_payload: RealmCreatePayload = create.typed_payload::<event_spec::RealmCreate>()?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .as_ref()
        .ok_or_else(|| {
            Error::Protocol("PCR genesis omits founding device descriptor".to_owned())
        })?;
    validate_root_anchored_authorize_payload_digest(
        &descriptor.founding_authorize_payload_digest,
        &Value::Object(authorize.payload.clone().into_iter().collect()),
        arkret_canonical::DigestSuite::Sha256,
    )?;
    if !authorized_by_matches
        || authorize.proofs.len() != 1
        || authorize.proofs[0].verification_method.as_str()
            != format!("{}#{}", payload.principal_id, descriptor.device_id)
        || descriptor.device_id != payload.device_id
        || descriptor.device_public_key != payload.device_public_key
        || descriptor.hpke_key != payload.hpke_key
        || descriptor.algorithms != payload.algorithms
    {
        return Err(Error::Protocol(
            "founding device authorize does not match its committed descriptor".to_owned(),
        ));
    }
    // The second slot used to be pinned by requiring an empty producer-written
    // effect array. v1 has no such array, so the equivalent statement is that
    // the registered contract derives exactly the one device-authorization
    // cell for this principal and device -- an authoritative claim the old
    // emptiness check could never make.
    let authorize_effects = direct_projection(authorize, project)?;
    let device_cell = CellRef::new(format!(
        "ak:cell:ak.component.device.authorization.v1:{}",
        composite_subject(&[payload.principal_id.as_str(), payload.device_id.as_str()])?
    ))?;
    if authorize_effects.len() != 1 || authorize_effects[0].cell != device_cell {
        return Err(Error::Protocol(
            "bootstrap device authorize does not derive its single device authorization cell"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_self_principal_pcr_create(
    event: &Event,
    require_proof: bool,
    project: CellWriteProjector<'_>,
) -> Result<()> {
    let expected_realm_id = arkret_wire::RealmId::from_event_id(&event.event_id);
    if event.kind != EventKind::RealmCreate
        || event.realm_id != expected_realm_id
        || event.actor_seq != 0
        || !event.prev_refs.is_empty()
        || event.refs.len() != 1
        || event.refs[0].role != DID_INCEPTION_REF_ROLE
        || !event.refs[0].critical
        || event.refs[0].proof.is_some()
        || !event.preconditions.is_empty()
        || event.seal_ref.is_some()
        || event.auth_context.is_some()
        || event.seal_basis.is_some()
        || event.redacts.is_some()
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || event.external_ref.is_some()
        || event.actor_kind.is_some()
        || !event.unsigned.is_empty()
    {
        return Err(Error::Protocol(
            "identity root may sign only the closed self principal PCR genesis shape".to_owned(),
        ));
    }
    if require_proof {
        validate_event_proof_digests(event)?;
        if event.proofs.len() != 1 || !event.proofs[0].verification_method.starts_with("did:key:") {
            return Err(Error::Protocol(
                "self principal PCR genesis requires exactly one identity-root proof".to_owned(),
            ));
        }
    } else if !event.proofs.is_empty() {
        return Err(Error::Protocol(
            "unsigned self principal PCR builder output must not contain proofs".to_owned(),
        ));
    }

    validate_principal_control_realm_payload(event)?;
    validate_realm_create_projection(event, &direct_projection(event, project)?)
}

fn validate_principal_control_realm_payload(event: &Event) -> Result<()> {
    let payload: RealmCreatePayload = event.typed_payload::<event_spec::RealmCreate>()?;
    let genesis = payload.object;
    let profile_count = genesis
        .schema_refs
        .iter()
        .filter(|profile| profile.as_str() == ProfileId::PRINCIPAL_CONTROL_REALM_V1)
        .count();
    let notary_matches = match &genesis.notary {
        NotaryValue::SingleDid { did, .. } => {
            ActorId::from(project_full_id_to_core_id(did)?) == event.actor_id
        }
        _ => false,
    };
    if genesis.schema != SchemaId::REALM_GENESIS_V1
        || genesis.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
        || genesis.security_class != SecurityClass::HighAssurance
        || profile_count != 1
        || genesis.encryption_profile != EncryptionProfile::MlsRfc9420
        || genesis.notary_profile != NotaryProfile::SingleDid
        || !notary_matches
    {
        return Err(Error::Protocol(
            "self principal PCR create payload violates create-locked profile".to_owned(),
        ));
    }
    genesis.validate()
}

fn validate_event_proof_digests(event: &Event) -> Result<()> {
    if event.proofs.is_empty() {
        return Err(Error::Protocol(
            "bootstrap event proof is missing".to_owned(),
        ));
    }
    let digest = event.event_digest()?;
    if event.proofs.iter().any(|proof| {
        proof.kind != proof_kind::DETACHED_JWS
            || proof.event_digest.as_str() != digest
            || proof.jws.is_empty()
    }) {
        return Err(Error::Protocol(
            "bootstrap event carries an invalid proof envelope".to_owned(),
        ));
    }
    Ok(())
}

fn payload_map<T: serde::Serialize>(payload: &T) -> Result<BTreeMap<String, Value>> {
    let Value::Object(map) = serde_json::to_value(payload)? else {
        return Err(Error::Protocol(
            "event payload must serialize to an object".to_owned(),
        ));
    };
    Ok(map.into_iter().collect())
}
