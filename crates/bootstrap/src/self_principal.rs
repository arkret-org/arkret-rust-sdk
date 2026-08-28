//! The closed self-principal PCR bootstrap unit: the unsigned genesis builder,
//! the two-slot submit request, and the validators both sides run.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    validate_root_anchored_authorize_payload_digest,
};
use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, RealmCreatePayload, RealmGenesis,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_wire::{
    CellRef, Did, DidCoreId, EncryptionProfile, Event, EventKind, EventRef, GenesisSalt, Hlc,
    NotaryValue, PcrGenesisUnit, ProfileId, Result, SchemaId, ScopeRef, SecurityClass,
    TrustDomainId, WireError, composite_subject, event_spec, project_did_to_core_id, proof_kind,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::DID_INCEPTION_REF_ROLE;
use crate::projection::{CellWriteProjector, direct_projection, validate_realm_create_projection};

/// Public inputs required to construct the unsigned, root-anchored first
/// Event of a self-principal PCR bootstrap unit.
#[derive(Clone, Debug)]
pub struct SelfPrincipalPcrCreateInput {
    pub principal_id: DidCoreId,
    /// Principal Server that admits this genesis Event and owns the public
    /// account-authority coordinate paired with `principal_id`.
    pub principal_server_id: DidCoreId,
    /// Resolvable DID admitted for the principal and published as Realm notary.
    pub principal_did: Did,
    pub notary: NotaryValue,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TrustDomainId,
    pub did_inception_ref: EventRef,
    /// Initial owner-published DID resolution state committed by PCR genesis.
    pub initial_resolution: ResolutionCommitment,
    pub founding_device_descriptor: FoundingDeviceDescriptor,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
}

/// Construct the only unsigned `ak.realm.create` shape that an identity root
/// may sign. Signing material remains entirely with the caller.
pub fn build_self_principal_pcr_create(
    input: SelfPrincipalPcrCreateInput,
    project: CellWriteProjector<'_>,
) -> Result<arkret_wire::AuthoredEvent> {
    let created_at = arkret_canonical::canonical::normalize_timestamp_canonical(input.created_at);
    let actor_id = input.principal_id.clone();
    if project_did_to_core_id(&input.principal_did)? != input.principal_id {
        return Err(WireError::Protocol(
            "self principal DID does not project to principal_id".to_owned(),
        ));
    }
    if input.initial_resolution.did != input.principal_did {
        return Err(WireError::Protocol(
            "self principal initial_resolution does not match principal_did".to_owned(),
        ));
    }
    if input.did_inception_ref.role != DID_INCEPTION_REF_ROLE
        || !input.did_inception_ref.critical
        || input.did_inception_ref.proof.is_some()
    {
        return Err(WireError::Protocol(
            "self principal PCR requires one direct critical did_inception ref".to_owned(),
        ));
    }

    let genesis = RealmGenesis::principal_control(
        input.genesis_salt,
        Some(input.founding_device_descriptor),
        input.initial_resolution,
        input.trust_domain,
        vec![
            SchemaId::REALM_V1.to_owned(),
            ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_canonical::DigestSuite::Sha256,
        SecurityClass::HighAssurance,
        EncryptionProfile::MlsRfc9420,
        input.notary,
    )?;

    let payload = RealmCreatePayload::new(genesis);
    let event = arkret_event_draft::TypedEventDraft::<event_spec::RealmCreate>::new(
        // zh/models/realm-and-space.md section 2.5.0: a Realm genesis scope
        // carries no realm_id. Every Realm id, including a PCR, is derived
        // from the authored create Event.
        ScopeRef::RealmGenesis,
        actor_id,
        input.principal_server_id,
        payload,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?
    .with_ref(input.did_inception_ref)
    .author_with_digest_suite(
        0,
        input.hlc,
        created_at,
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
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
        return Err(WireError::Protocol(
            "second self principal bootstrap slot is not the closed device authorize shape"
                .to_owned(),
        ));
    }
    let authorize_proof = validate_event_proof_digests(authorize)?;
    let payload: DeviceAuthorizePayload =
        authorize.typed_payload::<event_spec::DeviceAuthorize>()?;
    if payload.principal_id.as_core_id() != create.actor_id.as_core_id()
        || payload.authorization_binding_kind != DeviceAuthorizationBindingKind::RegistrationAnchor
        || payload.recovery_session_id.is_some()
    {
        return Err(WireError::Protocol(
            "founding device authorize must be root-anchored".to_owned(),
        ));
    }
    let authorized_by_matches = match &payload.authorized_by {
        DeviceOrPrincipalRef::Principal(principal_id) => {
            principal_id.as_core_id() == create.actor_id.as_core_id()
        }
        DeviceOrPrincipalRef::DeviceId(_) => false,
    };
    let create_payload: RealmCreatePayload = create.typed_payload::<event_spec::RealmCreate>()?;
    let NotaryValue::SingleSigner { signer, .. } = &create_payload.object.notary else {
        return Err(WireError::Protocol(
            "PCR genesis notary must identify the principal actor".to_owned(),
        ));
    };
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .as_ref()
        .ok_or_else(|| {
            WireError::Protocol("PCR genesis omits founding device descriptor".to_owned())
        })?;
    let initial_resolution = create_payload
        .object
        .initial_resolution
        .as_ref()
        .ok_or_else(|| WireError::Protocol("PCR genesis omits initial resolution".to_owned()))?;
    validate_root_anchored_authorize_payload_digest(
        &descriptor.founding_authorize_payload_digest,
        &Value::Object(authorize.payload.clone().into_iter().collect()),
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let (verification_controller, verification_fragment) = authorize_proof
        .verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| {
            WireError::Protocol("founding device proof requires a DID URL".to_owned())
        })?;
    let verification_controller = Did::new(verification_controller.to_owned())?;
    let verification_principal = project_did_to_core_id(&verification_controller)?;
    if !authorized_by_matches
        || signer.actor_id != create.actor_id
        || verification_principal != create.actor_id
        || verification_controller != initial_resolution.did
        || verification_fragment != descriptor.device_id.as_str()
        || descriptor.device_id != payload.device_id
        || descriptor.device_public_key_did != payload.device_public_key_did
        || descriptor.hpke_key != payload.hpke_key
        || descriptor.algorithms != payload.algorithms
    {
        return Err(WireError::Protocol(
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
    if authorize_effects.len() != 1 || authorize_effects[0].cell_id != device_cell {
        return Err(WireError::Protocol(
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
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || event.external_ref.is_some()
        || event.actor_kind.is_some()
        || !event.unsigned.is_empty()
    {
        return Err(WireError::Protocol(
            "identity root may sign only the closed self principal PCR genesis shape".to_owned(),
        ));
    }
    if require_proof {
        let proof = validate_event_proof_digests(event)?;
        if !proof.verification_method.starts_with("did:key:") {
            return Err(WireError::Protocol(
                "self principal PCR genesis requires exactly one identity-root proof".to_owned(),
            ));
        }
    } else if !event.proofs.is_empty() {
        return Err(WireError::Protocol(
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
        NotaryValue::SingleSigner { signer, .. } => signer.actor_id == event.actor_id,
        _ => false,
    };
    let resolution_matches = genesis
        .initial_resolution
        .as_ref()
        .is_some_and(|resolution| {
            project_did_to_core_id(&resolution.did)
                .is_ok_and(|principal_id| principal_id == event.actor_id)
                && !resolution.method_history_head.is_empty()
                && !resolution.version_id.is_empty()
        });
    if genesis.schema != SchemaId::REALM_GENESIS_V1
        || genesis.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
        || genesis.security_class != SecurityClass::HighAssurance
        || profile_count != 1
        || genesis.encryption_profile != EncryptionProfile::MlsRfc9420
        || !notary_matches
        || !resolution_matches
    {
        return Err(WireError::Protocol(
            "self principal PCR create payload violates create-locked profile".to_owned(),
        ));
    }
    genesis.validate()
}

fn validate_event_proof_digests(event: &Event) -> Result<&arkret_wire::ProducerEventProof> {
    // The producer form is used at initial registration. The accepted form is
    // returned by events.read and appends the origin Principal Server proof
    // needed for federation. Both represent one and only one Event author.
    let producer = match event.proofs.as_slice() {
        [arkret_wire::EventProof::Producer(producer)] => producer,
        [
            arkret_wire::EventProof::Producer(producer),
            arkret_wire::EventProof::PrincipalServerAdmission(_),
        ] => {
            event.validate_principal_server_admission_binding(
                arkret_canonical::DigestSuite::Sha256,
            )?;
            producer
        }
        _ => {
            return Err(WireError::Protocol(
                "bootstrap event must carry exactly one producer proof and at most one bound principal server admission proof"
                    .to_owned(),
            ));
        }
    };
    let digest = event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    if producer.kind != proof_kind::DETACHED_JWS
        || producer.event_digest.as_str() != digest
        || producer.jws.is_empty()
    {
        return Err(WireError::Protocol(
            "bootstrap event carries an invalid proof envelope".to_owned(),
        ));
    }
    Ok(producer)
}
