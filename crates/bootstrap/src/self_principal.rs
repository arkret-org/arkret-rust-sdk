//! The closed self-principal PCR bootstrap unit: the unsigned genesis builder,
//! the two-slot submit request, and the validators both sides run.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::RealmCreatePayload;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_collaboration::governance::circle::EncryptionFloor;
use arkret_models_collaboration::http_bodies::{
    EventsSubmitBatchRequestBody, EventsSubmitRequestBody,
};
use arkret_models_collaboration::objects::realm::{NotaryProfile, Realm};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_wire::{
    CellRef, Did, Discoverability, EncryptionProfile, Error, Event, EventId,
    EventInitialSubmission, EventKind, EventRef, EventRequirements, Hash, HistoryVisibility, Hlc,
    JoinRule, NotaryValue, ProfileId, RealmId, Result, SchemaId, ScopeRef, SecurityClass,
    TypedTrustDomainId, composite_subject, proof_kind,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::projection::{CellWriteProjector, direct_projection, validate_realm_create_projection};
use crate::{DID_INCEPTION_REF_ROLE, PRINCIPAL_CONTROL_PURPOSE};

/// Public inputs required to construct the unsigned, root-anchored first
/// Event of a self-principal PCR bootstrap unit.
#[derive(Clone, Debug)]
pub struct SelfPrincipalPcrCreateInput {
    pub principal_id: Did,
    pub realm_id: RealmId,
    pub trust_domain: TypedTrustDomainId,
    pub did_inception_ref: EventRef,
    /// Genesis capability-action registry basis copied into the Realm's
    /// authority-root cell (`models/realm-and-space.md` section 2.5).
    pub capability_action_registry_digest: Hash,
    pub event_id: EventId,
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
    let expected_realm_id = RealmId::new(principal_control_realm_id(&input.principal_id))?;
    if input.realm_id != expected_realm_id {
        return Err(Error::Protocol(
            "self principal PCR realm_id does not match principal_id".to_owned(),
        ));
    }
    if input.did_inception_ref.role != DID_INCEPTION_REF_ROLE
        || !input.did_inception_ref.critical
        || input.did_inception_ref.proof.is_some()
    {
        return Err(Error::Protocol(
            "self principal PCR requires one direct critical did_inception ref".to_owned(),
        ));
    }

    let mut realm = Realm::new(
        input.realm_id.clone(),
        "Principal Control Realm",
        input.principal_id.clone(),
        input.trust_domain,
        arkret_wire::CORE_REDUCER_PROFILE,
        NotaryProfile::SingleDid,
        NotaryValue::single_did(input.principal_id.clone()),
        input.capability_action_registry_digest.clone(),
    );
    realm.security_class = Some(SecurityClass::HighAssurance);
    realm.schema_refs = vec![
        SchemaId::REALM_V1.to_owned(),
        ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
    ];
    realm.default_discoverability = Discoverability::Secret;
    realm.default_join_rule = JoinRule::Closed;
    realm.history_visibility = HistoryVisibility::Restricted;
    realm.encryption_profile = EncryptionProfile::MlsRfc9420;
    realm.content_encryption_floor = Some(EncryptionFloor::E2eeRequired);
    realm.metadata_encryption_floor = Some(EncryptionFloor::E2eeRequired);
    realm.fields.insert(
        "purpose".to_owned(),
        Value::String(PRINCIPAL_CONTROL_PURPOSE.to_owned()),
    );
    realm.created_at = created_at;
    // R3.1: the create payload carries no object id.
    realm.id = None;

    let payload = payload_map(&RealmCreatePayload {
        object: realm,
        initial_relations: None,
    })?;
    let mut event = Event::new_with_id_at(
        input.event_id,
        EventKind::REALM_CREATE,
        // zh/models/realm-and-space.md section 2.5.0: a Realm genesis scope
        // carries no realm_id. For a PCR the id is subject-derived from the
        // principal DID rather than from this Event, but the wire shape is the
        // same closed `realm_genesis` scope for every ak.realm.create.
        ScopeRef::RealmGenesis,
        input.principal_id,
        0,
        input.hlc,
        Value::Object(payload.into_iter().collect()),
        created_at,
    )?;
    event.refs = vec![input.did_inception_ref];
    event.requirements = EventRequirements::default();
    validate_self_principal_pcr_create(&event, false, project)?;
    Ok(event)
}

/// Validate and package the closed two-slot self-principal bootstrap batch.
/// The receiver still verifies both cryptographic proofs and entry-0 history.
///
/// Each slot travels with one authorization lease bound to the complete
/// ordered anchor unit. The admitting Principal Server uses that pre-admission
/// evidence to mint the two Control Proposal Acks inside the atomic genesis
/// transaction, so callers must not attach Control Proposal Acks themselves.
pub fn self_principal_bootstrap_submit_request(
    create: EventInitialSubmission,
    authorize: EventInitialSubmission,
    project: CellWriteProjector<'_>,
) -> Result<EventsSubmitRequestBody> {
    validate_self_principal_bootstrap_unit(&create.event, &authorize.event, project)?;
    for submission in [&create, &authorize] {
        submission.validate_structural_in_context(arkret_wire::EventSubmitContext::AnchorUnit)?;
    }
    let leases = [
        create.authorization_lease.clone().ok_or_else(|| {
            Error::Protocol(
                "self principal bootstrap requires a complete anchor-unit authorization lease set"
                    .to_owned(),
            )
        })?,
        authorize.authorization_lease.clone().ok_or_else(|| {
            Error::Protocol(
                "self principal bootstrap requires a complete anchor-unit authorization lease set"
                    .to_owned(),
            )
        })?,
    ];
    arkret_wire::validate_anchor_unit_lease_bindings(
        &[create.event.clone(), authorize.event.clone()],
        &leases,
    )?;
    if create.control_proposal_ack.is_some() || authorize.control_proposal_ack.is_some() {
        return Err(Error::Protocol(
            "self principal bootstrap Control Proposal Acks are minted by the admitting server"
                .to_owned(),
        ));
    }
    Ok(EventsSubmitRequestBody::Batch(
        EventsSubmitBatchRequestBody {
            events: vec![create, authorize],
        },
    ))
}

pub fn validate_self_principal_bootstrap_unit(
    create: &Event,
    authorize: &Event,
    project: CellWriteProjector<'_>,
) -> Result<()> {
    validate_self_principal_pcr_create(create, true, project)?;
    if authorize.kind != EventKind::DEVICE_AUTHORIZE
        || authorize.realm_id != create.realm_id
        || authorize.actor_id != create.actor_id
        || authorize.actor_seq != 1
        || authorize.prev_refs != vec![create.event_id.clone()]
        || authorize.event_id == create.event_id
        || authorize.seal_ref.is_some()
        || authorize.auth_context.is_some()
        || authorize.seal_basis.is_some()
        || !authorize.preconditions.is_empty()
        || authorize.executed_by.is_none()
        || authorize.authorization_ref.is_none()
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
    let payload: DeviceAuthorizePayload = authorize.typed_payload(EventKind::DEVICE_AUTHORIZE)?;
    if payload.principal_id != create.actor_id
        || payload.cross_signing_binding.is_some()
        || payload.enrollment_authority_binding.is_none()
        || payload.recovery_session_id.is_some()
    {
        return Err(Error::Protocol(
            "bootstrap device authorize must use only enrollment authority binding".to_owned(),
        ));
    }
    payload.validate_service_attested_provenance(
        authorize.executed_by.as_ref(),
        authorize.authorization_ref.as_deref(),
        authorize.created_at,
    )?;
    let binding = payload
        .enrollment_authority_binding
        .as_ref()
        .expect("checked above");
    let authorized_by_matches = matches!(
        &payload.authorized_by,
        DeviceOrPrincipalRef::Did(did) if did == &binding.authority_did
    );
    if !authorized_by_matches
        || authorize.proofs.len() != 1
        || proof_controller(&authorize.proofs[0].verification_method)
            != Some(binding.authority_did.as_str())
    {
        return Err(Error::Protocol(
            "bootstrap authorize proof does not belong to its enrollment authority".to_owned(),
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
    let expected_realm_id = RealmId::new(principal_control_realm_id(&event.actor_id))?;
    if event.kind != EventKind::REALM_CREATE
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
    let payload: RealmCreatePayload = event.payload_as()?;
    let realm = payload.object;
    let profile_count = realm
        .schema_refs
        .iter()
        .filter(|profile| profile.as_str() == ProfileId::PRINCIPAL_CONTROL_REALM_V1)
        .count();
    let exact_purpose = realm.fields.len() == 1
        && realm.fields.get("purpose").and_then(Value::as_str) == Some(PRINCIPAL_CONTROL_PURPOSE);
    let notary_matches = matches!(
        &realm.notary,
        NotaryValue::SingleDid { did, .. } if did == &event.actor_id
    );
    // R3.1: the create payload MUST omit the object id; the Realm id is
    // derived from this genesis Event, so a payload copy would be a second,
    // forgeable truth (zh/models/realm-and-space.md section 2.5.0).
    if realm.id.is_some()
        || realm.schema != SchemaId::REALM_V1
        || realm.created_by != event.actor_id
        || realm.created_at != event.created_at
        || realm.security_class != Some(SecurityClass::HighAssurance)
        || profile_count != 1
        || realm.default_discoverability != Discoverability::Secret
        || realm.default_join_rule != JoinRule::Closed
        || realm.history_visibility != HistoryVisibility::Restricted
        || realm.encryption_profile != EncryptionProfile::MlsRfc9420
        || realm.content_encryption_floor != Some(EncryptionFloor::E2eeRequired)
        || realm.metadata_encryption_floor != Some(EncryptionFloor::E2eeRequired)
        || realm.notary_profile != NotaryProfile::SingleDid
        || !notary_matches
        || !exact_purpose
        || payload
            .initial_relations
            .is_some_and(|items| !items.is_empty())
    {
        return Err(Error::Protocol(
            "self principal PCR create payload violates create-locked profile".to_owned(),
        ));
    }
    realm.validate_kind_invariants()
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

fn proof_controller(verification_method: &str) -> Option<&str> {
    verification_method.split_once('#').map(|(did, _)| did)
}

fn payload_map<T: serde::Serialize>(payload: &T) -> Result<BTreeMap<String, Value>> {
    let Value::Object(map) = serde_json::to_value(payload)? else {
        return Err(Error::Protocol(
            "event payload must serialize to an object".to_owned(),
        ));
    };
    Ok(map.into_iter().collect())
}
