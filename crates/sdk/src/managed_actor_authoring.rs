//! Shared authoring kernel for the four-Event Applet-managed actor creation unit.
//!
//! Package-build authorities use this for the first managed Bot and running
//! Applet services use it for Ghost identities. Callers retain key custody,
//! replay persistence and frontier acquisition; this module owns the canonical
//! Event/payload/proof construction so those authorities cannot drift.

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_event_draft::{EventIntent, TypedEventDraft};
use arkret_identifiers::{AppletId, DidCoreId, EventId, GrantId, Hlc, RealmId, TrustDomainId};
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, RealmCreatePayload, RealmGenesis,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use arkret_models_identity::{ActorProfile, ResolutionCommitment, ResolutionMethodHistoryEvidence};
use arkret_models_integration::{
    AppletDelegatedEventAuthorization, AppletManagedActorAuthoringBundle,
    AppletManagedActorAuthoringRequest, AppletManagedActorProof,
    AppletManagedActorProvisionPayload, AppletManagedActorPurpose, AppletManagedActorRole,
};
use arkret_signatures::{SignEventOptions, sign_event};
use arkret_wire::{
    ActorId, ActorKind, EncryptionProfile, Event, EventRef, GenesisSalt, Hash, NotaryValue,
    PayloadProof, PayloadSigner, ProfileId, SchemaId, ScopeRef, SealBasis, SecurityClass,
    event_spec, proof_kind,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::Result;
use crate::sdk_error::Error;

/// Runtime inputs that are deliberately outside the signed author request.
///
/// The Station supplies the signed branch basis. The authoring
/// authority supplies the independently held actor identity, the accepted
/// service/Realm frontier and PCR policy selected by its deployment.
#[derive(Clone, Debug)]
pub struct AppletManagedActorBundleAuthoringInput {
    pub actor_id: DidCoreId,
    pub initial_resolution: ResolutionCommitment,
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    pub service_actor_seq: u64,
    pub service_prev_refs: Vec<EventId>,
    pub seal_basis: SealBasis,
    pub digest_suite: DigestSuite,
    pub trust_domain: TrustDomainId,
    pub security_class: SecurityClass,
    pub genesis_salt: GenesisSalt,
    /// Used only for the install-Bot branch. Ghost display names come from the
    /// signed request basis.
    pub bot_display_name: String,
}

struct Branch {
    realm_scope: ScopeRef,
    realm_id: RealmId,
    service_id: DidCoreId,
    station_id: DidCoreId,
    applet_id: AppletId,
    registration_ref: EventId,
    authorization_ref: GrantId,
    role: AppletManagedActorRole,
    external_ref: Option<arkret_models_integration::GhostExternalTuple>,
    display_name: String,
}

/// Build and sign the canonical managed-actor creation unit.
pub fn author_applet_managed_actor_bundle<S: PayloadSigner + ?Sized>(
    request: &AppletManagedActorAuthoringRequest,
    input: AppletManagedActorBundleAuthoringInput,
    signer: &S,
) -> Result<AppletManagedActorAuthoringBundle> {
    request.validate_bindings()?;
    let branch = branch(request, &input)?;
    let created_at = request.issued_at;
    let verification_method = signer.verification_method_id().clone();

    let provision_payload = AppletManagedActorProvisionPayload {
        schema: AppletManagedActorProvisionPayload::SCHEMA.to_owned(),
        applet_id: branch.applet_id.clone(),
        service_id: branch.service_id.clone(),
        actor_id: ActorId::account(arkret_wire::AccountId::new(
            input.actor_id.clone(),
            branch.station_id.clone(),
        )),
        actor_role: branch.role,
        initial_resolution: input.initial_resolution.clone(),
        method_history_evidence: input.method_history_evidence.clone().try_into()?,
        registration_ref: branch.registration_ref.clone(),
        applet_authority_ref: branch.authorization_ref.clone(),
        external_ref: branch.external_ref.clone(),
    };
    provision_payload.validate()?;
    let provision_intent = TypedEventDraft::<event_spec::AppletManagedActorProvision>::new(
        branch.realm_scope.clone(),
        ActorId::service(branch.service_id.clone()),
        provision_payload,
    )?
    .with_prev_refs(input.service_prev_refs)
    .with_seal_basis(input.seal_basis.clone())
    .with_authorization_ref(branch.authorization_ref.clone().into())
    .with_applet_id(branch.applet_id.clone())
    .into_intent(created_at)?;
    let provision_event = author_and_sign(
        provision_intent,
        input.service_actor_seq,
        authoring_hlc(created_at, "managed-provision")?,
        input.digest_suite,
        created_at,
        signer,
    )?;

    let genesis = RealmGenesis::applet_managed_control(
        input.genesis_salt,
        input.initial_resolution,
        input.trust_domain,
        vec![
            SchemaId::REALM_V1.to_owned(),
            ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        input.digest_suite,
        input.security_class,
        EncryptionProfile::MlsRfc9420,
        NotaryValue::single_signer(request.hosting_notary.clone()),
    )?;
    let pcr_intent = TypedEventDraft::<event_spec::RealmCreate>::new(
        ScopeRef::RealmGenesis,
        ActorId::account(arkret_wire::AccountId::new(
            input.actor_id.clone(),
            branch.station_id.clone(),
        )),
        RealmCreatePayload::new(genesis),
    )?
    .with_executed_by(ActorId::service(branch.service_id.clone()))
    .with_authorization_ref(branch.authorization_ref.clone().into())
    .with_applet_id(branch.applet_id.clone())
    .with_ref(EventRef::new(
        provision_event.event_id.as_str(),
        "applet_managed_actor_provision",
    ))
    .into_intent(created_at)?;
    let pcr_genesis_event = author_and_sign(
        pcr_intent,
        0,
        authoring_hlc(created_at, "pcr-genesis")?,
        input.digest_suite,
        created_at,
        signer,
    )?;

    let mut accountability = AccountabilityGrantPayload::new(
        branch.service_id.clone(),
        input.actor_id.clone(),
        AccountabilityScope::Single(AccountabilityScopeKind::ContractedService),
        created_at - chrono::Duration::seconds(1),
        None,
        PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: zero_hash()?,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        },
    );
    accountability.proof.payload_digest = accountability.payload_digest()?;
    accountability.proof.jws = signer
        .sign_payload(&accountability.canonical_proof_binding_bytes()?)?
        .jws;
    let accountability_intent = TypedEventDraft::<event_spec::IdentityAccountabilityGrant>::new(
        branch.realm_scope.clone(),
        ActorId::service(branch.service_id.clone()),
        accountability,
    )?
    .with_prev_refs(vec![provision_event.event_id.clone()])
    .with_seal_basis(input.seal_basis.clone())
    .with_authorization_ref(branch.authorization_ref.clone().into())
    .with_applet_id(branch.applet_id.clone())
    .into_intent(created_at)?;
    let accountability_grant_event = author_and_sign(
        accountability_intent,
        input.service_actor_seq + 1,
        authoring_hlc(created_at, "accountability")?,
        input.digest_suite,
        created_at,
        signer,
    )?;

    let delegation = AppletDelegatedEventAuthorization::new(
        branch.service_id.clone(),
        branch.authorization_ref.clone().into(),
        branch.applet_id.clone(),
    );
    delegation.validate()?;
    let profile = actor_profile(
        &branch,
        input.actor_id.clone(),
        branch.service_id.clone(),
        created_at,
    )?;
    let profile_intent = TypedEventDraft::<event_spec::ProfileCreate>::new(
        branch.realm_scope,
        ActorId::account(arkret_wire::AccountId::new(
            input.actor_id,
            branch.station_id.clone(),
        )),
        ActorProfileCreatePayload { object: profile },
    )?
    .with_executed_by(ActorId::service(delegation.executed_by))
    .with_authorization_ref(delegation.authorization_ref)
    .with_applet_id(delegation.applet_id)
    .with_refs(vec![EventRef::new(
        accountability_grant_event.event_id.as_str(),
        "accountability",
    )])
    .with_seal_basis(input.seal_basis)
    .into_intent(created_at)?;
    let profile_event = author_and_sign(
        profile_intent,
        0,
        authoring_hlc(created_at, "profile")?,
        input.digest_suite,
        created_at,
        signer,
    )?;

    let mut bundle = AppletManagedActorAuthoringBundle {
        schema: AppletManagedActorAuthoringBundle::SCHEMA.to_owned(),
        authoring_request_digest: request.canonical_digest()?,
        managed_actor_provision_event: provision_event,
        pcr_genesis_event,
        accountability_grant_event,
        profile_event,
        proof: AppletManagedActorProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: zero_hash()?,
            created_at,
            audience_id: branch.station_id,
            jws: String::new(),
        },
    };
    bundle.proof.payload_digest = bundle.payload_digest()?;
    bundle.proof.jws = signer.sign_payload(&bundle.proof_binding_bytes()?)?.jws;
    bundle.validate_bindings(request)?;
    Ok(bundle)
}

fn branch(
    request: &AppletManagedActorAuthoringRequest,
    input: &AppletManagedActorBundleAuthoringInput,
) -> Result<Branch> {
    match request.purpose {
        AppletManagedActorPurpose::InstallBot => {
            let basis = request.basis.install().ok_or_else(|| {
                Error::Protocol("install-Bot request has the wrong basis branch".to_owned())
            })?;
            let grant_event = basis.capability_grant_events.first().ok_or_else(|| {
                Error::Protocol("install-Bot request has no authority grant".to_owned())
            })?;
            Ok(Branch {
                realm_id: basis.effective_scope.realm_id().clone(),
                realm_scope: ScopeRef::Realm {
                    realm_id: basis.effective_scope.realm_id().clone(),
                },
                service_id: basis.service_id.clone(),
                station_id: basis.target_station_id.clone(),
                applet_id: basis.applet_id.clone(),
                registration_ref: basis.registration_event.event_id.clone(),
                authorization_ref: GrantId::from_event_id(&grant_event.event_id),
                role: AppletManagedActorRole::Bot,
                external_ref: None,
                display_name: input.bot_display_name.clone(),
            })
        }
        AppletManagedActorPurpose::ProvisionGhost => {
            let basis = request.basis.ghost().ok_or_else(|| {
                Error::Protocol("Ghost request has the wrong basis branch".to_owned())
            })?;
            Ok(Branch {
                realm_id: basis.realm_id.clone(),
                realm_scope: ScopeRef::Realm {
                    realm_id: basis.realm_id.clone(),
                },
                service_id: basis.service_id.clone(),
                station_id: basis.target_station_id.clone(),
                applet_id: basis.applet_id.clone(),
                registration_ref: basis.registration_event_ref.clone(),
                authorization_ref: basis.authorization_ref.clone(),
                role: AppletManagedActorRole::Ghost,
                external_ref: Some(basis.external_ref.clone()),
                display_name: basis
                    .display_name
                    .clone()
                    .unwrap_or_else(|| basis.external_ref.external_id.clone()),
            })
        }
    }
}

fn actor_profile(
    branch: &Branch,
    actor_id: DidCoreId,
    accountable_service: DidCoreId,
    created_at: DateTime<Utc>,
) -> Result<ActorProfile> {
    if branch.display_name.trim().is_empty() || branch.display_name.chars().count() > 128 {
        return Err(Error::Protocol(
            "managed actor display name must contain 1..=128 characters".to_owned(),
        ));
    }
    let mut profile_fields = BTreeMap::<String, Value>::from([(
        "managed_by_applet".to_owned(),
        Value::String(branch.applet_id.to_string()),
    )]);
    if let Some(external_ref) = &branch.external_ref {
        profile_fields.insert(
            "external_ref".to_owned(),
            serde_json::to_value(external_ref)?,
        );
    }
    Ok(ActorProfile {
        id: None,
        schema: SchemaId::ACTOR_PROFILE_V1.to_owned(),
        realm_id: Some(branch.realm_id.clone()),
        principal_id: actor_id,
        actor_kind: ActorKind::Integration,
        display_name: branch.display_name.clone(),
        handle: None,
        agent_slug: None,
        avatar_blob_ref: None,
        status: None,
        accountable_principal_ids: vec![accountable_service],
        resolution: None,
        profile_fields,
        created_at,
        updated_by: None,
        updated_at: None,
    })
}

fn author_and_sign<S: PayloadSigner + ?Sized>(
    intent: EventIntent,
    actor_seq: u64,
    hlc: Hlc,
    digest_suite: DigestSuite,
    proof_created_at: DateTime<Utc>,
    signer: &S,
) -> Result<Event> {
    let mut event = intent.author_with_digest_suite(actor_seq, hlc, digest_suite)?;
    sign_event(
        &mut event,
        signer,
        signer.verification_method_id(),
        SignEventOptions::new().with_created_at(proof_created_at),
    )?;
    Ok(event.into_event())
}

fn authoring_hlc(created_at: DateTime<Utc>, label: &str) -> Result<Hlc> {
    let digest = arkret_canonical::sha256_digest(label.as_bytes());
    let node = digest
        .strip_prefix("sha256:")
        .unwrap_or(&digest)
        .get(..8)
        .ok_or_else(|| Error::Protocol("authoring HLC digest is truncated".to_owned()))?;
    Hlc::new(format!(
        "{:012x}-0000-{node}",
        created_at.timestamp_millis().max(0) as u64,
    ))
    .map_err(Into::into)
}

fn zero_hash() -> Result<Hash> {
    Hash::new(format!("sha256:{}", "00".repeat(32))).map_err(Into::into)
}
