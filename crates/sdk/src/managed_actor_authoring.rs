//! Shared authoring kernel for the four-Event Applet-managed actor creation unit.
//!
//! Package-build authorities use this for the first managed Bot and running
//! Applet services use it for Ghost identities. Callers retain key custody,
//! durable replay persistence and the signed registration Event ID;
//! this module owns the canonical Event / payload / proof construction so those
//! authorities cannot drift.
//!
//! The unit is exactly four producer-authored Events in one fixed order:
//! `ak.applet.managed_actor.provision`, the `applet_managed_control`
//! `ak.realm.create` genesis, `ak.identity.accountability_grant` and
//! `ak.profile.create`. Each one reaches the receiving Station as an
//! [`EventAdmissionSubmission`]; the Station alone decides acceptance and signs the
//! authority-side commit that carries stream position and predecessor.

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_event_draft::{EventIntent, GhostActorProfileRequest, TypedEventDraft};
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, RealmCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use arkret_models_identity::{
    ActorProfileDefinition, ResolutionCommitment, ResolutionMethodHistoryEvidence,
};
use arkret_models_integration::{
    AppletDelegatedEventAuthorization, AppletManagedActorAuthoringBundle,
    AppletManagedActorAuthoringRequest, AppletManagedActorProof,
    AppletManagedActorProvisionPayload, AppletManagedActorPurpose, AppletManagedActorRole,
    GhostExternalTuple,
};
use arkret_signatures::{EventSigner, SignEventOptions, sign_event};
use arkret_wire::{
    AccountId, ActorId, ActorKind, AppletId, AuthorizationRef, DidCoreId, Discoverability, Event,
    EventAdmissionSubmission, EventId, EventKind, GenesisSalt, GrantId, Hash, HistoryAccess,
    JoinRule, PayloadProof, PayloadSigner, ScopeRef, SecurityClass, SemanticRef, TrustDomainId,
    event_spec, proof_kind,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::Result;
use crate::sdk_error::Error;

/// `semantic_refs[].role` the PCR genesis and the accountability grant use to name the
/// provision Event of their own creation unit.
pub const APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE: &str = "applet_managed_actor_provision";

/// `semantic_refs[].role` the managed actor Profile uses to name its accountability
/// grant.
pub const APPLET_MANAGED_ACTOR_ACCOUNTABILITY_REF_ROLE: &str = "accountability";

/// The four Event kinds of one Applet-managed actor creation unit, in the order
/// the unit is authored and submitted.
#[must_use]
pub fn applet_managed_actor_unit_event_kinds() -> [EventKind; 4] {
    [
        EventKind::AppletManagedActorProvision,
        EventKind::RealmCreate,
        EventKind::IdentityAccountabilityGrant,
        EventKind::ProfileCreate,
    ]
}

/// Runtime inputs that are deliberately outside the signed authoring request.
///
/// The Station supplies the signed branch basis. The authoring authority
/// supplies the independently held actor identity, the signed registration
/// Event ID and the PCR policy selected by its deployment.
#[derive(Clone, Debug)]
pub struct AppletManagedActorBundleAuthoringInput {
    /// Core id of the managed principal. Its account Station is the
    /// `target_station_id` named by the signed request basis.
    pub actor_id: DidCoreId,
    pub initial_resolution: ResolutionCommitment,
    /// Complete `did:webvh` history. Non-rotatable snapshots are rejected by the
    /// provision payload carrier.
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    /// Event ID of the exact Applet registration in the signed basis.
    ///
    /// The Ghost branch carries this inside its signed basis and the value
    /// supplied here MUST match it verbatim; the install-Bot basis carries the
    /// signed registration Event before its atomic acceptance.
    pub registration_ref: EventId,
    pub digest_suite: DigestSuite,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TrustDomainId,
    pub security_class: SecurityClass,
    pub initial_join_rule: JoinRule,
    pub initial_history_access: HistoryAccess,
    pub initial_discoverability: Discoverability,
    /// Used only for the install-Bot branch. Ghost display names come from the
    /// signed request basis.
    pub bot_display_name: String,
}

struct Branch {
    realm_scope: ScopeRef,
    service_id: DidCoreId,
    station_id: DidCoreId,
    applet_id: AppletId,
    registration_ref: EventId,
    authorization_ref: GrantId,
    role: AppletManagedActorRole,
    external_ref: Option<GhostExternalTuple>,
    display_name: String,
}

/// Build and sign the canonical managed-actor creation unit.
///
/// The returned bundle carries the four producer-signed Events in their fixed
/// order. Use [`applet_managed_actor_unit_submissions`] to obtain the
/// [`EventAdmissionSubmission`] carriers handed to the receiving Station.
pub fn author_applet_managed_actor_bundle<S: PayloadSigner + EventSigner + ?Sized>(
    request: &AppletManagedActorAuthoringRequest,
    input: AppletManagedActorBundleAuthoringInput,
    signer: &S,
) -> Result<AppletManagedActorAuthoringBundle> {
    request.validate_bindings()?;
    let branch = branch(request, &input)?;
    let AppletManagedActorBundleAuthoringInput {
        actor_id,
        initial_resolution,
        method_history_evidence,
        digest_suite,
        genesis_salt,
        trust_domain,
        security_class,
        initial_join_rule,
        initial_history_access,
        initial_discoverability,
        ..
    } = input;

    let created_at = request.issued_at;
    let verification_method = PayloadSigner::verification_method_id(signer).clone();
    let authorization_ref = AuthorizationRef::from(branch.authorization_ref.clone());
    let managed_actor_id =
        ActorId::account(AccountId::new(actor_id.clone(), branch.station_id.clone()));
    let service_actor_id = ActorId::service(branch.service_id.clone());

    let provision_payload = AppletManagedActorProvisionPayload {
        schema: AppletManagedActorProvisionPayload::SCHEMA.to_owned(),
        applet_id: branch.applet_id.clone(),
        service_id: branch.service_id.clone(),
        actor_id: managed_actor_id.clone(),
        actor_role: branch.role,
        initial_resolution: initial_resolution.clone(),
        method_history_evidence: method_history_evidence.try_into()?,
        registration_ref: branch.registration_ref.clone(),
        applet_authority_ref: branch.authorization_ref.clone(),
        external_ref: branch.external_ref.clone(),
    };
    provision_payload.validate()?;
    let provision_event = author_and_sign(
        TypedEventDraft::<event_spec::AppletManagedActorProvision>::new(
            branch.realm_scope.clone(),
            service_actor_id.clone(),
            provision_payload,
        )?
        .with_authorization_ref(authorization_ref.clone())
        .with_applet_id(branch.applet_id.clone())
        .into_intent(created_at)?,
        digest_suite,
        created_at,
        signer,
    )?;

    let genesis = RealmGenesis::new(
        RealmPurpose::AppletManagedControl,
        genesis_salt,
        trust_domain,
        security_class,
        branch.station_id.clone(),
        initial_join_rule,
        initial_history_access,
        initial_discoverability,
        None,
        Some(initial_resolution),
    )?;
    let pcr_genesis_event = author_and_sign(
        TypedEventDraft::<event_spec::RealmCreate>::new(
            ScopeRef::RealmGenesis,
            managed_actor_id.clone(),
            RealmCreatePayload::new(genesis),
        )?
        .with_executed_by(service_actor_id.clone())
        .with_authorization_ref(authorization_ref.clone())
        .with_applet_id(branch.applet_id.clone())
        .with_semantic_ref(SemanticRef::new(
            provision_event.event_id.as_str(),
            APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE,
        ))
        .into_intent(created_at)?,
        digest_suite,
        created_at,
        signer,
    )?;

    let mut accountability = AccountabilityGrantPayload::new(
        branch.service_id.clone(),
        actor_id.clone(),
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
    let accountability_grant_event = author_and_sign(
        TypedEventDraft::<event_spec::IdentityAccountabilityGrant>::new(
            branch.realm_scope.clone(),
            service_actor_id,
            accountability,
        )?
        .with_authorization_ref(authorization_ref.clone())
        .with_applet_id(branch.applet_id.clone())
        .with_semantic_ref(SemanticRef::new(
            provision_event.event_id.as_str(),
            APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE,
        ))
        .into_intent(created_at)?,
        digest_suite,
        created_at,
        signer,
    )?;

    let delegation = AppletDelegatedEventAuthorization::new(
        branch.service_id.clone(),
        authorization_ref,
        branch.applet_id.clone(),
    );
    delegation.validate()?;
    let profile_event = author_and_sign(
        profile_intent(
            &branch,
            actor_id,
            &delegation,
            managed_actor_id,
            SemanticRef::new(
                accountability_grant_event.event_id.as_str(),
                APPLET_MANAGED_ACTOR_ACCOUNTABILITY_REF_ROLE,
            ),
            created_at,
        )?,
        digest_suite,
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
    applet_managed_actor_unit_submissions(&bundle, request)?;
    Ok(bundle)
}

/// Check the closed four-Event unit and return its ordered submissions.
///
/// Every Event reaches the Station in the single submission carrier it accepts.
/// The unit is rejected when a kind is out of place, when a cross-binding does
/// not hold verbatim, or when the shared `authorization_ref` differs across the
/// four Events.
pub fn applet_managed_actor_unit_submissions(
    bundle: &AppletManagedActorAuthoringBundle,
    request: &AppletManagedActorAuthoringRequest,
) -> Result<[EventAdmissionSubmission; 4]> {
    let events = [
        &bundle.managed_actor_provision_event,
        &bundle.pcr_genesis_event,
        &bundle.accountability_grant_event,
        &bundle.profile_event,
    ];
    for (event, kind) in events.iter().zip(applet_managed_actor_unit_event_kinds()) {
        if event.kind != kind {
            return Err(protocol(&format!(
                "Applet-managed actor unit expects {} in this position, found {}",
                kind.as_str(),
                event.kind.as_str()
            )));
        }
        event.validate_for_submit_structural()?;
    }

    let provision = &bundle.managed_actor_provision_event;
    let payload: AppletManagedActorProvisionPayload =
        typed_payload(&bundle.managed_actor_provision_event)?;
    payload.validate()?;
    let authorization_ref = AuthorizationRef::from(payload.applet_authority_ref.clone());
    if events
        .iter()
        .any(|event| event.authorization_ref.as_ref() != Some(&authorization_ref))
        || events
            .iter()
            .any(|event| event.applet_id.as_ref() != Some(&payload.applet_id))
    {
        return Err(protocol(
            "Applet-managed actor unit requires one verbatim authorization_ref and applet_id across its four Events",
        ));
    }

    let service_actor_id = ActorId::service(payload.service_id.clone());
    if provision.actor_id != service_actor_id {
        return Err(protocol(
            "Applet-managed actor provision must be authored by its own registration service",
        ));
    }
    if let Some(basis) = request.basis.ghost()
        && basis.registration_event_ref != payload.registration_ref
    {
        return Err(protocol(
            "Applet-managed actor provision registration_ref does not match the signed basis",
        ));
    }

    let genesis = &bundle.pcr_genesis_event;
    let genesis_payload: RealmCreatePayload = typed_payload(genesis)?;
    genesis_payload.object.validate()?;
    let genesis_binds_provision = matches!(
        genesis.semantic_refs.as_slice(),
        [reference]
            if reference.role == APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE
                && reference.critical
                && reference.id == provision.event_id.as_str()
    );
    if !genesis_binds_provision
        || genesis.scope_ref != ScopeRef::RealmGenesis
        || genesis.actor_id != payload.actor_id
        || genesis.executed_by.as_ref() != Some(&service_actor_id)
        || genesis_payload.object.purpose != RealmPurpose::AppletManagedControl
        || genesis_payload.object.initial_resolution.as_ref() != Some(&payload.initial_resolution)
        || genesis_payload.object.governance_station_id != *payload.actor_id.route_service_id()
    {
        return Err(protocol(
            "Applet-managed PCR genesis does not cross-bind its own provision Event verbatim",
        ));
    }

    let accountability = &bundle.accountability_grant_event;
    let accountability_payload: AccountabilityGrantPayload = typed_payload(accountability)?;
    let accountability_binds_provision = accountability.semantic_refs.iter().any(|reference| {
        reference.role == APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE
            && reference.id == provision.event_id.as_str()
    });
    if !accountability_binds_provision
        || accountability.actor_id != service_actor_id
        || accountability_payload.issuer_id != payload.service_id
        || &accountability_payload.subject_id != payload.actor_id.signing_principal_id()
    {
        return Err(protocol(
            "Applet-managed accountability grant does not bind its provision Event, issuer and subject",
        ));
    }

    let profile = &bundle.profile_event;
    let profile_payload: ActorProfileCreatePayload = typed_payload(profile)?;
    let profile_binds_accountability = profile.semantic_refs.iter().any(|reference| {
        reference.role == APPLET_MANAGED_ACTOR_ACCOUNTABILITY_REF_ROLE
            && reference.id == accountability.event_id.as_str()
    });
    let expected_actor_kind = match payload.actor_role {
        AppletManagedActorRole::Bot => ActorKind::Bot,
        AppletManagedActorRole::Ghost => ActorKind::Integration,
    };
    if !profile_binds_accountability
        || profile.actor_id != payload.actor_id
        || profile.executed_by.as_ref() != Some(&service_actor_id)
        || &profile_payload.object.principal_id != payload.actor_id.signing_principal_id()
        || profile_payload.object.actor_kind != expected_actor_kind
        || !profile_payload
            .object
            .accountable_principal_ids
            .contains(&payload.service_id)
    {
        return Err(protocol(
            "Applet-managed actor Profile does not bind its accountability grant, principal and service",
        ));
    }

    bundle.validate_bindings(request)?;
    Ok([
        EventAdmissionSubmission::new(bundle.managed_actor_provision_event.clone()),
        EventAdmissionSubmission::new(bundle.pcr_genesis_event.clone()),
        EventAdmissionSubmission::new(bundle.accountability_grant_event.clone()),
        EventAdmissionSubmission::new(bundle.profile_event.clone()),
    ])
}

fn typed_payload<T: serde::de::DeserializeOwned>(event: &Event) -> Result<T> {
    Ok(serde_json::from_value(Value::Object(
        event.payload.clone().into_iter().collect(),
    ))?)
}

fn profile_intent(
    branch: &Branch,
    principal_id: DidCoreId,
    delegation: &AppletDelegatedEventAuthorization,
    managed_actor_id: ActorId,
    accountability_ref: SemanticRef,
    created_at: DateTime<Utc>,
) -> Result<EventIntent> {
    validate_display_name(&branch.display_name)?;
    let intent = match (&branch.external_ref, branch.role) {
        (Some(external_ref), AppletManagedActorRole::Ghost) => {
            let profile = GhostActorProfileRequest::new(
                principal_id,
                branch.display_name.clone(),
                branch.applet_id.clone(),
                external_ref.clone(),
            )
            .with_accountable_principal_ids(vec![branch.service_id.clone()]);
            profile.profile_create_intent(
                branch.realm_scope.clone(),
                managed_actor_id,
                created_at,
                Some(delegation),
            )?
        }
        (None, AppletManagedActorRole::Bot) => TypedEventDraft::<event_spec::ProfileCreate>::new(
            branch.realm_scope.clone(),
            managed_actor_id,
            ActorProfileCreatePayload {
                object: bot_profile(branch, principal_id),
            },
        )?
        .with_executed_by(ActorId::service(delegation.executed_by.clone()))
        .with_authorization_ref(delegation.authorization_ref.clone())
        .with_applet_id(delegation.applet_id.clone())
        .into_intent(created_at)?,
        _ => {
            return Err(protocol(
                "managed actor role and external_ref presence disagree",
            ));
        }
    };
    Ok(intent.with_semantic_refs(vec![accountability_ref]))
}

fn bot_profile(branch: &Branch, principal_id: DidCoreId) -> ActorProfileDefinition {
    ActorProfileDefinition {
        principal_id,
        actor_kind: ActorKind::Bot,
        display_name: branch.display_name.clone(),
        handle: None,
        agent_slug: None,
        avatar_blob_ref: None,
        accountable_principal_ids: vec![branch.service_id.clone()],
        profile_fields: BTreeMap::from([(
            "managed_by_applet".to_owned(),
            Value::String(branch.applet_id.to_string()),
        )]),
    }
}

fn branch(
    request: &AppletManagedActorAuthoringRequest,
    input: &AppletManagedActorBundleAuthoringInput,
) -> Result<Branch> {
    match request.purpose {
        AppletManagedActorPurpose::InstallBot => {
            let basis = request
                .basis
                .install()
                .ok_or_else(|| protocol("install-Bot request has the wrong basis branch"))?;
            let realm_id = basis
                .effective_scope
                .realm_id_opt()
                .ok_or_else(|| protocol("install-Bot request has no exact Realm scope"))?
                .clone();
            let grant_event = basis
                .capability_grant_events
                .first()
                .ok_or_else(|| protocol("install-Bot request has no authority grant"))?;
            Ok(Branch {
                realm_scope: ScopeRef::Realm { realm_id },
                service_id: basis.service_id.clone(),
                station_id: basis.target_station_id.clone(),
                applet_id: basis.applet_id.clone(),
                registration_ref: input.registration_ref.clone(),
                authorization_ref: GrantId::from_event_id(&grant_event.event_id),
                role: AppletManagedActorRole::Bot,
                external_ref: None,
                display_name: input.bot_display_name.clone(),
            })
        }
        AppletManagedActorPurpose::ProvisionGhost => {
            let basis = request
                .basis
                .ghost()
                .ok_or_else(|| protocol("Ghost request has the wrong basis branch"))?;
            if basis.registration_event_ref != input.registration_ref {
                return Err(protocol(
                    "Ghost authoring registration_ref must equal the signed basis registration_event_ref",
                ));
            }
            Ok(Branch {
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

fn validate_display_name(display_name: &str) -> Result<()> {
    if display_name.trim().is_empty() || display_name.chars().count() > 128 {
        return Err(protocol(
            "managed actor display name must contain 1..=128 characters",
        ));
    }
    Ok(())
}

fn author_and_sign<S: EventSigner + ?Sized>(
    intent: EventIntent,
    digest_suite: DigestSuite,
    proof_created_at: DateTime<Utc>,
    signer: &S,
) -> Result<Event> {
    let mut event = intent.author_with_digest_suite(digest_suite)?;
    sign_event(
        &mut event,
        signer,
        SignEventOptions::new().with_created_at(proof_created_at),
    )?;
    Ok(event.into_event())
}

fn zero_hash() -> Result<Hash> {
    Hash::new(format!("sha256:{}", "00".repeat(32))).map_err(Into::into)
}

fn protocol(message: &str) -> Error {
    Error::Protocol(message.to_owned())
}
