//! Producer-side contract for the closed four-Event Applet-managed actor unit.
//!
//! `zh/extensions/applet-integration.md` section 9.1 and
//! `zh/identity/key-management.md` section 3.6.3 both require the producer to
//! call this unified authoring API and to hand the receiving Station exactly
//! four cross-bound Events, each in the single `EventAdmissionSubmission` carrier.

use arkret::{
    APPLET_MANAGED_ACTOR_ACCOUNTABILITY_REF_ROLE, APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE,
    AppletDidMethodVersionEvidence, AppletGhostAuthoringRequestBasis,
    AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest,
    AppletManagedActorBundleAuthoringInput, AppletManagedActorProvisionPayload,
    AppletManagedActorPurpose, AppletRegistrationEpochEvidence, GhostExternalTuple,
    applet_managed_actor_unit_event_kinds, applet_managed_actor_unit_submissions,
    author_applet_managed_actor_bundle,
};
use arkret_canonical::DigestSuite;
use arkret_models_identity::did_document::DidDocument;
use arkret_models_identity::{
    ResolutionCommitment, ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
    ResolutionDidBindingMethodProof, ResolutionDidBindingMethodProofKind,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_wire::{
    AppletId, Did, DidCoreId, DidUrl, Discoverability, EventId, GenesisSalt, GrantId, Hash,
    HistoryAccess, JoinRule, RealmId, ScopeRef, SecurityClass, TrustDomainId,
};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

const STATION_DID: &str = "did:webvh:zstationscid:station.example";
const SERVICE_DID: &str = "did:webvh:zservicescid:applet.example";
const GHOST_DID: &str = "did:webvh:zghostscid:applet.example:actors:slack:u123";

fn issued_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap()
}

fn did(value: &str) -> Did {
    Did::new(value.to_owned()).unwrap()
}

fn core_id(value: &str) -> DidCoreId {
    arkret_wire::project_did_to_core_id(&did(value)).unwrap()
}

fn signer(seed: u8, subject: &str) -> Ed25519PayloadSigner {
    Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[seed; 32]),
        did(subject),
        DidUrl::new(format!("{subject}#key-1")).unwrap(),
    )
}

fn realm_id() -> RealmId {
    RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x21; 32]))
}

fn applet_id() -> AppletId {
    AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
}

fn grant_id() -> GrantId {
    GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x33; 32]))
}

fn hash(byte: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn registration_ref() -> EventId {
    EventId::from_digest(DigestSuite::Sha256, [0x44; 32])
}

fn external_ref() -> GhostExternalTuple {
    GhostExternalTuple {
        protocol: "slack".to_owned(),
        instance_id: "t123".to_owned(),
        external_id: "u123".to_owned(),
    }
}

fn registration_epoch_evidence() -> AppletRegistrationEpochEvidence {
    let document = DidDocument::new(
        did(SERVICE_DID),
        "key-1",
        "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
    );
    AppletRegistrationEpochEvidence::from_did_document(
        &document,
        AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some("1-ghost-provision-fixture".to_owned()),
            None,
        )
        .unwrap(),
    )
    .unwrap()
}

fn initial_resolution() -> ResolutionCommitment {
    ResolutionCommitment {
        did: did(GHOST_DID),
        method_history_head: "head-1".to_owned(),
        version_id: "1-ghost".to_owned(),
    }
}

fn method_history_evidence() -> ResolutionMethodHistoryEvidence {
    ResolutionMethodHistoryEvidence::WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: "head-0".to_owned(),
            from_version_id: "0-ghost".to_owned(),
            to_method_history_head: "head-1".to_owned(),
            to_version_id: "1-ghost".to_owned(),
        },
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".to_owned(),
            document_digest: hash(0x55),
            method_proofs: vec![ResolutionDidBindingMethodProof {
                kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                history_head: "head-1".to_owned(),
                witnesses: Vec::new(),
                witness_proofs_digest: hash(0x66),
            }],
        },
        log_entries: vec![json!({"versionId": "1-ghost"})],
        witness_records: Vec::new(),
    }
}

fn ghost_authoring_request() -> AppletManagedActorAuthoringRequest {
    let station = signer(0x11, STATION_DID);
    let basis = AppletGhostAuthoringRequestBasis {
        schema: AppletGhostAuthoringRequestBasis::SCHEMA.to_owned(),
        purpose: AppletManagedActorPurpose::ProvisionGhost,
        target_station_id: core_id(STATION_DID),
        applet_id: applet_id(),
        service_id: core_id(SERVICE_DID),
        effective_scope: ScopeRef::Realm {
            realm_id: realm_id(),
        },
        existing_managed_actor: None,
        external_ref: external_ref(),
        display_name: Some("Alice on Slack".to_owned()),
        registration_event_ref: registration_ref(),
        authorization_ref: grant_id(),
        registration_epoch_evidence: registration_epoch_evidence(),
        package_digest: hash(0x77),
    };
    AppletManagedActorAuthoringRequest::sign_ghost(
        basis,
        core_id(STATION_DID),
        issued_at(),
        issued_at() + chrono::Duration::minutes(2),
        &station,
    )
    .unwrap()
}

fn authoring_input() -> AppletManagedActorBundleAuthoringInput {
    AppletManagedActorBundleAuthoringInput {
        actor_id: core_id(GHOST_DID),
        initial_resolution: initial_resolution(),
        method_history_evidence: method_history_evidence(),
        registration_ref: registration_ref(),
        digest_suite: DigestSuite::Sha256,
        genesis_salt: GenesisSalt::generate().unwrap(),
        trust_domain: TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
        security_class: SecurityClass::HighAssurance,
        initial_join_rule: JoinRule::Closed,
        initial_history_access: HistoryAccess::SinceJoin,
        initial_discoverability: Discoverability::Secret,
        bot_display_name: "unused for the Ghost branch".to_owned(),
    }
}

fn authored_unit() -> (
    AppletManagedActorAuthoringRequest,
    AppletManagedActorAuthoringBundle,
) {
    let request = ghost_authoring_request();
    let service = signer(0x22, SERVICE_DID);
    let bundle = author_applet_managed_actor_bundle(&request, authoring_input(), &service).unwrap();
    (request, bundle)
}

#[test]
fn authoring_emits_exactly_the_four_spec_events_in_order() {
    let (request, bundle) = authored_unit();

    let submissions = applet_managed_actor_unit_submissions(&bundle, &request).unwrap();
    let kinds = applet_managed_actor_unit_event_kinds();
    assert_eq!(
        kinds
            .iter()
            .map(arkret_wire::EventKind::as_str)
            .collect::<Vec<_>>(),
        vec![
            "ak.applet.managed_actor.provision",
            "ak.realm.create",
            "ak.identity.accountability_grant",
            "ak.profile.create",
        ]
    );
    for (submission, kind) in submissions.iter().zip(kinds) {
        assert_eq!(submission.event.kind, kind);
    }

    assert_eq!(submissions[0].event, bundle.managed_actor_provision_event);
    assert_eq!(submissions[1].event, bundle.pcr_genesis_event);
    assert_eq!(submissions[2].event, bundle.accountability_grant_event);
    assert_eq!(submissions[3].event, bundle.profile_event);
}

#[test]
fn every_event_of_the_unit_shares_one_authorization_ref() {
    let (_, bundle) = authored_unit();
    let expected = bundle
        .managed_actor_provision_event
        .authorization_ref
        .clone()
        .expect("provision carries the Applet capability grant");
    for event in [
        &bundle.pcr_genesis_event,
        &bundle.accountability_grant_event,
        &bundle.profile_event,
    ] {
        assert_eq!(event.authorization_ref.as_ref(), Some(&expected));
    }
}

#[test]
fn provision_registration_ref_is_a_precommit_event_id_on_the_wire() {
    let (_, bundle) = authored_unit();
    let payload: AppletManagedActorProvisionPayload = serde_json::from_value(
        serde_json::to_value(&bundle.managed_actor_provision_event.payload).unwrap(),
    )
    .unwrap();
    assert_eq!(payload.registration_ref, registration_ref());
    let mut encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["registration_ref"], registration_ref().as_str());
    let restored: AppletManagedActorProvisionPayload =
        serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(restored, payload);
    encoded["registration_ref"] = serde_json::json!({"event_id": registration_ref()});
    assert!(serde_json::from_value::<AppletManagedActorProvisionPayload>(encoded).is_err());
}

#[test]
fn the_unit_cross_binds_provision_genesis_accountability_and_profile() {
    let (_, bundle) = authored_unit();

    let genesis_ref = bundle
        .pcr_genesis_event
        .semantic_refs
        .iter()
        .find(|reference| reference.role == APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE)
        .expect("PCR genesis names its provision Event");
    assert!(genesis_ref.critical);
    assert_eq!(
        genesis_ref.id,
        bundle.managed_actor_provision_event.event_id.as_str()
    );

    assert!(
        bundle
            .accountability_grant_event
            .semantic_refs
            .iter()
            .any(
                |reference| reference.role == APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE
                    && reference.id == bundle.managed_actor_provision_event.event_id.as_str()
            )
    );
    assert!(
        bundle
            .profile_event
            .semantic_refs
            .iter()
            .any(
                |reference| reference.role == APPLET_MANAGED_ACTOR_ACCOUNTABILITY_REF_ROLE
                    && reference.id == bundle.accountability_grant_event.event_id.as_str()
            )
    );
}

#[test]
fn an_absent_event_cannot_deserialize_as_a_closed_unit() {
    let (_, bundle) = authored_unit();
    for absent in [
        "managed_actor_provision_event",
        "pcr_genesis_event",
        "accountability_grant_event",
        "profile_event",
    ] {
        let mut value = serde_json::to_value(&bundle).unwrap();
        value
            .as_object_mut()
            .expect("bundle serializes as an object")
            .remove(absent)
            .expect("the removed member was present");
        assert!(
            serde_json::from_value::<AppletManagedActorAuthoringBundle>(value).is_err(),
            "a unit without {absent} must not deserialize"
        );
    }
}

#[test]
fn a_reordered_unit_is_rejected() {
    let (request, mut reordered) = authored_unit();
    std::mem::swap(
        &mut reordered.accountability_grant_event,
        &mut reordered.profile_event,
    );
    let error = applet_managed_actor_unit_submissions(&reordered, &request)
        .expect_err("a reordered unit must fail closed");
    assert!(
        error
            .to_string()
            .contains("ak.identity.accountability_grant"),
        "{error}"
    );
}

#[test]
fn a_genesis_that_names_another_provision_is_rejected() {
    let (request, mut mis_bound) = authored_unit();
    mis_bound.pcr_genesis_event.semantic_refs[0].id =
        EventId::from_digest(DigestSuite::Sha256, [0x99; 32]).to_string();
    let error = applet_managed_actor_unit_submissions(&mis_bound, &request)
        .expect_err("a genesis bound to a foreign provision must fail closed");
    assert!(error.to_string().contains("PCR genesis"), "{error}");
}

#[test]
fn a_profile_that_drops_its_accountability_ref_is_rejected() {
    let (request, mut mis_bound) = authored_unit();
    mis_bound.profile_event.semantic_refs.clear();
    let error = applet_managed_actor_unit_submissions(&mis_bound, &request)
        .expect_err("a Profile without its accountability ref must fail closed");
    assert!(error.to_string().contains("Profile"), "{error}");
}

/// `zh/discovery/profiles-presence.md` section 2.3: `ak.profile.create` is
/// principal-scoped and its Realm MUST be the actor's principal control Realm,
/// which is the Realm the unit's own PCR genesis founds.
#[test]
fn the_profile_is_written_to_the_managed_actor_principal_control_realm() {
    let (_, bundle) = authored_unit();
    let pcr_realm_id = RealmId::from_event_id(&bundle.pcr_genesis_event.event_id);
    assert_eq!(bundle.profile_event.realm_id, pcr_realm_id);
    assert_eq!(
        bundle.profile_event.scope_ref,
        ScopeRef::Realm {
            realm_id: pcr_realm_id
        }
    );
    for event in [
        &bundle.managed_actor_provision_event,
        &bundle.accountability_grant_event,
    ] {
        assert_eq!(event.realm_id, realm_id());
    }
}

#[test]
fn a_profile_outside_the_principal_control_realm_is_rejected() {
    let (request, mut mis_scoped) = authored_unit();
    mis_scoped.profile_event.realm_id = realm_id();
    mis_scoped.profile_event.scope_ref = ScopeRef::Realm {
        realm_id: realm_id(),
    };
    let error = applet_managed_actor_unit_submissions(&mis_scoped, &request)
        .expect_err("a Profile written to the portal Realm must fail closed");
    assert!(
        error.to_string().contains("principal control Realm"),
        "{error}"
    );
}

#[test]
fn a_registration_ref_outside_the_signed_basis_is_rejected() {
    let request = ghost_authoring_request();
    let service = signer(0x22, SERVICE_DID);
    let mut input = authoring_input();
    input.registration_ref = EventId::from_digest(DigestSuite::Sha256, [0xaa; 32]);
    let error = author_applet_managed_actor_bundle(&request, input, &service)
        .expect_err("an unpinned registration Event ID must fail closed");
    assert!(error.to_string().contains("registration_ref"), "{error}");
}

/// One producer-side round trip: the authored unit satisfies the receiver-side
/// binding check verbatim.
///
/// The authoring API and the receiver share one implementation of the
/// cross-binding rules — `applet_managed_actor_unit_submissions` is the only
/// place they are written, and it ends by calling
/// `AppletManagedActorAuthoringBundle::validate_bindings`, so the producer
/// cannot satisfy a rule the receiver does not apply.
#[test]
fn an_authored_unit_passes_the_receiver_side_binding_check() {
    let (request, bundle) = authored_unit();

    bundle
        .validate_bindings(&request)
        .expect("the authored bundle binds its own signed authoring request");

    let submissions = applet_managed_actor_unit_submissions(&bundle, &request)
        .expect("the receiver accepts the authored unit");
    assert_eq!(submissions.len(), 4);

    // The same check refuses a bundle re-pointed at another signed request.
    let mut foreign = request.clone();
    foreign.issued_at = request.issued_at + chrono::Duration::seconds(1);
    assert!(
        bundle.validate_bindings(&foreign).is_err(),
        "a bundle must not validate against a request it was not authored for"
    );
    assert!(applet_managed_actor_unit_submissions(&bundle, &foreign).is_err());
}

// These tests cover native PCR Commit identity/signature and structural context
// binding. Method history fixtures do not establish a live admission or DID trust.
fn signed_pcr_commit(
    event: &arkret_wire::Event,
    previous: Option<&arkret_wire::RealmCommit>,
    ordinary_fact: Option<Hash>,
) -> arkret_wire::RealmCommit {
    use arkret_signatures::detached_object::{
        sign_detached_object, verify_detached_object_signature,
    };
    let key = SigningKey::from_bytes(&[0x11; 32]);
    let method = DidUrl::new(format!("{STATION_DID}#key-1")).unwrap();
    let mut commit = arkret_wire::RealmCommit {
        commit_id: arkret_wire::RealmCommitId::from_digest([0; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        stream_position: previous.map_or(0, |p| p.stream_position + 1),
        previous_commit_ref: previous.map(|p| p.commit_id.clone()),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: previous.map_or_else(
            || arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
            |p| p.authority_ref.clone(),
        ),
        committed_at: event.created_at,
        producer_signer_fact_digest: ordinary_fact,
        signature: sign_detached_object(
            &json!({}),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            method.clone(),
            event.created_at,
            &key,
        )
        .unwrap(),
    };
    let preimage = arkret_canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&preimage).unwrap(),
    ));
    let unsigned = arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        method,
        event.created_at,
        &key,
    )
    .unwrap();
    commit.validate_content_address().unwrap();
    verify_detached_object_signature(
        &commit.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    commit
}

fn context_for_pcr(
    request: AppletManagedActorAuthoringRequest,
    bundle: AppletManagedActorAuthoringBundle,
    pcr: arkret_wire::RealmCommit,
) -> arkret_models_integration::AppletManagedActorAuthoringContext {
    use arkret_models_identity::authenticated_signer_resolution_evidence::{
        build_principal_signer_evidence, build_service_signer_evidence,
    };
    let jwk = |seed: u8| -> arkret_wire::NonEmptyJsonObject {
        serde_json::from_value(json!({"kty":"OKP", "crv":"Ed25519", "x":arkret_canonical::base64url_encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())})).unwrap()
    };
    let portal_head = arkret_wire::RealmCommitId::from_digest([0x81; 32]);
    let service = build_service_signer_evidence(
        core_id(SERVICE_DID),
        DidUrl::new(format!("{SERVICE_DID}#key-1")).unwrap(),
        jwk(0x22),
        portal_head.clone(),
        issued_at(),
    )
    .unwrap();
    let principal = build_principal_signer_evidence(
        core_id(GHOST_DID),
        DidUrl::new(format!("{GHOST_DID}#key-1")).unwrap(),
        jwk(0x33),
        pcr.commit_id.clone(),
        pcr.committed_at,
    )
    .unwrap();
    let attester = build_service_signer_evidence(
        core_id(STATION_DID),
        pcr.signature.verification_method.clone(),
        jwk(0x11),
        pcr.commit_id.clone(),
        pcr.committed_at,
    )
    .unwrap();
    arkret_models_integration::AppletManagedActorAuthoringContext {
        committed_request: arkret_models_integration::AppletManagedActorCommittedRequest::Ghost(
            Box::new(arkret_models_integration::GhostActorProvisionRequestBody {
                authoring_request: request,
                managed_actor_bundle: Some(bundle),
                approval_signatures: vec![],
                existing_managed_actor: None,
            }),
        ),
        realm_stream_head: arkret_wire::CommitStreamHead {
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: 12,
            commit_id: portal_head,
        },
        principal_control_commit: pcr,
        applet_service_signer_evidence: arkret_models_integration::AppletServiceSignerEvidence {
            signer_resolution_evidence_ref: service.signer_evidence_ref().unwrap(),
            authenticated_signer_evidence: service,
        },
        managed_actor_signer_evidence:
            arkret_models_integration::ManagedActorPrincipalSignerEvidence {
                signer_resolution_evidence_ref: principal.signer_evidence_ref().unwrap(),
                authenticated_signer_evidence: principal,
                attester_signer_evidence: attester,
            },
        resolution_update: None,
    }
}

#[test]
fn native_pcr_completion_requires_original_content_id_and_excludes_ordinary_fact() {
    let (request, bundle) = authored_unit();
    let valid = signed_pcr_commit(&bundle.pcr_genesis_event, None, None);
    context_for_pcr(request.clone(), bundle.clone(), valid.clone())
        .validate()
        .unwrap();
    let mut changed = valid;
    changed.commit_id = arkret_wire::RealmCommitId::from_digest([0x82; 32]);
    assert!(
        context_for_pcr(request.clone(), bundle.clone(), changed)
            .validate()
            .is_err()
    );
    // A correctly re-ID'd and signed Commit must still fail the native gate.
    let forbidden = signed_pcr_commit(&bundle.pcr_genesis_event, None, Some(hash(0x99)));
    assert!(
        context_for_pcr(request, bundle, forbidden)
            .validate()
            .is_err()
    );
}

#[test]
fn native_pcr_resolution_lineage_requires_original_content_ids_and_no_ordinary_facts() {
    use arkret_event_draft::TypedEventDraft;
    use arkret_wire::{AccountId, ActorId, event_spec};
    let (_, bundle) = authored_unit();
    let genesis = signed_pcr_commit(&bundle.pcr_genesis_event, None, None);
    let next = ResolutionCommitment {
        did: did(GHOST_DID),
        method_history_head: "head-2".into(),
        version_id: "2-ghost".into(),
    };
    let intent = TypedEventDraft::<event_spec::IdentityResolutionUpdate>::new(
        ScopeRef::Realm {
            realm_id: genesis.realm_id.clone(),
        },
        ActorId::account(AccountId::new(core_id(GHOST_DID), core_id(STATION_DID))),
        arkret_models_identity::PrincipalResolutionUpdatePayload { next },
    )
    .unwrap()
    .into_intent(issued_at() + chrono::Duration::seconds(1))
    .unwrap();
    let mut authored = intent
        .author_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &signer(0x33, GHOST_DID),
        arkret_signatures::SignEventOptions::new()
            .with_created_at(issued_at() + chrono::Duration::seconds(1)),
    )
    .unwrap();
    let resolution_event = authored.into_event();
    let successor = signed_pcr_commit(&resolution_event, Some(&genesis), None);
    let evidence = arkret_models_integration::ManagedActorResolutionUpdateEvidence {
        resolution_event: resolution_event.clone(),
        commits: vec![genesis.clone(), successor],
        method_history_evidence: method_history_evidence(),
        attester_resolution: arkret_models_identity::AuthenticatedServiceResolution {
            service_id: core_id(STATION_DID),
            service_kind: "station".into(),
            method_history_evidence: method_history_evidence(),
            normalized_did_document: DidDocument::new(
                did(STATION_DID),
                "key-1",
                "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
            ),
        },
    };
    evidence.validate_shape().unwrap();
    let mut wrong_id = evidence.clone();
    wrong_id.commits[1].commit_id = arkret_wire::RealmCommitId::from_digest([0x82; 32]);
    assert!(wrong_id.validate_shape().is_err());
    let mut ordinary = evidence;
    ordinary.commits[1] = signed_pcr_commit(&resolution_event, Some(&genesis), Some(hash(0x99)));
    assert!(ordinary.validate_shape().is_err());
}
