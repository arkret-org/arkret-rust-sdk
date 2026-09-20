use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use arkret_canonical as canonical;
use arkret_models_identity::DidDocument;
use arkret_models_identity::authenticated_signer_resolution_evidence::{
    AuthenticatedSignerKind, AuthenticatedSignerResolutionEvidence,
    build_principal_signer_evidence, build_service_signer_evidence,
};
use arkret_models_integration::{
    AppletDidMethodVersionEvidence, AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod,
    AppletInstallAuthoringRequestBasis, AppletInstallCreateRequestBody, AppletInstallPlan,
    AppletInstallPreviewRequestBody, AppletInstallRequestBody, AppletManagedActorAuthoringBundle,
    AppletManagedActorAuthoringContext, AppletManagedActorAuthoringRequest,
    AppletManagedActorCommittedRequest, AppletManagedActorProof, AppletManagedActorPurpose,
    AppletNamespaceDomain, AppletNamespaceEntry, AppletPackage, AppletPingOutcome,
    AppletRegistrationEpochEvidence, AppletRegistrationEpochTranscript, AppletRegistrationPayload,
    AppletServiceSignerEvidence, AppletTransactionOutcome, AppletWireNamespaces, DetachedProof,
    E2eeEffect, HttpMessageSignatureAlgorithm, ManagedActorPrincipalSignerEvidence, WebhookAuth,
    WidgetEffect,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_wire::{
    ActorId, AppletId, CircleId, CommitStreamHead, CommitStreamRef, CommittedEventRef, Did,
    DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyJsonObject, PayloadSignature, PayloadSigner,
    PlanId, ProducerEventProof, RealmCommitId, RealmId, Result as WireResult, ScopeRef, SidecarId,
    SignerEvidenceRef,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

struct StubSigner {
    did: Did,
    verification_method: DidUrl,
}

impl PayloadSigner for StubSigner {
    fn signer_did(&self) -> &Did {
        &self.did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.verification_method
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> WireResult<PayloadSignature> {
        let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))?;
        Ok(PayloadSignature {
            verification_method: self.verification_method.clone(),
            payload_digest: payload_digest.clone(),
            created_at: canonical_now(),
            jws: stub_detached_jws(&payload_digest),
        })
    }
}

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:{name}:{name}.example")).unwrap()
}

fn actor(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:webvh:{name}")).unwrap()
}

fn principal(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:webvh:{name}")).unwrap()
}

fn service(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:webvh:{name}")).unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
}

fn sample_epoch() -> Hash {
    Hash::new(format!("sha256:{}", "bb".repeat(32))).unwrap()
}

fn canonical_now() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
}

/// Attach the one structural-only producer proof the wire contract requires of
/// every caller-signed Event embedded in an authoring basis or bundle.
fn with_caller_proof(mut event: Event, verification_method: &DidUrl) -> Event {
    let event_digest = Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let jws = arkret_wire::test_support::structural_only_detached_jws(&event_digest);
    event.producer_proof = Some(ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws,
    });
    event
}

fn governance_station_id() -> DidCoreId {
    actor("station")
}

fn committed_ref(stream_ref: CommitStreamRef, seed: u8, stream_position: u64) -> CommittedEventRef {
    CommittedEventRef {
        event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]),
        commit_id: RealmCommitId::from_digest([seed.wrapping_add(1); 32]),
        stream_ref,
        stream_position,
    }
}

fn sample_epoch_evidence(service_id: &DidCoreId) -> AppletRegistrationEpochEvidence {
    let document = DidDocument::new(
        did(service_id.as_str().rsplit(':').next().unwrap()),
        "key-1",
        "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
    );
    AppletRegistrationEpochEvidence::from_did_document(
        &document,
        AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some("QmSdkAppletTestVersion1".to_owned()),
            None,
        )
        .unwrap(),
    )
    .unwrap()
}

/// Deterministic detached compact JWS for the stub signer. Only the digest hex
/// enters the signature segment because `sha256:` is not a base64url character
/// and the wire pattern for `proof.jws` admits base64url segments only.
fn stub_detached_jws(payload_digest: &Hash) -> String {
    format!(
        "eyJhbGciOiJFZDI1NTE5In0..{}",
        payload_digest
            .as_str()
            .rsplit(':')
            .next()
            .unwrap_or_default()
    )
}

fn sample_wire_registration() -> AppletRegistrationPayload {
    let mut package = package_with_required_fields();
    let evidence = sample_epoch_evidence(&package.service_id);
    package.stamp_registration_epoch(&evidence).unwrap();
    package.stamp_package_digest().unwrap();
    package.proof = Some(DetachedProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        payload_digest: sample_epoch(),
        created_at: canonical_now(),
        domain: None,
        audience: None,
        jws: "header..sig".to_owned(),
        extra: Default::default(),
    });
    package.to_registration(&evidence).unwrap()
}

#[test]
fn exclusive_namespace_claims_conflict_only_within_the_same_domain() {
    let exclusive_pattern = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::exclusive(
            "did:webvh:z6mkmanagedfixture:actors.example:managed:*",
        )],
        ..Default::default()
    };
    let exclusive_concrete = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::exclusive(
            "did:webvh:z6mkmanagedfixture:actors.example:managed:u1",
        )],
        ..Default::default()
    };
    let conflicts = exclusive_pattern.conflicts_with(&exclusive_concrete);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].domain, AppletNamespaceDomain::Actors);

    let shared_pattern = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::shared(
            "did:webvh:z6mkmanagedfixture:actors.example:managed:*",
        )],
        ..Default::default()
    };
    let shared_concrete = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::shared(
            "did:webvh:z6mkmanagedfixture:actors.example:managed:u1",
        )],
        ..Default::default()
    };
    assert!(shared_pattern.conflicts_with(&shared_concrete).is_empty());

    let realm_only = AppletWireNamespaces {
        realms: vec![AppletNamespaceEntry::exclusive("slack:team:*")],
        ..Default::default()
    };
    assert!(exclusive_pattern.conflicts_with(&realm_only).is_empty());
}

fn package_with_required_fields() -> AppletPackage {
    let mut package = AppletPackage::new(
        "applet_pkg_todo",
        AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
        service("slackbridge"),
        did("slackbridge"),
        principal("alice"),
        "https://applet.example/cx",
        ActorId::account(arkret_wire::AccountId::new(actor("bot"), actor("station"))),
        vec!["slack".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(
                "did:webvh:z6mkmanagedfixture:actors.example:managed:*",
            )],
            realms: vec![],
            handles: vec![],
        },
    );
    package.requested_scopes = vec!["ak.message.create".to_owned()];
    package.endpoint_policy.endpoints.push(AppletEndpointEntry {
        method: AppletEndpointMethod::Post,
        path: "/_arkret/edge/applet/transactions".to_owned(),
        auth: Some(AppletEndpointAuth::WebhookSignature),
        description: None,
        extra: Default::default(),
    });
    package.webhook_auth = WebhookAuth::http_message_signature(
        DidUrl::new(format!("{}#key-1", did("slackbridge"))).unwrap(),
        vec![HttpMessageSignatureAlgorithm::Ed25519],
    );
    package
}

fn stamp_and_sign_test_package(package: &mut AppletPackage) {
    package.stamp_package_digest().unwrap();
    let verification_method = package.webhook_auth.key_ref.clone();
    let signer = StubSigner {
        did: did("slackbridge"),
        verification_method: verification_method.clone(),
    };
    package.sign(&signer, &verification_method).unwrap();
}

fn finalized_package_with_required_fields() -> AppletPackage {
    let mut package = package_with_required_fields();
    let evidence = sample_epoch_evidence(&package.service_id);
    package.stamp_registration_epoch(&evidence).unwrap();
    stamp_and_sign_test_package(&mut package);
    package
}
#[test]
fn wire_registration_round_trips_with_the_exact_package_proof() {
    let registration = sample_wire_registration();
    let value = serde_json::to_value(&registration).unwrap();
    assert!(value.get("kind").is_none());
    let round_trip: AppletRegistrationPayload = serde_json::from_value(value).unwrap();
    assert_eq!(round_trip.applet_id, registration.applet_id);
    assert_eq!(round_trip.namespaces.actors, registration.namespaces.actors);
    assert_eq!(round_trip.proof, registration.proof);
}

#[test]
fn wire_registration_rejects_missing_and_recursively_unknown_fields() {
    let value = serde_json::to_value(sample_wire_registration()).unwrap();

    let mut missing_claimed_profiles = value.clone();
    missing_claimed_profiles
        .as_object_mut()
        .unwrap()
        .remove("claimed_profiles");
    assert!(serde_json::from_value::<AppletRegistrationPayload>(missing_claimed_profiles).is_err());

    let mut unknown_top_level = value.clone();
    unknown_top_level["unknown_member"] = json!(true);
    assert!(serde_json::from_value::<AppletRegistrationPayload>(unknown_top_level).is_err());

    let mut unknown_manifest = value.clone();
    unknown_manifest["manifest"]["unknown_member"] = json!(true);
    assert!(serde_json::from_value::<AppletRegistrationPayload>(unknown_manifest).is_err());

    let mut old_event_digest_proof = value;
    let proof = old_event_digest_proof["proof"].as_object_mut().unwrap();
    let digest = proof.remove("payload_digest").unwrap();
    proof.insert("event_digest".to_owned(), digest);
    assert!(serde_json::from_value::<AppletRegistrationPayload>(old_event_digest_proof).is_err());
}

#[test]
fn applet_package_derives_registration_and_rejects_stale_epoch() {
    let mut package = package_with_required_fields();
    let evidence = sample_epoch_evidence(&package.service_id);
    package.stamp_registration_epoch(&evidence).unwrap();
    assert!(package.validate().is_err());

    package.stamp_package_digest().unwrap();
    package.proof = Some(DetachedProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        payload_digest: package.package_digest.clone().unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: "header..sig".to_owned(),
        extra: Default::default(),
    });
    package.validate().unwrap();
    package.validate_with_epoch_evidence(&evidence).unwrap();
    let mut carried_payload = package.clone();
    carried_payload.proof.as_mut().unwrap().jws = "header.payload.sig".to_owned();
    assert!(carried_payload.validate().is_err());

    let registration = package.to_registration(&evidence).unwrap();
    assert_eq!(registration.registration_epoch, package.registration_epoch);
    assert_eq!(registration.namespaces, package.namespaces);
    assert_eq!(registration.manifest.registration_epoch_evidence, evidence);
    let registration_value = serde_json::to_value(&registration).unwrap();
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.applet.registration", &registration_value)
        .unwrap();

    let mut stale = package;
    stale.base_url = "https://other.example/cx".to_owned();
    assert!(stale.validate().is_err());
    assert!(stale.validate_with_epoch_evidence(&evidence).is_err());
}

#[test]
fn applet_package_rejects_invalid_extensions_and_missing_base_profile() {
    let mut package = package_with_required_fields();
    assert!(
        package
            .endpoint_policy
            .extra
            .insert("unexpected".to_owned(), Value::Bool(true))
            .is_err()
    );

    let mut missing_profile = package_with_required_fields();
    missing_profile.claimed_profiles = vec!["ak.profile.applet_bridge.v1".to_owned()];
    let evidence = sample_epoch_evidence(&missing_profile.service_id);
    missing_profile.stamp_registration_epoch(&evidence).unwrap();
    missing_profile.stamp_package_digest().unwrap();
    assert!(missing_profile.validate().is_err());
}

#[test]
fn applet_package_rejects_install_evidence_as_an_unknown_member() {
    let package = package_with_required_fields();
    let evidence = sample_epoch_evidence(&package.service_id);
    let mut value = serde_json::to_value(&package).unwrap();
    value["registration_epoch_evidence"] = serde_json::to_value(evidence).unwrap();
    assert!(serde_json::from_value::<AppletPackage>(value).is_err());

    let mut malformed_id = serde_json::to_value(package).unwrap();
    malformed_id["applet_id"] = json!("did:web:malformed-applet.example");
    assert!(serde_json::from_value::<AppletPackage>(malformed_id).is_err());
}

#[test]
fn closed_registration_transcript_and_namespace_carriers_reject_unknown_members() {
    let package = package_with_required_fields();
    let evidence = sample_epoch_evidence(&package.service_id);
    let transcript = AppletRegistrationEpochTranscript::from_package(&package, &evidence).unwrap();

    let mut root_unknown = serde_json::to_value(&transcript).unwrap();
    root_unknown["unknown"] = json!(true);
    assert!(serde_json::from_value::<AppletRegistrationEpochTranscript>(root_unknown).is_err());

    let mut nested_unknown = serde_json::to_value(&transcript).unwrap();
    nested_unknown["derived_registration"]["namespaces"]["actors"][0]["unknown"] = json!(true);
    assert!(serde_json::from_value::<AppletRegistrationEpochTranscript>(nested_unknown).is_err());

    let mut policy_unknown = serde_json::to_value(transcript).unwrap();
    policy_unknown["security_policy"]["unknown"] = json!(true);
    assert!(serde_json::from_value::<AppletRegistrationEpochTranscript>(policy_unknown).is_err());
}

#[test]
fn closed_applet_edge_outcomes_reject_unknown_members() {
    let ping = json!({
        "ok": true,
        "applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "service_id": service("slackbridge"),
        "protocol_version": "1",
        "unknown": true
    });
    assert!(serde_json::from_value::<AppletPingOutcome>(ping).is_err());

    let transaction = json!({"ok": true, "rejected": [], "unknown": true});
    assert!(serde_json::from_value::<AppletTransactionOutcome>(transaction).is_err());
}

#[test]
fn applet_ping_consumes_protocol_version_bootstrap() {
    let base = json!({
        "applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "service_id": service("slackbridge"),
        "protocol_version": "1.0"
    });
    serde_json::from_value::<AppletPingOutcome>(base.clone()).unwrap();

    let mut unsupported = base.clone();
    unsupported["protocol_version"] = json!("2.0");
    let error = serde_json::from_value::<AppletPingOutcome>(unsupported).unwrap_err();
    assert!(error.to_string().contains("unsupported_protocol_version"));

    for malformed in [json!("1.0.0"), json!(1), json!(null)] {
        let mut value = base.clone();
        value["protocol_version"] = malformed;
        let error = serde_json::from_value::<AppletPingOutcome>(value).unwrap_err();
        if error.to_string().contains("1.0.0") {
            assert!(error.to_string().contains("schema_violation"));
        }
    }
}

#[test]
fn epoch_method_version_rules_follow_the_active_v1_adapters() {
    let web_did = Did::new("did:web:applet.example".to_owned()).unwrap();
    let disguised_web =
        AppletDidMethodVersionEvidence::versioned("did:web", Some("synthetic".to_owned()), None)
            .unwrap();
    assert!(disguised_web.validate_for_did(&web_did).is_err());

    let webvh_did = Did::new("did:webvh:z6mkfixture:applet.example".to_owned()).unwrap();
    let unpinned_webvh = AppletDidMethodVersionEvidence::unversioned("did:webvh").unwrap();
    assert!(unpinned_webvh.validate_for_did(&webvh_did).is_err());

    let wrong_method = AppletDidMethodVersionEvidence::versioned(
        "did:key",
        Some("synthetic-did-sha256:abc".to_owned()),
        None,
    )
    .unwrap();
    assert!(wrong_method.validate_for_did(&webvh_did).is_err());
}

#[test]
fn registration_epoch_evidence_rejects_rotation_swap_and_empty_key_set() {
    let mut package = package_with_required_fields();
    let did = did("slackbridge");
    let key_ref = package.webhook_auth.key_ref.to_string();
    let old_document = DidDocument::new(
        did.clone(),
        key_ref.clone(),
        r#"{"crv":"Ed25519","kty":"OKP","x":"old"}"#,
    );
    let method_version = AppletDidMethodVersionEvidence::versioned(
        "did:webvh",
        Some("QmSdkAppletRotationVersion1".to_owned()),
        None,
    )
    .unwrap();
    let old_evidence =
        AppletRegistrationEpochEvidence::from_did_document(&old_document, method_version.clone())
            .unwrap();
    old_evidence
        .validate_against_did_document(&old_document)
        .unwrap();
    package.stamp_registration_epoch(&old_evidence).unwrap();
    stamp_and_sign_test_package(&mut package);
    package.validate_with_epoch_evidence(&old_evidence).unwrap();
    let old_epoch = package.registration_epoch.clone();

    let rotated_document = DidDocument::new(
        did,
        key_ref,
        r#"{"crv":"Ed25519","kty":"OKP","x":"rotated"}"#,
    );
    assert!(
        old_evidence
            .validate_against_did_document(&rotated_document)
            .is_err()
    );
    let rotated_evidence = AppletRegistrationEpochEvidence::from_did_document(
        &rotated_document,
        AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some("QmSdkAppletRotationVersion2".to_owned()),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        package
            .validate_with_epoch_evidence(&rotated_evidence)
            .is_err()
    );
    package.stamp_registration_epoch(&rotated_evidence).unwrap();
    stamp_and_sign_test_package(&mut package);
    assert_ne!(package.registration_epoch, old_epoch);
    package
        .validate_with_epoch_evidence(&rotated_evidence)
        .unwrap();

    let mut keyless_document = rotated_document;
    keyless_document.verification_methods.clear();
    assert!(
        AppletRegistrationEpochEvidence::from_did_document(&keyless_document, method_version,)
            .is_err()
    );
    let mut empty_keys = rotated_evidence;
    empty_keys.accepted_signing_keys.clear();
    assert!(
        empty_keys
            .validate_against_did_document(&keyless_document)
            .is_err()
    );
    assert!(package.validate_with_epoch_evidence(&empty_keys).is_err());
}

#[test]
fn registration_epoch_evidence_rejects_deactivated_and_swapped_did() {
    let package = package_with_required_fields();
    let mut document = DidDocument::new(
        did("slackbridge"),
        package.webhook_auth.key_ref.to_string(),
        r#"{"crv":"Ed25519","kty":"OKP","x":"active"}"#,
    );
    let method_version = AppletDidMethodVersionEvidence::versioned(
        "did:webvh",
        Some("QmSdkAppletDeactivationVersion1".to_owned()),
        None,
    )
    .unwrap();
    let active_evidence =
        AppletRegistrationEpochEvidence::from_did_document(&document, method_version.clone())
            .unwrap();
    document
        .raw_properties
        .insert("deactivated".to_owned(), json!(true));
    assert!(
        active_evidence
            .validate_against_did_document(&document)
            .is_err()
    );
    assert!(AppletRegistrationEpochEvidence::from_did_document(&document, method_version).is_err());

    let other_document = DidDocument::new(
        did("other-service"),
        "#key-1",
        r#"{"crv":"Ed25519","kty":"OKP","x":"other"}"#,
    );
    let swapped = AppletRegistrationEpochEvidence::from_did_document(
        &other_document,
        AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some("QmSdkAppletOtherVersion1".to_owned()),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(package.validate_with_epoch_evidence(&swapped).is_err());
    assert!(
        active_evidence
            .validate_against_did_document(&other_document)
            .is_err()
    );
}

#[test]
fn install_plan_digest_excludes_itself_and_scope_round_trips() {
    let mut plan = AppletInstallPlan {
        schema: "ak.schema.applet_install_plan.v1".to_owned(),
        plan_id: PlanId::new("ak:plan:plan_1").unwrap(),
        applet_id: AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
        package_digest: sample_epoch(),
        registration_epoch: sample_epoch(),
        effective_scope: ScopeRef::Realm { realm_id: realm() },
        requested_scopes: vec!["ak.message.create".to_owned()],
        approved_scopes: vec![],
        denied_scopes: vec![],
        event_submissions: vec![],
        capability_constraints: vec![],
        namespace_conflicts: vec![],
        e2ee_effect: E2eeEffect {
            mls_join_required: false,
            plaintext_access: "none".to_owned(),
            authorization_refs: None,
        },
        widget_effect: WidgetEffect {
            widget_allowed: false,
            policy_event_ref: None,
        },
        warnings: vec![],
        plan_digest: sample_epoch(),
    };
    let expected = plan.compute_plan_digest().unwrap();
    plan.stamp_plan_digest().unwrap();
    assert_eq!(plan.plan_digest, expected);

    let value = serde_json::to_value(&plan).unwrap();
    assert_eq!(value["effective_scope"]["kind"], "realm");
    let round_trip: AppletInstallPlan = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(round_trip.effective_scope.realm_id(), &realm());

    let mut invalid_id = value;
    invalid_id["plan_id"] = json!("plan_1");
    assert!(serde_json::from_value::<AppletInstallPlan>(invalid_id).is_err());
}

#[test]
fn committed_applet_refs_preserve_independent_circle_and_sidecar_streams() {
    let realm_id = realm();
    let circle_ref = committed_ref(
        CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: CircleId::new("ak:circle:ARIqxK3jWXYxpb544UphWaZm_ti9wclu9_0-eSuyZ2e_")
                .unwrap(),
        },
        7,
        4,
    );
    let sidecar_ref = committed_ref(
        CommitStreamRef::Sidecar {
            realm_id,
            sidecar_id: SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml")
                .unwrap(),
        },
        9,
        2,
    );

    let e2ee = E2eeEffect {
        mls_join_required: true,
        plaintext_access: "none".to_owned(),
        authorization_refs: Some(vec![circle_ref.clone()]),
    };
    let widget = WidgetEffect {
        widget_allowed: true,
        policy_event_ref: Some(sidecar_ref),
    };
    let e2ee_wire = serde_json::to_value(e2ee).unwrap();
    let widget_wire = serde_json::to_value(widget).unwrap();

    assert_eq!(
        e2ee_wire["authorization_refs"][0]["stream_ref"]["kind"],
        "circle"
    );
    assert_eq!(
        widget_wire["policy_event_ref"]["stream_ref"]["kind"],
        "sidecar"
    );

    let outcome = AppletTransactionOutcome {
        status: arkret_models_integration::AppletTransactionStatus::Accepted,
        committed_event_refs: vec![circle_ref],
        rejections: Vec::new(),
        retry_after_ms: None,
    };
    let outcome_wire = serde_json::to_value(outcome).unwrap();
    assert_eq!(
        outcome_wire["committed_event_refs"][0]["stream_ref"]["kind"],
        "circle"
    );
}

/// One fully signed `Create` install request, plus the managed-actor bundle
/// beside it.
///
/// Two suites need the byte-identical committed request: the carrier test
/// below, and the authoring-context conformance test that replays it as the
/// `committed_request` an Applet persists.
fn sample_install_request_body() -> (AppletInstallRequestBody, AppletManagedActorAuthoringBundle) {
    let admin_key = DidUrl::new(format!("{}#admin-key", did("admin"))).unwrap();
    let bot_key = DidUrl::new(format!("{}#actor-key", did("applet-bot"))).unwrap();
    let scope = ScopeRef::Realm { realm_id: realm() };
    let package = finalized_package_with_required_fields();
    let install_actor_id = ActorId::account(arkret_wire::AccountId::new(
        actor("admin"),
        actor("station"),
    ));
    let requested_at = canonical_now();
    let requested_expires_at = requested_at + chrono::Duration::minutes(5);
    let registration_epoch_evidence = sample_epoch_evidence(&package.service_id);
    let registration_event = with_caller_proof(
        arkret_wire::test_support::raw_event(
            "ak.applet.registration",
            scope.clone(),
            actor("admin"),
            actor("station"),
            // The spec binds this payload to the package-derived registration
            // payload byte for byte, so the fixture derives it rather than
            // hand-rolling a second spelling.
            serde_json::to_value(
                package
                    .to_registration(&registration_epoch_evidence)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
        &admin_key,
    );
    let capability_grant_event = with_caller_proof(
        arkret_wire::test_support::raw_event(
            "ak.capability.grant",
            scope.clone(),
            actor("admin"),
            actor("station"),
            json!({"grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm(),
                "issuer_id": install_actor_id,
                "subject": package.bot_actor_id,
                "actions": ["ak.message.create"],
                "resources": [{"kind": "*"}],
                "issued_at": arkret_canonical::format_timestamp_canonical(requested_at),
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm(),
                    "authority_event_ref":
                        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]),
                    "authority_generation": 1
                }]
            }}),
        )
        .unwrap(),
        &admin_key,
    );
    let basis = AppletInstallAuthoringRequestBasis {
        schema: "ak.schema.applet_install_authoring_request_basis.v1".to_owned(),
        purpose: AppletManagedActorPurpose::InstallBot,
        target_station_id: actor("station"),
        install_actor_id: install_actor_id.clone(),
        applet_id: package.applet_id.clone(),
        service_id: package.service_id.clone(),
        package_digest: package.package_digest.clone().unwrap(),
        effective_scope: scope.clone(),
        approval_request: arkret_models_integration::AppletApprovalRequest {
            approve_actions: vec!["ak.message.create".to_owned()],
            ghost_actor_mode: arkret_models_integration::AppletGhostActorMode::Disallowed,
            delegated_native_actors_allowed: false,
            e2ee_join_allowed: false,
            widget_allowed: false,
        },
        actor_policy: None,
        e2ee_policy: None,
        widget_policy: None,
        registration_event,
        capability_grant_events: vec![capability_grant_event],
    };
    let signer = StubSigner {
        did: did("station"),
        verification_method: DidUrl::new(format!("{}#authority-key", did("station"))).unwrap(),
    };
    let authoring_request = AppletManagedActorAuthoringRequest::sign(
        basis,
        package.registration_epoch.clone(),
        governance_station_id(),
        requested_at,
        requested_expires_at,
        &signer,
    )
    .unwrap();
    let bot_actor_provision_event = with_caller_proof(
        arkret_wire::test_support::raw_event_at(
            "ak.applet.managed_actor.provision",
            scope.clone(),
            service("slackbridge"),
            actor("station"),
            json!({"actor_id": package.bot_actor_id, "actor_station_id": actor("station")}),
            requested_at,
        )
        .unwrap(),
        &admin_key,
    );
    let bot_pcr_genesis_event = with_caller_proof(
        arkret_wire::test_support::raw_event_for_actor_at(
            "ak.realm.create",
            ScopeRef::RealmGenesis,
            package.bot_actor_id.clone(),
            json!({"realm_kind": "pcr"}),
            requested_at,
        )
        .unwrap(),
        &bot_key,
    );
    let bot_accountability_grant_event = with_caller_proof(
        arkret_wire::test_support::raw_event_at(
            "ak.identity.accountability_grant",
            scope.clone(),
            service("slackbridge"),
            actor("station"),
            json!({"accountable_principal_id": package.bot_actor_id}),
            requested_at,
        )
        .unwrap(),
        &admin_key,
    );
    let bot_profile_event = with_caller_proof(
        arkret_wire::test_support::raw_event_for_actor_at(
            "ak.profile.create",
            scope,
            package.bot_actor_id.clone(),
            json!({"display_name": "Applet Bot"}),
            requested_at,
        )
        .unwrap(),
        &bot_key,
    );
    let mut managed_actor_bundle = AppletManagedActorAuthoringBundle {
        schema: AppletManagedActorAuthoringBundle::SCHEMA.to_owned(),
        authoring_request_digest: authoring_request.canonical_digest().unwrap(),
        managed_actor_provision_event: bot_actor_provision_event,
        pcr_genesis_event: bot_pcr_genesis_event,
        accountability_grant_event: bot_accountability_grant_event,
        profile_event: bot_profile_event,
        proof: AppletManagedActorProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: signer.verification_method,
            payload_digest: sample_epoch(),
            created_at: requested_at,
            audience_id: actor("station"),
            jws: "eyJhbGciOiJFZDI1NTE5In0..c2lnbmF0dXJl".to_owned(),
        },
    };
    managed_actor_bundle.proof.payload_digest = managed_actor_bundle.payload_digest().unwrap();
    let request = AppletInstallRequestBody::Create(Box::new(AppletInstallCreateRequestBody {
        applet_package: package,
        authoring_request,
        managed_actor_bundle: managed_actor_bundle.clone(),
    }));
    (request, managed_actor_bundle)
}

#[test]
fn install_commit_uses_each_signed_event_carrier_once() {
    let (request, managed_actor_bundle) = sample_install_request_body();
    let registration_epoch_evidence = match &request {
        AppletInstallRequestBody::Create(body) => {
            sample_epoch_evidence(&body.applet_package.service_id)
        }
        AppletInstallRequestBody::Reuse(_) => unreachable!(),
    };
    let value = serde_json::to_value(&request).unwrap();
    let binding: Value =
        serde_json::from_slice(&managed_actor_bundle.proof_binding_bytes().unwrap()).unwrap();
    assert_eq!(
        value["managed_actor_bundle"]["proof"]["audience_id"],
        json!(actor("station"))
    );
    assert_eq!(binding["audience_id"], json!(actor("station")));
    assert!(binding.get("audience").is_none());
    let mut rejected_proof = value["managed_actor_bundle"]["proof"].clone();
    let audience_id = rejected_proof
        .as_object_mut()
        .unwrap()
        .remove("audience_id")
        .unwrap();
    rejected_proof["audience"] = audience_id;
    assert!(serde_json::from_value::<AppletManagedActorProof>(rejected_proof).is_err());
    assert_eq!(
        value["authoring_request"]["basis"]["registration_event"]["kind"],
        json!("ak.applet.registration")
    );
    assert_eq!(
        value["authoring_request"]["basis"]["capability_grant_events"][0]["kind"],
        json!("ak.capability.grant")
    );
    assert_eq!(
        value["authoring_request"]["basis"]["registration_event"]["payload"]["manifest"]["registration_epoch_evidence"],
        serde_json::to_value(&registration_epoch_evidence).unwrap()
    );

    let mut missing_bundle_role = value.clone();
    missing_bundle_role["managed_actor_bundle"]
        .as_object_mut()
        .unwrap()
        .remove("profile_event");
    assert!(serde_json::from_value::<AppletInstallRequestBody>(missing_bundle_role).is_err());

    let mut duplicate_bundle_role = value.clone();
    duplicate_bundle_role["managed_actor_bundle"]["bot_profile_event"] =
        duplicate_bundle_role["managed_actor_bundle"]["profile_event"].clone();
    assert!(serde_json::from_value::<AppletInstallRequestBody>(duplicate_bundle_role).is_err());

    let mut mismatched_bundle = managed_actor_bundle.clone();
    mismatched_bundle.authoring_request_digest = sample_epoch();
    assert!(
        mismatched_bundle
            .validate_bindings(match &request {
                AppletInstallRequestBody::Create(request) => &request.authoring_request,
                AppletInstallRequestBody::Reuse(_) => unreachable!(),
            })
            .is_err()
    );

    let mut late_bundle = managed_actor_bundle;
    let authoring_request = match &request {
        AppletInstallRequestBody::Create(request) => &request.authoring_request,
        AppletInstallRequestBody::Reuse(_) => unreachable!(),
    };
    late_bundle.proof.created_at = authoring_request.expires_at;
    assert!(late_bundle.validate_bindings(authoring_request).is_err());

    let mut missing_evidence = value.clone();
    missing_evidence["authoring_request"]["basis"]["registration_event"]["payload"]["manifest"]
        .as_object_mut()
        .unwrap()
        .remove("registration_epoch_evidence");
    assert!(serde_json::from_value::<AppletInstallRequestBody>(missing_evidence).is_err());

    let mut unknown_nested_evidence = value.clone();
    unknown_nested_evidence["authoring_request"]["basis"]["registration_event"]["payload"]["manifest"]
        ["registration_epoch_evidence"]["method_version_evidence"]["unknown_version_hint"] =
        json!("forbidden");
    assert!(serde_json::from_value::<AppletInstallRequestBody>(unknown_nested_evidence).is_err());

    let mut old_wire = value;
    old_wire["registration_epoch_evidence"] = json!({});
    assert!(serde_json::from_value::<AppletInstallRequestBody>(old_wire).is_err());
}

#[test]
fn install_preview_has_only_package_and_authoring_basis() {
    let package = finalized_package_with_required_fields();
    let evidence = sample_epoch_evidence(&package.service_id);
    let scope = ScopeRef::Realm { realm_id: realm() };
    let registration_event = arkret_wire::test_support::raw_event(
        "ak.applet.registration",
        scope.clone(),
        actor("admin"),
        actor("station"),
        json!({"manifest": {"registration_epoch_evidence": evidence}}),
    )
    .unwrap();
    let capability_grant_event = arkret_wire::test_support::raw_event(
        "ak.capability.grant",
        scope.clone(),
        actor("admin"),
        actor("station"),
        json!({"grant_id": "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"}),
    )
    .unwrap();
    let request = AppletInstallPreviewRequestBody {
        authoring_request_basis: AppletInstallAuthoringRequestBasis {
            schema: "ak.schema.applet_install_authoring_request_basis.v1".to_owned(),
            purpose: AppletManagedActorPurpose::InstallBot,
            target_station_id: actor("station"),
            install_actor_id: ActorId::account(arkret_wire::AccountId::new(
                actor("admin"),
                actor("station"),
            )),
            applet_id: package.applet_id.clone(),
            service_id: package.service_id.clone(),
            package_digest: package.package_digest.clone().unwrap(),
            effective_scope: scope,
            approval_request: arkret_models_integration::AppletApprovalRequest {
                approve_actions: vec!["ak.message.create".to_owned()],
                ghost_actor_mode: arkret_models_integration::AppletGhostActorMode::Disallowed,
                delegated_native_actors_allowed: false,
                e2ee_join_allowed: false,
                widget_allowed: false,
            },
            actor_policy: None,
            e2ee_policy: None,
            widget_policy: None,
            registration_event,
            capability_grant_events: vec![capability_grant_event],
        },
        applet_package: package,
    };
    let value = serde_json::to_value(request).unwrap();
    assert!(
        value["applet_package"]
            .get("registration_epoch_evidence")
            .is_none()
    );
    serde_json::from_value::<AppletInstallPreviewRequestBody>(value.clone()).unwrap();

    for station in ["station", "other-station"] {
        let install_actor =
            ActorId::account(arkret_wire::AccountId::new(actor("admin"), actor(station)));
        let mut scoped = value.clone();
        scoped["authoring_request_basis"]["install_actor_id"] = json!(install_actor);
        let decoded = serde_json::from_value::<AppletInstallPreviewRequestBody>(scoped).unwrap();
        assert_eq!(
            decoded.authoring_request_basis.install_actor_id,
            install_actor
        );
    }
    let mut bare_installer = value.clone();
    bare_installer["authoring_request_basis"]["install_actor_id"] = json!(actor("admin"));
    assert!(serde_json::from_value::<AppletInstallPreviewRequestBody>(bare_installer).is_err());

    let mut old_sibling = value.clone();
    old_sibling["registration_epoch_evidence"] = json!({});
    assert!(serde_json::from_value::<AppletInstallPreviewRequestBody>(old_sibling).is_err());

    let mut wrong_basis_schema = value.clone();
    wrong_basis_schema["authoring_request_basis"]["schema"] = json!("ak.schema.other.v1");
    assert!(serde_json::from_value::<AppletInstallPreviewRequestBody>(wrong_basis_schema).is_err());

    let mut malformed_applet_id = value;
    malformed_applet_id["authoring_request_basis"]["applet_id"] = json!("applet-local-id");
    assert!(
        serde_json::from_value::<AppletInstallPreviewRequestBody>(malformed_applet_id).is_err()
    );
}

#[test]
fn authoring_request_signing_is_byte_identical_for_exact_basis_replay() {
    let package = finalized_package_with_required_fields();
    let scope = ScopeRef::Realm { realm_id: realm() };
    let requested_at = canonical_now();
    let expires_at = requested_at + chrono::Duration::minutes(5);
    let registration_event = arkret_wire::test_support::raw_event(
        "ak.applet.registration",
        scope.clone(),
        actor("admin"),
        actor("station"),
        json!({"manifest": {"registration_epoch_evidence": sample_epoch_evidence(&package.service_id)}}),
    ).unwrap();
    let capability_grant_event = arkret_wire::test_support::raw_event(
        "ak.capability.grant",
        scope.clone(),
        actor("admin"),
        actor("station"),
        json!({"grant_id": "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"}),
    )
    .unwrap();
    let basis = AppletInstallAuthoringRequestBasis {
        schema: AppletInstallAuthoringRequestBasis::SCHEMA.to_owned(),
        purpose: AppletManagedActorPurpose::InstallBot,
        target_station_id: actor("station"),
        install_actor_id: ActorId::account(arkret_wire::AccountId::new(
            actor("admin"),
            actor("station"),
        )),
        applet_id: package.applet_id.clone(),
        service_id: package.service_id.clone(),
        package_digest: package.package_digest.clone().unwrap(),
        effective_scope: scope,
        approval_request: arkret_models_integration::AppletApprovalRequest {
            approve_actions: vec!["ak.message.create".to_owned()],
            ghost_actor_mode: arkret_models_integration::AppletGhostActorMode::Disallowed,
            delegated_native_actors_allowed: false,
            e2ee_join_allowed: false,
            widget_allowed: false,
        },
        actor_policy: None,
        e2ee_policy: None,
        widget_policy: None,
        registration_event,
        capability_grant_events: vec![capability_grant_event],
    };
    let signer = StubSigner {
        did: did("station"),
        verification_method: DidUrl::new(format!("{}#authority-key", did("station"))).unwrap(),
    };
    let first = AppletManagedActorAuthoringRequest::sign(
        basis.clone(),
        package.registration_epoch.clone(),
        governance_station_id(),
        requested_at,
        expires_at,
        &signer,
    )
    .unwrap();
    assert!(
        AppletManagedActorAuthoringRequest::sign(
            basis.clone(),
            package.registration_epoch.clone(),
            governance_station_id(),
            requested_at,
            requested_at + chrono::Duration::minutes(6),
            &signer,
        )
        .is_err()
    );
    let second = AppletManagedActorAuthoringRequest::sign(
        basis,
        package.registration_epoch,
        governance_station_id(),
        requested_at,
        expires_at,
        &signer,
    )
    .unwrap();
    assert_eq!(
        canonical::canonical_json_bytes(&first).unwrap(),
        canonical::canonical_json_bytes(&second).unwrap()
    );
    first.validate_bindings().unwrap();
    second.validate_bindings().unwrap();
    let mut carried_payload = first.clone();
    carried_payload.proof.jws = "header.payload.signature".to_owned();
    assert!(carried_payload.validate_bindings().is_err());

    // The dedicated managed-actor proof schema spells this field `audience_id`.
    // Check signed bytes as well as serialization so both cannot drift together.
    let wire = serde_json::to_value(&first).unwrap();
    let binding: Value = serde_json::from_slice(&first.proof_binding_bytes().unwrap()).unwrap();
    assert_eq!(wire["proof"]["audience_id"], json!(service("slackbridge")));
    assert_eq!(binding["audience_id"], wire["proof"]["audience_id"]);
    assert!(wire["proof"].get("audience").is_none());
    assert_eq!(wire["governance_station_id"], json!(actor("station")));
    assert!(wire.get("authoring_authority").is_none());
    assert!(binding.get("audience").is_none());
    let mut rejected = wire;
    let proof = rejected["proof"].as_object_mut().unwrap();
    let audience_id = proof.remove("audience_id").unwrap();
    proof.insert("audience".to_owned(), audience_id);
    assert!(serde_json::from_value::<AppletManagedActorAuthoringRequest>(rejected).is_err());
    let mut wrong_audience_id = first;
    wrong_audience_id.proof.audience_id = actor("station");
    assert!(wrong_audience_id.validate_bindings().is_err());

    // A request that names a Station other than the one whose key signed it is
    // rejected: the identity is the whole binding, so nothing else can carry it.
    let mut borrowed_station = second;
    borrowed_station.governance_station_id = service("slackbridge");
    assert!(borrowed_station.validate_bindings().is_err());
}

// ---------------------------------------------------------------------------
// Applet-managed Actor authoring context
//
// The context is the one artifact an Applet persists before it may return
// `accepted`, so it is checked three ways: against the published schema
// fragment, byte-for-byte through a serde round trip, and against every
// closure rule a schema cannot express (a ref is a content address, a root has
// one exact signer kind, an attester is pinned to one commit).
// ---------------------------------------------------------------------------

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable for conformance")
}

fn schema_text(file: &str) -> String {
    let path = artifacts_dir().join("schemas").join(file);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn registry() -> ProtocolSchemaRegistry {
    arkret_schema_conformance::schema_registry_from_spec_artifacts(artifacts_dir())
        .expect("the spec artifacts must produce a schema registry")
}

/// Validate `value` against one `$defs` fragment of a published schema file.
fn validate_fragment(file: &str, fragment: &str, value: &Value) {
    let mut registry = registry();
    let schema: Value = serde_json::from_str(&schema_text(file)).expect("schema artifact is JSON");
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    // The registry splits a schema id on `#`, so the lookup key must not
    // contain one; the fragment is stored beside the id, not inside it.
    let schema_id = format!("test:{file}{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap_or_else(|error| panic!("{file}{fragment}: {error}"));
    registry
        .validate_value(&schema_id, value)
        .unwrap_or_else(|error| panic!("{file}{fragment} rejected the document: {error}"));
}

/// Top-level member names of a serialized JSON object, in source order.
///
/// `serde_json` parses objects into a sorted map, which destroys the very
/// ordering the caller below exists to assert, so the names are read off the
/// raw text instead. serde emits struct fields in declaration order.
fn declared_member_names(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    assert_eq!(bytes[0], b'{', "expected a JSON object");
    let mut members = Vec::new();
    let mut index = 1usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut key_start = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                let start = key_start.take().expect("a string always has a start");
                if depth == 0 && bytes.get(index + 1) == Some(&b':') {
                    members
                        .push(serde_json::from_str::<String>(&text[start..=index]).expect("key"));
                }
            }
        } else {
            match byte {
                b'"' => {
                    in_string = true;
                    key_start = Some(index);
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    members
}

/// Member names of one `$defs` entry's `properties`, in published order.
fn published_property_order(file: &str, def: &str) -> Vec<String> {
    let text = schema_text(file);
    let start = text
        .find(&format!("\n    \"{def}\": {{"))
        .unwrap_or_else(|| panic!("{file} has no $defs entry `{def}`"));
    let rest = &text[start + 1..];
    // Every `$defs` entry is published at one exact indent, so the next line
    // that opens a quoted member there ends this one.
    let end = rest[1..]
        .find("\n    \"")
        .map_or(rest.len(), |offset| offset + 1);
    let marker = "\"properties\": ";
    let at = rest[..end]
        .find(marker)
        .unwrap_or_else(|| panic!("{def} declares no `properties`"));
    declared_member_names(&rest[at + marker.len()..end])
}

/// Member names one `$defs` entry lists as `required`, in published order.
fn published_required(file: &str, def: &str) -> Vec<String> {
    let schema: Value = serde_json::from_str(&schema_text(file)).expect("schema artifact is JSON");
    serde_json::from_value(schema["$defs"][def]["required"].clone())
        .unwrap_or_else(|error| panic!("{def} has no `required` list: {error}"))
}

/// Assert that a struct's members are exactly its `$defs` entry's members, in
/// the published order, with nothing optional on either side.
///
/// The SDK convention is that field declaration order equals the schema's
/// `properties` order byte-for-byte, and `required` is read separately so a
/// member that exists in the schema but not in the struct fails too.
fn assert_matches_published_shape<T: serde::Serialize>(file: &str, def: &str, value: &T) {
    let declared = declared_member_names(&serde_json::to_string(value).expect("value serializes"));
    assert_eq!(
        declared,
        published_property_order(file, def),
        "{def}: field declaration order must equal the published `properties` order"
    );
    assert_eq!(
        declared,
        published_required(file, def),
        "{def}: every published member is required, and the struct carries all of them"
    );
}
fn sample_jwk() -> NonEmptyJsonObject {
    NonEmptyJsonObject::new(BTreeMap::from([
        ("kty".to_owned(), json!("OKP")),
        ("crv".to_owned(), json!("Ed25519")),
        (
            "x".to_owned(),
            json!("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
        ),
    ]))
    .unwrap()
}

fn authority_commit(seed: u8) -> RealmCommitId {
    RealmCommitId::from_digest([seed; 32])
}

fn service_root(commit: &RealmCommitId) -> AppletServiceSignerEvidence {
    let evidence = build_service_signer_evidence(
        service("slackbridge"),
        DidUrl::new(format!("{}#service-key", did("slackbridge"))).unwrap(),
        sample_jwk(),
        commit.clone(),
        DateTime::from_timestamp_millis(1_756_000_000_000).unwrap(),
    )
    .unwrap();
    AppletServiceSignerEvidence {
        signer_resolution_evidence_ref: evidence.signer_evidence_ref().unwrap(),
        authenticated_signer_evidence: evidence,
    }
}

fn station_attester(commit: &RealmCommitId) -> AuthenticatedSignerResolutionEvidence {
    build_service_signer_evidence(
        service("station"),
        DidUrl::new(format!("{}#authority-key", did("station"))).unwrap(),
        sample_jwk(),
        commit.clone(),
        DateTime::from_timestamp_millis(1_756_000_001_000).unwrap(),
    )
    .unwrap()
}

fn managed_actor_root(commit: &RealmCommitId) -> ManagedActorPrincipalSignerEvidence {
    let evidence = build_principal_signer_evidence(
        principal("applet-bot"),
        DidUrl::new(format!("{}#actor-key", did("applet-bot"))).unwrap(),
        sample_jwk(),
        commit.clone(),
        DateTime::from_timestamp_millis(1_756_000_002_000).unwrap(),
    )
    .unwrap();
    ManagedActorPrincipalSignerEvidence {
        signer_resolution_evidence_ref: evidence.signer_evidence_ref().unwrap(),
        authenticated_signer_evidence: evidence,
        attester_signer_evidence: station_attester(commit),
    }
}

fn sample_authoring_context() -> AppletManagedActorAuthoringContext {
    let commit = authority_commit(0x2c);
    let (request, _) = sample_install_request_body();
    AppletManagedActorAuthoringContext {
        committed_request: AppletManagedActorCommittedRequest::Install(Box::new(request)),
        realm_stream_head: CommitStreamHead {
            stream_ref: CommitStreamRef::Realm { realm_id: realm() },
            stream_position: 41,
            commit_id: commit.clone(),
        },
        applet_service_signer_evidence: service_root(&commit),
        managed_actor_signer_evidence: managed_actor_root(&commit),
    }
}

const EDGE_SCHEMA: &str = "applet-edge-operations.schema.json";

#[test]
fn the_authoring_context_matches_the_published_fragment_and_round_trips() {
    let context = sample_authoring_context();
    context.validate().unwrap();

    let wire = serde_json::to_value(&context).unwrap();
    validate_fragment(
        EDGE_SCHEMA,
        "#/$defs/applet_service_signer_evidence",
        &wire["applet_service_signer_evidence"],
    );
    validate_fragment(
        EDGE_SCHEMA,
        "#/$defs/managed_actor_principal_signer_evidence",
        &wire["managed_actor_signer_evidence"],
    );
    validate_fragment(
        "realm-commit.schema.json",
        "#/$defs/stream_head",
        &wire["realm_stream_head"],
    );

    // The whole context is not handed to
    // `#/$defs/applet_managed_actor_authoring_context` yet: through
    // `committed_request` that fragment reaches the entire install request
    // body, whose four bundle Events need conformant `ak.realm.create`,
    // `ak.identity.accountability_grant`, `ak.profile.create` and
    // `ak.applet.managed_actor.provision` payloads that this repository has no
    // fixture for. The context's own shape is therefore pinned against the
    // published member lists instead, and the install body has its own task.
    assert_matches_published_shape(
        EDGE_SCHEMA,
        "applet_managed_actor_authoring_context",
        &context,
    );
    assert_matches_published_shape(
        EDGE_SCHEMA,
        "applet_service_signer_evidence",
        &context.applet_service_signer_evidence,
    );
    assert_matches_published_shape(
        EDGE_SCHEMA,
        "managed_actor_principal_signer_evidence",
        &context.managed_actor_signer_evidence,
    );

    let parsed: AppletManagedActorAuthoringContext = serde_json::from_value(wire).unwrap();
    assert_eq!(
        serde_json::to_string(&parsed).unwrap(),
        serde_json::to_string(&context).unwrap(),
        "the context must survive a round trip byte for byte"
    );
}
#[test]
fn every_authoring_context_member_is_required() {
    let wire = serde_json::to_value(sample_authoring_context()).unwrap();
    for member in [
        "committed_request",
        "realm_stream_head",
        "applet_service_signer_evidence",
        "managed_actor_signer_evidence",
    ] {
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove(member).unwrap();
        assert!(
            serde_json::from_value::<AppletManagedActorAuthoringContext>(missing).is_err(),
            "`{member}` must not be droppable from an authoring context"
        );
    }

    let mut unknown = wire;
    unknown["attester_signer_evidence"] = json!({});
    assert!(serde_json::from_value::<AppletManagedActorAuthoringContext>(unknown).is_err());
}

#[test]
fn a_signer_root_ref_that_is_not_its_own_content_address_is_rejected() {
    let mut borrowed_ref = sample_authoring_context();
    borrowed_ref
        .applet_service_signer_evidence
        .signer_resolution_evidence_ref = borrowed_ref
        .managed_actor_signer_evidence
        .signer_resolution_evidence_ref
        .clone();
    assert!(borrowed_ref.validate().is_err());

    // A ref that is well formed but addresses nothing at all fails the same
    // way: the consumer recomputes, it never trusts the reported sibling.
    let mut empty_ref = sample_authoring_context();
    empty_ref
        .managed_actor_signer_evidence
        .signer_resolution_evidence_ref =
        SignerEvidenceRef::new(format!("ak:signer_evidence:sha256:{}", "0".repeat(64))).unwrap();
    assert!(empty_ref.validate().is_err());
}

#[test]
fn each_signer_root_carries_its_own_signer_kind() {
    let principal_evidence = build_principal_signer_evidence(
        service("slackbridge"),
        DidUrl::new(format!("{}#service-key", did("slackbridge"))).unwrap(),
        sample_jwk(),
        authority_commit(0x2c),
        DateTime::from_timestamp_millis(1_756_000_000_000).unwrap(),
    )
    .unwrap();
    let mut wrong_service_kind = sample_authoring_context();
    wrong_service_kind.applet_service_signer_evidence = AppletServiceSignerEvidence {
        signer_resolution_evidence_ref: principal_evidence.signer_evidence_ref().unwrap(),
        authenticated_signer_evidence: principal_evidence,
    };
    assert!(wrong_service_kind.validate().is_err());

    let mut wrong_attester_kind = sample_authoring_context();
    wrong_attester_kind
        .managed_actor_signer_evidence
        .attester_signer_evidence
        .signer_kind = AuthenticatedSignerKind::Agent;
    assert!(
        wrong_attester_kind.validate().is_err(),
        "the attester leaf must be the Station Service that signed the resolution"
    );
}

#[test]
fn the_attester_leaf_is_pinned_to_the_commit_the_context_froze() {
    let mut drifted_attester = sample_authoring_context();
    drifted_attester
        .managed_actor_signer_evidence
        .attester_signer_evidence
        .authority_commit_id = authority_commit(0x5d);
    assert!(drifted_attester.validate().is_err());

    // The Applet Service root is resolved against its own registration epoch,
    // so it is deliberately not pinned to the managed Actor's commit.
    let evidence = build_service_signer_evidence(
        service("slackbridge"),
        DidUrl::new(format!("{}#service-key", did("slackbridge"))).unwrap(),
        sample_jwk(),
        authority_commit(0x5d),
        DateTime::from_timestamp_millis(1_756_000_000_000).unwrap(),
    )
    .unwrap();
    let mut independent_service_commit = sample_authoring_context();
    independent_service_commit.applet_service_signer_evidence = AppletServiceSignerEvidence {
        signer_resolution_evidence_ref: evidence.signer_evidence_ref().unwrap(),
        authenticated_signer_evidence: evidence,
    };
    independent_service_commit.validate().unwrap();
}
