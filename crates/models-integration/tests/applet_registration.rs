use arkret_canonical as canonical;
use arkret_models_identity::DidDocument;
use arkret_models_integration::{
    AppletDidMethodVersionEvidence, AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod,
    AppletInstallAuthoringRequestBasis, AppletInstallCreateRequestBody, AppletInstallPlan,
    AppletInstallPreviewRequestBody, AppletInstallRequestBody, AppletManagedActorAuthoringBundle,
    AppletManagedActorAuthoringRequest, AppletManagedActorProof, AppletManagedActorPurpose,
    AppletNamespaceDomain, AppletNamespaceEntry, AppletPackage, AppletPingOutcome,
    AppletRegistrationEpochEvidence, AppletRegistrationEpochTranscript, AppletRegistrationPayload,
    AppletTransactionOutcome, AppletWireNamespaces, DetachedProof, E2eeEffect,
    HttpMessageSignatureAlgorithm, WebhookAuth, WidgetEffect,
};
use arkret_wire::{
    AppletId, Did, DidCoreId, DidUrl, Hash, Hlc, NotaryJoseAlgorithm, NotaryKeyKind,
    NotarySignerDescriptor, PayloadSignature, PayloadSigner, PlanId, RealmId, Result as WireResult,
    ScopeRef,
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

    fn sign_notary_payload_with_digest_suite(
        &self,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> WireResult<PayloadSignature> {
        let mut signature = self.sign_payload(canonical_bytes)?;
        signature.payload_digest = Hash::new(canonical::digest(digest_suite, canonical_bytes))?;
        Ok(signature)
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

fn hosting_notary() -> NotarySignerDescriptor {
    NotarySignerDescriptor {
        actor_id: actor("principal-server"),
        verification_method: DidUrl::new(format!("{}#notary-key", did("principal-server")))
            .unwrap(),
        key_kind: NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: "A".repeat(43),
        frozen_public_key_digest: Hash::new(
            "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        )
        .unwrap(),
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
    package.seal_registration_epoch(&evidence).unwrap();
    package.seal().unwrap();
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
        actor("bot"),
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

fn seal_and_sign_test_package(package: &mut AppletPackage) {
    package.seal().unwrap();
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
    package.seal_registration_epoch(&evidence).unwrap();
    seal_and_sign_test_package(&mut package);
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
    unknown_top_level["legacy"] = json!(true);
    assert!(serde_json::from_value::<AppletRegistrationPayload>(unknown_top_level).is_err());

    let mut unknown_manifest = value.clone();
    unknown_manifest["manifest"]["legacy"] = json!(true);
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
    package.seal_registration_epoch(&evidence).unwrap();
    assert!(package.validate().is_err());

    package.seal().unwrap();
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

    let registration = package.to_registration(&evidence).unwrap();
    assert_eq!(registration.registration_epoch, package.registration_epoch);
    assert_eq!(registration.namespaces, package.namespaces);
    assert_eq!(registration.manifest.registration_epoch_evidence, evidence);
    let registration_value = serde_json::to_value(&registration).unwrap();
    arkret_schema::event_payload_validator_catalog()
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
    missing_profile.seal_registration_epoch(&evidence).unwrap();
    missing_profile.seal().unwrap();
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
    malformed_id["applet_id"] = json!("did:web:legacy-applet.example");
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
    package.seal_registration_epoch(&old_evidence).unwrap();
    seal_and_sign_test_package(&mut package);
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
    package.seal_registration_epoch(&rotated_evidence).unwrap();
    seal_and_sign_test_package(&mut package);
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
    plan.seal().unwrap();
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
fn install_commit_uses_each_signed_event_carrier_once() {
    let scope = ScopeRef::Realm { realm_id: realm() };
    let package = finalized_package_with_required_fields();
    let requested_at = canonical_now();
    let requested_expires_at = requested_at + chrono::Duration::minutes(5);
    let registration_epoch_evidence = sample_epoch_evidence(&package.service_id);
    let registration_event = arkret_wire::test_support::raw_event(
        "ak.applet.registration",
        scope.clone(),
        actor("admin"),
        actor("principal-server"),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({
            "applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            "manifest": {"registration_epoch_evidence": registration_epoch_evidence}
        }),
    )
    .unwrap();
    let capability_grant_event = arkret_wire::test_support::raw_event(
        "ak.capability.grant",
        scope.clone(),
        actor("admin"),
        actor("principal-server"),
        2,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        json!({"grant_id": "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"}),
    )
    .unwrap();
    let basis = AppletInstallAuthoringRequestBasis {
        schema: "ak.schema.applet_install_authoring_request_basis.v1".to_owned(),
        purpose: AppletManagedActorPurpose::InstallBot,
        target_principal_server_id: actor("principal-server"),
        install_actor_id: actor("admin"),
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
        did: did("principal-server"),
        verification_method: DidUrl::new(format!("{}#notary-key", did("principal-server")))
            .unwrap(),
    };
    let authoring_request = AppletManagedActorAuthoringRequest::sign(
        basis,
        package.registration_epoch.clone(),
        hosting_notary(),
        requested_at,
        requested_expires_at,
        &signer,
    )
    .unwrap();
    let bot_actor_provision_event = arkret_wire::test_support::raw_event_at(
        "ak.applet.managed_actor.provision", scope.clone(), service("slackbridge"), actor("principal-server"), 1,
        Hlc::new("01970e589d21-0100-a13f9c2e").unwrap(),
        json!({"actor_id": package.bot_actor_id, "actor_principal_server_id": actor("principal-server")}),
        requested_at,
    ).unwrap();
    let bot_pcr_genesis_event = arkret_wire::test_support::raw_event_at(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        package.bot_actor_id.clone(),
        actor("principal-server"),
        0,
        Hlc::new("01970e589d21-0101-a13f9c2e").unwrap(),
        json!({"realm_kind": "pcr"}),
        requested_at,
    )
    .unwrap();
    let bot_accountability_grant_event = arkret_wire::test_support::raw_event_at(
        "ak.identity.accountability_grant",
        scope.clone(),
        service("slackbridge"),
        actor("principal-server"),
        2,
        Hlc::new("01970e589d21-0102-a13f9c2e").unwrap(),
        json!({"accountable_principal_id": package.bot_actor_id}),
        requested_at,
    )
    .unwrap();
    let bot_profile_event = arkret_wire::test_support::raw_event_at(
        "ak.profile.create",
        scope,
        package.bot_actor_id.clone(),
        actor("principal-server"),
        0,
        Hlc::new("01970e589d21-0103-a13f9c2e").unwrap(),
        json!({"display_name": "Applet Bot"}),
        requested_at,
    )
    .unwrap();
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
            audience_id: actor("principal-server"),
            jws: "eyJhbGciOiJFZDI1NTE5In0..c2lnbmF0dXJl".to_owned(),
        },
    };
    managed_actor_bundle.proof.payload_digest = managed_actor_bundle.payload_digest().unwrap();
    let request = AppletInstallRequestBody::Create(Box::new(AppletInstallCreateRequestBody {
        applet_package: package,
        authoring_request,
        managed_actor_bundle: managed_actor_bundle.clone(),
    }));
    let value = serde_json::to_value(&request).unwrap();
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
        ["registration_epoch_evidence"]["method_version_evidence"]["legacy_version_hint"] =
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
        actor("principal-server"),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({"manifest": {"registration_epoch_evidence": evidence}}),
    )
    .unwrap();
    let capability_grant_event = arkret_wire::test_support::raw_event(
        "ak.capability.grant",
        scope.clone(),
        actor("admin"),
        actor("principal-server"),
        2,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        json!({"grant_id": "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"}),
    )
    .unwrap();
    let request = AppletInstallPreviewRequestBody {
        authoring_request_basis: AppletInstallAuthoringRequestBasis {
            schema: "ak.schema.applet_install_authoring_request_basis.v1".to_owned(),
            purpose: AppletManagedActorPurpose::InstallBot,
            target_principal_server_id: actor("principal-server"),
            install_actor_id: actor("admin"),
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
        "ak.applet.registration", scope.clone(), actor("admin"), actor("principal-server"), 1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({"manifest": {"registration_epoch_evidence": sample_epoch_evidence(&package.service_id)}}),
    ).unwrap();
    let capability_grant_event = arkret_wire::test_support::raw_event(
        "ak.capability.grant",
        scope.clone(),
        actor("admin"),
        actor("principal-server"),
        2,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        json!({"grant_id": "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu"}),
    )
    .unwrap();
    let basis = AppletInstallAuthoringRequestBasis {
        schema: AppletInstallAuthoringRequestBasis::SCHEMA.to_owned(),
        purpose: AppletManagedActorPurpose::InstallBot,
        target_principal_server_id: actor("principal-server"),
        install_actor_id: actor("admin"),
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
        did: did("principal-server"),
        verification_method: DidUrl::new(format!("{}#notary-key", did("principal-server")))
            .unwrap(),
    };
    let first = AppletManagedActorAuthoringRequest::sign(
        basis.clone(),
        package.registration_epoch.clone(),
        hosting_notary(),
        requested_at,
        expires_at,
        &signer,
    )
    .unwrap();
    assert!(
        AppletManagedActorAuthoringRequest::sign(
            basis.clone(),
            package.registration_epoch.clone(),
            hosting_notary(),
            requested_at,
            requested_at + chrono::Duration::minutes(6),
            &signer,
        )
        .is_err()
    );
    let second = AppletManagedActorAuthoringRequest::sign(
        basis,
        package.registration_epoch,
        hosting_notary(),
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
}
