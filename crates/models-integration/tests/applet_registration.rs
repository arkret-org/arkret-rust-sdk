use std::fs;
use std::path::PathBuf;

use arkret_canonical as canonical;
use arkret_models_identity::DidDocument;
use arkret_models_integration::{
    AppletBotAuthoringRequestBasis, AppletDidMethodVersionEvidence, AppletEndpointAuth,
    AppletEndpointEntry, AppletEndpointMethod, AppletInstallAuthoringRequestBasis,
    AppletInstallPlan, AppletInstallPreviewRequestBody, AppletManagedActorAuthoringRequest,
    AppletManagedActorPurpose, AppletNamespaceDomain, AppletNamespaceEntry, AppletPackage,
    AppletPingResponseBody, AppletRegistrationEpochEvidence, AppletRegistrationEpochTranscript,
    AppletRegistrationPayload, AppletTransactionResponseBody, AppletWireNamespaces, DetachedProof,
    E2eeEffect, HttpMessageSignatureAlgorithm, WebhookSignaturePolicy, WidgetEffect,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_wire::{
    ActorId, AppletId, CircleId, CommitStreamRef, CommittedEventRef, Did, DidCoreId, DidUrl, Event,
    EventId, Hash, PayloadSignature, PayloadSigner, PlanId, ProducerEventProof, RealmCommitId,
    RealmId, Result as WireResult, ScopeRef, SidecarId,
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
        jws: "header..signature".to_owned(),
        extra: Default::default(),
    });
    package.to_registration(&evidence, None).unwrap()
}

#[test]
fn exclusive_namespace_claims_conflict_only_within_the_same_domain() {
    let exclusive_pattern = AppletWireNamespaces {
        realms: vec![AppletNamespaceEntry::exclusive("slack:workspace:channel:*")],
        ..Default::default()
    };
    let exclusive_concrete = AppletWireNamespaces {
        realms: vec![AppletNamespaceEntry::exclusive(
            "slack:workspace:channel:u1",
        )],
        ..Default::default()
    };
    let conflicts = exclusive_pattern.conflicts_with(&exclusive_concrete);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].domain, AppletNamespaceDomain::Realms);

    let shared_pattern = AppletWireNamespaces {
        realms: vec![AppletNamespaceEntry::shared("slack:workspace:channel:*")],
        ..Default::default()
    };
    let shared_concrete = AppletWireNamespaces {
        realms: vec![AppletNamespaceEntry::shared("slack:workspace:channel:u1")],
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
        vec!["slack".to_owned()],
        AppletWireNamespaces {
            realms: vec![AppletNamespaceEntry::exclusive("slack:workspace:channel:*")],
            handles: vec![],
        },
    );
    package.requested_scopes = vec!["ak.message.create".to_owned()];
    package.endpoint_policy.endpoints.push(AppletEndpointEntry {
        method: AppletEndpointMethod::Post,
        path: "/_arkret/edge/applet/transactions".to_owned(),
        authentication_kind: Some(AppletEndpointAuth::WebhookSignature),
        description: None,
        extra: Default::default(),
    });
    package.webhook_signature_policy = WebhookSignaturePolicy::http_message_signature(
        DidUrl::new(format!("{}#key-1", did("slackbridge"))).unwrap(),
        vec![HttpMessageSignatureAlgorithm::Ed25519],
    );
    package
}

fn stamp_and_sign_test_package(package: &mut AppletPackage) {
    package.stamp_package_digest().unwrap();
    let verification_method = package.webhook_signature_policy.key_ref.clone();
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
    assert_eq!(round_trip.namespaces.realms, registration.namespaces.realms);
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
        jws: "header..signature".to_owned(),
        extra: Default::default(),
    });
    package.validate().unwrap();
    package.validate_with_epoch_evidence(&evidence).unwrap();
    let mut carried_payload = package.clone();
    carried_payload.proof.as_mut().unwrap().jws = "header.payload.signature".to_owned();
    assert!(carried_payload.validate().is_err());

    let registration = package.to_registration(&evidence, None).unwrap();
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
    nested_unknown["derived_registration"]["namespaces"]["realms"][0]["unknown"] = json!(true);
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
    assert!(serde_json::from_value::<AppletPingResponseBody>(ping).is_err());

    let transaction = json!({"ok": true, "rejected": [], "unknown": true});
    assert!(serde_json::from_value::<AppletTransactionResponseBody>(transaction).is_err());
}

#[test]
fn applet_ping_consumes_protocol_version_bootstrap() {
    let base = json!({
        "applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "service_id": service("slackbridge"),
        "protocol_version": "1.0"
    });
    serde_json::from_value::<AppletPingResponseBody>(base.clone()).unwrap();

    let mut unsupported = base.clone();
    unsupported["protocol_version"] = json!("2.0");
    let error = serde_json::from_value::<AppletPingResponseBody>(unsupported).unwrap_err();
    assert!(error.to_string().contains("unsupported_protocol_version"));

    for malformed in [json!("1.0.0"), json!(1), json!(null)] {
        let mut value = base.clone();
        value["protocol_version"] = malformed;
        let error = serde_json::from_value::<AppletPingResponseBody>(value).unwrap_err();
        if error.to_string().contains("1.0.0") {
            assert!(error.to_string().contains("schema_violation"));
        }
    }
}

#[test]
fn epoch_method_version_rules_follow_the_active_v1_adapters() {
    assert!(
        AppletDidMethodVersionEvidence::versioned("did:web", Some("synthetic".to_owned()), None)
            .is_err()
    );
    assert!(AppletDidMethodVersionEvidence::versioned("did:key", None, Some(Utc::now())).is_err());
    assert!(AppletDidMethodVersionEvidence::versioned("did:webvh", None, None).is_err());
    assert!(
        AppletDidMethodVersionEvidence::versioned(
            "did:webvh",
            Some("ak:event:typed".to_owned()),
            None
        )
        .is_err()
    );
    for invalid in [
        json!({"method": "did:web", "unversioned_refetch": true}),
        json!({"method": "did:webvh", "unversioned_refetch": true}),
        json!({"method": "did:webvh", "version_id": "1-Qm", "unversioned_refetch": true}),
        json!({"method": "did:key", "version_created_at": "2026-01-01T00:00:00Z", "unversioned_refetch": false}),
    ] {
        assert!(
            serde_json::from_value::<AppletDidMethodVersionEvidence>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
    serde_json::from_value::<AppletDidMethodVersionEvidence>(json!({
        "method": "did:webvh",
        "version_created_at": "2026-01-01T00:00:00Z",
        "unversioned_refetch": false
    }))
    .unwrap();

    let webvh_did = Did::new("did:webvh:z6mkfixture:applet.example".to_owned()).unwrap();
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
    let key_ref = package.webhook_signature_policy.key_ref.to_string();
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
        package.webhook_signature_policy.key_ref.to_string(),
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

/// `applet-registration-epoch-evidence.schema.json`: `accepted_signing_keys`
/// is `minItems: 1` / `uniqueItems: true`, and `did` is only a bare
/// `did:webvh` or `did:key` bound to `method_version_evidence.method`.
#[test]
fn registration_epoch_evidence_wire_enforces_the_closed_schema_shape() {
    let evidence = sample_epoch_evidence(&service("slackbridge"));
    let valid = serde_json::to_value(&evidence).unwrap();
    validate_fragment(
        "applet-registration-epoch-evidence.schema.json",
        "#",
        &valid,
    );
    assert_eq!(
        serde_json::from_value::<AppletRegistrationEpochEvidence>(valid.clone()).unwrap(),
        evidence
    );

    let mut empty_keys = valid.clone();
    empty_keys["accepted_signing_keys"] = json!([]);
    let mut duplicate_keys = valid.clone();
    let key = valid["accepted_signing_keys"][0].clone();
    duplicate_keys["accepted_signing_keys"] = json!([key.clone(), key]);
    let mut current_snapshot_did = valid.clone();
    current_snapshot_did["did"] = json!("did:web:slackbridge.example");
    let mut method_mismatch = valid.clone();
    method_mismatch["did"] = json!("did:key:z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT");
    let mut webvh_without_host = valid;
    webvh_without_host["did"] = json!("did:webvh:slackbridge");
    for (label, value) in [
        ("empty accepted_signing_keys", empty_keys),
        ("duplicate accepted_signing_keys", duplicate_keys),
        ("did:web current snapshot", current_snapshot_did),
        (
            "did method differs from method_version_evidence",
            method_mismatch,
        ),
        ("did:webvh without a host segment", webvh_without_host),
    ] {
        assert!(
            serde_json::from_value::<AppletRegistrationEpochEvidence>(value).is_err(),
            "{label} must not deserialize"
        );
    }
}

#[test]
fn install_plan_digest_excludes_itself_and_scope_round_trips() {
    let mut plan = AppletInstallPlan {
        service_id: service("slackbridge"),
        schema: "ak.schema.applet_install_plan.v1".to_owned(),
        plan_id: PlanId::new("ak:plan:plan_1").unwrap(),
        applet_id: AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
        package_digest: sample_epoch(),
        registration_epoch: sample_epoch(),
        effective_scope: ScopeRef::Realm { realm_id: realm() },
        requested_scopes: vec!["ak.message.create".to_owned()],
        approved_scopes: vec![],
        denied_scopes: vec![],
        planned_events: vec![],
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

    let outcome = AppletTransactionResponseBody::Accepted {
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

#[test]
fn transaction_outcome_requires_commit_refs_only_for_successful_branches() {
    for status in ["accepted", "partial"] {
        assert!(
            serde_json::from_value::<AppletTransactionResponseBody>(json!({"status": status}))
                .is_err()
        );
        let outcome: AppletTransactionResponseBody =
            serde_json::from_value(json!({"status": status, "committed_event_refs": []})).unwrap();
        assert_eq!(
            serde_json::to_value(outcome).unwrap(),
            json!({"status": status, "committed_event_refs": []})
        );
    }
    let rejected: AppletTransactionResponseBody =
        serde_json::from_value(json!({"status": "rejected", "retry_after_ms": 1000})).unwrap();
    assert_eq!(
        serde_json::to_value(rejected).unwrap(),
        json!({"status": "rejected", "retry_after_ms": 1000})
    );
    assert!(
        serde_json::from_value::<AppletTransactionResponseBody>(
            json!({"status": "rejected", "committed_event_refs": []})
        )
        .is_err()
    );
}

/// One fully signed `Create` install request, plus the managed-actor bundle
/// beside it.
///
/// Two suites need the byte-identical committed request: the carrier test
/// below, and the authoring-context conformance test that replays it as the
/// `committed_request` an Applet persists.
fn sample_authoring_request() -> AppletManagedActorAuthoringRequest {
    let admin_key = DidUrl::new(format!("{}#admin-key", did("admin"))).unwrap();
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
                    .to_registration(&registration_epoch_evidence, None)
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
                "subject": ActorId::account(arkret_wire::AccountId::new(actor("bot"), actor("station"))),
                "actions": ["ak.message.create"],
                "resources": [{"kind": "*"}],
                "issued_at": arkret_canonical::format_timestamp_canonical(requested_at),
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm(),
                    "authority_event_ref":
                        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]),
                    "authority_generation": "1"
                }]
            }}),
        )
        .unwrap(),
        &admin_key,
    );
    let basis = AppletBotAuthoringRequestBasis {
        schema: AppletBotAuthoringRequestBasis::SCHEMA.into(),
        purpose: AppletManagedActorPurpose::ProvisionBot,
        target_station_id: actor("station"),
        applet_id: package.applet_id.clone(),
        service_id: package.service_id.clone(),
        display_name: Some("Applet Bot".into()),
        registration_event_ref: registration_event.event_id,
        authorization_ref: arkret_wire::GrantId::from_event_id(&capability_grant_event.event_id),
        registration_epoch_evidence,
        package_digest: package.package_digest.unwrap(),
        effective_scope: scope,
        request_id: "bot-create-001".into(),
    };
    let signer = StubSigner {
        did: did("station"),
        verification_method: DidUrl::new(format!("{}#authority-key", did("station"))).unwrap(),
    };

    AppletManagedActorAuthoringRequest::sign_bot(
        basis,
        governance_station_id(),
        requested_at,
        requested_expires_at,
        &signer,
    )
    .unwrap()
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
            purpose: AppletManagedActorPurpose::InstallService,
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
    let request = sample_authoring_request();
    let basis = request.basis.bot().unwrap().clone();
    let signer = StubSigner {
        did: did("station"),
        verification_method: DidUrl::new(format!("{}#authority-key", did("station"))).unwrap(),
    };
    let sign = || {
        AppletManagedActorAuthoringRequest::sign_bot(
            basis.clone(),
            governance_station_id(),
            request.issued_at,
            request.expires_at,
            &signer,
        )
        .unwrap()
    };
    assert_eq!(
        canonical::canonical_json_bytes(&sign()).unwrap(),
        canonical::canonical_json_bytes(&sign()).unwrap()
    );
    assert!(
        AppletManagedActorAuthoringRequest::sign_bot(
            basis,
            governance_station_id(),
            request.issued_at,
            request.issued_at + chrono::Duration::minutes(6),
            &signer
        )
        .is_err()
    );
}

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
