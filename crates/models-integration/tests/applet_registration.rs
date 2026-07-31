use arkret_canonical as canonical;
use arkret_models_identity::DidDocument;
use arkret_models_integration::{
    AppletDidMethodVersionEvidence, AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod,
    AppletInstallAppletId, AppletInstallPlan, AppletInstallRequestBody, AppletNamespaceDomain,
    AppletNamespaceEntry, AppletPackage, AppletRegistrationEpochEvidence, AppletWireNamespaces,
    E2eeEffect, WebhookAuth, WebhookSignatureAlg, WidgetEffect, WireAppletRegistration,
    sign_registration,
};
use arkret_wire::{
    AppletId, Did, DidUrl, Event, Hash, Hlc, PayloadSignature, PayloadSigner, Proof, RealmId,
    Result as WireResult, ScopeRef,
};
use chrono::Utc;
use serde_json::{Value, json};

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
}

fn sample_epoch() -> Hash {
    Hash::new(format!("sha256:{}", "bb".repeat(32))).unwrap()
}

fn sample_epoch_evidence(service_id: &Did) -> AppletRegistrationEpochEvidence {
    let document = DidDocument::new(
        service_id.clone(),
        format!("{service_id}#key-1"),
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

fn sample_wire_registration() -> WireAppletRegistration {
    WireAppletRegistration::new(
        "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
        did("slackbridge"),
        did("alice"),
        "https://applet.example/cx",
        did("bot"),
        vec!["ak.applet.v1".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(
                "did:webvh:z6mkfixture:slackbridge.example#ghost-*",
            )],
            realms: vec![],
            handles: vec![],
        },
        sample_epoch(),
    )
}

#[test]
fn exclusive_namespace_claims_conflict_only_within_the_same_domain() {
    let exclusive_pattern = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::exclusive(
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
        )],
        ..Default::default()
    };
    let exclusive_concrete = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::exclusive(
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:u1",
        )],
        ..Default::default()
    };
    let conflicts = exclusive_pattern.conflicts_with(&exclusive_concrete);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].domain, AppletNamespaceDomain::Actors);

    let shared_pattern = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::shared(
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
        )],
        ..Default::default()
    };
    let shared_concrete = AppletWireNamespaces {
        actors: vec![AppletNamespaceEntry::shared(
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:u1",
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
        "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
        did("slackbridge"),
        did("alice"),
        "https://applet.example/cx",
        did("bot"),
        vec!["slack".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(
                "did:webvh:z6mkfixture:slackbridge.example:ghost:*",
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
        format!("{}#key-1", package.service_id),
        vec![WebhookSignatureAlg::EdDsa],
    );
    package
}

#[test]
fn wire_registration_round_trips_and_excludes_proof_from_digest() {
    let registration = sample_wire_registration();
    let value = serde_json::to_value(&registration).unwrap();
    assert!(value.get("kind").is_none());
    let round_trip: WireAppletRegistration = serde_json::from_value(value).unwrap();
    assert_eq!(round_trip.applet_id, registration.applet_id);
    assert_eq!(round_trip.namespaces.actors, registration.namespaces.actors);

    let expected_digest = registration.payload_digest().unwrap();
    let mut signed = registration;
    signed.proof = Some(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: expected_digest.clone(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "header..sig".to_owned(),
    });
    assert_eq!(signed.payload_digest().unwrap(), expected_digest);
}

#[test]
fn applet_package_derives_registration_and_rejects_stale_epoch() {
    let mut package = package_with_required_fields();
    package
        .seal_registration_epoch(sample_epoch_evidence(&package.service_id))
        .unwrap();
    assert!(package.validate().is_err());

    package.seal().unwrap();
    package.proof = Some(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: package.package_digest.clone().unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "header..sig".to_owned(),
    });
    package.validate().unwrap();

    let registration = package.to_registration().unwrap();
    assert_eq!(registration.registration_epoch, package.registration_epoch);
    assert_eq!(registration.namespaces, package.namespaces);
    assert!(registration.manifest.is_some());

    let mut stale = package;
    stale.base_url = "https://other.example/cx".to_owned();
    assert!(stale.validate().is_err());
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
    missing_profile
        .seal_registration_epoch(sample_epoch_evidence(&missing_profile.service_id))
        .unwrap();
    missing_profile.seal().unwrap();
    assert!(missing_profile.validate().is_err());
}

#[test]
fn install_plan_digest_excludes_itself_and_scope_round_trips() {
    let mut plan = AppletInstallPlan {
        schema: "ak.schema.applet_install_plan.v1".to_owned(),
        plan_id: "plan_1".to_owned(),
        applet_id: AppletInstallAppletId::AppletId(
            AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
        ),
        package_digest: sample_epoch(),
        registration_epoch: sample_epoch(),
        effective_scope: ScopeRef::Realm { realm_id: realm() },
        requested_scopes: vec!["ak.message.create".to_owned()],
        approved_scopes: vec![],
        denied_scopes: vec![],
        events_to_submit: vec![],
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
    let round_trip: AppletInstallPlan = serde_json::from_value(value).unwrap();
    assert_eq!(round_trip.effective_scope.realm_id(), &realm());
}

#[test]
fn install_commit_uses_only_caller_signed_formal_events() {
    let scope = ScopeRef::Realm { realm_id: realm() };
    let registration_event = Event::new(
        "ak.applet.registration",
        scope.clone(),
        did("admin"),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({"applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa"}),
    )
    .unwrap();
    let capability_grant_event = Event::new(
        "ak.capability.grant",
        scope.clone(),
        did("admin"),
        2,
        Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
        json!({"grant_id": "ak:grant:01904100-0000-7000-8000-aaaaaaaaaaaa"}),
    )
    .unwrap();
    let request = AppletInstallRequestBody {
        plan_digest: sample_epoch(),
        applet_package: package_with_required_fields(),
        effective_scope: scope,
        registration_event,
        capability_grant_events: vec![capability_grant_event],
        actor_policy: None,
        e2ee_policy: None,
        widget_policy: None,
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value["registration_event"]["kind"],
        json!("ak.applet.registration")
    );
    assert_eq!(
        value["capability_grant_events"][0]["kind"],
        json!("ak.capability.grant")
    );

    let mut old_wire = value;
    old_wire
        .as_object_mut()
        .unwrap()
        .remove("registration_event");
    old_wire
        .as_object_mut()
        .unwrap()
        .remove("capability_grant_events");
    old_wire["approved_scopes"] = json!([]);
    assert!(serde_json::from_value::<AppletInstallRequestBody>(old_wire).is_err());
}

#[test]
fn sign_registration_attaches_matching_payload_digest() {
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
                alg: "EdDSA".to_owned(),
                verification_method: self.verification_method.clone(),
                payload_digest: payload_digest.clone(),
                created_at: Utc::now(),
                jws: format!("stub..{}", payload_digest.as_str()),
                extra: Default::default(),
            })
        }
    }

    let signer = StubSigner {
        did: did("alice"),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
    };
    let mut registration = sample_wire_registration();
    sign_registration(
        &mut registration,
        &signer,
        &DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
    )
    .unwrap();

    let proof = registration.proof.as_ref().unwrap();
    assert_eq!(proof.alg, "EdDSA");
    assert_eq!(proof.event_digest, registration.payload_digest().unwrap());
}
