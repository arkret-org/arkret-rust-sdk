use arkret_models_integration::{AppletPackage, AppletWireNamespaces};
use arkret_wire::{
    AccountId, AppletId, Did, DidKey, DidUrl, Hlc, ProducerEventProof, RealmId,
    StationAdmissionProof, StationAdmissionProofKind,
};
use serde_json::json;

use super::*;

fn core(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap()
}
fn account(name: &str) -> ActorId {
    ActorId::account(AccountId::new(core(name), core("station")))
}

fn resign(event: &mut Event, accepted: bool) {
    let suite = arkret_canonical::DigestSuite::Sha256;
    event
        .refresh_content_bound_identity_with_digest_suite(suite)
        .unwrap();
    let digest = Hash::new(event.event_digest_with_digest_suite(suite).unwrap()).unwrap();
    let author = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let method = if author == &ActorId::service(core("applet")) {
        "did:web:applet.example#applet-webhook".to_owned()
    } else {
        format!(
            "did:{}#device",
            author
                .signing_principal_id()
                .as_str()
                .strip_prefix("ak:did_core:")
                .unwrap()
        )
    };
    let producer = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new(method).unwrap(),
        event_digest: digest.clone(),
        signer_resolution_evidence_ref: None,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    };
    event.proofs = vec![producer.clone().into()];
    if accepted {
        event.proofs.push(
            StationAdmissionProof {
                kind: StationAdmissionProofKind::StationAdmission,
                verification_method: DidUrl::new("did:web:station.example#admission").unwrap(),
                event_digest: digest.clone(),
                producer_proof_digest: StationAdmissionProof::producer_proof_digest(&producer)
                    .unwrap(),
                producer_verification_method: producer.verification_method,
                producer_signing_key_did: DidKey::new(
                    "did:key:z6MkvLM6yK9N3Z1GYikAQLnhdjZoFQv4u4sRZNzgmwLkYsXx",
                )
                .unwrap(),
                producer_signer_resolution_evidence_ref: None,
                signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "33".repeat(32)
                ))
                .unwrap(),
                applet_installation_digest: None,
                accepted_at: event.created_at,
                jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
            }
            .into(),
        );
    }
}

fn fixture() -> (Event, AppletInstallationAuthority) {
    let realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [7; 32],
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let applet_id = AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap();
    let package = AppletPackage::new(
        "fixture",
        applet_id.clone(),
        core("applet"),
        Did::new("did:web:applet.example").unwrap(),
        core("admin"),
        "https://applet.example",
        account("bot"),
        vec!["demo".to_owned()],
        AppletWireNamespaces::default(),
    );
    let package = serde_json::to_value(package).unwrap();
    let mut registration = serde_json::Map::new();
    for field in [
        "applet_id",
        "service_id",
        "controller_principal_id",
        "base_url",
        "bot_actor_id",
        "claimed_profiles",
        "protocols",
        "namespaces",
        "receive_events",
        "receive_signals",
        "rate_limited",
        "requested_scopes",
        "registration_epoch",
        "webhook_auth",
        "created_at",
    ] {
        registration.insert(field.to_owned(), package[field].clone());
    }
    let epoch = format!("sha256:{}", "11".repeat(32));
    registration.insert("registration_epoch".to_owned(), json!(epoch));
    registration.insert("manifest".to_owned(), json!({
        "claimed_profiles": package["claimed_profiles"], "limits": package["limits"],
        "ghost_policy": package["ghost_policy"], "delegation_policy": package["delegation_policy"], "e2ee_policy": package["e2ee_policy"],
        "registration_epoch_evidence": {"did":"did:web:applet.example", "document_digest":epoch,
            "method_version_evidence":{"method":"did:web", "unversioned_refetch":true},
            "accepted_signing_keys":[{"key_ref":"did:web:applet.example#applet-webhook", "public_key_digest":epoch}]}
    }));
    registration.insert("proof".to_owned(), json!({"kind":"detached_jws", "verification_method":"did:web:admin.example#key", "payload_digest":epoch, "created_at":"2026-09-08T00:00:00.000Z", "jws":"a..b"}));
    let make = |kind: &str, payload: serde_json::Value| {
        let mut event = arkret_wire::test_support::raw_event(
            kind,
            scope.clone(),
            core("admin"),
            core("station"),
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap();
        event.seal_basis = Some(
            serde_json::from_value(
                json!({"leaves":[format!("ak:seal:sha256:{}", "22".repeat(32))]}),
            )
            .unwrap(),
        );
        resign(&mut event, true);
        event
    };
    let registration_event = make("ak.applet.registration", json!(registration));
    let capability_grant_event = make(
        "ak.capability.grant",
        json!({"grant":{
            "schema":"ak.schema.capability.v1", "realm_id":realm_id, "issuer_id":account("admin"),
            "subject":ActorId::service(core("applet")), "actions":["ak.message.create"], "resources":[WireResourceSelector::realm(realm_id.clone())],
            "constraints":[{"constraint_kind":"authority_control", "effect":"allow", "evaluation_class":"grant_local", "constraint_subkind":"applet_authority", "applet_id":applet_id, "executed_by":ActorId::service(core("applet")), "registration_epoch":epoch}],
            "issuer_authority_refs":[], "issued_at":"2026-09-08T00:00:00.000Z"
        }}),
    );
    let mut event = make("ak.message.create", json!({}));
    event.actor_id = account("bot");
    event.executed_by = Some(ActorId::service(core("applet")));
    event.applet_id = Some(applet_id);
    event.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(
            GrantId::from_event_id(&capability_grant_event.event_id).to_string(),
        )
        .unwrap(),
    );
    resign(&mut event, false);
    (
        event,
        AppletInstallationAuthority {
            registration_event,
            capability_grant_event,
        },
    )
}

#[test]
fn external_producer_and_service_action_use_installation_station() {
    let (mut event, authority) = fixture();
    assert_eq!(
        validate_applet_installation_coordinates(&event, &authority).unwrap(),
        core("station")
    );
    event.actor_id = ActorId::service(core("applet"));
    event.executed_by = None;
    resign(&mut event, false);
    assert_eq!(
        validate_applet_installation_coordinates(&event, &authority).unwrap(),
        core("station")
    );
    assert!(
        verify_applet_installation_authority(&event, &authority, |_| Err(WireError::Protocol(
            "invalid signature".to_owned()
        )))
        .is_err()
    );
}

#[test]
fn crossed_scope_applet_grant_epoch_and_action_fail_closed() {
    let (event, authority) = fixture();
    for field in ["applet_id", "authorization_ref", "scope_ref", "actor_id"] {
        let mut wrong = event.clone();
        match field {
            "applet_id" => {
                wrong.applet_id =
                    Some(AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap())
            }
            "authorization_ref" => {
                wrong.authorization_ref = Some(
                    arkret_wire::AuthorizationRef::new(
                        GrantId::from_event_id(&event.event_id).to_string(),
                    )
                    .unwrap(),
                )
            }
            "scope_ref" => {
                wrong.scope_ref = ScopeRef::Circle {
                    realm_id: event.realm_id.clone(),
                    circle_id: arkret_wire::CircleId::from_event_id(&event.event_id),
                }
            }
            _ => {
                wrong.actor_id =
                    ActorId::account(AccountId::new(core("bot"), core("wrong-station")))
            }
        }
        assert!(
            validate_applet_installation_coordinates(&wrong, &authority).is_err(),
            "{field}"
        );
    }
    for field in ["registration_epoch", "actions"] {
        let mut wrong = authority.clone();
        if field == "actions" {
            wrong
                .capability_grant_event
                .payload
                .get_mut("grant")
                .unwrap()["actions"] = json!(["ak.message.update"]);
        } else {
            wrong
                .capability_grant_event
                .payload
                .get_mut("grant")
                .unwrap()["constraints"][0]["registration_epoch"] =
                json!(format!("sha256:{}", "99".repeat(32)));
        }
        resign(&mut wrong.capability_grant_event, true);
        let mut event = event.clone();
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(
                GrantId::from_event_id(&wrong.capability_grant_event.event_id).to_string(),
            )
            .unwrap(),
        );
        resign(&mut event, false);
        assert!(
            validate_applet_installation_coordinates(&event, &wrong).is_err(),
            "{field}"
        );
    }
}

#[test]
fn replica_binds_frozen_authority_and_discovers_its_signers() {
    let (mut event, authority) = fixture();
    resign(&mut event, true);
    let digest = authority.canonical_sha256_digest().unwrap();
    if let EventProof::StationAdmission(admission) = &mut event.proofs[1] {
        admission.applet_installation_digest = Some(digest.clone());
    }
    let mut verified = Vec::new();
    let origin = verify_applet_installation_authority(&event, &authority, |dependency| {
        verified.push(dependency.event_id.clone());
        Ok(())
    })
    .unwrap();
    assert_eq!(origin, core("station"));
    assert_eq!(
        verified,
        [
            authority.registration_event.event_id.clone(),
            authority.capability_grant_event.event_id.clone()
        ]
    );
    let dependency = arkret_models_collaboration::governance_dependencies::GovernanceDependency::AppletInstallationAuthority {
        selector: arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AppletInstallationAuthority { content_digest: digest },
        applet_installation_authority: Box::new(authority.clone()),
    };
    assert_eq!(dependency.dependency_selectors().unwrap().len(), 1);
    for mutation in ["missing", "wrong-digest", "wrong-station", "producer"] {
        let mut wrong = event.clone();
        if let EventProof::StationAdmission(admission) = &mut wrong.proofs[1] {
            match mutation {
                "missing" => admission.applet_installation_digest = None,
                "wrong-digest" => {
                    admission.applet_installation_digest =
                        Some(Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap())
                }
                "wrong-station" => {
                    admission.verification_method =
                        DidUrl::new("did:web:other.example#admission").unwrap()
                }
                _ => {
                    admission.producer_proof_digest =
                        Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap()
                }
            }
        }
        assert!(
            validate_applet_installation_coordinates(&wrong, &authority).is_err(),
            "{mutation}"
        );
    }
    // There is deliberately no current installation or revocation lookup in
    // historical origin verification: only the original frozen evidence wins.
    assert_eq!(
        validate_applet_installation_coordinates(&event, &authority).unwrap(),
        origin
    );
}

#[test]
fn native_delegation_preserves_the_full_account_executor() {
    let (mut event, mut authority) = fixture();
    let native = account("native");
    let executor = account("bot");
    event.actor_id = native.clone();
    event.executed_by = Some(executor.clone());
    authority.capability_grant_event.actor_id = native.clone();
    let grant = authority
        .capability_grant_event
        .payload
        .get_mut("grant")
        .unwrap();
    grant["issuer_id"] = json!(native);
    grant["subject"] = json!(executor);
    grant["constraints"][0]["executed_by"] = json!(executor);
    resign(&mut authority.capability_grant_event, true);
    event.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(
            GrantId::from_event_id(&authority.capability_grant_event.event_id).to_string(),
        )
        .unwrap(),
    );
    resign(&mut event, false);
    assert_eq!(
        validate_applet_installation_coordinates(&event, &authority).unwrap(),
        core("station")
    );
    let mut self_signed = event.clone();
    self_signed.actor_id = executor;
    self_signed.executed_by = None;
    resign(&mut self_signed, false);
    assert_eq!(
        validate_applet_installation_coordinates(&self_signed, &authority).unwrap(),
        core("station")
    );
    event.executed_by = Some(ActorId::account(AccountId::new(
        core("bot"),
        core("foreign"),
    )));
    resign(&mut event, false);
    assert!(validate_applet_installation_coordinates(&event, &authority).is_err());
}
