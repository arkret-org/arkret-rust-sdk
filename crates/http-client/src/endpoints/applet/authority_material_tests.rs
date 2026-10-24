//! Request/cut consistency only; these fixtures do not claim live installation admission.

use arkret_models_collaboration::applet_installation_authority::{
    AppletAuthorityMaterialRequestBody, AppletAuthorityMaterialResponseBody, AppletCommittedEvent,
    AppletInstallationCurrentBinding,
};
use arkret_models_collaboration::exact_current_state::{
    CapabilityGrantExactCurrentSelector, CapabilityGrantExactCurrentSelectorKind,
    CurrentCapabilityGrant, ExactCurrentStateEntry, ExactCurrentStateReadResponseBody,
};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_test_kit::SignedEventFixtureBuilder;
use arkret_test_kit::authority_objects::signed_commit;
use arkret_wire::{
    ActorId, AppletId, CommitStreamHead, CurrentRevision, EventId, GrantId, RealmId, ScopeRef,
};
use chrono::{DateTime, Utc};
use serde_json::json;

fn fixture() -> (
    AppletId,
    AppletAuthorityMaterialRequestBody,
    AppletAuthorityMaterialResponseBody,
) {
    let now: DateTime<Utc> = "2026-10-21T01:00:00.000Z".parse().unwrap();
    let applet: AppletId = "ak:applet:01964137-0000-7000-8000-000000000081"
        .parse()
        .unwrap();
    let service = ActorId::service("ak:did_core:web:applet.example".parse().unwrap());
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [31; 32],
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let root = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [31; 32]);
    let method = arkret_wire::DidUrl::new("did:web:applet.example#admin").unwrap();
    let signer = arkret_test_kit::seeded_signer("did:web:applet.example".parse().unwrap(), method);
    let station_method = arkret_wire::DidUrl::new("did:web:station.example#authority").unwrap();
    let station_key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    let registration = SignedEventFixtureBuilder::new(
        "ak.applet.registration",
        scope.clone(),
        service.clone(),
        json!({"applet_id":applet,"service_id":"ak:did_core:web:applet.example"}),
    )
    .with_created_at(now)
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    let registration_commit = signed_commit(
        &station_method,
        &station_key,
        &registration,
        0,
        None,
        root.clone(),
        None,
    )
    .unwrap();
    let body = json!({
        "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":service,"subject":service,
        "actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[GrantConstraint::applet_authority(applet.clone(), service.clone(), format!("sha256:{}","4".repeat(64)).parse().unwrap())],
        "issued_at":arkret_canonical::format_timestamp_canonical(now),
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":root,"authority_generation":"0"}],
    });
    let grant = SignedEventFixtureBuilder::new(
        "ak.capability.grant",
        scope.clone(),
        service,
        json!({"grant":body}),
    )
    .with_created_at(now)
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    let grant_commit = signed_commit(
        &station_method,
        &station_key,
        &grant,
        1,
        Some(registration_commit.commit_id.clone()),
        root,
        None,
    )
    .unwrap();
    let id = GrantId::from_event_id(&grant.event_id);
    let mut value = body;
    value["id"] = json!(id);
    value["status"] = json!("active");
    value["authority_depth"] = json!(1);
    value["authority_root_refs"] = value["issuer_authority_refs"].clone();
    let current = ExactCurrentStateReadResponseBody::Present {
        realm_id: realm,
        governance_generation: 0,
        effective_stream_head: CommitStreamHead {
            stream_ref: grant_commit.stream_ref.clone(),
            stream_position: 1,
            commit_id: grant_commit.commit_id.clone(),
        },
        entry: ExactCurrentStateEntry::CapabilityGrant(CurrentCapabilityGrant {
            selector: CapabilityGrantExactCurrentSelector {
                kind: CapabilityGrantExactCurrentSelectorKind::CapabilityGrant,
                grant_id: id.clone(),
            },
            source_stream_ref: grant_commit.stream_ref.clone(),
            revision: CurrentRevision {
                commit_id: grant_commit.commit_id.clone(),
                stream_position: 1,
            },
            value: serde_json::from_value(value).unwrap(),
        }),
    };
    let outcome = AppletAuthorityMaterialResponseBody {
        applet_id: applet.clone(),
        service_id: "ak:did_core:web:applet.example".parse().unwrap(),
        effective_scope: scope.clone(),
        registration: AppletCommittedEvent {
            event: registration,
            commit: registration_commit,
            producer_device_evidence: None,
        },
        grant_events: vec![AppletCommittedEvent {
            event: grant,
            commit: grant_commit,
            producer_device_evidence: None,
        }],
        current_states: vec![current],
        current_binding: AppletInstallationCurrentBinding::Inactive,
    };
    (
        applet,
        AppletAuthorityMaterialRequestBody {
            effective_scope: scope,
            grant_ids: vec![id],
        },
        outcome,
    )
}

#[test]
fn material_read_matches_exact_requested_grants_without_requiring_an_active_installation() {
    let (applet, request, outcome) = fixture();
    outcome.validate_for_request(&applet, &request).unwrap();
    for mutation in 0..5 {
        let mut changed = outcome.clone();
        match mutation {
            0 => changed.grant_events.clear(),
            1 => changed
                .current_states
                .push(changed.current_states[0].clone()),
            2 => {
                if let ExactCurrentStateReadResponseBody::Present {
                    entry: ExactCurrentStateEntry::CapabilityGrant(row),
                    ..
                } = &mut changed.current_states[0]
                {
                    row.value.actions = vec!["ak.realm.delete".into()];
                }
            }
            3 => {
                if let ExactCurrentStateReadResponseBody::Present {
                    entry: ExactCurrentStateEntry::CapabilityGrant(row),
                    ..
                } = &mut changed.current_states[0]
                {
                    row.selector.grant_id = GrantId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [73; 32],
                    ));
                }
            }
            _ => {
                changed.applet_id = "ak:applet:01964137-0000-7000-8000-000000000092"
                    .parse()
                    .unwrap()
            }
        }
        assert!(
            changed.validate_for_request(&applet, &request).is_err(),
            "accepted mutation {mutation}"
        );
    }
}

#[test]
fn active_binding_keeps_same_scope_cut_and_service_but_can_renew_the_historical_epoch() {
    let (applet, request, mut outcome) = fixture();
    let original = &outcome.grant_events[0].commit;
    outcome.current_binding = AppletInstallationCurrentBinding::Active {
        registration_ref: arkret_wire::CommittedEventRef {
            event_id: outcome.registration.event.event_id.clone(),
            commit_id: outcome.registration.commit.commit_id.clone(),
            stream_ref: original.stream_ref.clone(),
            stream_position: 0,
        },
        registration_epoch: format!("sha256:{}", "9".repeat(64)).parse().unwrap(),
        service_id: "ak:did_core:web:applet.example".parse().unwrap(),
    };
    // Current epoch is deliberately different from the accepted old grant.
    outcome.validate_for_request(&applet, &request).unwrap();
    if let AppletInstallationCurrentBinding::Active { service_id, .. } =
        &mut outcome.current_binding
    {
        *service_id = "ak:did_core:web:other.example".parse().unwrap();
    }
    assert!(outcome.validate_for_request(&applet, &request).is_err());
}
