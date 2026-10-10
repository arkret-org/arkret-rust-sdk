use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind, RealmJoinTarget,
};
use arkret_models_collaboration::objects::realm::Realm;
use arkret_wire::{ActorId, CircleId, CommitStreamRef, DidCoreId, RealmId, TrustDomainId};

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
}

fn station_id() -> DidCoreId {
    DidCoreId::new("ak:did_core:web:station.example").unwrap()
}

#[test]
fn realm_and_circle_are_independent_commit_streams() {
    let realm = realm_id();
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let circle_stream = CommitStreamRef::Circle {
        realm_id: realm,
        circle_id: CircleId::new("ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0").unwrap(),
    };
    assert_ne!(realm_stream, circle_stream);
    assert_eq!(realm_stream.realm_id(), circle_stream.realm_id());
}

#[test]
fn join_locator_is_only_a_bounded_https_hint() {
    let target = RealmJoinTarget {
        realm_id: realm_id(),
        invite_id: None,
        authority_locator_hints: vec![RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: station_id(),
            source: AuthorityLocatorSource::Invite,
            endpoint_url: Some("https://station.example".to_owned()),
        }],
    };
    target.validate().unwrap();

    let mut invalid = target;
    invalid.authority_locator_hints.clear();
    assert!(invalid.validate().is_err());
}

#[test]
fn realm_projection_exposes_current_authority_coordinates() {
    let realm = Realm::new(
        realm_id(),
        "Example",
        ActorId::service(station_id()),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        station_id(),
    );
    let value = serde_json::to_value(realm).unwrap();
    assert_eq!(
        value["governance_station_id"],
        "ak:did_core:web:station.example"
    );
    assert_eq!(value["governance_generation"], 0);
}
