use arkret_wire::{ActorId, DidCoreId, EventId, RealmAuthorityRootValue};

#[test]
fn authority_generation_keeps_its_full_width_without_widening_controller_epoch() {
    let mut root = RealmAuthorityRootValue {
        controller_actor_id: ActorId::service(
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ),
        controller_epoch: 0,
        authority_generation: u64::MAX,
        authority_event_ref: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]),
    };
    root.validate().unwrap();
    let mut value = serde_json::to_value(&root).unwrap();
    assert_eq!(value["authority_generation"], u64::MAX.to_string());
    value["authority_generation"] = serde_json::json!(u64::MAX);
    assert!(serde_json::from_value::<RealmAuthorityRootValue>(value).is_err());
    root.controller_epoch = 9_007_199_254_740_992;
    assert!(root.validate().is_err());
}
