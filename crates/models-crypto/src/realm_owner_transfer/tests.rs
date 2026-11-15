use super::*;

fn source() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/detached-object-signature-kat-fixture.json",
    )
    .unwrap()["owner_transfer"]
        .clone()
}

#[test]
fn finite_intent_matches_the_registered_signature_without_an_event_id_cycle() {
    let sample = source();
    let intent: RealmOwnerTransferAcceptanceIntent =
        serde_json::from_value(sample["unsigned_projection"].clone()).unwrap();
    let acceptance: DetachedObjectSignature =
        serde_json::from_value(sample["acceptance"].clone()).unwrap();
    intent.validate_acceptance(&acceptance).unwrap();
    assert_eq!(intent.digest().unwrap(), acceptance.signed_digest);
    assert_eq!(
        serde_json::to_value(&intent).unwrap(),
        sample["unsigned_projection"]
    );
    for member in [
        "event_id",
        "producer_proof",
        "successor_acceptance",
        "controller_epoch",
    ] {
        let mut value = sample["unsigned_projection"].clone();
        value[member] = serde_json::json!("surplus");
        assert!(serde_json::from_value::<RealmOwnerTransferAcceptanceIntent>(value).is_err());
    }
}

#[test]
fn the_exact_author_scope_root_and_successor_are_all_signed() {
    let sample = source();
    let intent: RealmOwnerTransferAcceptanceIntent =
        serde_json::from_value(sample["unsigned_projection"].clone()).unwrap();
    let acceptance: DetachedObjectSignature =
        serde_json::from_value(sample["acceptance"].clone()).unwrap();
    let mut other = intent.clone();
    other
        .payload_without_successor_acceptance
        .expected_state_digest = Hash::new(format!("sha256:{}", "12".repeat(32))).unwrap();
    assert!(other.validate_acceptance(&acceptance).is_err());
    let mut other = intent.clone();
    other.actor_id = intent
        .payload_without_successor_acceptance
        .patch
        .controller_actor_id
        .clone();
    assert!(other.validate_acceptance(&acceptance).is_err());
    let mut other = intent.clone();
    other
        .payload_without_successor_acceptance
        .patch
        .controller_actor_id = intent.actor_id.clone();
    assert!(other.validate_acceptance(&acceptance).is_err());
    let mut other = intent;
    other.scope_ref = ScopeRef::Realm {
        realm_id: RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [109; 32],
        )),
    };
    assert!(other.validate_acceptance(&acceptance).is_err());
}

#[test]
fn finite_lookup_is_single_account_device_and_cannot_be_a_contact_lookup() {
    let sample = source();
    let query = sample["transport"]["query"].clone();
    let request: crate::keys::PeerKeysQueryRequestBody =
        serde_json::from_value(query.clone()).unwrap();
    request.validate().unwrap();
    let mut changed = request.clone();
    changed.owner_transfer_acceptance = None;
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    changed.purpose = crate::keys::PeerKeysQueryPurpose::CallMedia;
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    changed.relationship_basis = crate::keys::PeerKeysRelationshipBasis::Contact {};
    assert!(changed.validate().is_err());
    let mut changed = request;
    changed.device_keys.push(changed.device_keys[0].clone());
    assert!(changed.validate().is_err());
    let mut null = query;
    null["owner_transfer_acceptance"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<crate::keys::PeerKeysQueryRequestBody>(null).is_err());
}
