use super::*;

fn event(byte: u8) -> EventId {
    EventId::from_event_digest(&Hash::new(arkret_wire::canonical::sha256_digest([byte])).unwrap())
        .unwrap()
}

fn cbor_fixture() -> Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/mls-governance-binding-closure-fixture.json",
    )
    .unwrap()["cases"][0]
        .clone()
}

#[test]
fn history_scope_validator_rejects_sidecar_without_rejecting_sidecar_mls() {
    let binding = MlsGovernanceBindingPayload::sidecar(
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
        Some(event(1)),
        1,
        2,
        0,
        Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
    )
    .unwrap();
    binding.validate().unwrap();
    assert!(binding.validate_realm_or_circle_scope().is_err());
}

#[test]
fn sidecar_participant_digest_is_closed_and_bound_by_cbor() {
    let binding = MlsGovernanceBindingPayload::sidecar(
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
        None,
        0,
        0,
        0,
        Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap(),
    )
    .unwrap();
    let encoded = binding.to_deterministic_cbor().unwrap();
    assert_eq!(
        MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap(),
        binding
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert!(MlsGovernanceBindingPayload::from_deterministic_cbor(&trailing).is_err());

    let mut missing_digest = serde_json::to_value(&binding).unwrap();
    missing_digest
        .as_object_mut()
        .unwrap()
        .remove("participant_authority_digest");
    assert!(
        serde_json::from_value::<MlsGovernanceBindingPayload>(missing_digest)
            .unwrap()
            .validate()
            .is_err()
    );

    let mut realm = MlsGovernanceBindingPayload::realm(
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        None,
        0,
        0,
        0,
    )
    .unwrap();
    realm.participant_authority_digest = binding.participant_authority_digest.clone();
    assert!(realm.validate().is_err());
    realm.participant_authority_digest = None;

    let mut circle = MlsGovernanceBindingPayload::circle(
        realm.effective_scope().realm_id().clone(),
        CircleId::new("ak:circle:AcQajqaKFvyDoMpqpSlBvMh0d4gheZsVPhbHaTlqXtkV").unwrap(),
        None,
        0,
        0,
        0,
    )
    .unwrap();
    circle.participant_authority_digest = binding.participant_authority_digest.clone();
    assert!(circle.validate().is_err());
    circle.participant_authority_digest = None;

    for scope_binding in [binding, realm, circle] {
        for forbidden in [Value::Null, serde_json::json!([event(1)])] {
            let mut value = serde_json::to_value(&scope_binding).unwrap();
            value["authority_stream_head"] = forbidden;
            assert!(serde_json::from_value::<MlsGovernanceBindingPayload>(value.clone()).is_err());
            for field in ["previous_epoch", "next_epoch", "key_access_revision"] {
                value[field] = Value::from(0_u64);
            }
            let mut encoded = Vec::new();
            encode_deterministic_cbor(&value, &mut encoded).unwrap();
            let error = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap_err();
            assert_eq!(error.error_code(), Some(ErrorCode::SchemaViolation));
        }
    }
}

#[test]
fn sidecar_binding_encodes_members_in_schema_map_key_order() {
    let case = cbor_fixture();
    let sample = case["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["name"] == "sidecar_scope_commit")
        .unwrap();
    let binding: MlsGovernanceBindingPayload =
        serde_json::from_value(sample["binding"].clone()).unwrap();
    let encoded = binding.to_deterministic_cbor().unwrap();
    assert_eq!(
        encoded,
        hex::decode(sample["encoded_map_hex"].as_str().unwrap()).unwrap()
    );
    assert_eq!(encoded[0], 0xa6);
    let order = [
        "next_epoch",
        "previous_epoch",
        "effective_scope",
        "key_access_revision",
        "base_group_state_ref",
        "participant_authority_digest",
    ];
    let positions = order
        .iter()
        .map(|key| {
            let mut encoded_key = Vec::new();
            encode_deterministic_cbor(&Value::String((*key).to_owned()), &mut encoded_key).unwrap();
            encoded
                .windows(encoded_key.len())
                .position(|window| window == encoded_key.as_slice())
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn deterministic_cbor_matches_formal_acceptance_and_rejection_kats() {
    let case = cbor_fixture();
    for sample in case["accepted"].as_array().unwrap() {
        let encoded = hex::decode(sample["encoded_map_hex"].as_str().unwrap()).unwrap();
        let binding = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap();
        assert_eq!(serde_json::to_value(&binding).unwrap(), sample["binding"]);
        assert_eq!(binding.to_deterministic_cbor().unwrap(), encoded);
    }
    for sample in case["rejection_samples"].as_array().unwrap() {
        let encoded = hex::decode(sample["encoded_map_hex"].as_str().unwrap()).unwrap();
        let error = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap_err();
        assert_eq!(
            error.error_code(),
            Some(ErrorCode::SchemaViolation),
            "{}",
            sample["name"]
        );
    }
}

#[test]
fn binding_members_reject_null_or_absent_spellings() {
    let realm = MlsGovernanceBindingPayload::realm(
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        None,
        0,
        0,
        0,
    )
    .unwrap();
    let value = serde_json::to_value(&realm).unwrap();
    assert_eq!(value["base_group_state_ref"], Value::Null);
    let mut absent_base = value.clone();
    absent_base
        .as_object_mut()
        .unwrap()
        .remove("base_group_state_ref");
    assert!(serde_json::from_value::<MlsGovernanceBindingPayload>(absent_base).is_err());
    for member in ["participant_authority_digest", "authority_stream_head"] {
        let mut null_member = value.clone();
        null_member[member] = Value::Null;
        assert!(serde_json::from_value::<MlsGovernanceBindingPayload>(null_member).is_err());
    }
}
