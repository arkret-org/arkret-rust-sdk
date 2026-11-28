use arkret_models_collaboration::events_payloads::{JoinPolicyGate, ReadReceiptPolicyPayload};
use arkret_models_collaboration::governance::realm_governance::RealmLinkKind;
use serde_json::json;

const SOURCE_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

#[test]
fn realm_link_kind_registry_has_seven_kinds() {
    assert_eq!(RealmLinkKind::all().len(), 7);
}

#[test]
fn parent_membership_remains_a_closed_authoring_shape_without_authority_evidence() {
    let value = json!({
        "kind": "parent_membership",
        "gate_id": "same-station-membership",
        "membership_source_realm_ids": [SOURCE_REALM],
        "require_min_membership": "join"
    });
    let gate: JoinPolicyGate = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(gate).unwrap(), value);

    for forbidden in ["proof", "authority_basis", "source_checkpoint"] {
        let mut invalid = value.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), json!({}));
        assert!(serde_json::from_value::<JoinPolicyGate>(invalid).is_err());
    }
}

#[test]
fn read_receipt_policy_rejects_the_retired_parent_floor_switch() {
    assert!(
        serde_json::from_value::<ReadReceiptPolicyPayload>(json!({
            "child_privacy_tightening_against_required": true
        }))
        .is_err()
    );
}
