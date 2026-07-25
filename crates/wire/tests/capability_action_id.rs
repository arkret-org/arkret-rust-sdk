use arkret_wire::CapabilityActionId;

#[test]
fn capability_action_id_uses_registry_wire_string() {
    let action = CapabilityActionId::CircleManage;

    assert_eq!(action.to_string(), "ak.circle.manage");
    assert_eq!(
        serde_json::to_string(&action).expect("serialize capability action"),
        r#""ak.circle.manage""#
    );
    assert_eq!(
        serde_json::from_str::<CapabilityActionId>(r#""ak.circle.manage""#)
            .expect("deserialize capability action"),
        action
    );
}

#[test]
fn capability_action_id_rejects_unregistered_wire_string() {
    let error = serde_json::from_str::<CapabilityActionId>(r#""ak.circle.*""#)
        .expect_err("umbrella action is not registered");

    assert!(error.to_string().contains("unknown capability action id"));
}
