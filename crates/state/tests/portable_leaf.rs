use arkret_state::causal_register_leaf_value;
use arkret_wire::{EventId, Hash};
use serde_json::json;

#[test]
fn portable_causal_heads_require_a_closed_ordered_set_with_one_value() {
    let id = |byte: &str| {
        EventId::from_event_digest(&Hash::new(format!("sha256:{}", byte.repeat(32))).unwrap())
            .unwrap()
    };
    let first = json!({"event_id": id("11"), "value": "authority"});
    let second = json!({"event_id": id("22"), "value": "authority"});
    assert_eq!(
        causal_register_leaf_value(&json!([first, second])).unwrap(),
        json!("authority")
    );
    for invalid in [
        json!([]),
        json!([first, first]),
        json!([second, first]),
        json!([first, {"event_id": id("22"), "value": "other"}]),
        json!([{"event_id": id("11"), "value": "authority", "extra": true}]),
        json!([{"event_id": "invalid", "value": "authority"}]),
    ] {
        assert!(causal_register_leaf_value(&invalid).is_err(), "{invalid}");
    }
}
