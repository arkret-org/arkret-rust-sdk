//! The `message_reactions` typed current row is judged by both the live Spec
//! schema and the strong SDK types.

use std::fs;

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::reaction::MessageReactionsCurrentValue;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{CurrentSelector, EventId, TypedCurrentRow};
use serde_json::{Value, json};

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const TARGET: &str = "ak:message:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
const OTHER_TARGET: &str = "ak:message:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(
            artifacts
                .join("schemas")
                .join("typed-current-result.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let id = "test:message-reactions-current-result".to_owned();
    registry
        .register_fragment(id.clone(), schema, "#/$defs/message_reactions_result")
        .unwrap();
    registry.validate_value(&id, value).is_ok()
}

fn sdk_accepts(value: &Value) -> bool {
    serde_json::from_value::<TypedCurrentRow>(value.clone())
        .ok()
        .and_then(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::MessageReactions { target_ref },
                value,
                ..
            } => serde_json::from_value::<MessageReactionsCurrentValue>(value)
                .ok()
                .filter(|set| set.validate_for_target(&target_ref).is_ok()),
            TypedCurrentRow::Value { .. } => None,
        })
        .is_some()
}

fn row_accepted_by_both(value: &Value) -> bool {
    let schema = schema_accepts(value);
    assert_eq!(
        schema,
        sdk_accepts(value),
        "schema and SDK disagree on {value}"
    );
    schema
}

/// Two canonical dots in ascending string order.
fn dots() -> [String; 2] {
    let mut dots = [0x21_u8, 0x42].map(|byte| {
        format!(
            "{}:0",
            EventId::from_digest(DigestSuite::Sha256, [byte; 32]).as_str()
        )
    });
    dots.sort();
    dots
}

fn row() -> Value {
    let [first, second] = dots();
    json!({
        "selector": {"kind": "message_reactions", "target_ref": TARGET},
        "source_stream_ref": {"kind": "realm", "realm_id": REALM},
        "revision": {"commit_id": COMMIT, "stream_position": 9},
        "value": {"assertions": [
            {"tag_id": first, "value": {"target_ref": TARGET, "key": "+1"}},
            {"tag_id": second, "value": {"target_ref": TARGET, "key": "+1", "annotation": "triage"}}
        ]}
    })
}

#[test]
fn message_reactions_row_round_trips_through_strong_types() {
    let value = row();
    assert!(row_accepted_by_both(&value));
    let typed: TypedCurrentRow = serde_json::from_value(value.clone()).unwrap();
    let TypedCurrentRow::Value {
        selector,
        value: set,
        ..
    } = &typed;
    assert_eq!(
        selector,
        &CurrentSelector::MessageReactions {
            target_ref: TARGET.to_owned(),
        }
    );
    let set: MessageReactionsCurrentValue = serde_json::from_value(set.clone()).unwrap();
    assert_eq!(set.assertions().len(), 2);
    assert_eq!(serde_json::to_value(&set).unwrap(), value["value"]);
    assert_eq!(serde_json::to_value(&typed).unwrap(), value);
}

#[test]
fn message_reactions_selector_drift_is_rejected_by_schema_and_sdk() {
    let mut event_keyed = row();
    event_keyed["selector"] = json!({
        "kind": "message_reactions",
        "event_id": TARGET.replacen("ak:message:", "ak:event:", 1)
    });
    assert!(!row_accepted_by_both(&event_keyed));

    let mut extra = row();
    extra["selector"]["key"] = json!("+1");
    assert!(!row_accepted_by_both(&extra));

    let mut malformed = row();
    malformed["selector"]["target_ref"] = json!("message-1");
    assert!(!row_accepted_by_both(&malformed));

    let mut no_source = row();
    no_source
        .as_object_mut()
        .unwrap()
        .remove("source_stream_ref");
    assert!(!row_accepted_by_both(&no_source));
}

#[test]
fn message_reactions_value_drift_is_rejected_by_schema_and_sdk() {
    let mut roster = row();
    roster.as_object_mut().unwrap().remove("value");
    roster["reactions"] = json!([{"actor_id": "ak:did_core:web:alice.example", "key": "+1"}]);
    assert!(!row_accepted_by_both(&roster));

    let mut open_value = row();
    open_value["value"]["count"] = json!(2);
    assert!(!row_accepted_by_both(&open_value));

    let mut assembled = row();
    assembled["value"]["assertions"][0]["actor_id"] = json!("ak:did_core:web:alice.example");
    assert!(!row_accepted_by_both(&assembled));

    let mut polarity = row();
    polarity["value"]["assertions"][0]["value"]["kind"] = json!("add");
    assert!(!row_accepted_by_both(&polarity));

    let mut bare_event = row();
    let tag = bare_event["value"]["assertions"][0]["tag_id"]
        .as_str()
        .unwrap()
        .trim_end_matches(":0")
        .to_owned();
    bare_event["value"]["assertions"][0]["tag_id"] = json!(tag);
    assert!(!row_accepted_by_both(&bare_event));

    let mut repeated = row();
    let first = repeated["value"]["assertions"][0].clone();
    repeated["value"]["assertions"] = json!([first.clone(), first]);
    assert!(!row_accepted_by_both(&repeated));

    let mut malformed_target = row();
    malformed_target["value"]["assertions"][0]["value"]["target_ref"] = json!("message-1");
    assert!(!row_accepted_by_both(&malformed_target));

    let mut long_key = row();
    long_key["value"]["assertions"][0]["value"]["key"] = json!("k".repeat(129));
    assert!(!row_accepted_by_both(&long_key));

    let mut empty_key = row();
    empty_key["value"]["assertions"][0]["value"]["key"] = json!("");
    assert!(!row_accepted_by_both(&empty_key));
}

/// Invariants the prose fixes and the schema cannot express: the dot set is
/// canonically sorted, each reaction Event contributes its single write, and
/// every element reacts to the selector's own target.
#[test]
fn message_reactions_set_invariants_beyond_the_schema_are_enforced_by_the_sdk() {
    let mut unsorted = row();
    let assertions = unsorted["value"]["assertions"].as_array_mut().unwrap();
    assertions.reverse();
    assert!(schema_accepts(&unsorted));
    assert!(!sdk_accepts(&unsorted));

    let mut second_write = row();
    let tag = second_write["value"]["assertions"][1]["tag_id"]
        .as_str()
        .unwrap()
        .replace(":0", ":1");
    second_write["value"]["assertions"][1]["tag_id"] = json!(tag);
    assert!(schema_accepts(&second_write));
    assert!(!sdk_accepts(&second_write));

    let mut foreign = row();
    foreign["value"]["assertions"][1]["value"]["target_ref"] = json!(OTHER_TARGET);
    assert!(schema_accepts(&foreign));
    assert!(!sdk_accepts(&foreign));

    let mut retargeted = row();
    retargeted["selector"]["target_ref"] = json!(OTHER_TARGET);
    assert!(schema_accepts(&retargeted));
    assert!(!sdk_accepts(&retargeted));
}

#[test]
fn message_reactions_insert_keeps_the_canonical_dot_order() {
    let value = row();
    let set: MessageReactionsCurrentValue = serde_json::from_value(value["value"].clone()).unwrap();
    let mut entries = set.into_assertions();
    let last = entries.pop().unwrap();
    let first = entries.pop().unwrap();
    let rebuilt = MessageReactionsCurrentValue::new(vec![last])
        .unwrap()
        .with_assertion(first.clone())
        .unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), value["value"]);
    assert!(rebuilt.with_assertion(first).is_err());
}
