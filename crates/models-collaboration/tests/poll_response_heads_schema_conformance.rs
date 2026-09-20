//! Poll replacement declarations stay on the formal message payload, not Event causal refs.

use std::fs;

use arkret_models_collaboration::events_payloads::message::{
    MessageCreatePayload, PollResponseHead,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:message-create-poll-heads",
            schema,
            "#/$defs/message_create_payload",
        )
        .unwrap();
    registry
}

fn payload() -> Value {
    json!({
        "strand_id": "ak:strand:AUOjN8M8xm-W1G1Ve9UR6sHKJh7JPG7bM8ZDnzcGJ2Vh",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "vote", "format": "plain"}
    })
}

fn head() -> Value {
    json!({
        "poll_event_ref": "ak:event:AWnAqJ5-2jBzaey4VIckTGtKAtXIQYxWPNXLYnqGCMmg",
        "response_event_ref": "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB"
    })
}

#[test]
fn exact_poll_heads_round_trip_and_validate() {
    let mut value = payload();
    value["poll_response_heads"] = json!([head()]);
    registry()
        .validate_value("test:message-create-poll-heads", &value)
        .unwrap();
    let parsed: MessageCreatePayload = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);

    let without: MessageCreatePayload = serde_json::from_value(payload()).unwrap();
    assert!(without.poll_response_heads.is_empty());
    assert!(
        serde_json::to_value(without)
            .unwrap()
            .get("poll_response_heads")
            .is_none()
    );
}

#[test]
fn schema_and_typed_builder_reject_duplicate_or_oversized_heads() {
    let mut empty = payload();
    empty["poll_response_heads"] = json!([]);
    assert!(
        registry()
            .validate_value("test:message-create-poll-heads", &empty)
            .is_err()
    );
    assert!(serde_json::from_value::<MessageCreatePayload>(empty).is_err());

    let mut duplicate = payload();
    duplicate["poll_response_heads"] = json!([head(), head()]);
    assert!(
        registry()
            .validate_value("test:message-create-poll-heads", &duplicate)
            .is_err()
    );
    assert!(serde_json::from_value::<MessageCreatePayload>(duplicate).is_err());

    let typed_head: PollResponseHead = serde_json::from_value(head()).unwrap();
    let base: MessageCreatePayload = serde_json::from_value(payload()).unwrap();
    assert!(
        base.clone()
            .with_poll_response_heads(vec![typed_head.clone(); 2])
            .is_err()
    );
    assert!(base.with_poll_response_heads(vec![typed_head; 65]).is_err());

    let mut unknown = head();
    unknown["causal_ref"] = json!("retired");
    assert!(serde_json::from_value::<PollResponseHead>(unknown).is_err());
}
