use arkret_models_collaboration::events_payloads::{
    ContentBlock, MentionNode, MentionTarget, RealmMention, collect_mention_subject_account_ids,
    collect_mention_subject_actor_ids, parse_mention_node, validate_mentions_in_realm,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{ActorId, RealmId};
use serde_json::{Value, json};

const REALM: &str = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
const OTHER_REALM: &str = "ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr";

fn realm_subject(realm: &str) -> Value {
    json!({
        "kind": "realm",
        "realm_actor_id": {
            "realm_id": realm,
            "principal_id": "ak:did_core:webvh:z6mkfixtureBot"
        }
    })
}

fn mention() -> Value {
    json!({
        "kind": "mention",
        "subject_actor_id": realm_subject(REALM),
        "display_name_at_time": "Helper",
        "mention_text_original": "@Helper",
        "resolved_at": "2026-10-21T00:00:00.000Z"
    })
}

#[test]
fn realm_mentions_match_the_formal_closed_branch() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment("test:mention", schema, "#/$defs/mention_node")
        .unwrap();
    let valid = mention();
    registry.validate_value("test:mention", &valid).unwrap();
    let node: MentionNode = serde_json::from_value(valid.clone()).unwrap();
    assert_eq!(serde_json::to_value(&node).unwrap(), valid);
    assert!(matches!(node.target(), MentionTarget::RealmSubject(_)));
    assert_eq!(node.mention_text_original(), Some("@Helper"));
    assert!(node.as_mention().is_none());
    assert!(node.as_realm_mention().is_some());
    let account = json!({
        "principal_id": "ak:did_core:webvh:z6mkfixtureBot",
        "station_id": "ak:did_core:web:accounts.example"
    });
    let mut invalid = Vec::new();
    for (field, value) in [
        ("subject_account_id", account.clone()),
        ("handle_at_time", json!("helper:accounts.example")),
        ("controller_subject_account_id", account.clone()),
        ("controller_handle_at_time", json!("alice:accounts.example")),
        ("agent_slug_at_time", json!("helper")),
        ("display_name_at_time", Value::Null),
        ("mention_text_original", Value::Null),
        ("resolved_at", Value::Null),
    ] {
        let mut value_with_field = valid.clone();
        value_with_field[field] = value;
        invalid.push(value_with_field);
    }
    for actor in [
        json!({"kind":"account","account_id":account}),
        json!({"kind":"service","service_id":"ak:did_core:web:service.example"}),
        Value::Null,
    ] {
        let mut value = valid.clone();
        value["subject_actor_id"] = actor;
        invalid.push(value);
    }
    for value in invalid {
        assert!(
            registry.validate_value("test:mention", &value).is_err(),
            "{value}"
        );
        assert!(parse_mention_node(&value).is_err(), "{value}");
        assert!(
            serde_json::from_value::<MentionNode>(value.clone()).is_err(),
            "{value}"
        );
    }
}

#[test]
fn nested_mentions_preserve_full_identity_and_reject_another_realm() {
    let actor: ActorId = serde_json::from_value(realm_subject(REALM)).unwrap();
    let content = json!({"kind":"ak.content.composite","parts":[
        {"kind":"ak.content.text","body":"Hello","mentions":[mention()]}
    ]});
    let realm = RealmId::new(REALM).unwrap();
    validate_mentions_in_realm(&content, &realm).unwrap();
    assert_eq!(
        collect_mention_subject_actor_ids(&content).unwrap(),
        vec![actor.clone()]
    );
    assert!(
        collect_mention_subject_account_ids(&content)
            .unwrap()
            .is_empty()
    );
    let mut wrong = content;
    wrong["parts"][0]["mentions"][0]["subject_actor_id"] = realm_subject(OTHER_REALM);
    assert!(validate_mentions_in_realm(&wrong, &realm).is_err());
    assert_ne!(
        collect_mention_subject_actor_ids(&wrong).unwrap(),
        vec![actor]
    );
}

#[test]
fn typed_content_authoring_retains_the_realm_target() {
    let actor: ActorId = serde_json::from_value(realm_subject(REALM)).unwrap();
    let node = MentionNode::RealmMention(RealmMention::new(actor.clone()).unwrap());
    let content = ContentBlock::text("Hello @Helper")
        .with_direct_mention_nodes(vec![node])
        .unwrap();
    let value = content.to_value().unwrap();
    assert_eq!(
        collect_mention_subject_actor_ids(&value).unwrap(),
        vec![actor]
    );
    validate_mentions_in_realm(&value, &RealmId::new(REALM).unwrap()).unwrap();
    let account: ActorId = serde_json::from_value(json!({
        "kind":"account",
        "account_id": {
            "principal_id":"ak:did_core:webvh:z6mkfixtureBot",
            "station_id":"ak:did_core:web:accounts.example"
        }
    }))
    .unwrap();
    assert!(RealmMention::new(account).is_err());
}
