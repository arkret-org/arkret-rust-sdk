//! Active Reaction metadata has one closed row and no historical union API.

use std::fs;

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::reaction::MessageReactionsCurrentValue;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{CommitStreamHead, CurrentRevision, CurrentSelector, CurrentState, EventId};
use serde_json::{Value, json};

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const TARGET: &str = "ak:message:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/current-state.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let id = "test:message-reactions-current-state".to_owned();
    registry
        .register_fragment(id.clone(), schema, "#/$defs/current_message_reactions")
        .unwrap();
    registry.validate_value(&id, value).is_ok()
}
fn sdk_accepts(value: &Value) -> bool {
    serde_json::from_value::<CurrentState>(value.clone())
        .ok()
        .is_some_and(|row| match row {
            CurrentState::Value {
                selector: CurrentSelector::MessageReactions { target_ref },
                source_stream_ref,
                revision,
                value,
            } => serde_json::from_value::<MessageReactionsCurrentValue>(value)
                .ok()
                .is_some_and(|current| {
                    let head = CommitStreamHead {
                        stream_ref: source_stream_ref.clone(),
                        stream_position: revision.stream_position,
                        commit_id: revision.commit_id.clone(),
                    };
                    current
                        .validate_installation(
                            &target_ref,
                            &source_stream_ref,
                            &revision,
                            &head,
                            None,
                        )
                        .is_ok()
                }),
            _ => false,
        })
}
fn both(value: &Value) -> bool {
    let schema = schema_accepts(value);
    assert_eq!(
        schema,
        sdk_accepts(value),
        "schema/SDK shape disagreement: {value}"
    );
    schema
}
fn row() -> Value {
    let actor = |station| json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":station}});
    let source = |seed, position| {
        json!({"event_id":EventId::from_digest(DigestSuite::Sha256,[seed;32]),
        "commit_id":arkret_wire::RealmCommitId::from_digest([seed;32]),"stream_ref":{"kind":"realm","realm_id":REALM},"stream_position":position})
    };
    json!({"selector":{"kind":"message_reactions","target_ref":TARGET},
        "source_stream_ref":{"kind":"realm","realm_id":REALM},"revision":{"commit_id":COMMIT,"stream_position":9},
        "value":{"entries":[
            {"actor_id":actor("ak:did_core:web:a-station.example"),"key":"+1","source":source(0x21,1)},
            {"actor_id":actor("ak:did_core:web:b-station.example"),"key":"+1","source":source(0x42,2)}]}})
}
fn current(value: &Value) -> MessageReactionsCurrentValue {
    serde_json::from_value(value["value"].clone()).unwrap()
}
fn revision(value: &Value) -> CurrentRevision {
    serde_json::from_value(value["revision"].clone()).unwrap()
}
fn head(value: &Value) -> CommitStreamHead {
    CommitStreamHead {
        stream_ref: serde_json::from_value(value["source_stream_ref"].clone()).unwrap(),
        stream_position: 12,
        commit_id: arkret_wire::RealmCommitId::from_digest([0x77; 32]),
    }
}

#[test]
fn active_entries_round_trip_and_full_station_identity_never_aliases() {
    let value = row();
    assert!(both(&value));
    let typed: CurrentState = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(typed).unwrap(), value);
    let active = current(&value);
    assert_eq!(active.entries().len(), 2);
    assert_ne!(active.entries()[0].actor_id, active.entries()[1].actor_id);
    assert_eq!(serde_json::to_value(active).unwrap(), value["value"]);
}

#[test]
fn empty_after_remove_is_a_real_row_with_its_last_revision() {
    let mut value = row();
    value["value"] = json!({"entries":[]});
    assert!(both(&value));
    assert_eq!(revision(&value).stream_position, 9);
    assert!(current(&value).entries().is_empty());
}

#[test]
fn old_assertions_tombstones_payloads_and_partial_values_are_rejected() {
    let mut old = row();
    old["value"] = json!({"assertions":[]});
    assert!(!both(&old));
    for (field, item) in [
        ("last_action", json!("remove")),
        ("annotation", json!("secret")),
        ("encrypted_payload", json!({})),
    ] {
        let mut value = row();
        value["value"]["entries"][0][field] = item;
        assert!(!both(&value));
    }
    let mut partial = row();
    partial["value"]["partial"] = json!(true);
    assert!(!both(&partial));
    let mut count = row();
    count["value"]["count"] = json!(2);
    assert!(!both(&count));
}

#[test]
fn formal_target_actor_key_and_complete_source_shapes_remain_required() {
    for (path, item) in [
        ("/selector/target_ref", json!("message-1")),
        (
            "/value/entries/0/actor_id",
            json!("ak:did_core:web:alice.example"),
        ),
        ("/value/entries/0/key", json!("")),
        ("/value/entries/0/key", json!("k".repeat(129))),
        ("/value/entries/0/source/event_id", json!(COMMIT)),
        ("/value/entries/0/source/stream_position", json!(-1)),
    ] {
        let mut value = row();
        *value.pointer_mut(path).unwrap() = item;
        assert!(!both(&value), "{path}");
    }
    let mut incomplete = row();
    incomplete["value"]["entries"][0]["source"]
        .as_object_mut()
        .unwrap()
        .remove("commit_id");
    assert!(!both(&incomplete));
}

#[test]
fn duplicate_or_unsorted_business_keys_are_refused_without_normalizing_bytes() {
    let mut reversed = row();
    reversed["value"]["entries"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(schema_accepts(&reversed));
    assert!(!sdk_accepts(&reversed));
    let mut duplicate = row();
    duplicate["value"]["entries"][1]["actor_id"] =
        duplicate["value"]["entries"][0]["actor_id"].clone();
    assert!(schema_accepts(&duplicate));
    assert!(!sdk_accepts(&duplicate));
    let active = current(&row());
    let mut entries = active.into_entries();
    entries.reverse();
    assert!(MessageReactionsCurrentValue::new(entries).is_err());
}

#[test]
fn nested_sources_are_bound_to_the_outer_stream_and_revision() {
    for path in [
        "/value/entries/0/source/stream_ref/realm_id",
        "/value/entries/0/source/stream_position",
    ] {
        let mut value = row();
        *value.pointer_mut(path).unwrap() = if path.ends_with("realm_id") {
            json!(arkret_wire::RealmId::from_event_id(&EventId::from_digest(
                DigestSuite::Sha256,
                [0x33; 32]
            )))
        } else {
            json!(10)
        };
        assert!(schema_accepts(&value));
        assert!(!sdk_accepts(&value));
    }
    let mut wrong_commit = row();
    wrong_commit["value"]["entries"][0]["source"]["stream_position"] = json!(9);
    assert!(!sdk_accepts(&wrong_commit));
}

#[test]
fn a_new_head_cannot_install_an_older_row_or_change_a_known_revision() {
    let previous = row();
    let prior = current(&previous);
    let prior_revision = revision(&previous);
    let stream = head(&previous).stream_ref;
    let later_head = head(&previous);
    let mut older = previous.clone();
    older["value"] = json!({"entries":[]});
    older["revision"]["stream_position"] = json!(1);
    assert!(
        current(&older)
            .validate_installation(
                TARGET,
                &stream,
                &revision(&older),
                &later_head,
                Some((&prior, &prior_revision))
            )
            .is_err()
    );
    let mut equivocation = previous.clone();
    equivocation["revision"]["commit_id"] =
        json!(arkret_wire::RealmCommitId::from_digest([0x66; 32]));
    assert!(
        current(&equivocation)
            .validate_installation(
                TARGET,
                &stream,
                &revision(&equivocation),
                &later_head,
                Some((&prior, &prior_revision))
            )
            .is_err()
    );
    let mut altered = previous.clone();
    altered["value"] = json!({"entries":[]});
    assert!(
        current(&altered)
            .validate_installation(
                TARGET,
                &stream,
                &prior_revision,
                &later_head,
                Some((&prior, &prior_revision))
            )
            .is_err()
    );
    assert!(
        prior
            .validate_installation(
                TARGET,
                &stream,
                &prior_revision,
                &later_head,
                Some((&prior, &prior_revision))
            )
            .is_ok()
    );
}

#[test]
fn current_metadata_does_not_require_below_floor_event_or_key_fetches() {
    let value = row();
    let active = current(&value);
    assert!(
        active
            .entries()
            .iter()
            .all(|entry| entry.source.stream_position < 7)
    );
    assert!(
        active
            .validate_installation(
                TARGET,
                &head(&value).stream_ref,
                &revision(&value),
                &head(&value),
                None
            )
            .is_ok()
    );
    assert!(
        serde_json::to_string(&active)
            .unwrap()
            .find("encrypted_payload")
            .is_none()
    );
}

#[test]
fn an_available_original_must_be_the_exact_active_add_binding() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/reaction-authority-order-fixture.json")).unwrap(),
    )
    .unwrap();
    let original: arkret_wire::CommittedEventFullView =
        serde_json::from_value(fixture["original_rows"][0].clone()).unwrap();
    let active: MessageReactionsCurrentValue = serde_json::from_value(
        fixture["checkpoints"][0]["current_state_entries"][0]["value"].clone(),
    )
    .unwrap();
    let target = fixture["trusted_basis"]["target_ref"].as_str().unwrap();
    let entry = &active.entries()[0];
    entry.validate_source_binding(target, &original).unwrap();
    let mut removed = original.clone();
    removed.event.kind = arkret_wire::EventKind::ReactionRemove;
    assert!(entry.validate_source_binding(target, &removed).is_err());
    let mut wrong_key = entry.clone();
    wrong_key.key = "wrong".into();
    assert!(
        wrong_key
            .validate_source_binding(target, &original)
            .is_err()
    );
    assert!(
        entry
            .validate_source_binding(
                "ak:message:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0",
                &original
            )
            .is_err()
    );
}
