//! Execute the canonical wire vectors against the shared authoring types.

use arkret_models_collaboration::events_payloads::StrandPatchPayload;
use arkret_models_collaboration::objects::space::{Space, SpaceMetadata};
use arkret_models_collaboration::objects::strand::StrandTopic;
use serde_json::{Value, json};

#[test]
fn all_structure_wire_vectors_match_sdk_validation() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/direct-conversation-structure-fixture.json"))
            .unwrap(),
    )
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let value = case["value"].clone();
        let accepted = match case["schema_ref"].as_str().unwrap() {
            "schemas/space.schema.json" => {
                serde_json::from_value::<Space>(value).is_ok_and(|space| space.validate().is_ok())
            }
            "schemas/space.schema.json#/$defs/space_metadata" => {
                serde_json::from_value::<SpaceMetadata>(value)
                    .is_ok_and(|metadata| metadata.validate().is_ok())
            }
            "schemas/strand.schema.json#/$defs/strand_topic" => {
                serde_json::from_value::<StrandTopic>(value).is_ok()
            }
            "schemas/event-payload.schema.json#/$defs/strand_patch_payload" => {
                serde_json::from_value::<StrandPatchPayload>(value)
                    .is_ok_and(|body| body.validate().is_ok())
            }
            reference => panic!("unexecuted structure vector: {reference}"),
        };
        assert_eq!(
            accepted,
            case["expect_valid"].as_bool().unwrap(),
            "{}",
            case["case_id"]
        );
    }
}

#[test]
fn participant_topic_gate_rejects_lists_boards_nested_topics_and_missing_cas() {
    use std::collections::BTreeMap;

    use arkret_models_collaboration::direct_conversation::direct_conversation_structure_admits;
    use arkret_models_collaboration::objects::strand::Strand;
    use arkret_wire::{
        AccountId, ActorId, DidCoreId, EventKind, Hash, RealmId, ScopeRef, SpaceId, SpaceState,
        StrandId,
    };

    let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let actor = ActorId::account(AccountId::new(principal.clone(), station.clone()));
    let token = "ASOv-EoZPg5yuM1Pv__u1K8vD3Q9342GxwoWmkKwjqOn";
    let realm = RealmId::new(format!("ak:realm:{token}")).unwrap();
    let main = StrandId::new(format!("ak:strand:{token}")).unwrap();
    let topic_id = SpaceId::new(format!("ak:space:{token}")).unwrap();
    let mut chat = Strand::discussion(main.clone(), realm.clone(), "Main", actor.clone());
    let mut topic = Space::new(topic_id.clone(), realm.clone(), "topic", "Topic", actor);
    topic.state = Some(SpaceState::Active);
    let mut strands = BTreeMap::from([(main.clone(), chat.clone())]);
    let mut spaces = BTreeMap::from([(topic_id.clone(), topic.clone())]);
    let body = StrandPatchPayload::for_topic(
        main.clone(),
        Some(StrandTopic {
            space_id: topic_id.clone(),
            rank: "a0".into(),
        }),
        Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
    )
    .unwrap();
    let mut event = arkret_wire::test_support::raw_event(
        EventKind::StrandUpdate.as_str(),
        ScopeRef::Realm { realm_id: realm },
        principal,
        station,
        serde_json::to_value(body).unwrap(),
    )
    .unwrap();
    assert!(direct_conversation_structure_admits(
        &event, &main, &strands, &spaces
    ));
    for kind in ["list", "board"] {
        topic.kind = kind.into();
        spaces.insert(topic_id.clone(), topic.clone());
        assert!(!direct_conversation_structure_admits(
            &event, &main, &strands, &spaces
        ));
    }
    topic.kind = "topic".into();
    topic.parent_space_id = Some(topic_id.clone());
    spaces.insert(topic_id.clone(), topic.clone());
    assert!(!direct_conversation_structure_admits(
        &event, &main, &strands, &spaces
    ));
    topic.parent_space_id = None;
    topic.state = Some(SpaceState::Archived);
    spaces.insert(topic_id.clone(), topic);
    assert!(!direct_conversation_structure_admits(
        &event, &main, &strands, &spaces
    ));
    chat.topic = Some(StrandTopic {
        space_id: topic_id,
        rank: "a0".into(),
    });
    strands.insert(main.clone(), chat);
    event
        .payload
        .insert("patch".into(), json!({"topic":{"$op":"unset"}}));
    assert!(direct_conversation_structure_admits(
        &event, &main, &strands, &spaces
    ));
    event.payload.remove("expected_state_digest");
    assert!(!direct_conversation_structure_admits(
        &event, &main, &strands, &spaces
    ));
}
