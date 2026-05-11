use super::*;
use crate::Hlc;
use serde_json::json;

#[test]
fn space_state_creates_empty() {
    let state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    assert_eq!(state.entities.len(), 0);
    assert_eq!(state.subjects.len(), 0);
    assert_eq!(state.relations.len(), 0);
}

#[test]
fn flow_events_create_update_and_link_surfaces() {
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let actor_id = Did::new("did:web:alice.example.com").unwrap();
    let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad3f";
    let card_ref = "cx:flow:01904100-0000-7000-8000-08ca7b733afd";

    let create = Event::new(
        "cx.flow.create",
        space_id.clone(),
        actor_id.clone(),
        1,
        Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap(),
        json!({
            "flow_id": flow_id,
            "title": "Payment refactor",
            "brief": "Unify payment flows",
            "flow_kind": "initiative"
        }),
    )
    .unwrap();
    let mut update = Event::new(
        "cx.flow.update",
        space_id.clone(),
        actor_id.clone(),
        2,
        Hlc::new("01970e589d21-00000002-a13f9c2e").unwrap(),
        json!({
            "flow_id": flow_id,
            "summary": "Risk, refunds and callbacks are tracked together.",
            "fields": {"priority": "high"}
        }),
    )
    .unwrap();
    update.prev_refs.push(create.event_id.clone());
    let mut link = Event::new(
        "cx.flow.link_surface",
        space_id.clone(),
        actor_id,
        3,
        Hlc::new("01970e589d21-00000003-a13f9c2e").unwrap(),
        json!({
            "flow_id": flow_id,
            "surface_ref": card_ref,
            "surface_role": "status_card",
            "primary": true,
            "relation_id": "cx:relation:01904100-0000-7000-8000-4da53c8b9e89"
        }),
    )
    .unwrap();
    link.prev_refs.push(update.event_id.clone());

    let mut state = SpaceState::new(space_id, "1".to_owned());
    state.apply_events(&[link, update, create]).unwrap();

    let flow = state.subjects.get(flow_id).unwrap();
    assert_eq!(flow.title, "Payment refactor");
    assert_eq!(
        flow.summary.as_deref(),
        Some("Risk, refunds and callbacks are tracked together.")
    );
    assert_eq!(flow.fields["priority"], "high");
    assert_eq!(flow.version, Some(1));

    let relation =
        state.relations.get("cx:relation:01904100-0000-7000-8000-4da53c8b9e89").unwrap();
    assert_eq!(relation.relation_kind, crate::RelationKind::HasSurface);
    assert_eq!(relation.from_ref.as_deref(), Some(flow_id));
    assert_eq!(relation.to_ref.as_deref(), Some(card_ref));
    assert_eq!(relation.fields["surface_role"], "status_card");
    assert_eq!(relation.fields["primary"], true);
}

#[test]
fn space_state_applies_events_in_order() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );

    let actor_id = Did::new("did:web:alice.example.com").unwrap();
    let hlc = Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap();

    let create_event = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-51495aba0a08").unwrap(),
        kind: "cx.entity.create".to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        space_version: "1".to_owned(),
        actor_id,
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc,
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({
            "id": "cx:entity:01904100-0000-7000-8000-bbe051c5f72e",
            "entity_type": "task",
            "title": "Test task"
        }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };

    state.apply_events(&[create_event]).unwrap();
    assert_eq!(state.entities.len(), 1);
}

#[test]
fn space_state_sorts_events_by_hlc() {
    let actor_id = Did::new("did:web:alice.example.com").unwrap();
    let hlc1 = Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap();
    let hlc2 = Hlc::new("01970e589d21-00000002-a13f9c2e").unwrap();

    let event1 = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-000000000001").unwrap(),
        kind: "cx.entity.create".to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        space_version: "1".to_owned(),
        actor_id: actor_id.clone(),
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc: hlc2, // Later HLC
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({
            "id": "cx:entity:01904100-0000-7000-8000-d48c478ecd0b",
            "entity_type": "task",
            "title": "Task 1"
        }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };

    let event2 = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-000000000002").unwrap(),
        kind: "cx.entity.create".to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        space_version: "1".to_owned(),
        actor_id,
        actor_seq: 2,
        created_at: chrono::Utc::now(),
        hlc: hlc1, // Earlier HLC
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({
            "id": "cx:entity:01904100-0000-7000-8000-e75dc3f6ab2e",
            "entity_type": "task",
            "title": "Task 2"
        }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };

    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );

    state.apply_events(&[event1, event2]).unwrap();

    // event2 should be applied first (earlier HLC)
    assert_eq!(
        state.frontier.first().unwrap().as_str(),
        "cx:event:01904100-0000-7000-8000-000000000001"
    );
}

#[test]
fn member_state_conflict_prefers_ban_semantics() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();

    let leave = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-d64fc8cb7d63").unwrap(),
        kind: "cx.member.state".to_owned(),
        space_id: space_id.clone(),
        space_version: "1".to_owned(),
        actor_id: Did::new("did:web:admin-b.example").unwrap(),
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d21-00000004-a13f9d2e").unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({ "actor_id": "did:web:alice.example", "membership": "leave" }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };
    let ban = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-c9d398595fe8").unwrap(),
        kind: "cx.member.state".to_owned(),
        space_id,
        space_version: "1".to_owned(),
        actor_id: Did::new("did:web:admin-a.example").unwrap(),
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({ "actor_id": "did:web:alice.example", "membership": "ban" }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };

    state.apply_events(&[leave, ban]).unwrap();

    let resolved = state.resolved_state.get("cx.member.state|did:web:alice.example").unwrap();
    assert_eq!(resolved.content["membership"], "ban");
    assert_eq!(
        resolved.source_event_id.as_str(),
        "cx:event:01904100-0000-7000-8000-c9d398595fe8"
    );
    assert_eq!(state.conflict_records.len(), 1);
}

#[test]
fn capability_rebind_uses_deterministic_lww_order() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let actor_id = Did::new("did:web:moderator.example").unwrap();

    let revoke = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-f205d4bec6cc").unwrap(),
        kind: "cx.capability.revoke".to_owned(),
        space_id: space_id.clone(),
        space_version: "1".to_owned(),
        actor_id: actor_id.clone(),
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d22-00000001-22222222").unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({ "target_capability_id": "cap-chan-post" }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };
    let grant = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-59b4ef49b3f6").unwrap(),
        kind: "cx.capability.grant".to_owned(),
        space_id,
        space_version: "1".to_owned(),
        actor_id,
        actor_seq: 2,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d22-00000001-33333333").unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({
            "capability_id": "cap-chan-post",
            "subject": "did:web:alice.example",
            "actions": ["message.send", "message.react"]
        }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };

    state.apply_events(&[revoke, grant]).unwrap();

    let resolved = state.resolved_state.get("cx.capability|cap-chan-post").unwrap();
    assert_eq!(resolved.content["actions"][1], "message.react");
    assert!(state.capability_allows("cap-chan-post", "message.react"));
    assert!(!state.capability_allows("cap-chan-post", "message.delete"));
}

#[test]
fn message_revision_redaction_and_reaction_converge() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let actor_id = Did::new("did:web:alice.example").unwrap();

    let base = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-6d2450f52c40").unwrap(),
        kind: "cx.message.create".to_owned(),
        space_id: space_id.clone(),
        space_version: "1".to_owned(),
        actor_id: actor_id.clone(),
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d22-00000001-11111111").unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({ "message_id": "m1", "body": "hello" }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };
    let revise = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-408e1c1e6fef").unwrap(),
        kind: "cx.message.revise".to_owned(),
        space_id: space_id.clone(),
        space_version: "1".to_owned(),
        actor_id: actor_id.clone(),
        actor_seq: 2,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d22-00000002-11111111").unwrap(),
        prev_refs: vec![base.event_id.clone()],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({ "target_message_id": "m1", "content": { "body": "edited" } }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };
    let reaction_add = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-494928f6a281").unwrap(),
        kind: "cx.reaction.add".to_owned(),
        space_id,
        space_version: "1".to_owned(),
        actor_id,
        actor_seq: 3,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d22-00000003-11111111").unwrap(),
        prev_refs: vec![revise.event_id.clone()],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({ "message_id": "m1", "reaction_key": "+1" }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    };

    state.apply_events(&[reaction_add, revise, base]).unwrap();

    let message = state.messages.get("m1").unwrap();
    assert_eq!(message.content["body"], "edited");
    assert_eq!(message.revision_event_ids.len(), 1);

    let reaction = state.reactions.get("m1|did:web:alice.example|+1").unwrap();
    assert!(reaction.active);
}

#[test]
fn snapshot_manifest_tracks_state_hash_and_merkle_root() {
    let mut state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let event = entity_event("cx:event:01904100-0000-7000-8000-333d5a4f911c", "Snapshot task");

    state.apply_events(std::slice::from_ref(&event)).unwrap();
    let snapshot = state.snapshot();
    let manifest = snapshot.manifest.as_ref().unwrap();

    assert_eq!(manifest.schema, REDUCER_SNAPSHOT_SCHEMA);
    assert_eq!(manifest.reducer_profile, REDUCER_SNAPSHOT_PROFILE);
    assert_eq!(manifest.state_hash, snapshot.state_hash);
    assert_eq!(manifest.merkle_root, snapshot.state_merkle_root().unwrap());
    snapshot.verify().unwrap();
}

#[test]
fn snapshot_chunk_manifest_verifies_digests() {
    let state = SpaceState::new(
        SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        "1".to_owned(),
    );
    let snapshot = state.snapshot();
    let manifest = snapshot.manifest_with_chunks(16).unwrap();
    let bytes = snapshot.canonical_snapshot_bytes().unwrap();
    let chunks: Vec<Vec<u8>> = bytes.chunks(16).map(|chunk| chunk.to_vec()).collect();

    verify_snapshot_chunks(&manifest, chunks.clone()).unwrap();

    let mut tampered = chunks;
    tampered[0][0] ^= 1;
    assert!(verify_snapshot_chunks(&manifest, tampered).is_err());
}

#[test]
fn merkle_root_is_order_independent_for_leaf_hashes() {
    let a = merkle_root(vec![
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    ])
    .unwrap();
    let b = merkle_root(vec![
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
    ])
    .unwrap();

    assert_eq!(a, b);
}

#[test]
fn restore_snapshot_or_replay_falls_back_on_verification_failure() {
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let event = entity_event("cx:event:01904100-0000-7000-8000-5cdf783dccf7", "Replayed task");
    let mut state = SpaceState::new(space_id.clone(), "1".to_owned());
    state.apply_events(std::slice::from_ref(&event)).unwrap();
    let mut snapshot = state.snapshot();
    snapshot.state_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();

    let restored =
        SpaceState::restore_snapshot_or_replay(Some(snapshot), space_id, "1", &[event])
            .unwrap();

    assert_eq!(restored.source, SnapshotRestoreSource::RepoReplay);
    assert!(restored.snapshot_error.unwrap().contains("state hash mismatch"));
    assert_eq!(restored.state.entities.len(), 1);
}

fn entity_event(event_id: &str, title: &str) -> Event {
    Event {
        event_id: EventId::new(event_id).unwrap(),
        kind: "cx.entity.create".to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
        space_version: "1".to_owned(),
        actor_id: Did::new("did:web:alice.example.com").unwrap(),
        actor_seq: 1,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new("01970e589d22-00000009-11111111").unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content: json!({
            "id": "cx:entity:01904100-0000-7000-8000-b7a4e10c8c77",
            "entity_type": "task",
            "title": title
        }),
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

#[test]
fn reducer_convergence_is_order_independent() {
    // Property: applying the same events in any permutation produces the same
    // final state, because the reducer sorts by HLC before applying.
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let actor = Did::new("did:web:alice.example.com").unwrap();

    let events: Vec<Event> = (0..5)
        .map(|i| {
            let hlc = Hlc::new(format!("01970e589d22-{i:08x}-11111111")).unwrap();
            Event {
                event_id: EventId::new(format!("cx:event:01904100-0000-7000-8000-{i:012x}"))
                    .unwrap(),
                kind: OP_ENTITY_CREATE.to_owned(),
                space_id: space_id.clone(),
                space_version: "1".to_owned(),
                actor_id: actor.clone(),
                actor_seq: i + 1,
                created_at: chrono::Utc::now(),
                hlc,
                prev_refs: vec![],
                auth_refs: vec![],
                schema_profile_refs: vec![],
                reducer_profile_ref: None,
                required_features: vec![],
                critical_extensions: vec![],
                redacts: None,
                content: json!({
                    "id": format!("cx:entity:01904100-0000-7000-8000-{i:012x}"),
                    "entity_type": "task",
                    "title": format!("Task {i}")
                }),
                unsigned: BTreeMap::new(),
                proofs: vec![],
            }
        })
        .collect();

    // Apply in original order.
    let mut state_a = SpaceState::new(space_id.clone(), "1".to_owned());
    state_a.apply_events(&events).unwrap();

    // Apply in reversed order.
    let mut reversed = events.clone();
    reversed.reverse();
    let mut state_b = SpaceState::new(space_id, "1".to_owned());
    state_b.apply_events(&reversed).unwrap();

    // Both must converge to the same entity set and frontier.
    assert_eq!(state_a.entities.len(), state_b.entities.len());
    for (id, entity_a) in &state_a.entities {
        let entity_b = state_b.entities.get(id).unwrap();
        assert_eq!(entity_a.title, entity_b.title);
        assert_eq!(entity_a.version, entity_b.version);
    }
    assert_eq!(state_a.frontier, state_b.frontier);
}
