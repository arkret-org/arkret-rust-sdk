use super::*;
use crate::events::kinds::FLOW_TRACKS_UPDATE as OP_FLOW_TRACKS_UPDATE;
use crate::{EventRequirements, Hlc, RealmId};
use serde_json::json;

fn space_id() -> SpaceId {
    SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
}

fn actor_id() -> Did {
    Did::new("did:web:alice.example.com").unwrap()
}

fn event(kind: &str, seq: u64, content: Value) -> Event {
    Event {
        event_id: EventId::new(format!("cx:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.to_owned(),
        realm_id: realm_id(),
        actor_id: actor_id(),
        actor_seq: seq,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new(format!("01970e589d22-{seq:04x}-11111111")).unwrap(),
        prev_refs: vec![],
        effective_scope: None,
        refs: vec![],
        preconditions: vec![],
        effects: vec![],
        anchor_ref: None,
        requirements: EventRequirements::default(),
        redacts: None,
        content,
        executed_by: None,
        authorization_ref: None,
        actor_kind: None,
        applet_id: None,
        external_ref: None,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

fn realm_id() -> RealmId {
    RealmId::new("cx:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
}

fn morph_event(seq: u64, morph_id: &str, title: &str) -> Event {
    event(
        OP_MORPH_CREATE,
        seq,
        json!({
            "object": {
                "id": morph_id,
                "schema": crate::MORPH_SCHEMA,
                "space_id": space_id().as_str(),
                "morph_type": "task",
                "metadata": {"title": title},
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
}

#[test]
fn space_state_creates_empty() {
    let state = SpaceState::new(space_id(), "1".to_owned());
    assert_eq!(state.morphs.len(), 0);
    assert_eq!(state.places.len(), 0);
    assert_eq!(state.subjects.len(), 0);
    assert_eq!(state.relations.len(), 0);
}

#[test]
fn place_events_create_update_parent_and_tombstone() {
    let place_id = "cx:space:01904100-0000-7000-8000-1fb50799ad3f";
    let create = event(
        OP_SPACE_CREATE,
        1,
        json!({
            "object": {
                "id": place_id,
                "schema": crate::SPACE_SCHEMA,
                "space_id": space_id().as_str(),
                "kind": "board",
                "title": "Roadmap",
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    );
    let mut update = event(
        OP_SPACE_UPDATE,
        2,
        json!({
            "place_id": place_id,
            "patch": {
                "title": "Roadmap 2026",
                "rank": "a0",
                "fields": {"wip_limit": 5}
            }
        }),
    );
    update.prev_refs.push(create.event_id.clone());
    let mut parent = event(
        OP_SPACE_PARENT,
        3,
        json!({
            "place_id": place_id,
            "parent_space_id": space_id().as_str()
        }),
    );
    parent.prev_refs.push(update.event_id.clone());
    let mut tombstone = event(OP_SPACE_TOMBSTONE, 4, json!({ "place_id": place_id }));
    tombstone.prev_refs.push(parent.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[tombstone, parent, update, create]).unwrap();

    let place = state.places.get(place_id).unwrap();
    assert_eq!(place.kind, "board");
    assert_eq!(place.title, "Roadmap 2026");
    assert_eq!(place.parent_space_id.as_ref().map(|p| p.as_str()), Some(space_id().as_str()));
    assert_eq!(place.rank.as_deref(), Some("a0"));
    assert_eq!(place.fields["wip_limit"], 5);
    assert_eq!(place.state, Some(crate::PlaceState::Tombstoned));
}

fn place_create_event(seq: u64, place_id: &str) -> Event {
    event(
        OP_SPACE_CREATE,
        seq,
        json!({
            "object": {
                "id": place_id,
                "schema": crate::SPACE_SCHEMA,
                "space_id": space_id().as_str(),
                "kind": "board",
                "title": "Roadmap",
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
}

#[test]
fn place_archive_then_restore_round_trip() {
    let place_id = "cx:space:01904100-0000-7000-8000-1fb50799ad42";
    let create = place_create_event(1, place_id);

    let mut archive = event(OP_SPACE_ARCHIVE, 2, json!({ "place_id": place_id }));
    archive.prev_refs.push(create.event_id.clone());

    let mut restore = event(OP_SPACE_RESTORE, 3, json!({ "place_id": place_id }));
    restore.prev_refs.push(archive.event_id.clone());
    let restore_at = restore.created_at;

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[create, archive, restore]).unwrap();

    let place = state.places.get(place_id).unwrap();
    assert_eq!(place.state, Some(crate::PlaceState::Active));
    assert_eq!(place.state_changed_at, Some(restore_at));
}

#[test]
fn place_restore_rejected_when_active() {
    let place_id = "cx:space:01904100-0000-7000-8000-1fb50799ad43";
    let create = place_create_event(1, place_id);

    let mut restore = event(OP_SPACE_RESTORE, 2, json!({ "place_id": place_id }));
    restore.prev_refs.push(create.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, restore]).unwrap_err();
    assert!(err.to_string().contains("place_not_archived"), "unexpected error: {err}");

    let place = state.places.get(place_id).unwrap();
    assert_eq!(place.state, Some(crate::PlaceState::Active));
}

#[test]
fn place_restore_rejected_when_tombstoned() {
    let place_id = "cx:space:01904100-0000-7000-8000-1fb50799ad44";
    let create = place_create_event(1, place_id);

    let mut tombstone = event(OP_SPACE_TOMBSTONE, 2, json!({ "place_id": place_id }));
    tombstone.prev_refs.push(create.event_id.clone());
    let tombstone_at = tombstone.created_at;

    let mut restore = event(OP_SPACE_RESTORE, 3, json!({ "place_id": place_id }));
    restore.prev_refs.push(tombstone.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, tombstone, restore]).unwrap_err();
    assert!(err.to_string().contains("place_not_archived"), "unexpected error: {err}");

    let place = state.places.get(place_id).unwrap();
    assert_eq!(place.state, Some(crate::PlaceState::Tombstoned));
    assert_eq!(place.state_changed_at, Some(tombstone_at));
}

fn flow_create_event(seq: u64, flow_id: &str) -> Event {
    event(
        OP_FLOW_CREATE,
        seq,
        json!({
            "object": {
                "id": flow_id,
                "schema": crate::FLOW_SCHEMA,
                "space_id": space_id().as_str(),
                "metadata": {"title": "Payment refactor"},
                "tracks": {"synthesis": {}},
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
}

#[test]
fn flow_archive_then_restore_round_trip() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad50";
    let create = flow_create_event(1, flow_id);

    let mut archive = event(OP_FLOW_ARCHIVE, 2, json!({ "flow_id": flow_id }));
    archive.prev_refs.push(create.event_id.clone());

    let mut restore = event(OP_FLOW_RESTORE, 3, json!({ "flow_id": flow_id }));
    restore.prev_refs.push(archive.event_id.clone());
    let restore_at = restore.created_at;

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[create, archive, restore]).unwrap();

    let flow = state.subjects.get(flow_id).unwrap();
    assert_eq!(flow.state, Some(crate::ObjectState::Active));
    assert_eq!(flow.state_changed_at, Some(restore_at));
}

#[test]
fn flow_restore_rejected_when_active() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad51";
    let create = flow_create_event(1, flow_id);

    let mut restore = event(OP_FLOW_RESTORE, 2, json!({ "flow_id": flow_id }));
    restore.prev_refs.push(create.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, restore]).unwrap_err();
    assert!(err.to_string().contains("flow_not_archived"), "unexpected error: {err}");

    // create_flow defaults the Flow to Active. The failed restore must
    // be a no-op — state stays Active, state_changed_at stays unset
    // (only create touched it, which doesn't set state_changed_at).
    let flow = state.subjects.get(flow_id).unwrap();
    assert_eq!(flow.state, Some(crate::ObjectState::Active));
    assert!(
        flow.state_changed_at.is_none(),
        "restore must not write state_changed_at when rejected"
    );
}

#[test]
fn morph_archive_then_restore_round_trip() {
    let morph_id = "cx:morph:01904100-0000-7000-8000-1fb50799ad60";
    let create = morph_event(1, morph_id, "Task A");

    let mut archive = event(OP_MORPH_ARCHIVE, 2, json!({ "morph_id": morph_id }));
    archive.prev_refs.push(create.event_id.clone());

    let mut restore = event(OP_MORPH_RESTORE, 3, json!({ "morph_id": morph_id }));
    restore.prev_refs.push(archive.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[create, archive, restore]).unwrap();

    let morph = state.morphs.get(morph_id).unwrap();
    assert_eq!(morph.state, Some(crate::ObjectState::Active));
}

#[test]
fn morph_restore_rejected_when_active() {
    let morph_id = "cx:morph:01904100-0000-7000-8000-1fb50799ad61";
    let create = morph_event(1, morph_id, "Task B");

    let mut restore = event(OP_MORPH_RESTORE, 2, json!({ "morph_id": morph_id }));
    restore.prev_refs.push(create.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, restore]).unwrap_err();
    assert!(err.to_string().contains("morph_not_archived"), "unexpected error: {err}");

    // morph_event constructs `create_morph` without an explicit state;
    // create_morph defaults to ObjectState::Active. The failed restore
    // must not corrupt that.
    let morph = state.morphs.get(morph_id).unwrap();
    assert_eq!(morph.state, Some(crate::ObjectState::Active));
}

// ── Round 10 (2026-05-15): archive / tombstone / update source-state guards ──
// Per spec common-fields.md §5.1 canonical state-transition table. Mirror
// the round 9 restore guards but for the rest of the transition matrix.

#[test]
fn place_archive_rejected_when_already_archived() {
    let place_id = "cx:space:01904100-0000-7000-8000-2fb50799ad42";
    let create = place_create_event(1, place_id);
    let mut archive1 = event(OP_SPACE_ARCHIVE, 2, json!({ "place_id": place_id }));
    archive1.prev_refs.push(create.event_id.clone());
    let mut archive2 = event(OP_SPACE_ARCHIVE, 3, json!({ "place_id": place_id }));
    archive2.prev_refs.push(archive1.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, archive1, archive2]).unwrap_err();
    assert!(err.to_string().contains("place_not_active"), "unexpected error: {err}");

    // First archive succeeded; second archive (the rejected one) must not
    // touch Place state.
    let place = state.places.get(place_id).unwrap();
    assert_eq!(place.state, Some(crate::PlaceState::Archived));
}

#[test]
fn place_archive_rejected_when_tombstoned() {
    let place_id = "cx:space:01904100-0000-7000-8000-2fb50799ad43";
    let create = place_create_event(1, place_id);
    let mut tombstone = event(OP_SPACE_TOMBSTONE, 2, json!({ "place_id": place_id }));
    tombstone.prev_refs.push(create.event_id.clone());
    let mut archive = event(OP_SPACE_ARCHIVE, 3, json!({ "place_id": place_id }));
    archive.prev_refs.push(tombstone.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, tombstone, archive]).unwrap_err();
    assert!(err.to_string().contains("place_not_active"), "unexpected error: {err}");
    assert_eq!(state.places.get(place_id).unwrap().state, Some(crate::PlaceState::Tombstoned));
}

#[test]
fn place_tombstone_rejected_when_already_terminal() {
    let place_id = "cx:space:01904100-0000-7000-8000-2fb50799ad44";
    let create = place_create_event(1, place_id);
    let mut tombstone1 = event(OP_SPACE_TOMBSTONE, 2, json!({ "place_id": place_id }));
    tombstone1.prev_refs.push(create.event_id.clone());
    let mut tombstone2 = event(OP_SPACE_TOMBSTONE, 3, json!({ "place_id": place_id }));
    tombstone2.prev_refs.push(tombstone1.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, tombstone1, tombstone2]).unwrap_err();
    assert!(err.to_string().contains("place_already_terminal"), "unexpected error: {err}");
    assert_eq!(state.places.get(place_id).unwrap().state, Some(crate::PlaceState::Tombstoned));
}

#[test]
fn flow_archive_rejected_when_already_archived() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-2fb50799ad50";
    let create = flow_create_event(1, flow_id);
    let mut archive1 = event(OP_FLOW_ARCHIVE, 2, json!({ "flow_id": flow_id }));
    archive1.prev_refs.push(create.event_id.clone());
    let mut archive2 = event(OP_FLOW_ARCHIVE, 3, json!({ "flow_id": flow_id }));
    archive2.prev_refs.push(archive1.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, archive1, archive2]).unwrap_err();
    assert!(err.to_string().contains("flow_not_active"), "unexpected error: {err}");
    assert_eq!(state.subjects.get(flow_id).unwrap().state, Some(crate::ObjectState::Archived));
}

#[test]
fn morph_archive_rejected_when_already_archived() {
    let morph_id = "cx:morph:01904100-0000-7000-8000-2fb50799ad60";
    let create = morph_event(1, morph_id, "Task C");
    let mut archive1 = event(OP_MORPH_ARCHIVE, 2, json!({ "morph_id": morph_id }));
    archive1.prev_refs.push(create.event_id.clone());
    let mut archive2 = event(OP_MORPH_ARCHIVE, 3, json!({ "morph_id": morph_id }));
    archive2.prev_refs.push(archive1.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, archive1, archive2]).unwrap_err();
    assert!(err.to_string().contains("morph_not_active"), "unexpected error: {err}");
    assert_eq!(state.morphs.get(morph_id).unwrap().state, Some(crate::ObjectState::Archived));
}

#[test]
fn place_update_rejected_when_archived() {
    let place_id = "cx:space:01904100-0000-7000-8000-3fb50799ad42";
    let create = place_create_event(1, place_id);
    let mut archive = event(OP_SPACE_ARCHIVE, 2, json!({ "place_id": place_id }));
    archive.prev_refs.push(create.event_id.clone());
    let mut update =
        event(OP_SPACE_UPDATE, 3, json!({ "place_id": place_id, "patch": { "title": "Renamed" } }));
    update.prev_refs.push(archive.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, archive, update]).unwrap_err();
    assert!(err.to_string().contains("place_not_active"), "unexpected error: {err}");
    // Title must NOT have been changed.
    assert_eq!(state.places.get(place_id).unwrap().title, "Roadmap");
}

#[test]
fn flow_update_rejected_when_archived() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-3fb50799ad50";
    let create = flow_create_event(1, flow_id);
    let mut archive = event(OP_FLOW_ARCHIVE, 2, json!({ "flow_id": flow_id }));
    archive.prev_refs.push(create.event_id.clone());
    let mut update = event(
        OP_FLOW_UPDATE,
        3,
        json!({ "flow_id": flow_id, "patch": { "metadata": {"title": "New title"} } }),
    );
    update.prev_refs.push(archive.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, archive, update]).unwrap_err();
    assert!(err.to_string().contains("flow_not_active"), "unexpected error: {err}");
    assert_eq!(state.subjects.get(flow_id).unwrap().title, "Payment refactor");
}

#[test]
fn morph_update_rejected_when_archived() {
    let morph_id = "cx:morph:01904100-0000-7000-8000-3fb50799ad60";
    let create = morph_event(1, morph_id, "Original Title");
    let mut archive = event(OP_MORPH_ARCHIVE, 2, json!({ "morph_id": morph_id }));
    archive.prev_refs.push(create.event_id.clone());
    let mut update = event(
        OP_MORPH_UPDATE,
        3,
        json!({ "morph_id": morph_id, "patch": { "metadata.title": "Renamed Morph" } }),
    );
    update.prev_refs.push(archive.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, archive, update]).unwrap_err();
    assert!(err.to_string().contains("morph_not_active"), "unexpected error: {err}");
    assert_eq!(state.morphs.get(morph_id).unwrap().title.as_deref(), Some("Original Title"));
}

#[test]
fn flow_events_create_update_and_default_view_relation() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad3f";
    let view_ref = "cx:view:01904100-0000-7000-8000-08ca7b733afd";

    let create = Event::new(
        OP_FLOW_CREATE,
        realm_id(),
        actor_id(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        json!({
            "object": {
                "id": flow_id,
                "schema": crate::FLOW_SCHEMA,
                "space_id": space_id().as_str(),
                "metadata": {
                    "title": "Payment refactor",
                    "summary": "Unify payment flows"
                },
                "tracks": {"synthesis": {}},
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
    .unwrap();
    let mut update = Event::new(
        OP_FLOW_UPDATE,
        realm_id(),
        actor_id(),
        2,
        Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
        json!({
            "flow_id": flow_id,
            "patch": {
                "metadata": {
                    "summary": "Risk, refunds and callbacks are tracked together.",
                    "fields": {"priority": "high"}
                }
            }
        }),
    )
    .unwrap();
    update.prev_refs.push(create.event_id.clone());
    let mut relation = Event::new(
        OP_RELATION_CREATE,
        realm_id(),
        actor_id(),
        3,
        Hlc::new("01970e589d21-0003-a13f9c2e").unwrap(),
        json!({
            "relation": {
                "id": "cx:relation:01904100-0000-7000-8000-4da53c8b9e89",
                "schema": crate::RELATION_SCHEMA,
                "space_id": space_id().as_str(),
                "relation_kind": "has_default_view",
                "from_ref": flow_id,
                "to_ref": view_ref,
                "fields": {"primary": true},
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
    .unwrap();
    relation.prev_refs.push(update.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[relation, update, create]).unwrap();

    let flow = state.subjects.get(flow_id).unwrap();
    assert_eq!(flow.title, "Payment refactor");
    assert_eq!(flow.summary.as_deref(), Some("Risk, refunds and callbacks are tracked together."));
    assert_eq!(flow.fields["priority"], "high");

    let relation = state.relations.get("cx:relation:01904100-0000-7000-8000-4da53c8b9e89").unwrap();
    assert_eq!(relation.relation_kind, crate::RelationKind::HasDefaultView);
    assert_eq!(relation.from_ref, flow_id);
    assert_eq!(relation.to_ref, view_ref);
    assert_eq!(relation.fields["primary"], true);
}

#[test]
fn space_state_applies_morph_events() {
    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let create_event = morph_event(1, "cx:morph:01904100-0000-7000-8000-bbe051c5f72e", "Test task");

    state.apply_events(&[create_event]).unwrap();
    assert_eq!(state.morphs.len(), 1);
}

#[test]
fn space_state_sorts_events_by_hlc() {
    let event1 = Event {
        hlc: Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
        ..morph_event(1, "cx:morph:01904100-0000-7000-8000-d48c478ecd0b", "Task 1")
    };
    let event2 = Event {
        hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        ..morph_event(2, "cx:morph:01904100-0000-7000-8000-e75dc3f6ab2e", "Task 2")
    };

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[event1, event2]).unwrap();

    assert_eq!(
        state.frontier.first().unwrap().as_str(),
        "cx:event:01904100-0000-7000-8000-000000000001"
    );
}

#[test]
fn member_state_conflict_prefers_ban_semantics() {
    let leave = event(
        "cx.member.state",
        4,
        json!({ "actor_id": "did:web:alice.example", "membership": "leave" }),
    );
    let mut ban = event(
        "cx.member.state",
        5,
        json!({ "actor_id": "did:web:alice.example", "membership": "ban" }),
    );
    ban.hlc = leave.hlc.clone();
    ban.event_id = EventId::new("cx:event:01904100-0000-7000-8000-c9d398595fe8").unwrap();

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[leave, ban]).unwrap();

    let resolved = state.resolved_state.get("cx.member.state|did:web:alice.example").unwrap();
    assert_eq!(resolved.content["membership"], "ban");
    assert_eq!(state.conflict_records.len(), 1);
}

#[test]
fn capability_rebind_uses_deterministic_lww_order() {
    let revoke =
        event("cx.capability.revoke", 1, json!({ "target_capability_id": "cap-chan-post" }));
    let grant = event(
        "cx.capability.grant",
        2,
        json!({
            "capability_id": "cap-chan-post",
            "subject": "did:web:alice.example",
            "actions": ["cx.message.create", "cx.reaction.add"]
        }),
    );

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[revoke, grant]).unwrap();

    let resolved = state.resolved_state.get("cx.capability|cap-chan-post").unwrap();
    assert_eq!(resolved.content["actions"][1], "cx.reaction.add");
    assert!(state.capability_allows("cap-chan-post", "cx.reaction.add"));
    assert!(!state.capability_allows("cap-chan-post", "message.delete"));
}

#[test]
fn message_revision_redaction_and_reaction_converge() {
    let base = event("cx.message.create", 1, json!({ "message_id": "m1", "body": "hello" }));
    let mut revise = event(
        "cx.message.revise",
        2,
        json!({ "target_message_id": "m1", "content": { "body": "edited" } }),
    );
    revise.prev_refs.push(base.event_id.clone());
    let mut reaction_add =
        event("cx.reaction.add", 3, json!({ "message_id": "m1", "reaction_key": "+1" }));
    reaction_add.prev_refs.push(revise.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[reaction_add, revise, base]).unwrap();

    let message = state.messages.get("m1").unwrap();
    assert_eq!(message.content["body"], "edited");
    assert_eq!(message.revision_event_ids.len(), 1);

    let reaction = state.reactions.get("m1|did:web:alice.example.com|+1").unwrap();
    assert!(reaction.active);
}

#[test]
fn snapshot_manifest_tracks_state_digest_and_merkle_root() {
    let event = morph_event(9, "cx:morph:01904100-0000-7000-8000-b7a4e10c8c77", "Snapshot task");
    let mut state = SpaceState::new(space_id(), "1".to_owned());

    state.apply_events(std::slice::from_ref(&event)).unwrap();
    let snapshot = state.snapshot();
    let manifest = snapshot.manifest.as_ref().unwrap();

    assert_eq!(manifest.schema, REDUCER_SNAPSHOT_SCHEMA);
    assert_eq!(manifest.reducer_profile, REDUCER_SNAPSHOT_PROFILE);
    assert_eq!(manifest.state_digest, snapshot.state_digest);
    assert_eq!(manifest.merkle_root, snapshot.state_merkle_root().unwrap());
    snapshot.verify().unwrap();
}

#[test]
fn snapshot_chunk_manifest_verifies_digests() {
    let state = SpaceState::new(space_id(), "1".to_owned());
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
    let event = morph_event(10, "cx:morph:01904100-0000-7000-8000-b7a4e10c8c77", "Replayed task");
    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(std::slice::from_ref(&event)).unwrap();
    let mut snapshot = state.snapshot();
    snapshot.state_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();

    let restored =
        SpaceState::restore_snapshot_or_replay(Some(snapshot), space_id(), "1", &[event]).unwrap();

    assert_eq!(restored.source, SnapshotRestoreSource::RepoReplay);
    assert!(restored.snapshot_error.unwrap().contains("state hash mismatch"));
    assert_eq!(restored.state.morphs.len(), 1);
}

#[test]
fn reducer_convergence_is_order_independent() {
    let events: Vec<Event> = (0..5)
        .map(|i| {
            morph_event(
                i + 1,
                &format!("cx:morph:01904100-0000-7000-8000-{i:012x}"),
                &format!("Task {i}"),
            )
        })
        .collect();

    let mut state_a = SpaceState::new(space_id(), "1".to_owned());
    state_a.apply_events(&events).unwrap();

    let mut reversed = events.clone();
    reversed.reverse();
    let mut state_b = SpaceState::new(space_id(), "1".to_owned());
    state_b.apply_events(&reversed).unwrap();

    assert_eq!(state_a.morphs.len(), state_b.morphs.len());
    for (id, morph_a) in &state_a.morphs {
        let morph_b = state_b.morphs.get(id).unwrap();
        assert_eq!(morph_a.title, morph_b.title);
        assert_eq!(morph_a.state, morph_b.state);
    }
    assert_eq!(state_a.frontier, state_b.frontier);
}

// ── SDK Round 11 (2026-05-16): cx.redaction → Flow / Morph state flip ──
// Mirror of soland round 14b. When cx.redaction event content carries
// `object_ref` pointing to a Flow / Morph, the reducer flips the subject
// state to Redacted (terminal). State-machine guard rejects already-
// terminal source with `<kind>_already_terminal`.

fn redaction_event(seq: u64, object_ref: &str) -> Event {
    let mut ev = event(
        "cx.redaction",
        seq,
        json!({
            "target_event_id": format!("cx:event:01904100-0000-7000-8000-{:012x}", 0xdeadbeef + seq),
            "object_ref": object_ref,
        }),
    );
    // `cx.redaction` dispatch path uses `event.redacts`; populate it so
    // the dispatcher invokes redact_event AND redact_object_for_event.
    ev.redacts = Some(
        EventId::new(format!("cx:event:01904100-0000-7000-8000-{:012x}", 0xdeadbeef + seq))
            .unwrap(),
    );
    ev
}

#[test]
fn redaction_with_flow_object_ref_flips_subject_to_redacted() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-3fb50799ad50";
    let create = flow_create_event(1, flow_id);
    let mut redact = redaction_event(2, flow_id);
    redact.prev_refs.push(create.event_id.clone());
    let redact_at = redact.created_at;

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[create, redact]).unwrap();

    let flow = state.subjects.get(flow_id).unwrap();
    assert_eq!(flow.state, Some(crate::ObjectState::Redacted));
    assert_eq!(flow.state_changed_at, Some(redact_at));
}

#[test]
fn redaction_with_morph_object_ref_flips_subject_to_redacted() {
    let morph_id = "cx:morph:01904100-0000-7000-8000-3fb50799ad60";
    let create = morph_event(1, morph_id, "Sensitive task");
    let mut redact = redaction_event(2, morph_id);
    redact.prev_refs.push(create.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[create, redact]).unwrap();

    let morph = state.morphs.get(morph_id).unwrap();
    assert_eq!(morph.state, Some(crate::ObjectState::Redacted));
}

#[test]
fn redaction_against_already_redacted_flow_rejects() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-3fb50799ad51";
    let create = flow_create_event(1, flow_id);
    let mut redact1 = redaction_event(2, flow_id);
    redact1.prev_refs.push(create.event_id.clone());
    let mut redact2 = redaction_event(3, flow_id);
    redact2.prev_refs.push(redact1.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, redact1, redact2]).unwrap_err();
    assert!(err.to_string().contains("flow_already_terminal"), "unexpected error: {err}");
    assert_eq!(state.subjects.get(flow_id).unwrap().state, Some(crate::ObjectState::Redacted));
}

#[test]
fn flow_tracks_update_merges_tracks_from_patch_tracks_and_top_level_tracks() {
    let flow_id = "cx:flow:01904100-0000-7000-8000-4fb50799ad55";
    let create = flow_create_event(1, flow_id);
    let mut update = event(
        OP_FLOW_TRACKS_UPDATE,
        2,
        json!({
            "flow_id": flow_id,
            "tracks": {
                "discussion": {
                    "profile": "discussion",
                    "metadata": {"capacity": 25}
                }
            },
            "patch": {
                "tracks": {
                    "review": {
                        "profile": "review",
                        "template": "Review"
                    }
                }
            }
        }),
    );
    update.prev_refs.push(create.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    state.apply_events(&[create, update]).unwrap();

    let flow = state.subjects.get(flow_id).unwrap();
    assert!(flow.tracks.contains_key(crate::FLOW_TRACK_NAME_SYNTHESIS));
    assert_eq!(flow.tracks["discussion"].profile.as_deref(), Some("discussion"));
    assert_eq!(flow.tracks["discussion"].metadata["capacity"], 25);
    assert_eq!(flow.tracks["review"].profile.as_deref(), Some("review"));
    assert_eq!(flow.tracks["review"].template.as_deref(), Some("Review"));
}

#[test]
fn redaction_against_already_redacted_morph_rejects() {
    let morph_id = "cx:morph:01904100-0000-7000-8000-3fb50799ad61";
    let create = morph_event(1, morph_id, "Task");
    let mut redact1 = redaction_event(2, morph_id);
    redact1.prev_refs.push(create.event_id.clone());
    let mut redact2 = redaction_event(3, morph_id);
    redact2.prev_refs.push(redact1.event_id.clone());

    let mut state = SpaceState::new(space_id(), "1".to_owned());
    let err = state.apply_events(&[create, redact1, redact2]).unwrap_err();
    assert!(err.to_string().contains("morph_already_terminal"), "unexpected error: {err}");
    assert_eq!(state.morphs.get(morph_id).unwrap().state, Some(crate::ObjectState::Redacted));
}
