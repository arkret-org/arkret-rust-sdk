use arkret_wire::EventKind;
use serde_json::json;

use super::*;
use crate::{EventRequirements, Hlc, RealmId};

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
}

fn actor_id() -> Did {
    Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap()
}

fn event(kind: &str, seq: u64, content: Value) -> Event {
    Event {
        event_id: EventId::new(format!("ak:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.into(),
        realm_id: realm_id(),
        actor_id: actor_id(),
        actor_seq: seq,
        created_at: chrono::Utc::now(),
        hlc: Some(Hlc::new(format!("01970e589d22-{seq:04x}-11111111")).unwrap()),
        prev_refs: vec![],
        effective_scope: None,
        refs: vec![],
        preconditions: vec![],
        effects: vec![],
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload: serde_json::from_value(content).unwrap(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: BTreeMap::new(),
        causal_refs: Vec::new(),
        conflict_keys_digest: None,
        proofs: vec![],
    }
}

fn morph_event(seq: u64, morph_id: &str, title: &str) -> Event {
    event(
        EventKind::MORPH_CREATE,
        seq,
        json!({
            "object": {
                "id": morph_id,
                "schema": crate::MORPH_SCHEMA,
                "realm_id": realm_id().as_str(),
                "schema_refs": [crate::MORPH_SCHEMA],
                "morph_kind": "task",
                "metadata": {"title": title},
                "stage": "draft",
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
}

#[test]
fn realm_state_creates_empty() {
    let state = RealmState::new(realm_id());
    assert_eq!(state.morphs.len(), 0);
    assert_eq!(state.spaces.len(), 0);
    assert_eq!(state.subjects.len(), 0);
    assert_eq!(state.relations.len(), 0);
}

#[test]
fn space_events_create_update_parent_and_tombstone() {
    let space_id = "ak:space:01904100-0000-7000-8000-1fb50799ad3f";
    let parent_space_id = "ak:space:01904100-0000-7000-8000-1fb50799ad40";
    let create = event(
        EventKind::SPACE_CREATE,
        1,
        json!({
            "object": {
                "id": space_id,
                "schema": crate::SPACE_SCHEMA,
                "realm_id": realm_id().as_str(),
                "kind": "list",
                "title": "Roadmap",
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    );
    let mut update = event(
        EventKind::SPACE_UPDATE,
        2,
        json!({
            "space_id": space_id,
            "patch": {
                "title": "Roadmap 2026",
                "rank": "a0",
                "fields": {"wip_limit": 5, "wip_limit_enforcement": "reject"}
            }
        }),
    );
    update.prev_refs.push(create.event_id.clone());
    let mut parent = event(
        EventKind::SPACE_PARENT,
        3,
        json!({
            "space_id": space_id,
            "parent_space_id": parent_space_id
        }),
    );
    parent.prev_refs.push(update.event_id.clone());
    let mut tombstone = event(
        EventKind::SPACE_TOMBSTONE,
        4,
        json!({ "space_id": space_id }),
    );
    tombstone.prev_refs.push(parent.event_id.clone());

    let mut state = RealmState::new(realm_id());
    state
        .apply_events(&[tombstone, parent, update, create])
        .unwrap();

    let space = state.spaces.get(space_id).unwrap();
    assert_eq!(space.kind, "list");
    assert_eq!(space.title, "Roadmap 2026");
    assert_eq!(
        space.parent_space_id.as_ref().map(|p| p.as_str()),
        Some(parent_space_id)
    );
    assert_eq!(space.rank.as_deref(), Some("a0"));
    assert_eq!(space.fields["wip_limit"], 5);
    assert_eq!(space.fields["wip_limit_enforcement"], "reject");
    assert_eq!(space.state, Some(crate::models::SpaceState::Tombstoned));
}

fn space_create_event(seq: u64, space_id: &str) -> Event {
    event(
        EventKind::SPACE_CREATE,
        seq,
        json!({
            "object": {
                "id": space_id,
                "schema": crate::SPACE_SCHEMA,
                "realm_id": realm_id().as_str(),
                "kind": "board",
                "title": "Roadmap",
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
}

#[test]
fn space_archive_then_restore_round_trip() {
    let space_id = "ak:space:01904100-0000-7000-8000-1fb50799ad42";
    let create = space_create_event(1, space_id);

    let mut archive = event(EventKind::SPACE_ARCHIVE, 2, json!({ "space_id": space_id }));
    archive.prev_refs.push(create.event_id.clone());

    let mut restore = event(EventKind::SPACE_RESTORE, 3, json!({ "space_id": space_id }));
    restore.prev_refs.push(archive.event_id.clone());
    let restore_at = restore.created_at;

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[create, archive, restore]).unwrap();

    let space = state.spaces.get(space_id).unwrap();
    assert_eq!(space.state, Some(crate::models::SpaceState::Active));
    assert_eq!(space.state_changed_at, Some(restore_at));
}

#[test]
fn space_restore_rejected_when_active() {
    let space_id = "ak:space:01904100-0000-7000-8000-1fb50799ad43";
    let create = space_create_event(1, space_id);

    let mut restore = event(EventKind::SPACE_RESTORE, 2, json!({ "space_id": space_id }));
    restore.prev_refs.push(create.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, restore]).unwrap_err();
    assert!(
        err.to_string().contains("space_not_archived"),
        "unexpected error: {err}"
    );

    let space = state.spaces.get(space_id).unwrap();
    assert_eq!(space.state, Some(crate::models::SpaceState::Active));
}

#[test]
fn space_restore_rejected_when_tombstoned() {
    let space_id = "ak:space:01904100-0000-7000-8000-1fb50799ad44";
    let create = space_create_event(1, space_id);

    let mut tombstone = event(
        EventKind::SPACE_TOMBSTONE,
        2,
        json!({ "space_id": space_id }),
    );
    tombstone.prev_refs.push(create.event_id.clone());
    let tombstone_at = tombstone.created_at;

    let mut restore = event(EventKind::SPACE_RESTORE, 3, json!({ "space_id": space_id }));
    restore.prev_refs.push(tombstone.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state
        .apply_events(&[create, tombstone, restore])
        .unwrap_err();
    assert!(
        err.to_string().contains("space_not_archived"),
        "unexpected error: {err}"
    );

    let space = state.spaces.get(space_id).unwrap();
    assert_eq!(space.state, Some(crate::models::SpaceState::Tombstoned));
    assert_eq!(space.state_changed_at, Some(tombstone_at));
}

fn strand_create_event(seq: u64, strand_id: &str) -> Event {
    event(
        EventKind::STRAND_CREATE,
        seq,
        json!({
            "object": {
                "id": strand_id,
                "schema": crate::STRAND_SCHEMA,
                "realm_id": realm_id().as_str(),
                "metadata": {"title": "Payment refactor"},
                "tracks": {"synthesis": {}},
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
}

#[test]
fn strand_archive_then_restore_round_trip() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-1fb50799ad50";
    let create = strand_create_event(1, strand_id);

    let mut archive = event(
        EventKind::STRAND_ARCHIVE,
        2,
        json!({ "target_ref": strand_id }),
    );
    archive.prev_refs.push(create.event_id.clone());

    let mut restore = event(
        EventKind::STRAND_RESTORE,
        3,
        json!({ "target_ref": strand_id }),
    );
    restore.prev_refs.push(archive.event_id.clone());
    let restore_at = restore.created_at;

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[create, archive, restore]).unwrap();

    let strand = state.subjects.get(strand_id).unwrap();
    assert_eq!(strand.state, Some(crate::ObjectState::Active));
    assert_eq!(strand.state_changed_at, Some(restore_at));
}

#[test]
fn strand_restore_rejected_when_active() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-1fb50799ad51";
    let create = strand_create_event(1, strand_id);

    let mut restore = event(
        EventKind::STRAND_RESTORE,
        2,
        json!({ "target_ref": strand_id }),
    );
    restore.prev_refs.push(create.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, restore]).unwrap_err();
    assert!(
        err.to_string().contains("strand_not_archived"),
        "unexpected error: {err}"
    );

    // create_strand defaults the Strand to Active. The failed restore must
    // be a no-op — state stays Active, state_changed_at stays unset
    // (only create touched it, which doesn't set state_changed_at).
    let strand = state.subjects.get(strand_id).unwrap();
    assert_eq!(strand.state, Some(crate::ObjectState::Active));
    assert!(
        strand.state_changed_at.is_none(),
        "restore must not write state_changed_at when rejected"
    );
}

#[test]
fn morph_archive_then_restore_round_trip() {
    let morph_id = "ak:morph:01904100-0000-7000-8000-1fb50799ad60";
    let create = morph_event(1, morph_id, "Task A");

    let mut archive = event(
        EventKind::MORPH_ARCHIVE,
        2,
        json!({ "target_ref": morph_id }),
    );
    archive.prev_refs.push(create.event_id.clone());

    let mut restore = event(
        EventKind::MORPH_RESTORE,
        3,
        json!({ "target_ref": morph_id }),
    );
    restore.prev_refs.push(archive.event_id.clone());

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[create, archive, restore]).unwrap();

    let morph = state.morphs.get(morph_id).unwrap();
    assert_eq!(morph.state, Some(crate::ObjectState::Active));
}

#[test]
fn morph_restore_rejected_when_active() {
    let morph_id = "ak:morph:01904100-0000-7000-8000-1fb50799ad61";
    let create = morph_event(1, morph_id, "Task B");

    let mut restore = event(
        EventKind::MORPH_RESTORE,
        2,
        json!({ "target_ref": morph_id }),
    );
    restore.prev_refs.push(create.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, restore]).unwrap_err();
    assert!(
        err.to_string().contains("morph_not_archived"),
        "unexpected error: {err}"
    );

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
fn space_archive_rejected_when_already_archived() {
    let space_id = "ak:space:01904100-0000-7000-8000-2fb50799ad42";
    let create = space_create_event(1, space_id);
    let mut archive1 = event(EventKind::SPACE_ARCHIVE, 2, json!({ "space_id": space_id }));
    archive1.prev_refs.push(create.event_id.clone());
    let mut archive2 = event(EventKind::SPACE_ARCHIVE, 3, json!({ "space_id": space_id }));
    archive2.prev_refs.push(archive1.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state
        .apply_events(&[create, archive1, archive2])
        .unwrap_err();
    assert!(
        err.to_string().contains("space_not_active"),
        "unexpected error: {err}"
    );

    // First archive succeeded; second archive (the rejected one) must not
    // touch Space state.
    let space = state.spaces.get(space_id).unwrap();
    assert_eq!(space.state, Some(crate::models::SpaceState::Archived));
}

#[test]
fn space_archive_rejected_when_tombstoned() {
    let space_id = "ak:space:01904100-0000-7000-8000-2fb50799ad43";
    let create = space_create_event(1, space_id);
    let mut tombstone = event(
        EventKind::SPACE_TOMBSTONE,
        2,
        json!({ "space_id": space_id }),
    );
    tombstone.prev_refs.push(create.event_id.clone());
    let mut archive = event(EventKind::SPACE_ARCHIVE, 3, json!({ "space_id": space_id }));
    archive.prev_refs.push(tombstone.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state
        .apply_events(&[create, tombstone, archive])
        .unwrap_err();
    assert!(
        err.to_string().contains("space_not_active"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.spaces.get(space_id).unwrap().state,
        Some(crate::models::SpaceState::Tombstoned)
    );
}

#[test]
fn space_tombstone_rejected_when_already_terminal() {
    let space_id = "ak:space:01904100-0000-7000-8000-2fb50799ad44";
    let create = space_create_event(1, space_id);
    let mut tombstone1 = event(
        EventKind::SPACE_TOMBSTONE,
        2,
        json!({ "space_id": space_id }),
    );
    tombstone1.prev_refs.push(create.event_id.clone());
    let mut tombstone2 = event(
        EventKind::SPACE_TOMBSTONE,
        3,
        json!({ "space_id": space_id }),
    );
    tombstone2.prev_refs.push(tombstone1.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state
        .apply_events(&[create, tombstone1, tombstone2])
        .unwrap_err();
    assert!(
        err.to_string().contains("space_already_terminal"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.spaces.get(space_id).unwrap().state,
        Some(crate::models::SpaceState::Tombstoned)
    );
}

#[test]
fn strand_archive_rejected_when_already_archived() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-2fb50799ad50";
    let create = strand_create_event(1, strand_id);
    let mut archive1 = event(
        EventKind::STRAND_ARCHIVE,
        2,
        json!({ "target_ref": strand_id }),
    );
    archive1.prev_refs.push(create.event_id.clone());
    let mut archive2 = event(
        EventKind::STRAND_ARCHIVE,
        3,
        json!({ "target_ref": strand_id }),
    );
    archive2.prev_refs.push(archive1.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state
        .apply_events(&[create, archive1, archive2])
        .unwrap_err();
    assert!(
        err.to_string().contains("strand_not_active"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.subjects.get(strand_id).unwrap().state,
        Some(crate::ObjectState::Archived)
    );
}

#[test]
fn morph_archive_rejected_when_already_archived() {
    let morph_id = "ak:morph:01904100-0000-7000-8000-2fb50799ad60";
    let create = morph_event(1, morph_id, "Task C");
    let mut archive1 = event(
        EventKind::MORPH_ARCHIVE,
        2,
        json!({ "target_ref": morph_id }),
    );
    archive1.prev_refs.push(create.event_id.clone());
    let mut archive2 = event(
        EventKind::MORPH_ARCHIVE,
        3,
        json!({ "target_ref": morph_id }),
    );
    archive2.prev_refs.push(archive1.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state
        .apply_events(&[create, archive1, archive2])
        .unwrap_err();
    assert!(
        err.to_string().contains("morph_not_active"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.morphs.get(morph_id).unwrap().state,
        Some(crate::ObjectState::Archived)
    );
}

#[test]
fn space_update_rejected_when_archived() {
    let space_id = "ak:space:01904100-0000-7000-8000-3fb50799ad42";
    let create = space_create_event(1, space_id);
    let mut archive = event(EventKind::SPACE_ARCHIVE, 2, json!({ "space_id": space_id }));
    archive.prev_refs.push(create.event_id.clone());
    let mut update = event(
        EventKind::SPACE_UPDATE,
        3,
        json!({ "space_id": space_id, "patch": { "title": "Renamed" } }),
    );
    update.prev_refs.push(archive.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, archive, update]).unwrap_err();
    assert!(
        err.to_string().contains("space_not_active"),
        "unexpected error: {err}"
    );
    // Title must NOT have been changed.
    assert_eq!(state.spaces.get(space_id).unwrap().title, "Roadmap");
}

#[test]
fn strand_update_rejected_when_archived() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-3fb50799ad50";
    let create = strand_create_event(1, strand_id);
    let mut archive = event(
        EventKind::STRAND_ARCHIVE,
        2,
        json!({ "target_ref": strand_id }),
    );
    archive.prev_refs.push(create.event_id.clone());
    let mut update = event(
        EventKind::STRAND_UPDATE,
        3,
        json!({ "target_ref": strand_id, "patch": { "metadata": {"title": "New title"} } }),
    );
    update.prev_refs.push(archive.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, archive, update]).unwrap_err();
    assert!(
        err.to_string().contains("strand_not_active"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.subjects.get(strand_id).unwrap().metadata_title(),
        Some("Payment refactor")
    );
}

#[test]
fn morph_update_rejected_when_archived() {
    let morph_id = "ak:morph:01904100-0000-7000-8000-3fb50799ad60";
    let create = morph_event(1, morph_id, "Original Title");
    let mut archive = event(
        EventKind::MORPH_ARCHIVE,
        2,
        json!({ "target_ref": morph_id }),
    );
    archive.prev_refs.push(create.event_id.clone());
    let mut update = event(
        EventKind::MORPH_UPDATE,
        3,
        json!({ "target_ref": morph_id, "patch": { "metadata.title": "Renamed Morph" } }),
    );
    update.prev_refs.push(archive.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, archive, update]).unwrap_err();
    assert!(
        err.to_string().contains("morph_not_active"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.morphs.get(morph_id).unwrap().metadata_title(),
        Some("Original Title")
    );
}

#[test]
fn strand_events_create_update_and_default_view_relation() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-1fb50799ad3f";
    let view_ref = "ak:view:01904100-0000-7000-8000-08ca7b733afd";

    let create = Event::new(
        EventKind::STRAND_CREATE,
        realm_id(),
        actor_id(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        json!({
            "object": {
                "id": strand_id,
                "schema": crate::STRAND_SCHEMA,
                "realm_id": realm_id().as_str(),
                "metadata": {
                    "title": "Payment refactor",
                    "summary": "Unify payment strands"
                },
                "tracks": {"synthesis": {}},
                "created_by": actor_id().as_str(),
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }),
    )
    .unwrap();
    let mut update = Event::new(
        EventKind::STRAND_UPDATE,
        realm_id(),
        actor_id(),
        2,
        Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
        json!({
            "target_ref": strand_id,
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
        EventKind::RELATION_CREATE,
        realm_id(),
        actor_id(),
        3,
        Hlc::new("01970e589d21-0003-a13f9c2e").unwrap(),
        json!({
            "kind": "has_default_view",
            "from_ref": strand_id,
            "to_ref": view_ref
        }),
    )
    .unwrap();
    relation.prev_refs.push(update.event_id.clone());
    let relation_id = relation
        .event_id
        .as_str()
        .replacen("ak:event:", "ak:relation:", 1);

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[relation, update, create]).unwrap();

    let strand = state.subjects.get(strand_id).unwrap();
    assert_eq!(strand.metadata_title(), Some("Payment refactor"));
    assert_eq!(
        strand.metadata_summary(),
        Some("Risk, refunds and callbacks are tracked together.")
    );
    assert_eq!(strand.metadata_fields().unwrap()["priority"], "high");

    let relation = state.relations.get(&relation_id).unwrap();
    assert_eq!(relation.relation_kind, crate::RelationKind::HasDefaultView);
    assert_eq!(relation.from_ref, strand_id);
    assert_eq!(relation.to_ref, view_ref);
}

#[test]
fn realm_state_applies_morph_events() {
    let mut state = RealmState::new(realm_id());
    let create_event = morph_event(
        1,
        "ak:morph:01904100-0000-7000-8000-bbe051c5f72e",
        "Test task",
    );

    state.apply_events(&[create_event]).unwrap();
    assert_eq!(state.morphs.len(), 1);
}

#[test]
fn realm_state_sorts_events_by_hlc() {
    let event1 = Event {
        hlc: Some(Hlc::new("01970e589d21-0002-a13f9c2e").unwrap()),
        ..morph_event(1, "ak:morph:01904100-0000-7000-8000-d48c478ecd0b", "Task 1")
    };
    let event2 = Event {
        hlc: Some(Hlc::new("01970e589d21-0001-a13f9c2e").unwrap()),
        ..morph_event(2, "ak:morph:01904100-0000-7000-8000-e75dc3f6ab2e", "Task 2")
    };

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[event1, event2]).unwrap();

    assert_eq!(
        state.frontier.first().unwrap().as_str(),
        "ak:event:01904100-0000-7000-8000-000000000001"
    );
}

#[test]
fn member_state_conflict_prefers_ban_semantics() {
    let leave = event(
        "ak.member.state",
        4,
        json!({ "actor_id": "did:webvh:z6mkfixture:alice.example", "membership": "leave" }),
    );
    let mut ban = event(
        "ak.member.state",
        5,
        json!({ "actor_id": "did:webvh:z6mkfixture:alice.example", "membership": "ban" }),
    );
    ban.hlc = leave.hlc.clone();
    ban.event_id = EventId::new("ak:event:01904100-0000-7000-8000-c9d398595fe8").unwrap();

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[leave, ban]).unwrap();

    let resolved = state
        .resolved_state
        .get("ak.member.state|did:webvh:z6mkfixture:alice.example")
        .unwrap();
    assert_eq!(resolved.content["membership"], "ban");
    assert_eq!(state.conflict_records.len(), 1);
}

#[test]
fn capability_rebind_uses_deterministic_lww_order() {
    let revoke = event(
        "ak.capability.revoke",
        1,
        json!({ "grant_id": "cap-chan-post" }),
    );
    let grant = event(
        "ak.capability.grant",
        2,
        json!({
            "grant_id": "cap-chan-post",
            "subject": "did:webvh:z6mkfixture:alice.example",
            "actions": ["ak.message.create", "ak.reaction.add"]
        }),
    );

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[revoke, grant]).unwrap();

    let resolved = state
        .resolved_state
        .get("ak.capability|cap-chan-post")
        .unwrap();
    assert_eq!(resolved.content["actions"][1], "ak.reaction.add");
    assert!(state.capability_allows("cap-chan-post", "ak.reaction.add"));
    assert!(!state.capability_allows("cap-chan-post", "message.delete"));
}

#[test]
fn message_revision_redaction_and_reaction_converge() {
    let base = event(
        "ak.message.create",
        1,
        json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-1fb50799ad50",
            "message_id": "m1",
            "track_name": "discussion",
            "content": { "kind": "ak.content.text", "body": "hello" }
        }),
    );
    let mut revise = event(
        "ak.message.revise",
        2,
        json!({
            "target_message_id": "m1",
            "content": { "kind": "ak.content.text", "body": "edited" }
        }),
    );
    revise.prev_refs.push(base.event_id.clone());
    let mut reaction_add = event(
        "ak.reaction.add",
        3,
        json!({ "message_id": "m1", "reaction_key": "+1" }),
    );
    reaction_add.prev_refs.push(revise.event_id.clone());

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[reaction_add, revise, base]).unwrap();

    let message = state.messages.get("m1").unwrap();
    assert_eq!(message.content["body"], "edited");
    assert_eq!(message.revision_event_ids.len(), 1);

    let reaction = state
        .reactions
        .get("m1|did:webvh:z6mkfixture:alice.example.com|+1")
        .unwrap();
    assert!(reaction.active);
}

#[test]
fn snapshot_manifest_tracks_state_digest_and_merkle_root() {
    let event = morph_event(
        9,
        "ak:morph:01904100-0000-7000-8000-b7a4e10c8c77",
        "Snapshot task",
    );
    let mut state = RealmState::new(realm_id());

    state.apply_events(std::slice::from_ref(&event)).unwrap();
    let snapshot = state.snapshot().unwrap();
    let manifest = snapshot.manifest.as_ref().unwrap();

    assert_eq!(manifest.schema, REDUCER_SNAPSHOT_SCHEMA);
    assert_eq!(manifest.reducer_profile, REDUCER_SNAPSHOT_PROFILE);
    assert_eq!(manifest.state_digest, snapshot.state_digest);
    assert_eq!(manifest.merkle_root, snapshot.state_merkle_root().unwrap());
    snapshot.verify().unwrap();
}

#[test]
fn snapshot_chunk_manifest_verifies_digests() {
    let state = RealmState::new(realm_id());
    let snapshot = state.snapshot().unwrap();
    let manifest = snapshot.manifest_with_chunks(16).unwrap();
    let bytes = snapshot.canonical_snapshot_bytes().unwrap();
    let chunks: Vec<Vec<u8>> = bytes.chunks(16).map(|chunk| chunk.to_vec()).collect();

    verify_snapshot_chunks(&manifest, chunks.clone()).unwrap();

    let mut tampered = chunks;
    tampered[0][0] ^= 1;
    assert!(verify_snapshot_chunks(&manifest, tampered).is_err());
}

#[test]
fn merkle_root_preserves_caller_leaf_order() {
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

    assert_ne!(a, b);
}

#[test]
fn merkle_root_promotes_odd_tail_without_duplication() {
    let three = merkle_root(vec![
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
    ])
    .unwrap();
    let duplicate_tail = merkle_root(vec![
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
    ])
    .unwrap();

    assert_ne!(three, duplicate_tail);
}

#[test]
fn restore_snapshot_or_replay_falls_back_on_verification_failure() {
    let event = morph_event(
        10,
        "ak:morph:01904100-0000-7000-8000-b7a4e10c8c77",
        "Replayed task",
    );
    let mut state = RealmState::new(realm_id());
    state.apply_events(std::slice::from_ref(&event)).unwrap();
    let mut snapshot = state.snapshot().unwrap();
    snapshot.state_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();

    let restored =
        RealmState::restore_snapshot_or_replay(Some(snapshot), realm_id(), &[event]).unwrap();

    assert_eq!(restored.source, SnapshotRestoreSource::RepoReplay);
    assert!(
        restored
            .snapshot_error
            .unwrap()
            .contains("state hash mismatch")
    );
    assert_eq!(restored.state.morphs.len(), 1);
}

#[test]
fn reducer_convergence_is_order_independent() {
    let events: Vec<Event> = (0..5)
        .map(|i| {
            morph_event(
                i + 1,
                &format!("ak:morph:01904100-0000-7000-8000-{i:012x}"),
                &format!("Task {i}"),
            )
        })
        .collect();

    let mut state_a = RealmState::new(realm_id());
    state_a.apply_events(&events).unwrap();

    let mut reversed = events.clone();
    reversed.reverse();
    let mut state_b = RealmState::new(realm_id());
    state_b.apply_events(&reversed).unwrap();

    assert_eq!(state_a.morphs.len(), state_b.morphs.len());
    for (id, morph_a) in &state_a.morphs {
        let morph_b = state_b.morphs.get(id).unwrap();
        assert_eq!(morph_a.metadata_title(), morph_b.metadata_title());
        assert_eq!(morph_a.state, morph_b.state);
    }
    assert_eq!(state_a.frontier, state_b.frontier);
}

// ── SDK Round 11 (2026-05-16): ak.redaction → Strand / Morph state flip ──
// Mirror of soland round 14b. When ak.redaction event content carries
// `object_ref` pointing to a Strand / Morph, the reducer flips the subject
// state to Redacted (terminal). State-machine guard rejects already-
// terminal source with `<kind>_already_terminal`.

fn redaction_event(seq: u64, object_ref: &str) -> Event {
    let mut ev = event(
        "ak.redaction",
        seq,
        json!({
            "target_event_id": format!("ak:event:01904100-0000-7000-8000-{:012x}", 0xdeadbeef + seq),
            "object_ref": object_ref,
        }),
    );
    // `ak.redaction` dispatch path uses `event.redacts`; populate it so
    // the dispatcher invokes redact_event AND redact_object_for_event.
    ev.redacts = Some(
        EventId::new(format!(
            "ak:event:01904100-0000-7000-8000-{:012x}",
            0xdeadbeef + seq
        ))
        .unwrap(),
    );
    ev
}

#[test]
fn redaction_with_strand_object_ref_flips_subject_to_redacted() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-3fb50799ad50";
    let create = strand_create_event(1, strand_id);
    let mut redact = redaction_event(2, strand_id);
    redact.prev_refs.push(create.event_id.clone());
    let redact_at = redact.created_at;

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[create, redact]).unwrap();

    let strand = state.subjects.get(strand_id).unwrap();
    assert_eq!(strand.state, Some(crate::ObjectState::Redacted));
    assert_eq!(strand.state_changed_at, Some(redact_at));
}

#[test]
fn redaction_with_morph_object_ref_flips_subject_to_redacted() {
    let morph_id = "ak:morph:01904100-0000-7000-8000-3fb50799ad60";
    let create = morph_event(1, morph_id, "Sensitive task");
    let mut redact = redaction_event(2, morph_id);
    redact.prev_refs.push(create.event_id.clone());

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[create, redact]).unwrap();

    let morph = state.morphs.get(morph_id).unwrap();
    assert_eq!(morph.state, Some(crate::ObjectState::Redacted));
}

#[test]
fn redaction_against_already_redacted_strand_rejects() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-3fb50799ad51";
    let create = strand_create_event(1, strand_id);
    let mut redact1 = redaction_event(2, strand_id);
    redact1.prev_refs.push(create.event_id.clone());
    let mut redact2 = redaction_event(3, strand_id);
    redact2.prev_refs.push(redact1.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, redact1, redact2]).unwrap_err();
    assert!(
        err.to_string().contains("strand_already_terminal"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.subjects.get(strand_id).unwrap().state,
        Some(crate::ObjectState::Redacted)
    );
}

#[test]
fn strand_tracks_update_merges_tracks_from_patch_tracks_and_top_level_tracks() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-4fb50799ad55";
    let create = strand_create_event(1, strand_id);
    let mut update = event(
        EventKind::STRAND_TRACKS_UPDATE,
        2,
        json!({
            "strand_id": strand_id,
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

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[create, update]).unwrap();

    let strand = state.subjects.get(strand_id).unwrap();
    assert!(
        strand
            .tracks
            .contains_key(crate::STRAND_TRACK_NAME_SYNTHESIS)
    );
    assert_eq!(
        strand.tracks["discussion"].profile.as_deref(),
        Some("discussion")
    );
    assert_eq!(strand.tracks["discussion"].metadata["capacity"], 25);
    assert_eq!(strand.tracks["review"].profile.as_deref(), Some("review"));
    assert_eq!(strand.tracks["review"].template.as_deref(), Some("Review"));
}

// ── SDK-ORG-05 (2026-06-25): ak.realm.organization composite cell subject ──
// `ak.realm.organization` declares a tuple cell_subject
// `(organization_id, relationship)`. Distinct pairs must form independent
// CAS register cells so they never overwrite each other; only events sharing
// the same `(organization_id, relationship)` compete under LWW.

fn realm_organization_event(seq: u64, organization_id: &str, relationship: &str) -> Event {
    event(
        "ak.realm.organization",
        seq,
        json!({
            "organization_id": organization_id,
            "relationship": relationship,
        }),
    )
}

#[test]
fn realm_organization_distinct_organizations_coexist() {
    let org_a = "did:webvh:z6mkfixture:org-a.example.com";
    let org_b = "did:webvh:z6mkfixture:org-b.example.com";
    let ev_a = realm_organization_event(1, org_a, "member");
    let ev_b = realm_organization_event(2, org_b, "member");

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[ev_a, ev_b]).unwrap();

    // Two independent cells; neither overwrites the other, no conflicts.
    assert!(
        state
            .resolved_state
            .contains_key(&format!("ak.realm.organization|{org_a}::member"))
    );
    assert!(
        state
            .resolved_state
            .contains_key(&format!("ak.realm.organization|{org_b}::member"))
    );
    assert!(state.conflict_records.is_empty());
}

#[test]
fn realm_organization_distinct_relationships_coexist() {
    let org = "did:webvh:z6mkfixture:org-a.example.com";
    let ev_member = realm_organization_event(1, org, "member");
    let ev_partner = realm_organization_event(2, org, "partner");

    let mut state = RealmState::new(realm_id());
    state.apply_events(&[ev_member, ev_partner]).unwrap();

    // Same organization, different relationship → independent cells.
    assert!(
        state
            .resolved_state
            .contains_key(&format!("ak.realm.organization|{org}::member"))
    );
    assert!(
        state
            .resolved_state
            .contains_key(&format!("ak.realm.organization|{org}::partner"))
    );
    assert!(state.conflict_records.is_empty());
}

#[test]
fn realm_organization_same_subject_replaces_under_lww() {
    let org = "did:webvh:z6mkfixture:org-a.example.com";
    let mut first = realm_organization_event(1, org, "member");
    first.payload = serde_json::from_value(json!({
        "organization_id": org,
        "relationship": "member",
        "label": "first"
    }))
    .unwrap();
    let mut second = realm_organization_event(2, org, "member");
    second.payload = serde_json::from_value(json!({
        "organization_id": org,
        "relationship": "member",
        "label": "second"
    }))
    .unwrap();

    let mut state = RealmState::new(realm_id());
    // `second` has the higher HLC/seq, so it wins under the CAS-register LWW
    // order. Apply out of order to confirm convergence.
    state.apply_events(&[second, first]).unwrap();

    let resolved = state
        .resolved_state
        .get(&format!("ak.realm.organization|{org}::member"))
        .unwrap();
    assert_eq!(resolved.content["label"], "second");
    // A single cell keyed by the composite subject; the loser is a conflict.
    assert_eq!(state.conflict_records.len(), 1);
}

#[test]
fn realm_organization_requires_subject_fields() {
    // Missing relationship must surface a protocol error, not a silent
    // realm_id fallback.
    let mut ev = realm_organization_event(1, "did:webvh:z6mkfixture:org-a.example.com", "member");
    ev.payload = serde_json::from_value(
        json!({ "organization_id": "did:webvh:z6mkfixture:org-a.example.com" }),
    )
    .unwrap();

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[ev]).unwrap_err();
    assert!(
        err.to_string().contains("relationship"),
        "unexpected error: {err}"
    );
}

#[test]
fn redaction_against_already_redacted_morph_rejects() {
    let morph_id = "ak:morph:01904100-0000-7000-8000-3fb50799ad61";
    let create = morph_event(1, morph_id, "Task");
    let mut redact1 = redaction_event(2, morph_id);
    redact1.prev_refs.push(create.event_id.clone());
    let mut redact2 = redaction_event(3, morph_id);
    redact2.prev_refs.push(redact1.event_id.clone());

    let mut state = RealmState::new(realm_id());
    let err = state.apply_events(&[create, redact1, redact2]).unwrap_err();
    assert!(
        err.to_string().contains("morph_already_terminal"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.morphs.get(morph_id).unwrap().state,
        Some(crate::ObjectState::Redacted)
    );
}
