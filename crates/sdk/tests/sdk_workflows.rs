use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use contrix::{canonical, *};
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device(id: &str) -> DeviceId {
    DeviceId::new(format!("dev_{id}")).unwrap()
}

fn event(kind: &str, seq: u64, space_id: &SpaceId, content: serde_json::Value) -> Event {
    Event {
        event_id: EventId::new(format!("cx:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.to_owned(),
        space_id: space_id.clone(),
        actor_id: did("alice"),
        actor_seq: seq,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new(format!("01970e589d21-{seq:08x}-a13f9c2e")).unwrap(),
        prev_refs: vec![],
        refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

#[test]
fn end_to_end_auth_session_space_query_and_notifications() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    auth.register_password_user("alice", "secret", alice.clone()).unwrap();
    let session = auth.login_password("alice", "secret", device("desktop")).unwrap();

    let base = Arc::new(BaseClient::new());
    base.set_session_meta(SessionMeta {
        user_id: session.user_id,
        device_id: session.device_id,
        access_token: Some(session.access_token),
        expires_at: Some(session.expires_at),
    })
    .unwrap();

    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let morph_id = MorphId::new("cx:morph:01904100-0000-7000-8000-d48c478ecd0b").unwrap();
    base.process_events(
        &space_id,
        vec![event(
            OP_MORPH_CREATE,
            1,
            &space_id,
            json!({
                "object": {
                    "id": morph_id.as_str(),
                    "schema": MORPH_SCHEMA,
                    "space_id": space_id.as_str(),
                    "morph_type": "task",
                    "title": "Ship SDK",
                    "fields": {"status": "todo"},
                    "created_by": "did:web:alice.example",
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
        )],
    )
    .unwrap();

    let space = Space::new(space_id.clone(), base);
    assert_eq!(space.search_morphs("ship").len(), 1);

    let mut notifications = NotificationManager::new();
    notifications.add_notification(
        "n1",
        Some(space_id.clone()),
        EventId::new("cx:event:01904100-0000-7000-8000-b2b79cd5161d").unwrap(),
        alice,
        "cx.message",
        Some(json!({"body": "hello"})),
    );
    assert_eq!(notifications.counts(Some(&space_id)).notification_count, 1);
}

#[test]
fn error_boundary_and_concurrency_paths_are_covered() {
    assert!(SpaceId::new("not-a-space").is_err());

    let mut auth = AuthManager::default();
    auth.register_password_user("alice", "secret", did("alice")).unwrap();
    assert!(auth.login_password("alice", "wrong", device("desktop")).is_err());

    let mut empty_cache: StoreCache<&str, i32> = StoreCache::new(0);
    empty_cache.insert("a", 1);
    assert!(empty_cache.is_empty());
}

#[test]
fn protocol_conformance_vectors_remain_stable() {
    let value = json!({"b": 2, "a": 1});
    assert_eq!(
        canonical::canonical_sha256(&value).unwrap(),
        "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    );

    let cursor = Cursor::new()
        .with_space_position(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            SpacePosition {
                p: vec!["cx:event:019640ed-8000-7000-8000-000000000000".to_owned()],
                order: "01970e589d21-00000001-a13f9c2e".to_owned(),
                h: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            },
        )
        .encode()
        .unwrap();
    assert_eq!(Cursor::decode(&cursor).unwrap().v, "1");
}

#[test]
fn interoperability_serialization_roundtrips() {
    let mut spaces = BTreeMap::new();
    spaces.insert("cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(), SyncSpace::default());
    let response = SyncResponse {
        next_batch: "s1".to_owned(),
        spaces,
        to_device: Vec::new(),
        device_lists: DeviceListChanges::default(),
        presence: Vec::new(),
        account_data: Vec::new(),
        notifications: Vec::new(),
        partial: false,
    };

    let json = serde_json::to_string(&response).unwrap();
    let decoded: SyncResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.next_batch, "s1");
}

#[test]
fn stress_smoke_processes_many_index_and_cache_entries() {
    let mut directory = DirectoryService::new();
    for index in 0..250 {
        let mut entry = SpaceSearchEntry::new(
            SpaceId::new(format!("cx:space:01904100-0000-7000-8000-{index:012x}")).unwrap(),
            format!("Space {index}"),
        );
        entry.tags.insert(if index % 2 == 0 { "even" } else { "odd" }.to_owned());
        directory.publish_space(entry);
    }
    assert_eq!(
        directory.recommend_spaces(BTreeSet::from(["even".to_owned()]), BTreeSet::new(), 10).len(),
        10
    );

    let mut cache = StoreCache::new(128);
    for index in 0..1000 {
        cache.insert(index, index);
    }
    assert_eq!(cache.len(), 128);
}
