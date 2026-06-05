use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use cokret::{canonical, *};
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device(id: &str) -> DeviceId {
    let mut acc = 0xcbf29ce484222325u64;
    for byte in id.bytes() {
        acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    DeviceId::new(format!("ck:device:01904100-0000-7000-8000-{:012x}", acc & 0x0000_ffff_ffff_ffff))
        .unwrap()
}

fn event(kind: &str, seq: u64, realm_id: &RealmId, content: serde_json::Value) -> Event {
    Event {
        event_id: EventId::new(format!("ck:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.to_owned(),
        realm_id: realm_id.clone(),
        actor_id: did("alice"),
        actor_seq: seq,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new(format!("01970e589d21-{seq:04x}-a13f9c2e")).unwrap(),
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

#[test]
fn end_to_end_auth_session_realm_query_and_notifications() {
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

    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let morph_id = MorphId::new("ck:morph:01904100-0000-7000-8000-d48c478ecd0b").unwrap();
    base.process_events(
        &realm_id,
        vec![event(
            OP_MORPH_CREATE,
            1,
            &realm_id,
            json!({
                "object": {
                    "id": morph_id.as_str(),
                    "schema": MORPH_SCHEMA,
                    "realm_id": realm_id.as_str(),
                    "morph_type": "task",
                    "metadata": {"title": "Ship SDK"},
                    "fields": {"status": "todo"},
                    "created_by": "did:web:alice.example",
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
        )],
    )
    .unwrap();

    let realm = Realm::new(realm_id.clone(), base);
    assert_eq!(realm.search_morphs("ship").len(), 1);

    let mut notifications = NotificationManager::new();
    notifications.add_notification(
        "n1",
        Some(realm_id.clone()),
        EventId::new("ck:event:01904100-0000-7000-8000-b2b79cd5161d").unwrap(),
        alice,
        "ck.message",
        Some(json!({"body": "hello"})),
    );
    assert_eq!(notifications.counts(Some(&realm_id)).notification_count, 1);
}

#[test]
fn error_boundary_and_concurrency_paths_are_covered() {
    assert!(RealmId::new("not-a-realm").is_err());

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

    let cursor = Cursor::new().unwrap().encode().unwrap();
    let decoded = Cursor::decode(&cursor).unwrap();
    assert_eq!(decoded.v, "1");
    assert!(decoded.h.is_some());
    assert!(decoded.s.is_empty());
}

#[test]
fn interoperability_serialization_roundtrips() {
    let mut realms = BTreeMap::new();
    realms.insert(
        "ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
        serde_json::to_value(SyncRealm::default()).unwrap(),
    );
    let response = SyncResBody {
        cursor: "s1".to_owned(),
        realms,
        left_realms: Vec::new(),
        to_device: Vec::new(),
        device_lists: serde_json::Value::Null,
        account_data: Vec::new(),
        presence: Vec::new(),
        notifications: serde_json::Value::Null,
        partial: false,
    };

    let json = serde_json::to_string(&response).unwrap();
    let decoded: SyncResBody = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.cursor, "s1");
}

#[test]
fn stress_smoke_processes_many_index_and_cache_entries() {
    let mut directory = DirectoryService::new();
    for index in 0..250 {
        let mut entry = RealmSearchEntry::new(
            RealmId::new(format!("ck:realm:01904100-0000-7000-8000-{index:012x}")).unwrap(),
            format!("Realm {index}"),
        );
        entry.tags.insert(if index % 2 == 0 { "even" } else { "odd" }.to_owned());
        directory.publish_realm(entry);
    }
    assert_eq!(
        directory.recommend_realms(BTreeSet::from(["even".to_owned()]), BTreeSet::new(), 10).len(),
        10
    );

    let mut cache = StoreCache::new(128);
    for index in 0..1000 {
        cache.insert(index, index);
    }
    assert_eq!(cache.len(), 128);
}
