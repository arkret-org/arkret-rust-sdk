use serde_json::json;

use super::*;
use crate::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
}

#[test]
fn mimi_room_update_wire_uses_sender_actor_id_only() {
    let actor = did("alice");
    let body = MimiRoomUpdateRequestBody {
        mls_group_id: "group-1".to_owned(),
        update: json!({"kind": "room_update", "payload": {}}),
        epoch: Some(7),
        confirmed_transcript_hash: Some(
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        ),
        sender_actor_id: Some(actor.clone()),
    };
    let value = serde_json::to_value(&body).unwrap();
    assert_eq!(value["sender_actor_id"], json!(actor));
    assert!(value.get("sender").is_none());
    assert!(value.get("confirmed_transcript_hash").is_some());
    assert!(value.get("transcript_hash").is_none());

    let old_sender = json!({
        "mls_group_id": "group-1",
        "update": {"kind": "room_update", "payload": {}},
        "sender": "did:web:alice.example"
    });
    assert!(serde_json::from_value::<MimiRoomUpdateRequestBody>(old_sender).is_err());

    let old_transcript_hash = json!({
        "mls_group_id": "group-1",
        "update": {"kind": "room_update", "payload": {}},
        "transcript_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    assert!(serde_json::from_value::<MimiRoomUpdateRequestBody>(old_transcript_hash).is_err());
}

#[test]
fn mimi_submit_message_wire_uses_sender_actor_id_only() {
    let actor = did("alice");
    let body = MimiSubmitMessageRequestBody {
        sender_actor_id: actor.clone(),
        device_id: device_id(),
        ciphertext: json!({
            "content_type": "application/cokret",
            "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "payload": "AA"
        }),
        mls_group_id: Some("group-1".to_owned()),
        epoch: Some(7),
        associated_data: json!({}),
    };
    let value = serde_json::to_value(&body).unwrap();
    assert_eq!(value["sender_actor_id"], json!(actor));
    assert!(value.get("sender").is_none());

    let old_sender = json!({
        "sender": "did:web:alice.example",
        "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
        "ciphertext": {
            "content_type": "application/cokret",
            "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "payload": "AA"
        }
    });
    assert!(serde_json::from_value::<MimiSubmitMessageRequestBody>(old_sender).is_err());
}
