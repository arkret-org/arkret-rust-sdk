use serde_json::{Value, json};

use super::*;
use crate::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
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
        "sender": "did:webvh:z6mkfixture:alice.example"
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
            "content_type": "application/arkret",
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
        "sender": "did:webvh:z6mkfixture:alice.example",
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "ciphertext": {
            "content_type": "application/arkret",
            "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "payload": "AA"
        }
    });
    assert!(serde_json::from_value::<MimiSubmitMessageRequestBody>(old_sender).is_err());
}

#[test]
fn keypackages_claim_outcome_uses_typed_records_and_failures() {
    let outcome = json!({
        "claims": [{
            "claim_id": "ak:mls_keypackage:t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ssk_generation": 3,
            "expires_at": "2100-01-01T00:00:00Z",
            "device_signature": {
                "kid": "did:webvh:z6mkfixture:alice.example#ak:device:01904100-0000-7000-8000-000000000001",
                "alg": "EdDSA",
                "sig": "c2ln"
            },
            "revocation_status": "active"
        }],
        "failures": [{
            "keypackage_ref": "ak:mls:keypackage:missing",
            "reason_code": "not_found"
        }],
        "available_count": 1
    });
    let parsed: KeyPackagesClaimOutcome = serde_json::from_value(outcome).unwrap();
    assert_eq!(parsed.claims[0].principal_id, did("alice"));
    assert_eq!(parsed.claims[0].ssk_generation, Some(3));
    assert_eq!(parsed.claims[0].device_authorize_event_id, None);
    assert_eq!(parsed.failures[0].reason_code, "not_found");

    let malformed_claim = json!({
        "claims": [{
            "claim_id": "ak:mls_keypackage:t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ssk_generation": 3,
            "expires_at": "2100-01-01T00:00:00Z",
            "device_signature": {"kid": "did:webvh:z6mkfixture:alice.example#device", "sig": "c2ln"},
            "unexpected": true
        }]
    });
    assert!(serde_json::from_value::<KeyPackagesClaimOutcome>(malformed_claim).is_err());

    let malformed_failure = json!({
        "claims": [],
        "failures": [{
            "reason_code": "not_found",
            "unexpected": true
        }]
    });
    assert!(serde_json::from_value::<KeyPackagesClaimOutcome>(malformed_failure).is_err());
}

#[test]
fn events_subscribe_frame_parses_ndjson_line() {
    let line = r#"{"cursor":"ak:cursor:resume","kind":"event","payload":{"event_id":"ak:event:01904100-0000-7000-8000-834e21b98552"},"realm_id":"ak:realm:01904100-0000-7000-8000-9b64700c6ee8"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line)
        .unwrap()
        .unwrap();

    assert_eq!(frame.kind, EventsSubscribeFrameKind::Event);
    assert_eq!(
        frame.realm_id.as_ref().unwrap().as_str(),
        "ak:realm:01904100-0000-7000-8000-9b64700c6ee8"
    );
    assert_eq!(frame.cursor.as_ref().unwrap().as_str(), "ak:cursor:resume");
    assert_eq!(
        frame.payload["event_id"],
        "ak:event:01904100-0000-7000-8000-834e21b98552"
    );
    assert!(frame.is_event());
    assert!(!frame.requires_resubscribe());
    assert!(!frame.is_catchup_complete());
}

#[test]
fn events_subscribe_frame_control_helpers() {
    let dropped =
        EventsSubscribeFrame::from_ndjson_line(
            r#"{"cursor":"ak:cursor:resume","kind":"dropped","realm_id":"ak:realm:01904100-0000-7000-8000-9b64700c6ee8","reconnect_after_ms":10000}"#,
        )
        .unwrap()
        .unwrap();
    assert_eq!(dropped.kind, EventsSubscribeFrameKind::Dropped);
    assert_eq!(dropped.reconnect_after_ms, Some(10_000));
    assert!(dropped.requires_resubscribe());

    let catchup = EventsSubscribeFrame::from_ndjson_line(
        r#"{"cursor":"ak:cursor:live","kind":"catchup_complete"}"#,
    )
    .unwrap()
    .unwrap();
    assert!(catchup.is_catchup_complete());

    assert!(
        EventsSubscribeFrame::from_ndjson_line("")
            .unwrap()
            .is_none()
    );
    assert!(
        EventsSubscribeFrame::from_ndjson_line(r#"{"kind":"heartbeat","kind":"heartbeat"}"#)
            .is_err()
    );
}

#[test]
fn events_query_outcome_serializes_has_more_even_when_false() {
    let body = EventsQueryOutcome {
        events: Vec::new(),
        snapshot_bootstrap: None,
        next_cursor: None,
        prev_cursor: None,
        has_more: false,
        range_completeness: Value::Null,
    };

    let value = serde_json::to_value(&body).unwrap();
    assert_eq!(value["events"], json!([]));
    assert_eq!(value["has_more"], json!(false));
    assert!(value.get("next_cursor").is_none());
}

#[test]
fn events_query_params_helpers_use_core_wire_types() {
    let params = EventsQueryParams {
        realms: vec![RealmId::new("ak:realm:01904100-0000-7000-8000-f949e0272316").unwrap()],
        actors: vec![did("alice")],
        before: Some(identifiers::Cursor::new("ak:cursor:older").unwrap()),
        after: Some(identifiers::Cursor::new("ak:cursor:newer").unwrap()),
        order: Some(EventsQueryOrder::Descending),
        limit: Some(50),
        x_arkret_request_id: None,
        traceparent: None,
    };

    params.validate_non_empty().unwrap();
    let pairs = params.to_query_pairs();
    assert!(
        pairs.iter().any(|(key, value)| *key == "realms"
            && value == "ak:realm:01904100-0000-7000-8000-f949e0272316")
    );
    assert!(
        pairs
            .iter()
            .any(|(key, value)| *key == "actors" && value == "did:webvh:z6mkfixture:alice.example")
    );
    assert!(
        pairs
            .iter()
            .any(|(key, value)| *key == "order" && value == "descending")
    );
    assert!(
        pairs
            .iter()
            .any(|(key, value)| *key == "limit" && value == "50")
    );
}
