use arkret_models_collaboration::http_bodies::{
    EventReadRow, EventRedactionReason, EventView, EventsQueryOutcome, EventsSubscribeFrame,
    EventsSubscribeFrameKind, MimiRoomUpdateRequestBody, MimiSubmitMessageRequestBody,
    ReferenceLockedReasonCode,
};
use arkret_models_collaboration::objects::mimi::{
    MimiCiphertext, MimiOpaquePayload, MimiRoomUpdate,
};
use arkret_models_collaboration::session_grant_bodies::SessionLoginOutcome;
use arkret_wire::{
    Base64UrlString, DeviceId, DidCoreId, EventKind, Hash, MlsGroupId, NonEmptyString,
};
use serde_json::json;

fn did(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{name}")).unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
}

#[test]
fn mimi_room_update_wire_uses_sender_actor_id_only() {
    let actor = did("alice");
    let body = MimiRoomUpdateRequestBody {
        mls_group_id: MlsGroupId::new("group-1").unwrap(),
        update: MimiRoomUpdate {
            kind: NonEmptyString::new("room_update").unwrap(),
            payload: MimiOpaquePayload {
                content_type: NonEmptyString::new("application/arkret").unwrap(),
                payload_digest: Hash::new(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                payload: None,
            },
        },
        epoch: Some(7),
        confirmed_transcript_hash: Some(
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        ),
        sender_actor_id: Some(actor.clone()),
        room_binding_event: None,
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
        ciphertext: MimiCiphertext {
            content_type: NonEmptyString::new("application/arkret").unwrap(),
            ciphertext_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            payload: Base64UrlString::new("AA").unwrap(),
        },
        mls_group_id: Some(MlsGroupId::new("group-1").unwrap()),
        epoch: Some(7),
        associated_data: None,
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
fn events_subscribe_frame_parses_ndjson_line() {
    let line = r#"{"cursor":"ak:cursor:resume","kind":"event","payload":{"event_id":"ak:event:AUqXOT9Lj7xeL7HUnhfi7zyJzW1Z59QIVz7exmpHN2N6"},"realm_id":"ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line)
        .unwrap()
        .unwrap();

    assert_eq!(frame.kind, EventsSubscribeFrameKind::Event);
    assert_eq!(
        frame.realm_id.as_ref().unwrap().as_str(),
        "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs"
    );
    assert_eq!(frame.cursor.as_ref().unwrap().as_str(), "ak:cursor:resume");
    assert_eq!(
        frame.payload.as_ref().unwrap()["event_id"],
        "ak:event:AUqXOT9Lj7xeL7HUnhfi7zyJzW1Z59QIVz7exmpHN2N6"
    );
    assert!(!frame.requires_resubscribe());
    assert!(!frame.is_catchup_complete());
}

#[test]
fn events_subscribe_frame_control_helpers() {
    let dropped = EventsSubscribeFrame::from_ndjson_line(
        r#"{"cursor":"ak:cursor:resume","kind":"dropped","realm_id":"ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs","reconnect_after_ms":10000}"#,
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
        range_completeness: None,
    };

    let value = serde_json::to_value(&body).unwrap();
    assert_eq!(value["events"], json!([]));
    assert_eq!(value["has_more"], json!(false));
    assert!(value.get("next_cursor").is_none());

    assert!(
        serde_json::from_value::<EventsQueryOutcome>(json!({"has_more": false})).is_err(),
        "events is a required result-page field"
    );
}

#[test]
fn event_read_row_deserializes_closed_projection_variants() {
    let redacted: EventReadRow = serde_json::from_value(json!({
        "view_kind": "redacted_event_view",
        "event_id": "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq",
        "kind": EventKind::MessageCreate.as_str(),
        "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "created_at": "2026-08-09T00:00:00.000Z",
        "payload_digest": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "redaction_reason": "policy_hidden",
        "hidden_fields": ["payload.body", "proofs"],
        "inclusion_proof": {"root": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        "reducer_input": false
    }))
    .unwrap();
    let EventReadRow::Redacted(view) = redacted else {
        panic!("expected redacted event view");
    };
    assert_eq!(view.redaction_reason, EventRedactionReason::PolicyHidden);
    assert_eq!(view.hidden_fields.as_slice()[0].as_str(), "payload.body");

    let locked: EventReadRow = serde_json::from_value(json!({
        "view_kind": "reference_locked_event_stub",
        "status": "locked",
        "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "reason_code": "not_found_or_unauthorized",
        "reducer_input": false
    }))
    .unwrap();
    let EventReadRow::ReferenceLocked(stub) = locked else {
        panic!("expected reference-locked event stub");
    };
    assert_eq!(
        stub.reason_code,
        ReferenceLockedReasonCode::NotFoundOrUnauthorized
    );
    assert!(stub.event_id.is_none());
}

#[test]
fn event_read_row_rejects_non_closed_projection_shapes() {
    let duplicate_hidden_fields = json!({
        "view_kind": "redacted_event_view",
        "event_id": "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq",
        "kind": EventKind::MessageCreate.as_str(),
        "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "redaction_reason": "redacted",
        "hidden_fields": ["payload", "payload"],
        "reducer_input": false
    });
    assert!(serde_json::from_value::<EventReadRow>(duplicate_hidden_fields).is_err());

    let reducer_input = json!({
        "view_kind": "reference_locked_event_stub",
        "status": "locked",
        "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "reason_code": "reference_locked",
        "reducer_input": true
    });
    assert!(serde_json::from_value::<EventReadRow>(reducer_input).is_err());
}

#[test]
fn event_view_uses_the_same_closed_event_read_row_union() {
    let view: EventView = serde_json::from_value(json!({
        "event": {
            "view_kind": "reference_locked_event_stub",
            "status": "locked",
            "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "reason_code": "history_not_visible",
            "reducer_input": false
        },
        "visibility": {"history_access": "since_join"},
        "receipts": []
    }))
    .unwrap();
    assert!(matches!(view.event, EventReadRow::ReferenceLocked(_)));
}

#[test]
fn session_login_outcome_uses_typed_wire_fields() {
    let value = json!({
        "session_credential": "sx_token",
        "token_type": "Bearer",
        "actor": "ak:did_core:webvh:z6mkfixture",
        "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
        "expires_at": "2026-04-28T12:00:00.000Z"
    });
    let outcome: SessionLoginOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(outcome.actor.as_str(), "ak:did_core:webvh:z6mkfixture");
    assert_eq!(
        outcome.device_id.as_str(),
        "ak:device:01964137-0000-7000-8000-000000000001"
    );

    let serialized = serde_json::to_value(outcome).unwrap();
    assert_eq!(serialized["token_type"], "Bearer");
    assert_eq!(serialized["actor"], "ak:did_core:webvh:z6mkfixture");
    assert_eq!(
        serialized["device_id"],
        "ak:device:01964137-0000-7000-8000-000000000001"
    );
}
