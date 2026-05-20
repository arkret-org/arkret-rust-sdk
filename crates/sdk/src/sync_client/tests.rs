use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::Did;
use crate::sync::{DeviceListChanges, SyncSpace, UnreadCounts};

fn sync_response(cursor: &str) -> SyncResBody {
    SyncResBody {
        cursor: cursor.to_owned(),
        spaces: BTreeMap::new(),
        to_device: Vec::new(),
        device_lists: DeviceListChanges::default(),
        presence: Vec::new(),
        account_data: Vec::new(),
        notifications: Vec::new(),
        partial: false,
    }
}

#[test]
fn backoff_grows_until_capped() {
    let mut backoff = ExponentialBackoff::new(BackoffConfig {
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(250),
        multiplier: 2,
    });

    assert_eq!(backoff.record_failure(), Duration::from_millis(100));
    assert_eq!(backoff.record_failure(), Duration::from_millis(200));
    assert_eq!(backoff.record_failure(), Duration::from_millis(250));
    backoff.reset();
    assert_eq!(backoff.current_delay(), Duration::ZERO);
}

#[test]
fn sync_loop_recovers_after_failure() {
    let mut calls = 0;
    let mut transport = |request: SyncReqBody| {
        calls += 1;
        if calls == 1 {
            assert_eq!(request.timeout_ms, Some(30_000));
            Err(Error::Protocol("network down".to_owned()))
        } else {
            assert!(request.since.is_none());
            Ok(sync_response("s1"))
        }
    };
    let mut sync_loop = SyncLoop::new();

    assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Retry { .. }));
    assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Updates(_)));
    assert_eq!(sync_loop.token(), Some("s1"));
}

#[tokio::test]
async fn async_sync_loop_uses_transport_and_persists_token() {
    let transport = |request: SyncReqBody| async move {
        assert_eq!(request.timeout_ms, Some(15));
        assert!(request.since.is_none());
        Ok(sync_response("async1"))
    };
    let mut sync_loop = SyncLoop::new().with_timeout(Duration::from_millis(15));

    assert!(matches!(sync_loop.step_async(&transport).await, SyncLoopStep::Updates(_)));
    let snapshot = sync_loop.snapshot();
    assert_eq!(snapshot.token.as_deref(), Some("async1"));

    let restored = SyncLoop::from_snapshot(snapshot);
    assert_eq!(restored.next_request().since.as_deref(), Some("async1"));
}

#[tokio::test]
async fn async_sync_loop_honors_cancellation() {
    let transport = |_request: SyncReqBody| async { Ok(sync_response("unused")) };
    let control = SyncLoopControl::new();
    control.cancel();

    let mut sync_loop = SyncLoop::new();

    assert!(matches!(
        sync_loop.step_async_with_control(&transport, &control).await,
        SyncLoopStep::Cancelled
    ));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_control_applies_backpressure() {
    let control = SyncLoopControl::new().with_backpressure(BackpressureConfig {
        max_in_flight_requests: 1,
        retry_after: Duration::from_millis(25),
    });
    let permit = control.try_acquire().unwrap();

    assert!(control.try_acquire().is_none());
    assert_eq!(control.backpressure_retry_after(), Duration::from_millis(25));

    drop(permit);
    assert!(control.try_acquire().is_some());
}

#[test]
fn sync_loop_can_reset_token_on_limited_timeline_gap() {
    let space_id = "cx:space:01904100-0000-7000-8000-9b64700c6ee8";
    let mut response = sync_response("gap-token");
    response.spaces.insert(
        space_id.to_owned(),
        SyncSpace {
            timeline: Some(SyncTimeline {
                events: Vec::new(),
                limited: true,
                prev_batch: Some("prev".to_owned()),
            }),
            state: Vec::new(),
            summary: json!({}),
            ephemeral: Vec::new(),
            unread: UnreadCounts::default(),
        },
    );
    let mut transport = |_request: SyncReqBody| Ok(response.clone());
    let mut sync_loop =
        SyncLoop::new().with_gap_strategy(SyncGapStrategy::ResetTokenOnLimitedTimeline);

    assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Updates(_)));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_includes_wait_for_frontier() {
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let wait_for = WaitForFrontier {
        positions: vec![crate::sync::SyncStreamPosition {
            space_id,
            frontier: Vec::new(),
            timeline_order: crate::Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
            state_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        }],
        timeout_ms: 5000,
    };

    let request = SyncLoop::new().with_wait_for(wait_for.clone()).next_request();

    assert_eq!(request.wait_for, Some(wait_for));
}

#[test]
fn processor_dispatches_all_update_categories() {
    let space_id = "cx:space:01904100-0000-7000-8000-9b64700c6ee8";
    let mut response = sync_response("s2");
    response.spaces.insert(
        space_id.to_owned(),
        SyncSpace {
            timeline: None,
            state: vec![json!({"kind":"state"})],
            summary: json!({"name":"space"}),
            ephemeral: Vec::new(),
            unread: UnreadCounts { notification_count: 3, highlight_count: 1 },
        },
    );
    response.to_device.push(ToDeviceMessage {
        message_type: "m.test".to_owned(),
        content: json!({"ok":true}),
        sender_principal_id: None,
        sender_device_id: None,
        recipient_principal_id: None,
        recipient_device_id: None,
        sent_at: None,
        expires_at: None,
        device_proof: None,
        unsigned: None,
    });
    response.device_lists.changed.push("did:web:alice.example".to_owned());
    response.presence.push(PresenceEvent {
        user_id: "did:web:alice.example".to_owned(),
        presence: PresenceStatus::Online,
        last_active: None,
        device_id: None,
    });
    response.account_data.push(AccountData {
        data_type: "cx.settings".to_owned(),
        content: json!({"theme":"light"}),
    });
    response.notifications.push(NotificationDelta {
        id: "n1".to_owned(),
        notification_type: "mention".to_owned(),
        action: "add".to_owned(),
        data: None,
    });

    let mut processor = SyncResponseProcessor::new();
    let updates = processor.process(response).unwrap();
    let parsed_space_id = SpaceId::new(space_id).unwrap();

    assert_eq!(updates.space_updates.len(), 1);
    assert_eq!(processor.space(&parsed_space_id).unwrap().notification_count, 3);
    assert_eq!(processor.drain_to_device().len(), 1);
    assert!(processor.presence("did:web:alice.example").is_some());
    assert!(processor.account_data("cx.settings").is_some());
    assert!(processor.notification("n1").is_some());
    assert_eq!(processor.device_lists().changed.len(), 1);
}

#[test]
fn processor_tracks_limited_timelines_and_to_device_ack() {
    let space_id = "cx:space:01904100-0000-7000-8000-9b64700c6ee8";
    let parsed_space_id = SpaceId::new(space_id).unwrap();
    let event = Event::new(
        "cx.message.create",
        parsed_space_id.clone(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        crate::Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
        json!({"body":"hello"}),
    )
    .unwrap();
    let mut response = sync_response("s3");
    response.spaces.insert(
        space_id.to_owned(),
        SyncSpace {
            timeline: Some(SyncTimeline {
                events: vec![serde_json::to_value(event).unwrap()],
                limited: true,
                prev_batch: Some("prev".to_owned()),
            }),
            state: Vec::new(),
            summary: json!({}),
            ephemeral: Vec::new(),
            unread: UnreadCounts::default(),
        },
    );

    let mut processor = SyncResponseProcessor::new();
    processor.process(response).unwrap();
    let ack = processor.acknowledge_to_device(
        "devmsg1",
        DeviceId::new("cx:device:01904100-0000-7000-8000-000000000005").unwrap(),
        ToDeviceAckStatus::Processed,
    );

    assert_eq!(processor.space(&parsed_space_id).unwrap().limited_timeline_count, 1);
    assert_eq!(processor.limited_timelines().len(), 1);
    assert_eq!(processor.to_device_ack("devmsg1"), Some(&ack));
}

#[test]
fn send_queue_is_idempotent_orders_dependencies_and_snapshots() {
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let mut queue = SendQueue::new();
    let message = queue
        .enqueue_message(Some("txn1".to_owned()), space_id.clone(), json!({"body":"hello"}))
        .unwrap();
    let duplicate = queue
        .enqueue_message(Some("txn1".to_owned()), space_id.clone(), json!({"body":"hello"}))
        .unwrap();
    let edit = queue
        .enqueue_edit(
            Some("txn2".to_owned()),
            space_id,
            EventId::new("cx:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
            json!({"content":{"body":"hi"}}),
            vec!["txn1".to_owned()],
        )
        .unwrap();

    assert_eq!(message.payload_hash, duplicate.payload_hash);
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![message]);

    queue.mark_sending("txn1").unwrap();
    queue
        .mark_sent("txn1", EventId::new("cx:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap())
        .unwrap();
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![edit]);

    let restored = SendQueue::from_snapshot(queue.snapshot()).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.get("txn1").unwrap().status, SendQueueStatus::Sent);
}

#[test]
fn send_queue_cancels_dependent_edit_redaction_and_reaction() {
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let event_id = EventId::new("cx:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_message(Some("txn1".to_owned()), space_id.clone(), json!({"body":"hello"}))
        .unwrap();
    queue
        .enqueue_redaction(
            Some("txn2".to_owned()),
            space_id.clone(),
            event_id.clone(),
            None,
            vec!["txn1".to_owned()],
        )
        .unwrap();
    queue
        .enqueue_reaction(
            Some("txn3".to_owned()),
            space_id,
            event_id,
            "+1".to_owned(),
            true,
            vec!["txn2".to_owned()],
        )
        .unwrap();

    queue.cancel("txn1", true).unwrap();

    assert_eq!(queue.get("txn1").unwrap().status, SendQueueStatus::Cancelled);
    assert_eq!(queue.get("txn2").unwrap().status, SendQueueStatus::Cancelled);
    assert_eq!(queue.get("txn3").unwrap().status, SendQueueStatus::Cancelled);
}

#[test]
fn sliding_sync_builds_windowed_subscriptions_and_applies_deltas() {
    let s1 = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000001").unwrap();
    let s2 = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000002").unwrap();
    let s3 = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000003").unwrap();
    let s4 = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000004").unwrap();

    let mut sliding = SlidingSync::new();
    sliding.set_space_list(vec![s1.clone(), s2.clone(), s3]);
    sliding.set_windows(vec![SlidingWindow::new(0, 2).unwrap()]);
    sliding.apply_delta(&[s1], vec![(1, s4.clone())]);

    let config = sliding.subscription_config();

    assert_eq!(config.subscriptions.len(), 2);
    assert_eq!(config.subscriptions[0].space_id, s2);
    assert_eq!(config.subscriptions[1].space_id, s4);
    assert!(sliding.is_subscribed(&s4));
}

#[test]
fn space_list_sorts_filters_and_reports_incremental_changes() {
    let s1 = SpaceId::new("cx:space:01904100-0000-7000-8000-f949e0272316").unwrap();
    let s2 = SpaceId::new("cx:space:01904100-0000-7000-8000-46f8537dc94e").unwrap();
    let mut list = SpaceListService::new();
    let mut alpha = SpaceListEntry::joined(s1);
    alpha.name = Some("Alpha".to_owned());
    alpha.unread_count = 1;
    let mut beta = SpaceListEntry::joined(s2.clone());
    beta.name = Some("Beta".to_owned());
    beta.favorite = true;
    beta.unread_count = 5;

    let first = list.upsert(alpha);
    let second = list.upsert(beta);
    let sorted = list.set_sort(SpaceListSort::Unread);
    let filtered =
        list.set_filter(SpaceListFilter { unread_only: true, ..SpaceListFilter::default() });

    assert!(matches!(first.changes[0], SpaceListChange::Inserted { .. }));
    assert!(second.changes.iter().any(|change| matches!(change, SpaceListChange::Inserted { .. })));
    assert_eq!(sorted.ordered[0], s2);
    assert_eq!(filtered.ordered.len(), 2);

    let snapshot = list.snapshot();
    let restored = SpaceListService::from_snapshot(snapshot);
    assert_eq!(restored.entries().len(), 2);
    assert_eq!(restored.entries()[0].space_id, s2);
}

// ─── C17 typed EventsSubscribeFrame tests ─────────────────────────────

#[test]
fn frame_event_round_trip() {
    let line = r#"{"kind":"event","seq":42,"cursor":"sx:e2e:42","payload":{"event_id":"cx:event:01904100-0000-7000-8000-834e21b98552"}}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    match &frame {
        EventsSubscribeFrame::Event { seq, cursor, payload } => {
            assert_eq!(*seq, 42);
            assert_eq!(cursor, "sx:e2e:42");
            assert_eq!(payload["event_id"], "cx:event:01904100-0000-7000-8000-834e21b98552");
        }
        other => panic!("expected Event, got {other:?}"),
    }
    assert!(frame.is_event());
    assert!(!frame.requires_resubscribe());
    assert!(!frame.is_catchup_complete());
}

#[test]
fn frame_dropped_requires_resubscribe() {
    let line = r#"{"kind":"dropped","recovery_from":"sx:resume:9","reason":"buffer overflow"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    assert!(frame.requires_resubscribe());
    assert!(matches!(
        &frame,
        EventsSubscribeFrame::Dropped { recovery_from: Some(rf), .. } if rf == "sx:resume:9"
    ));
}

#[test]
fn frame_resync_required_carries_frontier() {
    let line = r#"{"kind":"resync_required","last_frontier":["sx:f1","sx:f2"]}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    assert!(frame.requires_resubscribe());
    match &frame {
        EventsSubscribeFrame::ResyncRequired { last_frontier, reason } => {
            assert_eq!(last_frontier, &["sx:f1".to_owned(), "sx:f2".to_owned()]);
            assert!(reason.is_none());
        }
        other => panic!("expected ResyncRequired, got {other:?}"),
    }
}

#[test]
fn frame_epoch_rotation_parses_space_and_epoch() {
    let line = r#"{"kind":"epoch_rotation","space_id":"cx:space:01904100-0000-7000-8000-9b64700c6ee8","new_epoch":7,"previous_epoch":6}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    match &frame {
        EventsSubscribeFrame::EpochRotation { space_id, new_epoch, previous_epoch } => {
            assert_eq!(space_id.as_str(), "cx:space:01904100-0000-7000-8000-9b64700c6ee8");
            assert_eq!(*new_epoch, 7);
            assert_eq!(*previous_epoch, Some(6));
        }
        other => panic!("expected EpochRotation, got {other:?}"),
    }
}

#[test]
fn frame_catchup_complete_signals_live_handover() {
    let line = r#"{"kind":"catchup_complete","cursor":"sx:live:0"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    assert!(frame.is_catchup_complete());
    assert!(!frame.requires_resubscribe());
}

#[test]
fn frame_heartbeat_minimal() {
    let line = r#"{"kind":"heartbeat"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    assert!(matches!(frame, EventsSubscribeFrame::Heartbeat { .. }));
}

#[test]
fn frame_unknown_kind_falls_back() {
    // Future spec additions land here; clients log + continue rather
    // than treat the unknown frame as an event.
    let line = r#"{"kind":"future_kind_42","extra":"data"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    assert!(matches!(frame, EventsSubscribeFrame::Unknown));
    assert!(!frame.is_event());
    assert!(!frame.requires_resubscribe());
}

#[test]
fn frame_blank_line_returns_none() {
    assert!(EventsSubscribeFrame::from_ndjson_line("").unwrap().is_none());
    assert!(EventsSubscribeFrame::from_ndjson_line("   \n").unwrap().is_none());
}

#[test]
fn frame_unauthorized_with_actor_only() {
    let line = r#"{"kind":"unauthorized","actor_id":"did:web:alice.example","reason":"revoked"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    match &frame {
        EventsSubscribeFrame::Unauthorized { space_id, actor_id, reason } => {
            assert!(space_id.is_none());
            assert_eq!(actor_id.as_deref(), Some("did:web:alice.example"));
            assert_eq!(reason.as_deref(), Some("revoked"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

// ─── C17 EventsQuerySelector tests ────────────────────────────────────

#[test]
fn events_query_selector_validates_non_empty() {
    let empty = EventsQuerySelector::default();
    assert!(empty.validate_non_empty().is_err());
    let with_space = EventsQuerySelector {
        spaces: vec![SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap()],
        ..Default::default()
    };
    with_space.validate_non_empty().unwrap();
    let with_actor = EventsQuerySelector {
        actors: vec!["did:web:alice.example".to_owned()],
        ..Default::default()
    };
    with_actor.validate_non_empty().unwrap();
}

#[test]
fn events_query_selector_renders_repeated_query_args() {
    let selector = EventsQuerySelector {
        spaces: vec![
            SpaceId::new("cx:space:01904100-0000-7000-8000-f949e0272316").unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-46f8537dc94e").unwrap(),
        ],
        actors: vec!["did:web:alice.example".to_owned()],
        from: Some("sx:cursor:1".to_owned()),
        direction: Some(EventsQueryDirection::Backward),
        limit: Some(50),
        ..Default::default()
    };
    let pairs = selector.to_query_pairs();
    assert_eq!(pairs.iter().filter(|(k, _)| *k == "spaces").count(), 2);
    assert_eq!(pairs.iter().filter(|(k, _)| *k == "actors").count(), 1);
    assert!(pairs.iter().any(|(k, v)| *k == "direction" && v == "backward"));
    assert!(pairs.iter().any(|(k, v)| *k == "limit" && v == "50"));
    assert!(pairs.iter().any(|(k, v)| *k == "from" && v == "sx:cursor:1"));
}

#[test]
fn events_query_direction_serde_round_trip() {
    let forward = serde_json::to_string(&EventsQueryDirection::Forward).unwrap();
    let backward = serde_json::to_string(&EventsQueryDirection::Backward).unwrap();
    assert_eq!(forward, "\"forward\"");
    assert_eq!(backward, "\"backward\"");
    let parsed: EventsQueryDirection = serde_json::from_str("\"backward\"").unwrap();
    assert_eq!(parsed, EventsQueryDirection::Backward);
}

#[test]
fn frame_frontier_advance_round_trip() {
    let line = r#"{"kind":"frontier","cursor":"sx:advance:7"}"#;
    let frame = EventsSubscribeFrame::from_ndjson_line(line).unwrap().unwrap();
    match &frame {
        EventsSubscribeFrame::Frontier { cursor } => assert_eq!(cursor, "sx:advance:7"),
        other => panic!("expected Frontier, got {other:?}"),
    }
    assert!(!frame.is_event());
    assert!(!frame.requires_resubscribe());
}

// ─── EventsQueryReqBody / EventsQueryResBody tests ─────────────

#[test]
fn events_query_request_validates_non_empty() {
    let empty = EventsQueryReqBody::new();
    assert!(empty.validate_non_empty().is_err());
    let with_space = EventsQueryReqBody::new()
        .with_spaces(vec![SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap()]);
    with_space.validate_non_empty().unwrap();
}

#[test]
fn events_query_request_renders_query_pairs() {
    let req = EventsQueryReqBody::new()
        .with_spaces(vec![
            SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-46f8537dc94e").unwrap(),
        ])
        .with_actors(vec!["did:web:alice.example".to_owned()])
        .with_from("hlc:0189c4d2af00-00000000-aabbccdd")
        .with_until("hlc:0189c4d2af01-00000000-aabbccdd")
        .with_direction(EventsQueryDirection::Backward)
        .with_limit(50);
    let pairs = req.to_query_pairs();
    assert_eq!(pairs.iter().filter(|(k, _)| *k == "spaces").count(), 2);
    assert_eq!(pairs.iter().filter(|(k, _)| *k == "actors").count(), 1);
    assert!(pairs.iter().any(|(k, v)| *k == "direction" && v == "backward"));
    assert!(pairs.iter().any(|(k, v)| *k == "limit" && v == "50"));
    assert!(pairs.iter().any(|(k, v)| *k == "until" && v.starts_with("hlc:")));
}

#[test]
fn events_query_response_round_trips_with_sync_backfill() {
    let body = serde_json::json!({
        "events": [],
        "next_cursor": "sx:next:1",
        "prev_cursor": "sx:prev:0",
        "limited": true,
    });
    let resp: EventsQueryResBody = serde_json::from_value(body).unwrap();
    assert_eq!(resp.next_cursor.as_deref(), Some("sx:next:1"));
    assert_eq!(resp.prev_cursor.as_deref(), Some("sx:prev:0"));
    assert!(resp.limited);
    // Round-trip via SyncBackfillResBody keeps cursors and flag.
    let bf: contrix_core::SyncBackfillResBody = resp.clone().into();
    let back: EventsQueryResBody = bf.into();
    assert_eq!(back.next_cursor, resp.next_cursor);
    assert_eq!(back.prev_cursor, resp.prev_cursor);
    assert_eq!(back.limited, resp.limited);
}

#[test]
fn events_query_request_default_direction_is_forward() {
    let req = EventsQueryReqBody::new();
    assert_eq!(req.direction, EventsQueryDirection::Forward);
}
