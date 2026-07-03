use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::sync::{PresenceStatus, SyncRealm, UnreadCounts};
use crate::{Did, RealmId};

fn sync_response(cursor: &str) -> SyncOutcome {
    SyncOutcome {
        cursor: cursor.to_owned(),
        realms: BTreeMap::new(),
        left_realms: Vec::new(),
        to_device: Vec::new(),
        to_device_ack_token: None,
        to_device_limited: false,
        to_device_next_cursor: None,
        to_device_lost: None,
        device_lists: Value::Null,
        account_data: Vec::new(),
        presence: Vec::new(),
        notifications: Value::Null,
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
    let mut transport = |request: SyncRequestBody| {
        calls += 1;
        if calls == 1 {
            assert_eq!(request.catchup, Some(true));
            Err(Error::Protocol("network down".to_owned()))
        } else {
            assert!(request.after.is_none());
            assert_eq!(request.catchup, Some(true));
            Ok(sync_response("s1"))
        }
    };
    let mut sync_loop = SyncLoop::new();

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Retry { .. }
    ));
    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Updates(_)
    ));
    assert_eq!(sync_loop.token(), Some("s1"));
}

#[test]
fn sync_loop_exposes_to_device_loss_recovery_actions() {
    let mut transport = |_request: SyncRequestBody| {
        let mut response = sync_response("loss1");
        response.to_device_lost = Some(true);
        Ok(response)
    };
    let mut sync_loop = SyncLoop::new();

    match sync_loop.step(&mut transport) {
        SyncLoopStep::Updates(updates) => assert!(updates.to_device_lost),
        other => panic!("expected sync updates, got {other:?}"),
    }
    let expected = vec![
        SyncRecoveryAction::RefetchDeviceLists,
        SyncRecoveryAction::RequestMissingMlsMaterial,
        SyncRecoveryAction::RestoreFromKeyBackup,
    ];
    assert_eq!(sync_loop.recovery_actions(), expected);
    assert_eq!(sync_loop.take_recovery_actions(), expected);
    assert!(sync_loop.recovery_actions().is_empty());
}

#[tokio::test]
async fn async_sync_loop_uses_transport_and_persists_token() {
    let transport = |request: SyncRequestBody| async move {
        assert_eq!(request.catchup, Some(true));
        assert!(request.after.is_none());
        Ok(sync_response("async1"))
    };
    let mut sync_loop = SyncLoop::new().with_timeout(Duration::from_millis(15));

    assert!(matches!(
        sync_loop.step_async(&transport).await,
        SyncLoopStep::Updates(_)
    ));
    let snapshot = sync_loop.snapshot();
    assert_eq!(snapshot.token.as_deref(), Some("async1"));

    let restored = SyncLoop::from_snapshot(snapshot);
    assert_eq!(restored.next_request().after.as_deref(), Some("async1"));
}

#[tokio::test]
async fn async_sync_loop_honors_cancellation() {
    let transport = |_request: SyncRequestBody| async { Ok(sync_response("unused")) };
    let control = SyncLoopControl::new();
    control.cancel();

    let mut sync_loop = SyncLoop::new();

    assert!(matches!(
        sync_loop
            .step_async_with_control(&transport, &control)
            .await,
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
    assert_eq!(
        control.backpressure_retry_after(),
        Duration::from_millis(25)
    );

    drop(permit);
    assert!(control.try_acquire().is_some());
}

#[test]
fn sync_loop_can_reset_token_on_limited_timeline_gap() {
    let realm_id = "ck:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let mut response = sync_response("gap-token");
    let sync_realm = SyncRealm {
        timeline: Some(SyncTimeline {
            events: Vec::new(),
            limited: true,
            prev_cursor: Some("prev".to_owned()),
        }),
        state: Vec::new(),
        summary: json!({}),
        ephemeral: Vec::new(),
        unread: UnreadCounts::default(),
        ..Default::default()
    };
    response.realms.insert(
        realm_id.to_owned(),
        serde_json::to_value(sync_realm).unwrap(),
    );
    let mut transport = |_request: SyncRequestBody| Ok(response.clone());
    let mut sync_loop =
        SyncLoop::new().with_gap_strategy(SyncGapStrategy::ResetTokenOnLimitedTimeline);

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Updates(_)
    ));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_includes_wait_for_frontier() {
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let wait_for = WaitForFrontier {
        positions: vec![crate::sync::SyncStreamPosition {
            realm_id,
            frontier: Vec::new(),
            timeline_order: crate::Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            state_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        }],
        timeout_ms: 5000,
    };

    let request = SyncLoop::new()
        .with_wait_for(wait_for.clone())
        .next_request();

    assert_eq!(request.wait_for, Some(wait_for));
}

#[test]
fn processor_dispatches_all_update_categories() {
    let realm_id = "ck:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let mut response = sync_response("s2");
    let sync_realm = SyncRealm {
        timeline: None,
        state: vec![json!({"kind":"state"})],
        summary: json!({"name":"realm"}),
        ephemeral: Vec::new(),
        unread: UnreadCounts {
            notification_count: 3,
            highlight_count: 1,
        },
        ..Default::default()
    };
    response.realms.insert(
        realm_id.to_owned(),
        serde_json::to_value(sync_realm).unwrap(),
    );
    response.to_device.push(
        serde_json::to_value(ToDeviceMessage {
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
        })
        .unwrap(),
    );
    response.to_device_lost = Some(true);
    response.device_lists = json!({"changed": ["did:web:alice.example"], "left": []});
    response.presence.push(
        serde_json::to_value(PresenceEvent {
            user_id: "did:web:alice.example".to_owned(),
            presence: PresenceStatus::Online,
            last_active_at: None,
            status_message: None,
            device_id: None,
        })
        .unwrap(),
    );
    response.account_data.push(
        serde_json::to_value(AccountData {
            data_type: "ck.settings".to_owned(),
            content: json!({"theme":"light"}),
        })
        .unwrap(),
    );
    response.notifications = json!({
        "events": [
            serde_json::to_value(NotificationDelta {
                id: "n1".to_owned(),
                notification_type: "mention".to_owned(),
                action: "add".to_owned(),
                data: None,
            }).unwrap()
        ]
    });

    let mut processor = SyncResponseProcessor::new();
    let updates = processor.process(response).unwrap();
    let parsed_realm_id = RealmId::new(realm_id).unwrap();

    assert_eq!(updates.realm_updates.len(), 1);
    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .unwrap()
            .notification_count,
        3
    );
    assert_eq!(processor.drain_to_device().len(), 1);
    assert!(updates.to_device_lost);
    let expected_recovery_actions = vec![
        SyncRecoveryAction::RefetchDeviceLists,
        SyncRecoveryAction::RequestMissingMlsMaterial,
        SyncRecoveryAction::RestoreFromKeyBackup,
    ];
    assert_eq!(processor.recovery_actions(), expected_recovery_actions);
    assert_eq!(processor.take_recovery_actions(), expected_recovery_actions);
    assert!(processor.recovery_actions().is_empty());
    assert!(processor.presence("did:web:alice.example").is_some());
    assert!(processor.account_data("ck.settings").is_some());
    assert!(processor.notification("n1").is_some());
    assert_eq!(processor.device_lists().changed.len(), 1);
}

#[test]
fn processor_tracks_limited_timelines_and_to_device_ack() {
    let realm_id = "ck:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let parsed_realm_id = RealmId::new(realm_id).unwrap();
    let event = Event::new(
        "ck.message.create",
        parsed_realm_id.clone(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        crate::Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
        json!({"body":"hello"}),
    )
    .unwrap();
    let mut response = sync_response("s3");
    let sync_realm = SyncRealm {
        timeline: Some(SyncTimeline {
            events: vec![serde_json::to_value(event).unwrap()],
            limited: true,
            prev_cursor: Some("prev".to_owned()),
        }),
        state: Vec::new(),
        summary: json!({}),
        ephemeral: Vec::new(),
        unread: UnreadCounts::default(),
        ..Default::default()
    };
    response.realms.insert(
        realm_id.to_owned(),
        serde_json::to_value(sync_realm).unwrap(),
    );

    let mut processor = SyncResponseProcessor::new();
    processor.process(response).unwrap();
    let ack = processor.acknowledge_to_device(
        "devmsg1",
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000005").unwrap(),
        ToDeviceAckStatus::Processed,
    );

    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .unwrap()
            .limited_timeline_count,
        1
    );
    assert_eq!(processor.limited_timelines().len(), 1);
    assert_eq!(processor.to_device_ack("devmsg1"), Some(&ack));
}

#[test]
fn send_queue_is_idempotent_orders_dependencies_and_snapshots() {
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let mut queue = SendQueue::new();
    let message = queue
        .enqueue_message(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    let duplicate = queue
        .enqueue_message(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    let edit = queue
        .enqueue_edit(
            Some("txn2".to_owned()),
            realm_id,
            EventId::new("ck:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
            json!({"content":{"body":"hi"}}),
            vec!["txn1".to_owned()],
        )
        .unwrap();

    assert_eq!(message.payload_digest, duplicate.payload_digest);
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![message]);

    queue.mark_sending("txn1").unwrap();
    queue
        .mark_sent(
            "txn1",
            EventId::new("ck:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
        )
        .unwrap();
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![edit]);

    let restored = SendQueue::from_snapshot(queue.snapshot()).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.get("txn1").unwrap().status, SendQueueStatus::Sent);
}

#[test]
fn send_queue_cancels_dependent_edit_redaction_and_reaction() {
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let event_id = EventId::new("ck:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_message(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    queue
        .enqueue_redaction(
            Some("txn2".to_owned()),
            realm_id.clone(),
            event_id.clone(),
            None,
            vec!["txn1".to_owned()],
        )
        .unwrap();
    queue
        .enqueue_reaction(
            Some("txn3".to_owned()),
            realm_id,
            event_id,
            "+1".to_owned(),
            true,
            vec!["txn2".to_owned()],
        )
        .unwrap();

    queue.cancel("txn1", true).unwrap();

    assert_eq!(
        queue.get("txn1").unwrap().status,
        SendQueueStatus::Cancelled
    );
    assert_eq!(
        queue.get("txn2").unwrap().status,
        SendQueueStatus::Cancelled
    );
    assert_eq!(
        queue.get("txn3").unwrap().status,
        SendQueueStatus::Cancelled
    );
}

#[test]
fn sliding_sync_builds_windowed_subscriptions_and_applies_deltas() {
    let s1 = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let s2 = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000002").unwrap();
    let s3 = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000003").unwrap();
    let s4 = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000004").unwrap();

    let mut sliding = SlidingSync::new();
    sliding.set_realm_list(vec![s1.clone(), s2.clone(), s3]);
    sliding.set_windows(vec![SlidingWindow::new(0, 2).unwrap()]);
    sliding.apply_delta(&[s1], vec![(1, s4.clone())]);

    let config = sliding.subscription_config();

    assert_eq!(config.subscriptions.len(), 2);
    assert_eq!(config.subscriptions[0].realm_id, s2);
    assert_eq!(config.subscriptions[1].realm_id, s4);
    assert!(sliding.is_subscribed(&s4));
}

#[test]
fn realm_list_sorts_filters_and_reports_incremental_changes() {
    let s1 = RealmId::new("ck:realm:01904100-0000-7000-8000-f949e0272316").unwrap();
    let s2 = RealmId::new("ck:realm:01904100-0000-7000-8000-46f8537dc94e").unwrap();
    let mut list = RealmListService::new();
    let mut alpha = RealmListEntry::joined(s1);
    alpha.name = Some("Alpha".to_owned());
    alpha.unread_count = 1;
    let mut beta = RealmListEntry::joined(s2.clone());
    beta.name = Some("Beta".to_owned());
    beta.favorite = true;
    beta.unread_count = 5;

    let first = list.upsert(alpha);
    let second = list.upsert(beta);
    let sorted = list.set_sort(RealmListSort::Unread);
    let filtered = list.set_filter(RealmListFilter {
        unread_only: true,
        ..RealmListFilter::default()
    });

    assert!(matches!(first.changes[0], RealmListChange::Inserted { .. }));
    assert!(
        second
            .changes
            .iter()
            .any(|change| matches!(change, RealmListChange::Inserted { .. }))
    );
    assert_eq!(sorted.ordered[0], s2);
    assert_eq!(filtered.ordered.len(), 2);

    let snapshot = list.snapshot();
    let restored = RealmListService::from_snapshot(snapshot);
    assert_eq!(restored.entries().len(), 2);
    assert_eq!(restored.entries()[0].realm_id, s2);
}
