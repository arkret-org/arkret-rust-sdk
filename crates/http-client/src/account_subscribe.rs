//! Incremental folding for `ak.self.account.stream.subscribe.v1` frames.
//!
//! The frame family and validated batch result types live in
//! `arkret-models-collaboration` (`sync_frames::account_subscribe`,
//! re-exported below). [`AccountSubscribeFolder`] is the client
//! consumption-side state machine over those frames; it lives in this
//! transport crate because it folds them through the client `Error` channel.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
    DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS, MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSyncRoundBudget, StreamTraceValidator, SyncRequestBody,
};

use crate::{Error, Result};

fn clamp_reconnect_after_ms(raw: Option<u64>) -> u64 {
    raw.unwrap_or(DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
        .min(MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
}

pub struct AccountSubscribeFolder {
    frames: Vec<AccountSubscribeFrame>,
    done: Option<AccountSubscribeSnapshotResult>,
    failed: bool,
    trace: StreamTraceValidator,
    round_budget: AccountSyncRoundBudget,
}

impl AccountSubscribeFolder {
    /// Create a folder bound to the exact account-subscribe request context.
    pub fn for_request(request: &SyncRequestBody) -> Self {
        Self {
            frames: Vec::new(),
            done: None,
            failed: false,
            round_budget: Default::default(),
            trace: StreamTraceValidator::new(
                request.catchup.unwrap_or(false),
                request.after.clone(),
            ),
        }
    }

    pub fn push(&mut self, frame: AccountSubscribeFrame) -> Result<bool> {
        if self.failed || self.done.is_some() {
            return Err(Error::Protocol(
                "account subscribe frame arrived after a terminal frame".to_owned(),
            ));
        }
        self.failed = true;
        self.round_budget
            .observe(arkret_canonical::canonical_json_bytes(&frame)?.len())?;
        self.trace.push(&frame)?;
        self.failed = false;
        match frame.kind {
            AccountSubscribeFrameKind::ResyncRequired | AccountSubscribeFrameKind::Unauthorized => {
                self.done = Some(AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms: clamp_reconnect_after_ms(frame.reconnect_after_ms()),
                    reconnect_cursor: self.trace.reconnect_cursor().map(ToOwned::to_owned),
                    reason: None,
                    reset_cursor: frame.kind == AccountSubscribeFrameKind::ResyncRequired,
                });
                return Ok(true);
            }
            AccountSubscribeFrameKind::Dropped => {
                self.done = Some(AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms: clamp_reconnect_after_ms(frame.reconnect_after_ms()),
                    reconnect_cursor: self.trace.reconnect_cursor().map(ToOwned::to_owned),
                    reason: None,
                    reset_cursor: false,
                });
                return Ok(true);
            }
            AccountSubscribeFrameKind::CatchupComplete => return Ok(true),
            _ => {}
        }
        if frame.kind == AccountSubscribeFrameKind::Delta {
            self.frames.push(frame);
        }
        Ok(false)
    }

    pub fn finish(mut self) -> Result<AccountSubscribeSnapshotResult> {
        if self.failed {
            return Err(Error::Protocol(
                "account subscribe folder was rejected".to_owned(),
            ));
        }
        self.trace.finish()?;
        if let Some(done) = self.done {
            return Ok(done);
        }
        let cursor = self
            .trace
            .reconnect_cursor()
            .ok_or_else(|| Error::Protocol("account subscribe batch has no cursor".to_owned()))?
            .to_owned();
        Ok(AccountSubscribeSnapshotResult::Batch(
            AccountSubscribeBatch {
                frames: self.frames,
                cursor,
            },
        ))
    }

    pub fn reconnect_cursor(&self) -> Option<&str> {
        self.trace.reconnect_cursor()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction;
    use serde_json::Value;

    use super::*;

    fn request(catchup: bool, after: Option<&str>) -> SyncRequestBody {
        SyncRequestBody {
            after: after.map(ToOwned::to_owned),
            catchup: Some(catchup),
            filter: None,

            realm_list: None,
            replace_filter: None,
        }
    }

    fn frame(json: Value) -> AccountSubscribeFrame {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn reconnect_delay_is_bounded() {
        assert_eq!(
            clamp_reconnect_after_ms(Some(u64::MAX)),
            MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS
        );
        assert_eq!(clamp_reconnect_after_ms(Some(2_000)), 2_000);
        assert_eq!(
            clamp_reconnect_after_ms(None),
            DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS
        );
    }

    #[test]
    fn folder_requires_request_context_and_valid_completion_order() {
        let mut folder = AccountSubscribeFolder::for_request(&request(true, None));
        let error = folder
            .push(frame(serde_json::json!({
                "kind": "catchup_complete",
                "cursor": "ak:cursor:complete",
            })))
            .unwrap_err();
        assert!(matches!(
            error,
            Error::StreamTrace(error)
                if error.violation() == "catchup_complete_before_delta"
        ));
    }

    #[test]
    fn folder_advances_only_through_validated_cursor_frames() {
        let mut folder =
            AccountSubscribeFolder::for_request(&request(true, Some("ak:cursor:saved")));
        assert!(
            !folder
                .push(frame(serde_json::json!({
                    "kind": "heartbeat",
                    "cursor": "ak:cursor:ignored",
                })))
                .unwrap()
        );
        assert_eq!(folder.reconnect_cursor(), Some("ak:cursor:saved"));
        assert!(
            !folder
                .push(frame(serde_json::json!({
                    "kind": "delta",
                    "cursor": "ak:cursor:delta",
                    "partial": false,
                })))
                .unwrap()
        );
        assert!(
            folder
                .push(frame(serde_json::json!({
                    "kind": "catchup_complete",
                    "cursor": "ak:cursor:complete",
                })))
                .unwrap()
        );

        let AccountSubscribeSnapshotResult::Batch(batch) = folder.finish().unwrap() else {
            panic!("expected frame batch");
        };
        assert_eq!(batch.cursor, "ak:cursor:complete");
        assert_eq!(batch.frames.len(), 1);
    }

    #[test]
    fn folder_accepts_checkpoint_only_bounded_long_poll_timeout() {
        let mut folder =
            AccountSubscribeFolder::for_request(&request(true, Some("ak:cursor:saved")));
        assert!(
            !folder
                .push(frame(serde_json::json!({
                    "kind": "checkpoint",
                    "cursor": "ak:cursor:idle",
                })))
                .unwrap()
        );
        assert!(
            folder
                .push(frame(serde_json::json!({
                    "kind": "catchup_complete",
                    "cursor": "ak:cursor:idle",
                })))
                .unwrap()
        );

        let AccountSubscribeSnapshotResult::Batch(batch) = folder.finish().unwrap() else {
            panic!("expected empty projection batch");
        };
        assert!(batch.frames.is_empty());
        assert_eq!(batch.cursor, "ak:cursor:idle");
    }

    #[test]
    fn folder_preserves_ordered_notification_deltas_across_frames() {
        let notification_id = "ak:notification:01964137-0000-7000-8000-000000000004";
        let approval = serde_json::json!({
            "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000004",
            "agent_id": "ak:did_core:webvh:z6mkfixture",
            "requested_at": "2026-07-13T10:00:00.000Z",
            "expires_at": "2026-07-13T10:15:00.000Z"
        });
        let mut folder = AccountSubscribeFolder::for_request(&request(false, None));
        folder
            .push(frame(serde_json::json!({
                "kind": "delta",
                "cursor": "ak:cursor:upsert",
                "notifications": {"items": [{
                    "id": notification_id,
                    "action": "upsert",
                    "data": approval
                }]}
            })))
            .unwrap();
        folder
            .push(frame(serde_json::json!({
                "kind": "delta",
                "cursor": "ak:cursor:remove",
                "notifications": {"items": [{
                    "id": notification_id,
                    "action": "remove",
                    "data": {"reason": "approved"}
                }]}
            })))
            .unwrap();

        let AccountSubscribeSnapshotResult::Batch(batch) = folder.finish().unwrap() else {
            panic!("expected frame batch");
        };
        assert_eq!(batch.frames.len(), 2);
        assert_eq!(
            batch.frames[0].notifications.as_ref().unwrap().items[0].action,
            NotificationDeltaAction::Upsert
        );
        assert_eq!(
            batch.frames[1].notifications.as_ref().unwrap().items[0].action,
            NotificationDeltaAction::Remove
        );
    }

    #[test]
    fn folder_rejects_cursorless_dropped() {
        let mut folder = AccountSubscribeFolder::for_request(&request(false, None));
        let error = folder
            .push(frame(serde_json::json!({"kind": "dropped"})))
            .unwrap_err();
        assert!(matches!(
            error,
            Error::StreamTrace(error) if error.violation() == "dropped_missing_cursor"
        ));
    }

    #[test]
    fn folder_surfaces_dropped_reconnect_cursor() {
        let mut folder = AccountSubscribeFolder::for_request(&request(false, None));
        assert!(
            folder
                .push(frame(serde_json::json!({
                    "kind": "dropped",
                    "cursor": "ak:cursor:drop",
                    "reconnect_after_ms": 1000,
                })))
                .unwrap()
        );
        let AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_cursor,
            reset_cursor,
            ..
        } = folder.finish().unwrap()
        else {
            panic!("expected reconnect result");
        };
        assert_eq!(reconnect_cursor.as_deref(), Some("ak:cursor:drop"));
        assert!(!reset_cursor);
    }
}
