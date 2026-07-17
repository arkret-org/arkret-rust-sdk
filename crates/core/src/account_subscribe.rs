//! Incremental folding for `ak.self.account.stream.subscribe` frames.

use crate::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, Error, Result, StreamTraceValidator,
    SyncRequestBody,
};

pub const DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 5_000;
pub const MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 60_000;

#[derive(Clone, Debug)]
pub enum AccountSubscribeSnapshotResult {
    Batch(AccountSubscribeBatch),
    ReconnectAfter {
        reconnect_after_ms: u64,
        reconnect_cursor: Option<String>,
        reason: Option<String>,
        reset_cursor: bool,
    },
}

/// Validated account-subscribe catch-up step.
///
/// `frames` may be empty when a bounded long-poll expires without account
/// changes. In that case the wire trace contains a cursor-bearing `frontier`
/// followed by `catchup_complete`; the cursor still advances the reconnect
/// baseline while the projection update is intentionally empty.
#[derive(Clone, Debug)]
pub struct AccountSubscribeBatch {
    pub frames: Vec<AccountSubscribeFrame>,
    pub cursor: String,
}

#[derive(Clone, Debug)]
pub struct AccountSubscribeReconnectAfter {
    pub reconnect_after_ms: u64,
    pub reconnect_cursor: Option<String>,
    pub reason: Option<String>,
    pub reset_cursor: bool,
}

impl std::fmt::Display for AccountSubscribeReconnectAfter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason.as_deref() {
            Some(reason) => write!(
                formatter,
                "account subscribe requested reconnect after {} ms: {}",
                self.reconnect_after_ms, reason
            ),
            None => write!(
                formatter,
                "account subscribe requested reconnect after {} ms",
                self.reconnect_after_ms
            ),
        }
    }
}

impl std::error::Error for AccountSubscribeReconnectAfter {}

fn clamp_reconnect_after_ms(raw: Option<u64>) -> u64 {
    raw.unwrap_or(DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
        .min(MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
}

pub struct AccountSubscribeFolder {
    frames: Vec<AccountSubscribeFrame>,
    done: Option<AccountSubscribeSnapshotResult>,
    trace: StreamTraceValidator,
}

impl AccountSubscribeFolder {
    /// Create a folder bound to the exact account-subscribe request context.
    pub fn for_request(request: &SyncRequestBody) -> Self {
        Self {
            frames: Vec::new(),
            done: None,
            trace: StreamTraceValidator::new(
                request.catchup.unwrap_or(false),
                request.after.clone(),
            ),
        }
    }

    pub fn push(&mut self, frame: AccountSubscribeFrame) -> Result<bool> {
        if self.done.is_some() {
            return Err(Error::Protocol(
                "account subscribe frame arrived after a terminal frame".to_owned(),
            ));
        }
        self.trace.push(&frame)?;
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
    use serde_json::Value;

    use super::*;
    use crate::NotificationDeltaAction;

    fn request(catchup: bool, after: Option<&str>) -> SyncRequestBody {
        SyncRequestBody {
            after: after.map(ToOwned::to_owned),
            catchup: Some(catchup),
            filter: None,
            subscriptions: None,
            wait_for: None,
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
        assert!(
            matches!(error, Error::Protocol(message) if message.contains("catchup_complete_before_delta"))
        );
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
    fn folder_accepts_frontier_only_bounded_long_poll_timeout() {
        let mut folder =
            AccountSubscribeFolder::for_request(&request(true, Some("ak:cursor:saved")));
        assert!(
            !folder
                .push(frame(serde_json::json!({
                    "kind": "frontier",
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
            "kind": "agent_runtime_approval",
            "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000004",
            "agent_id": "did:webvh:z6mkfixture:agent.example",
            "requested_at": "2026-07-13T10:00:00Z",
            "expires_at": "2026-07-13T10:15:00Z"
        });
        let mut folder = AccountSubscribeFolder::for_request(&request(false, None));
        folder
            .push(frame(serde_json::json!({
                "kind": "delta",
                "cursor": "ak:cursor:add",
                "notifications": {"items": [{
                    "id": notification_id,
                    "type": "agent",
                    "action": "add",
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
                    "type": "agent",
                    "action": "remove",
                    "data": {"kind": "agent_runtime_approval", "reason": "approved"}
                }]}
            })))
            .unwrap();

        let AccountSubscribeSnapshotResult::Batch(batch) = folder.finish().unwrap() else {
            panic!("expected frame batch");
        };
        assert_eq!(batch.frames.len(), 2);
        assert_eq!(
            batch.frames[0].notifications.as_ref().unwrap().items[0].action,
            NotificationDeltaAction::Add
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
        assert!(
            matches!(error, Error::Protocol(message) if message.contains("dropped_missing_cursor"))
        );
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
