//! Incremental folding for `ak.self.account.stream.subscribe` frames.

use serde_json::Value;

use crate::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, Error, Result, StreamTraceValidator,
    SyncOutcome, SyncRequestBody,
};

pub const DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 5_000;
pub const MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 60_000;

#[derive(Clone, Debug)]
pub enum AccountSubscribeSnapshotResult {
    Delta(Box<SyncOutcome>),
    ReconnectAfter {
        reconnect_after_ms: u64,
        reconnect_cursor: Option<String>,
        reason: Option<String>,
        reset_cursor: bool,
    },
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
    merged: Option<SyncOutcome>,
    done: Option<AccountSubscribeSnapshotResult>,
    trace: StreamTraceValidator,
}

impl AccountSubscribeFolder {
    /// Create a folder bound to the exact account-subscribe request context.
    pub fn for_request(request: &SyncRequestBody) -> Self {
        Self {
            merged: None,
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
        if let Some(delta) = SyncOutcome::from_account_subscribe_frame(frame) {
            self.merged = Some(match self.merged.take() {
                None => delta,
                Some(mut accumulated) => {
                    merge_account_subscribe_delta(&mut accumulated, delta);
                    accumulated
                }
            });
        }
        Ok(false)
    }

    pub fn finish(mut self) -> Result<AccountSubscribeSnapshotResult> {
        self.trace.finish()?;
        if let Some(done) = self.done {
            return Ok(done);
        }
        match self.merged {
            Some(mut response) => {
                if let Some(cursor) = self.trace.reconnect_cursor() {
                    response.cursor = cursor.to_owned();
                }
                Ok(AccountSubscribeSnapshotResult::Delta(Box::new(response)))
            }
            None => Err(Error::Protocol(
                "account subscribe stream ended before a delta frame".to_owned(),
            )),
        }
    }

    pub fn reconnect_cursor(&self) -> Option<&str> {
        self.trace.reconnect_cursor()
    }
}

fn merge_account_subscribe_delta(acc: &mut SyncOutcome, next: SyncOutcome) {
    for (realm_id, incoming) in next.realms {
        match acc.realms.entry(realm_id) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(incoming);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                merge_realm_delta_value(slot.get_mut(), incoming);
            }
        }
    }
    acc.cursor = next.cursor;
    acc.left_realms.extend(next.left_realms);
    acc.to_device.extend(next.to_device);
    if next.to_device_ack_token.is_some() {
        acc.to_device_ack_token = next.to_device_ack_token;
    }
    acc.to_device_limited = next.to_device_limited;
    if next.to_device_next_cursor.is_some() {
        acc.to_device_next_cursor = next.to_device_next_cursor;
    }
    if next.to_device_lost.is_some() {
        acc.to_device_lost = next.to_device_lost;
    }
    acc.account_data.extend(next.account_data);
    acc.presence.extend(next.presence);
    if !next.device_lists.is_null() {
        acc.device_lists = next.device_lists;
    }
    if !next.notifications.is_null() {
        acc.notifications = next.notifications;
    }
    acc.partial = next.partial;
}

fn merge_realm_delta_value(current: &mut Value, incoming: Value) {
    let Value::Object(incoming) = incoming else {
        *current = incoming;
        return;
    };
    let Value::Object(current_map) = current else {
        *current = Value::Object(incoming);
        return;
    };
    for (key, value) in incoming {
        if (key == "timeline" || key == "state")
            && let Some(Value::Object(existing_section)) = current_map.get_mut(&key)
            && let Value::Object(mut incoming_section) = value
        {
            if let (Some(Value::Array(existing_events)), Some(Value::Array(new_events))) = (
                existing_section.get_mut("events"),
                incoming_section.remove("events"),
            ) {
                existing_events.extend(new_events);
            }
            for (section_key, section_value) in incoming_section {
                existing_section.insert(section_key, section_value);
            }
            continue;
        }
        current_map.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let AccountSubscribeSnapshotResult::Delta(outcome) = folder.finish().unwrap() else {
            panic!("expected folded delta");
        };
        assert_eq!(outcome.cursor, "ak:cursor:complete");
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
