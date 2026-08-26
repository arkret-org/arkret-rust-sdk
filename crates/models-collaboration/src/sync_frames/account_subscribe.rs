//! `ak.self.account.stream.subscribe` NDJSON frame family and validated
//! batch results.

use arkret_wire::SchemaId;

use crate::internal_prelude::*;

/// One NDJSON frame on `ak.self.account.stream.subscribe`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeFrame {
    pub kind: AccountSubscribeFrameKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<AccountSubscribeRealms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device: Option<DeviceMessageContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_lists: Option<AccountSubscribeDeviceListChanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<NotificationContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_signer_evidence_bundle:
        Option<crate::agent_signer_evidence::AgentSignerEvidenceBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_after_ms: Option<u64>,
}

/// Account-subscribe NDJSON frame discriminator.
///
/// `#[non_exhaustive]`: a future spec revision may register additional frame
/// kinds. Downstream `match` expressions MUST carry a `_` arm with
/// fail-closed semantics (ignore/drop an unrecognised frame rather than
/// treating it as a delta or a state transition). Deserialisation itself
/// stays closed-set: an unknown wire value still fails the frame parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AccountSubscribeFrameKind {
    Delta,
    CatchupComplete,
    Frontier,
    Heartbeat,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

/// Structured control interrupt extracted from a `dropped` /
/// `resync_required` / `unauthorized` account-subscribe frame
/// (client-sync.md §2 / §2.2). These frames MUST NOT be silently
/// skipped: the client has to reconcile (dropped/resync) or
/// re-authenticate (unauthorized), and MUST honor any
/// `reconnect_after_ms` hold before reconnecting the same scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AccountStreamInterrupt {
    /// `dropped`: the server cannot continue from the current position.
    /// Reconnect with `after=<cursor>&catchup=true` (client-sync.md §2.2.3).
    Dropped {
        /// Suggested catch-up cursor, required by the v1 wire contract.
        cursor: String,
        /// Server-mandated hold before reconnecting the same scope.
        reconnect_after_ms: Option<u64>,
    },
    /// `resync_required`: clear the local cursor cache and redo the
    /// initial account sync (client-sync.md §2.2.4).
    ResyncRequired {
        /// Server-mandated hold before reconnecting the same scope.
        reconnect_after_ms: Option<u64>,
    },
    /// `unauthorized`: the session may no longer consume this stream;
    /// re-authenticate or sign out (client-sync.md §2.2.5).
    Unauthorized,
}

impl AccountSubscribeFrame {
    pub const SCHEMA: &'static str = SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1;
    /// Parse one NDJSON line. Empty / whitespace-only lines return
    /// `Ok(None)` so callers can chunk-read transparently. Mirrors the
    /// existing `EventsSubscribeFrame::from_ndjson_line` API
    /// (see `crates/models-collaboration/src/sync_frames/account_subscribe.rs`).
    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame: Self = canonical::from_canonical_json_str(trimmed)?;
        frame.validate()?;
        Ok(Some(frame))
    }

    pub fn validate(&self) -> Result<()> {
        let has_data = self.realms.is_some()
            || self.to_device.is_some()
            || self.device_lists.is_some()
            || self.account_data.is_some()
            || self.notifications.is_some()
            || self.agent_signer_evidence_bundle.is_some()
            || self.partial.is_some()
            || self.priority.is_some();
        if self.reconnect_after_ms == Some(0) {
            return Err(WireError::Protocol(
                "reconnect_after_ms must be greater than zero".to_owned(),
            ));
        }
        if let Some(to_device) = &self.to_device {
            to_device.validate()?;
        }
        if let Some(bundle) = &self.agent_signer_evidence_bundle
            && (bundle.schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_BUNDLE_V1
                || bundle.evidence.len() > 256)
        {
            return Err(WireError::Protocol(
                "agent_signer_evidence_bundle is invalid".to_owned(),
            ));
        }
        let valid = match self.kind {
            AccountSubscribeFrameKind::Delta => {
                self.cursor.is_some() && self.reconnect_after_ms.is_none()
            }
            AccountSubscribeFrameKind::CatchupComplete | AccountSubscribeFrameKind::Frontier => {
                self.cursor.is_some() && !has_data && self.reconnect_after_ms.is_none()
            }
            AccountSubscribeFrameKind::Dropped => self.cursor.is_some() && !has_data,
            AccountSubscribeFrameKind::Heartbeat | AccountSubscribeFrameKind::Unauthorized => {
                self.cursor.is_none() && !has_data && self.reconnect_after_ms.is_none()
            }
            AccountSubscribeFrameKind::ResyncRequired => self.cursor.is_none() && !has_data,
        };
        if !valid {
            return Err(WireError::Protocol(format!(
                "account subscribe fields are invalid for {:?}",
                self.kind
            )));
        }
        Ok(())
    }

    /// True iff this frame requires the client to reset its cursor and
    /// re-subscribe (kinds `dropped` / `resync_required`).
    pub fn requires_resubscribe(&self) -> bool {
        matches!(
            self.kind,
            AccountSubscribeFrameKind::Dropped | AccountSubscribeFrameKind::ResyncRequired
        )
    }

    /// Server-advertised lower bound before reconnecting the same
    /// account-subscribe scope.
    pub fn reconnect_after_ms(&self) -> Option<u64> {
        self.reconnect_after_ms
    }

    /// Structured control interrupt carried by this frame, if any.
    ///
    /// `dropped` / `resync_required` / `unauthorized` are terminal for the
    /// current subscription and MUST be surfaced to the sync loop instead of
    /// being skipped like benign keepalive frames.
    pub fn interrupt(&self) -> Result<Option<AccountStreamInterrupt>> {
        Ok(match self.kind {
            AccountSubscribeFrameKind::Dropped => Some(AccountStreamInterrupt::Dropped {
                cursor: self.cursor.clone().ok_or_else(|| {
                    WireError::Protocol("stream trace dropped_missing_cursor".to_owned())
                })?,
                reconnect_after_ms: self.reconnect_after_ms,
            }),
            AccountSubscribeFrameKind::ResyncRequired => {
                Some(AccountStreamInterrupt::ResyncRequired {
                    reconnect_after_ms: self.reconnect_after_ms,
                })
            }
            AccountSubscribeFrameKind::Unauthorized => Some(AccountStreamInterrupt::Unauthorized),
            AccountSubscribeFrameKind::Delta
            | AccountSubscribeFrameKind::CatchupComplete
            | AccountSubscribeFrameKind::Frontier
            | AccountSubscribeFrameKind::Heartbeat => None,
        })
    }

    /// True iff `kind == catchup_complete`.
    pub fn is_catchup_complete(&self) -> bool {
        matches!(self.kind, AccountSubscribeFrameKind::CatchupComplete)
    }
}

#[cfg(test)]
mod account_subscribe_frame_tests {
    use super::*;

    #[test]
    fn account_subscribe_frame_from_ndjson_line_delta() {
        let line = r#"{"cursor":"ak:cursor:acc-1","kind":"delta"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Delta);
        assert_eq!(frame.cursor.as_deref(), Some("ak:cursor:acc-1"));
        assert!(!frame.requires_resubscribe());
        assert!(!frame.is_catchup_complete());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_catchup_complete() {
        let line = r#"{"cursor":"ak:cursor:live-0","kind":"catchup_complete"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert!(frame.is_catchup_complete());
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_frontier() {
        let line = r#"{"cursor":"ak:cursor:adv-7","kind":"frontier"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Frontier);
        assert!(!frame.requires_resubscribe());
        assert!(!frame.is_catchup_complete());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_heartbeat() {
        let line = r#"{"kind":"heartbeat"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Heartbeat);
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_dropped_requires_resubscribe() {
        let line = r#"{"cursor":"ak:cursor:dropped","kind":"dropped","reconnect_after_ms":10000}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert!(frame.requires_resubscribe());
        assert_eq!(frame.reconnect_after_ms(), Some(10_000));
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_resync_required_requires_resubscribe() {
        let line = r#"{"kind":"resync_required","reconnect_after_ms":7500}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert!(frame.requires_resubscribe());
        assert_eq!(frame.reconnect_after_ms(), Some(7_500));
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_unauthorized() {
        let line = r#"{"kind":"unauthorized"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Unauthorized);
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_delta_accepts_closed_agent_notification_items() {
        let line = r#"{"cursor":"ak:cursor:account-2","kind":"delta","notifications":{"items":[{"action":"upsert","data":{"agent_id":"ak:did_core:webvh:z6mkfixture","approval_request_id":"agent_runtime_approval:01964137-0000-7000-8000-000000000002","expires_at":"2026-07-13T10:15:00.000Z","requested_at":"2026-07-13T10:00:00.000Z"},"id":"ak:notification:01964137-0000-7000-8000-000000000002"}]}}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.notifications.unwrap().items.len(), 1);
    }

    #[test]
    fn account_subscribe_delta_rejects_old_or_incomplete_notification_shapes() {
        let old_container =
            r#"{"cursor":"ak:cursor:account-3","kind":"delta","notifications":{"events":[]}}"#;
        assert!(AccountSubscribeFrame::from_ndjson_line(old_container).is_err());

        let missing_data = r#"{"cursor":"ak:cursor:account-4","kind":"delta","notifications":{"items":[{"id":"ak:notification:01964137-0000-7000-8000-000000000003","action":"upsert"}]}}"#;
        assert!(AccountSubscribeFrame::from_ndjson_line(missing_data).is_err());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_empty_returns_none() {
        assert!(
            AccountSubscribeFrame::from_ndjson_line("")
                .unwrap()
                .is_none()
        );
        assert!(
            AccountSubscribeFrame::from_ndjson_line("   \n  ")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn account_subscribe_frame_rejects_non_nfc_string() {
        let line = "{\"kind\":\"dropped\",\"reason\":\"cafe\u{301}\"}";
        assert!(AccountSubscribeFrame::from_ndjson_line(line).is_err());
    }

    #[test]
    fn account_subscribe_frame_rejects_duplicate_key() {
        let line = r#"{"kind":"heartbeat","kind":"heartbeat"}"#;
        assert!(AccountSubscribeFrame::from_ndjson_line(line).is_err());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_unknown_kind_errors() {
        // AccountSubscribeFrameKind is a closed enum: parsing an unknown
        // discriminant returns Err, distinct from the "Unknown" variant
        // tolerance EventsSubscribeFrame has.
        let line = r#"{"kind":"future_kind_42"}"#;
        let err = AccountSubscribeFrame::from_ndjson_line(line).unwrap_err();
        assert!(format!("{err}").contains("future_kind_42"));
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountSubscribeRealms {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub entries: BTreeMap<String, RealmSyncEntry>,
}

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
