//! `ak.self.account.stream.subscribe.v1` NDJSON frame family and validated
//! batch results.

use arkret_models_identity::account::AccountDataRow;
use arkret_wire::SchemaId;
use chrono::{DateTime, Utc};

use super::demand_sync::*;
use crate::internal_prelude::*;

/// One NDJSON frame on `ak.self.account.stream.subscribe.v1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeFrame {
    pub kind: AccountSubscribeFrameKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub cursor: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub realms: Option<AccountSubscribeRealms>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub to_device: Option<DeviceMessageContainer>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub device_lists: Option<AccountSubscribeDeviceListChanges>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub account_data: Option<AccountDataContainer>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub notifications: Option<NotificationContainer>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub partial: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub priority: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub reconnect_after_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub realm_list: Option<RealmListPage>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub realm_list_changes: Option<RealmListChanges>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub baseline: Option<AccountBaselineSegment>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub realm_invalidations: Option<Vec<RealmInvalidation>>,
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
        if line.len() > ACCOUNT_SYNC_MAX_WIRE_FRAME_BYTES {
            return Err(demand_error("Account frame exceeds its wire byte limit"));
        }
        let frame: Self = canonical::from_canonical_json_str(trimmed)?;
        frame.validate()?;
        Ok(Some(frame))
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(cursor) = &self.cursor {
            validate_demand_cursor(cursor)?;
        }
        if arkret_canonical::canonical_json_bytes(self)?.len() > ACCOUNT_SYNC_MAX_FRAME_BYTES {
            return Err(demand_error(
                "Account frame exceeds its canonical byte limit",
            ));
        }
        if let Some(page) = &self.realm_list {
            page.validate()?;
        }
        if let Some(changes) = &self.realm_list_changes {
            changes.validate()?;
        }
        if let Some(baseline) = &self.baseline {
            baseline.validate()?;
            if baseline
                .channels
                .contains(&AccountBaselineChannel::StationCas)
                && self
                    .account_data
                    .as_ref()
                    .and_then(|data| data.station_cas.as_ref())
                    .is_some_and(|data| !data.removals.is_empty())
            {
                return Err(demand_error(
                    "Station-CAS baseline segments cannot contain removals",
                ));
            }
        }
        if let Some(invalidations) = &self.realm_invalidations {
            if invalidations.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS {
                return Err(demand_error("Realm invalidations exceed 100 items"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for item in invalidations {
                item.validate()?;
                if !seen.insert(&item.realm_id) {
                    return Err(demand_error("Realm invalidations repeat a Realm"));
                }
            }
        }
        if let Some(realms) = &self.realms {
            if realms.entries.len() > ACCOUNT_SYNC_MAX_REALMS {
                return Err(demand_error("Account frame exceeds 16 Realm details"));
            }
            for (realm_key, realm) in &realms.entries {
                let realm_id = RealmId::new(realm_key.clone())?;
                realm.validate_demand()?;
                if let Some(current) = &realm.current {
                    for entry in &current.entries {
                        entry.selector().validate_for_realm(&realm_id)?;
                    }
                }
            }
        }
        if let Some(devices) = &self.device_lists {
            bounded_unique(&devices.changed_ids, 100, "device_lists.changed_ids")?;
            bounded_unique(&devices.left_ids, 100, "device_lists.left_ids")?;
        }
        if self
            .notifications
            .as_ref()
            .is_some_and(|items| items.items.len() > 100)
        {
            return Err(demand_error("Account notifications exceed 100 items"));
        }
        let has_data = self.realms.is_some()
            || self.to_device.is_some()
            || self.device_lists.is_some()
            || self.account_data.is_some()
            || self.notifications.is_some()
            || self.partial.is_some()
            || self.priority.is_some()
            || self.realm_list.is_some()
            || self.realm_list_changes.is_some()
            || self.baseline.is_some()
            || self.realm_invalidations.is_some();
        if self.reconnect_after_ms == Some(0) {
            return Err(WireError::Protocol(
                "reconnect_after_ms must be greater than zero".to_owned(),
            ));
        }
        if let Some(to_device) = &self.to_device {
            to_device.validate()?;
        }
        if let Some(account_data) = &self.account_data {
            account_data.validate()?;
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

/// Account-scoped private state carried by an account-subscribe delta.
///
/// Holder-authored events and Station-CAS registers have distinct authority
/// and therefore remain separate typed branches.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDataContainer {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub station_cas: Option<StationCasAccountDataContainer>,
}

impl AccountDataContainer {
    pub fn validate(&self) -> Result<()> {
        if self.events.len() > 100 {
            return Err(demand_error("Account Data exceeds 100 Events"));
        }
        if let Some(station_cas) = &self.station_cas {
            station_cas.validate()?;
        }
        Ok(())
    }
}

/// Cursor-covered Station-authored Account Data register projection.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationCasAccountDataContainer {
    #[serde(default)]
    pub upserts: Vec<AccountDataRow>,
    #[serde(default)]
    pub removals: Vec<StationCasAccountDataRemoval>,
}

impl StationCasAccountDataContainer {
    pub fn validate(&self) -> Result<()> {
        if self.upserts.len() > 100 || self.removals.len() > 100 {
            return Err(demand_error("Station-CAS data exceeds 100 items"));
        }

        let mut keys = std::collections::BTreeSet::new();
        for upsert in &self.upserts {
            if upsert.account_data_key.is_empty()
                || upsert.revision == 0
                || !keys.insert(upsert.account_data_key.as_str())
            {
                return Err(WireError::Protocol(
                    "station_cas upserts must have unique non-empty keys and positive revisions"
                        .to_owned(),
                ));
            }
        }
        for removal in &self.removals {
            if removal.account_data_key.is_empty()
                || removal.revision == 0
                || !keys.insert(removal.account_data_key.as_str())
            {
                return Err(WireError::Protocol(
                    "station_cas changes must have unique non-empty keys and positive revisions"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Explicit deletion of one Station-CAS Account Data register.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationCasAccountDataRemoval {
    pub account_data_key: String,
    pub revision: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
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
    fn account_subscribe_station_cas_uses_the_segment_completion_marker() {
        let value = serde_json::json!({"kind":"delta","cursor":"ak:cursor:next",
            "baseline":{"snapshot_cursor":"ak:cursor:snapshot","channels":["station_cas"],"completed_channels":[]},
            "account_data":{"events":[],"station_cas":{"upserts":[],"removals":[]}}});
        let frame: AccountSubscribeFrame = serde_json::from_value(value.clone()).unwrap();
        frame.validate().unwrap();
        assert!(frame.baseline.unwrap().completed_channels.is_empty());
        let mut retired = value.clone();
        retired["account_data"]["station_cas"]["complete"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AccountSubscribeFrame>(retired).is_err());
        let mut wrong = value;
        wrong["baseline"]["completed_channels"] = serde_json::json!(["device_lists"]);
        assert!(
            serde_json::from_value::<AccountSubscribeFrame>(wrong)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn account_subscribe_rejects_removal_inside_station_cas_snapshot() {
        let frame:AccountSubscribeFrame=serde_json::from_value(serde_json::json!({"kind":"delta","cursor":"ak:cursor:next",
            "baseline":{"snapshot_cursor":"ak:cursor:snapshot","channels":["station_cas"],"completed_channels":["station_cas"]},
            "account_data":{"events":[],"station_cas":{"upserts":[],"removals":[{"account_data_key":"ak.account.invite_delivery","revision":3,"updated_at":"2026-09-03T12:00:00.000Z"}]}}
        })).unwrap();
        assert!(frame.validate().is_err());
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
