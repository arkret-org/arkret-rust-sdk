use super::*;

/// Folded account-aggregate delta used by SDK internals.
///
/// Current wire delivery is `ck.self.account.stream.subscribe`: an NDJSON stream of
/// [`AccountSubscribeFrame`] values. The SDK folds `delta` frames into this
/// shape so existing reducers and UI code can consume a single account snapshot
/// value without depending on transport streaming details.
///
/// Per-realm bodies are kept as raw `Value` so consumers can introspect the
/// bucket / inner shape without colliding with the typed SDK sync_client
/// surface in [`crate::sync::SyncRealm`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncOutcome {
    /// Opaque stream cursor — clients MUST treat it as opaque and pass it back
    /// as `after` on the next `/account/subscribe` request.
    pub cursor: String,
    /// Realm sync bodies keyed by `ak:realm:*`. Kept as `Value` so the HTTP
    /// layer doesn't constrain per-realm extra
    /// fields (e.g. `state_after`, `strands`) that the spec leaves open.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub realms: BTreeMap<String, Value>,
    /// Realms the viewer no longer has access to after the supplied
    /// `after` cursor — left rooms, kicks, bans, server-side
    /// deletions. Empty on full sync (omission from `realms` is
    /// authoritative there).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_realms: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_device: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device_ack_token: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub to_device_limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device_next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device_lost: Option<bool>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_lists: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub account_data: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<Value>,
    /// Notification delta (inbox / push). `Value` to round-trip the
    /// spec's events-container shape without committing to a typed
    /// projection here.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub notifications: Value,
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
}

impl SyncOutcome {
    /// Realm sync map.
    pub fn effective_realms(&self) -> &BTreeMap<String, Value> {
        &self.realms
    }

    /// Fold a single `ck.self.account.stream.subscribe` data frame into the SDK aggregate
    /// snapshot shape. Control frames without data return `None`.
    pub fn from_account_subscribe_frame(frame: AccountSubscribeFrame) -> Option<Self> {
        if frame.kind != AccountSubscribeFrameKind::Delta {
            return None;
        }
        let cursor = frame.cursor?;
        let mut realms = BTreeMap::new();
        if let Some(frame_realms) = frame.realms {
            realms.extend(frame_realms.entries);
        }
        let to_device_value = frame.to_device;
        let to_device = to_device_value
            .as_ref()
            .and_then(|value| value.get("messages").cloned())
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        let to_device_ack_token = to_device_value
            .as_ref()
            .and_then(|value| value.get("ack_token"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let to_device_limited = to_device_value
            .as_ref()
            .and_then(|value| value.get("limited"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let to_device_next_cursor = to_device_value
            .as_ref()
            .and_then(|value| value.get("next_cursor"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let to_device_lost = to_device_value
            .as_ref()
            .and_then(|value| value.get("lost"))
            .and_then(Value::as_bool);

        Some(Self {
            cursor,
            realms,
            left_realms: Vec::new(),
            to_device,
            to_device_ack_token,
            to_device_limited,
            to_device_next_cursor,
            to_device_lost,
            device_lists: frame.device_lists.unwrap_or(Value::Null),
            account_data: frame
                .account_data
                .and_then(|value| value.get("events").cloned())
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default(),
            presence: frame
                .presence
                .and_then(|value| value.get("events").cloned())
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default(),
            notifications: frame.notifications.unwrap_or(Value::Null),
            partial: frame.partial.unwrap_or(false),
        })
    }
}

/// One NDJSON frame on `ck.self.account.stream.subscribe`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSubscribeFrame {
    pub kind: AccountSubscribeFrameKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<AccountSubscribeRealms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_lists: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_after_ms: Option<u64>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// Account-subscribe NDJSON frame discriminator.
///
/// `#[non_exhaustive]`: a future spec revision may register additional frame
/// kinds. Downstream `match` expressions MUST carry a `_` arm with
/// fail-closed semantics (ignore/drop an unrecognised frame rather than
/// treating it as a delta or a state transition). Deserialisation itself
/// stays closed-set: an unknown wire value still fails the frame parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
        /// Suggested catch-up cursor (REQUIRED on the wire per §2; a
        /// missing cursor is treated as `resync_required` by consumers).
        cursor: Option<String>,
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
    Unauthorized {
        /// Optional server-provided reason.
        reason: Option<String>,
    },
}

impl AccountSubscribeFrame {
    /// Parse one NDJSON line. Empty / whitespace-only lines return
    /// `Ok(None)` so callers can chunk-read transparently. Mirrors the
    /// existing `EventsSubscribeFrame::from_ndjson_line` API
    /// (see `crates/sdk/src/sync_client/wire.rs`).
    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame: Self = canonical::from_canonical_json_str(trimmed)?;
        Ok(Some(frame))
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
    pub fn interrupt(&self) -> Option<AccountStreamInterrupt> {
        match self.kind {
            AccountSubscribeFrameKind::Dropped => Some(AccountStreamInterrupt::Dropped {
                cursor: self.cursor.clone(),
                reconnect_after_ms: self.reconnect_after_ms,
            }),
            AccountSubscribeFrameKind::ResyncRequired => {
                Some(AccountStreamInterrupt::ResyncRequired {
                    reconnect_after_ms: self.reconnect_after_ms,
                })
            }
            AccountSubscribeFrameKind::Unauthorized => Some(AccountStreamInterrupt::Unauthorized {
                reason: self.reason.clone(),
            }),
            AccountSubscribeFrameKind::Delta
            | AccountSubscribeFrameKind::CatchupComplete
            | AccountSubscribeFrameKind::Frontier
            | AccountSubscribeFrameKind::Heartbeat => None,
        }
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
        let line = r#"{"cursor":"sx:acc:1","kind":"delta"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Delta);
        assert_eq!(frame.cursor.as_deref(), Some("sx:acc:1"));
        assert!(!frame.requires_resubscribe());
        assert!(!frame.is_catchup_complete());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_catchup_complete() {
        let line = r#"{"cursor":"sx:live:0","kind":"catchup_complete"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert!(frame.is_catchup_complete());
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_frontier() {
        let line = r#"{"cursor":"sx:adv:7","kind":"frontier"}"#;
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
        let line = r#"{"kind":"dropped","reason":"buffer overflow","reconnect_after_ms":10000}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert!(frame.requires_resubscribe());
        assert_eq!(frame.reason.as_deref(), Some("buffer overflow"));
        assert_eq!(frame.reconnect_after_ms(), Some(10_000));
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_resync_required_requires_resubscribe() {
        let line =
            r#"{"kind":"resync_required","reason":"epoch rotated","reconnect_after_ms":7500}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert!(frame.requires_resubscribe());
        assert_eq!(frame.reconnect_after_ms(), Some(7_500));
    }

    #[test]
    fn account_subscribe_frame_from_ndjson_line_unauthorized() {
        let line = r#"{"kind":"unauthorized","reason":"revoked"}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, AccountSubscribeFrameKind::Unauthorized);
        assert!(!frame.requires_resubscribe());
    }

    #[test]
    fn account_subscribe_delta_projects_to_device_ack_fields() {
        let line = r#"{"cursor":"ak:cursor:account-1","kind":"delta","to_device":{"ack_token":"ack-account-1","limited":true,"lost":false,"messages":[],"next_cursor":"ak:cursor:device-2"}}"#;
        let frame = AccountSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap();
        let outcome = SyncOutcome::from_account_subscribe_frame(frame).unwrap();

        assert_eq!(
            outcome.to_device_ack_token.as_deref(),
            Some("ack-account-1")
        );
        assert!(outcome.to_device_limited);
        assert_eq!(
            outcome.to_device_next_cursor.as_deref(),
            Some("ak:cursor:device-2")
        );
        assert_eq!(outcome.to_device_lost, Some(false));
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSubscribeRealms {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub entries: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncDescription {
    pub service_did: Did,
    #[serde(default)]
    pub supported_sync_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub frontier: Option<Value>,
}

#[cfg(test)]
mod sync_description_tests {
    use super::*;

    #[test]
    fn sync_description_frontier_preserves_raw_service_shape() {
        let object_frontier: SyncDescription = serde_json::from_value(serde_json::json!({
            "service_did": "did:web:server.local",
            "supported_sync_profiles": ["initial"],
            "limits": {},
            "frontier": {"storage": "memory"}
        }))
        .unwrap();
        assert_eq!(
            object_frontier
                .frontier
                .as_ref()
                .and_then(|value| value.get("storage"))
                .and_then(Value::as_str),
            Some("memory")
        );

        let array_frontier: SyncDescription = serde_json::from_value(serde_json::json!({
            "service_did": "did:web:server.local",
            "supported_sync_profiles": ["initial"],
            "limits": {},
            "frontier": ["ak:event:0196419b-0000-7000-8000-000000000001"]
        }))
        .unwrap();
        assert_eq!(
            array_frontier
                .frontier
                .as_ref()
                .and_then(Value::as_array)
                .and_then(|frontier| frontier.first())
                .and_then(Value::as_str),
            Some("ak:event:0196419b-0000-7000-8000-000000000001")
        );
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncBackfillOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}
