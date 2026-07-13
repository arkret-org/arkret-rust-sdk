use super::*;

/// Folded account-aggregate delta used by SDK internals.
///
/// Current wire delivery is `ak.self.account.stream.subscribe`: an NDJSON stream of
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
    /// Closed account-private notification projection deltas.
    #[serde(default, skip_serializing_if = "notification_container_is_empty")]
    pub notifications: NotificationContainer,
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
}

impl SyncOutcome {
    /// Realm sync map.
    pub fn effective_realms(&self) -> &BTreeMap<String, Value> {
        &self.realms
    }

    /// Fold a single `ak.self.account.stream.subscribe` data frame into the SDK aggregate
    /// snapshot shape. Control frames without data return `None`.
    pub(crate) fn from_account_subscribe_frame(frame: AccountSubscribeFrame) -> Option<Self> {
        if frame.kind != AccountSubscribeFrameKind::Delta {
            return None;
        }
        let cursor = frame.cursor?;
        let mut realms = BTreeMap::new();
        if let Some(frame_realms) = frame.realms {
            realms.extend(frame_realms.entries.into_iter().map(|(realm_id, entry)| {
                (
                    realm_id,
                    serde_json::to_value(entry)
                        .expect("typed Realm sync entries must serialize to JSON"),
                )
            }));
        }
        let (
            to_device,
            to_device_ack_token,
            to_device_limited,
            to_device_next_cursor,
            to_device_lost,
        ) = match frame.to_device {
            Some(container) => (
                container
                    .messages
                    .into_iter()
                    .map(|message| {
                        serde_json::to_value(message)
                            .expect("typed device messages must serialize to JSON")
                    })
                    .collect(),
                container.ack_token,
                container.limited.unwrap_or(false),
                container.next_cursor,
                container.lost,
            ),
            None => (Vec::new(), None, false, None, None),
        };
        let event_values = |container: Option<EventContainer>| {
            container
                .map(|container| {
                    container
                        .events
                        .into_iter()
                        .map(|event| {
                            serde_json::to_value(event)
                                .expect("typed event envelopes must serialize to JSON")
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        Some(Self {
            cursor,
            realms,
            left_realms: Vec::new(),
            to_device,
            to_device_ack_token,
            to_device_limited,
            to_device_next_cursor,
            to_device_lost,
            device_lists: frame
                .device_lists
                .map(|changes| {
                    serde_json::to_value(changes)
                        .expect("typed device-list changes must serialize to JSON")
                })
                .unwrap_or(Value::Null),
            account_data: event_values(frame.account_data),
            presence: event_values(frame.presence),
            notifications: frame.notifications.unwrap_or_default(),
            partial: frame.partial.unwrap_or(false),
        })
    }
}

/// One NDJSON frame on `ak.self.account.stream.subscribe`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeFrame {
    pub kind: AccountSubscribeFrameKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<AccountSubscribeRealms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub to_device: Option<DeviceMessageContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_lists: Option<AccountSubscribeDeviceListChanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub account_data: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub presence: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<NotificationContainer>,
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
        frame.validate()?;
        Ok(Some(frame))
    }

    pub fn validate(&self) -> Result<()> {
        let has_data = self.realms.is_some()
            || self.to_device.is_some()
            || self.device_lists.is_some()
            || self.account_data.is_some()
            || self.presence.is_some()
            || self.notifications.is_some()
            || self.partial.is_some()
            || self.priority.is_some();
        if self.reconnect_after_ms == Some(0) {
            return Err(Error::Protocol(
                "reconnect_after_ms must be greater than zero".to_owned(),
            ));
        }
        if let Some(to_device) = &self.to_device {
            to_device.validate()?;
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
            return Err(Error::Protocol(format!(
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
                    Error::Protocol("stream trace dropped_missing_cursor".to_owned())
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
    fn account_subscribe_delta_accepts_closed_agent_notification_items() {
        let line = r#"{"cursor":"ak:cursor:account-2","kind":"delta","notifications":{"items":[{"action":"add","data":{"agent_id":"did:webvh:z6mkfixture:agent.example","approval_request_id":"agent_runtime_approval:01964137-0000-7000-8000-000000000002","expires_at":"2026-07-13T10:15:00Z","kind":"agent_runtime_approval","requested_at":"2026-07-13T10:00:00Z"},"id":"ak:notification:01964137-0000-7000-8000-000000000002","type":"agent"}]}}"#;
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

        let missing_data = r#"{"cursor":"ak:cursor:account-4","kind":"delta","notifications":{"items":[{"id":"ak:notification:01964137-0000-7000-8000-000000000003","type":"agent","action":"add"}]}}"#;
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

    #[test]
    fn account_subscribe_fixture_cases_match_typed_wire_model() {
        let fixture = crate::schema::embedded_json_artifact("fixtures/sync-fixture.json").unwrap();
        for case in fixture["account_subscribe_schema_cases"]
            .as_array()
            .unwrap()
        {
            let line = serde_json::to_string(&case["instance"]).unwrap();
            let accepted = AccountSubscribeFrame::from_ndjson_line(&line).is_ok();
            assert_eq!(
                accepted,
                case["expect_valid"].as_bool().unwrap(),
                "fixture case {} drifted",
                case["name"]
            );
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSubscribeRealms {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub entries: BTreeMap<String, RealmSyncEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncDescription {
    pub service_id: Did,
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
            "service_id": "did:web:server.local",
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
            "service_id": "did:web:server.local",
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
