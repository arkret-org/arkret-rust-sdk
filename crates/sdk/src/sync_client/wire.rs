use super::*;

/// One frame off the `ck.self.events.stream.subscribe` NDJSON stream
/// (`GET /_cokret/self/events/subscribe`).
///
/// The contract uses `kind` as the top field and defines control kinds clients
/// **MUST** handle explicitly:
///
/// | kind                 | meaning                                                               |
/// |----------------------|-----------------------------------------------------------------------|
/// | `event`              | one Event Envelope (the original payload kind)                        |
/// | `dropped`            | server fell behind / cursor invalidated; client MUST reset cursor     |
/// | `epoch_rotation`     | E2EE epoch advanced; pending plaintext readers MUST refresh keys      |
/// | `unauthorized`       | per-frame authz drop (one selector dropped, others continue)          |
/// | `resync_required`    | server lost connection; client MUST resubscribe with current frontier |
/// | `frontier`           | informational frontier advance without an event                       |
/// | `heartbeat`          | keep-alive (no payload state change)                                  |
/// | `catchup_complete`   | history backfill done; subsequent frames are live                     |
///
/// Each variant carries the per-frame fields the spec requires; unknown
/// variants are surfaced as [`Self::Unknown`] so callers can log and continue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EventsSubscribeFrame {
    /// Carrying one Event Envelope. `seq` is monotonic per stream; `cursor`
    /// is the resume token for this exact event.
    #[serde(rename = "event")]
    Event {
        seq: u64,
        cursor: String,
        payload: Value,
    },
    /// Server fell behind; client MUST reset its cursor and re-issue
    /// `events.query` (or fresh `events.subscribe`) starting at
    /// `recovery_from`. Optional `reason` is human-readable.
    #[serde(rename = "dropped")]
    Dropped {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
    },
    /// E2EE epoch advanced for `realm_id`. Plaintext readers MUST refresh
    /// MLS group state before consuming subsequent encrypted events in this
    /// Realm.
    #[serde(rename = "epoch_rotation")]
    EpochRotation {
        realm_id: RealmId,
        new_epoch: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_epoch: Option<u64>,
    },
    /// One selector element became unauthorized mid-stream. Other selectors
    /// continue. Client MAY surface the drop in UI.
    #[serde(rename = "unauthorized")]
    Unauthorized {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm_id: Option<RealmId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Server lost wider connection / restart; client MUST close the stream
    /// and resubscribe from the last committed frontier. Carries the server's
    /// last frontier so the client can resume cleanly.
    #[serde(rename = "resync_required")]
    ResyncRequired {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        last_frontier: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
    },
    /// Informational frontier advance without an event payload. Useful when
    /// the server processed events that aren't visible to this subscriber
    /// but the cursor moved.
    #[serde(rename = "frontier")]
    Frontier { cursor: String },
    /// Keep-alive. No state change. Servers SHOULD emit at least every 30s
    /// when the stream is otherwise idle.
    #[serde(rename = "heartbeat")]
    Heartbeat {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts: Option<DateTime<Utc>>,
    },
    /// History backfill complete; subsequent frames are real-time. Emitted
    /// after `include_history=true` finishes draining the historical buffer.
    #[serde(rename = "catchup_complete")]
    CatchupComplete {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    },
    /// Frame whose `kind` value is not in the SDK's known set. The
    /// deserializer routes here so callers can log + continue rather than
    /// treat the unknown frame as an event. Future spec additions land here
    /// until the SDK is upgraded.
    #[serde(other)]
    Unknown,
}

impl EventsSubscribeFrame {
    /// Parse one NDJSON line. Empty / whitespace-only lines parse as
    /// `Ok(None)` so callers can chunk-read transparently.
    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame: Self = canonical::from_canonical_json_str(trimmed)?;
        Ok(Some(frame))
    }

    /// True for the two terminal kinds that require the client to abandon
    /// the current cursor and start a fresh subscribe.
    pub fn requires_resubscribe(&self) -> bool {
        matches!(self, Self::Dropped { .. } | Self::ResyncRequired { .. })
    }

    /// True when the frame indicates the historical backfill is done and
    /// subsequent frames are live.
    pub fn is_catchup_complete(&self) -> bool {
        matches!(self, Self::CatchupComplete { .. })
    }

    /// True when the frame carries an Event Envelope payload.
    pub fn is_event(&self) -> bool {
        matches!(self, Self::Event { .. })
    }
}

/// Selector + range parameters for `ck.self.events.query.scan` and
/// `ck.self.events.stream.subscribe`. Per spec C17, the selector is `realms[]` ∪
/// `actors[]` (at least one element). Range parameters apply only to
/// `query`; `subscribe` accepts `after` + `catchup`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQuerySelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<EventsQueryOrder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
}

impl EventsQuerySelector {
    /// Validate that the selector has at least one Realm or actor element
    /// (spec MUST). Returns `Err` if both are empty.
    pub fn validate_non_empty(&self) -> Result<()> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(Error::Protocol(
                "events.query/subscribe selector requires at least one of realms[] / actors[]"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Render selector + range as the wire query string for
    /// `GET /_cokret/self/events` or `GET /_cokret/self/events/subscribe`. Repeats
    /// `realms` / `actors` query args per spec convention.
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        for realm in &self.realms {
            pairs.push(("realms", realm.as_str().to_owned()));
        }
        for actor in &self.actors {
            pairs.push(("actors", actor.clone()));
        }
        if let Some(before) = &self.before {
            pairs.push(("before", before.clone()));
        }
        if let Some(after) = &self.after {
            pairs.push(("after", after.clone()));
        }
        if let Some(order) = &self.order {
            pairs.push(("order", order.as_str().to_owned()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(catchup) = self.catchup {
            pairs.push(("catchup", catchup.to_string()));
        }
        pairs
    }
}

/// Ordering parameter for `ck.self.events.query.scan`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryOrder {
    #[default]
    Default,
    Ascending,
    Descending,
}

/// Typed `ck.self.events.query.scan` request body.
///
/// This is the ergonomic typed surface downstream agents (coauth / soland /
/// yougen) call against. It mirrors the wire shape soland accepts on
/// `GET /_cokret/self/events`: the multi-selector is `realms[] ∪ actors[]`,
/// `before` / `after` are exclusive cursor bounds, `order` controls batch
/// ordering, and `limit` is the page cap.
///
/// Construct one with [`Self::new`] / fluent with-setters; render the
/// query string with [`Self::to_query_pairs`] (delegated to the inner
/// [`EventsQuerySelector`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQueryRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default)]
    pub order: EventsQueryOrder,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl EventsQueryRequestBody {
    /// Construct an empty request. Caller MUST add at least one Realm or
    /// actor before issuing or [`Self::validate_non_empty`] will fail.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_realms(mut self, realms: Vec<RealmId>) -> Self {
        self.realms = realms;
        self
    }

    pub fn with_actors(mut self, actors: Vec<String>) -> Self {
        self.actors = actors;
        self
    }

    pub fn with_before(mut self, before: impl Into<String>) -> Self {
        self.before = Some(before.into());
        self
    }

    pub fn with_after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    pub fn with_order(mut self, order: EventsQueryOrder) -> Self {
        self.order = order;
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Validate that the selector has at least one Realm or actor element
    /// (spec MUST). Returns `Err` if both are empty.
    pub fn validate_non_empty(&self) -> Result<()> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(Error::Protocol(
                "events.query request requires at least one of realms[] / actors[]".to_owned(),
            ));
        }
        Ok(())
    }

    /// Convert to the underlying [`EventsQuerySelector`] used by transport
    /// helpers. The selector is the `events.subscribe`-compatible parent
    /// shape; this request type is the `events.query`-only narrow view.
    pub fn as_selector(&self) -> EventsQuerySelector {
        EventsQuerySelector {
            realms: self.realms.clone(),
            actors: self.actors.clone(),
            before: self.before.clone(),
            after: self.after.clone(),
            order: Some(self.order),
            limit: self.limit,
            catchup: None,
        }
    }

    /// Render the request as repeated `?realms=...&actors=...&before=...`
    /// query pairs for `GET /_cokret/self/events`.
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        self.as_selector().to_query_pairs()
    }
}

impl EventsQueryOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}
