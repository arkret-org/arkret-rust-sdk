use super::*;

/// One frame off the `ck.events.subscribe` NDJSON stream
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
    Event { seq: u64, cursor: String, payload: Value },
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
    /// E2EE epoch advanced for `space_id`. Plaintext readers MUST refresh
    /// MLS group state before consuming subsequent encrypted events on this
    /// space.
    #[serde(rename = "epoch_rotation")]
    EpochRotation {
        space_id: SpaceId,
        new_epoch: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_epoch: Option<u64>,
    },
    /// One selector element became unauthorized mid-stream. Other selectors
    /// continue. Client MAY surface the drop in UI.
    #[serde(rename = "unauthorized")]
    Unauthorized {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        space_id: Option<SpaceId>,
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
        let frame: Self = serde_json::from_str(trimmed).map_err(Error::from)?;
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

/// Selector + range parameters for `ck.events.query` and
/// `ck.events.subscribe`. Per spec C17, the selector is `spaces[]` ∪
/// `actors[]` (at least one element). Range parameters apply only to
/// `query`; `subscribe` accepts `from` + `include_history`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQuerySelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<EventsQueryDirection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_history: Option<bool>,
}

impl EventsQuerySelector {
    /// Validate that the selector has at least one space or actor element
    /// (spec MUST). Returns `Err` if both are empty.
    pub fn validate_non_empty(&self) -> Result<()> {
        if self.spaces.is_empty() && self.actors.is_empty() {
            return Err(Error::Protocol(
                "events.query/subscribe selector requires at least one of spaces[] / actors[]"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Render selector + range as the wire query string for
    /// `GET /_cokret/self/events/query` or `GET /_cokret/self/events/subscribe`. Repeats
    /// `spaces` / `actors` query args per spec convention.
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        for space in &self.spaces {
            pairs.push(("spaces", space.as_str().to_owned()));
        }
        for actor in &self.actors {
            pairs.push(("actors", actor.clone()));
        }
        if let Some(from) = &self.from {
            pairs.push(("from", from.clone()));
        }
        if let Some(until) = &self.until {
            pairs.push(("until", until.clone()));
        }
        if let Some(direction) = &self.direction {
            pairs.push(("direction", direction.as_str().to_owned()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(include_history) = self.include_history {
            pairs.push(("include_history", include_history.to_string()));
        }
        pairs
    }
}

/// Direction parameter for `ck.events.query`. `forward` returns events
/// after `from` (default); `backward` returns events before `from`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryDirection {
    #[default]
    Forward,
    Backward,
}

/// Typed `ck.events.query` request body.
///
/// This is the ergonomic typed surface downstream agents (coauth / soland /
/// yougen) call against. It mirrors the wire shape soland accepts on
/// `GET /_cokret/self/events/query`: the multi-selector is `spaces[] ∪ actors[]`,
/// `from` / `until` are HLC bounds, `direction` switches between forward
/// (default) and backward iteration, and `limit` is the page cap.
///
/// Construct one with [`Self::new`] / fluent with-setters; render the
/// query string with [`Self::to_query_pairs`] (delegated to the inner
/// [`EventsQuerySelector`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQueryReqBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(default)]
    pub direction: EventsQueryDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl EventsQueryReqBody {
    /// Construct an empty request. Caller MUST add at least one space or
    /// actor before issuing or [`Self::validate_non_empty`] will fail.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_spaces(mut self, spaces: Vec<SpaceId>) -> Self {
        self.spaces = spaces;
        self
    }

    pub fn with_actors(mut self, actors: Vec<String>) -> Self {
        self.actors = actors;
        self
    }

    pub fn with_from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    pub fn with_until(mut self, until: impl Into<String>) -> Self {
        self.until = Some(until.into());
        self
    }

    pub fn with_direction(mut self, direction: EventsQueryDirection) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Validate that the selector has at least one space or actor element
    /// (spec MUST). Returns `Err` if both are empty.
    pub fn validate_non_empty(&self) -> Result<()> {
        if self.spaces.is_empty() && self.actors.is_empty() {
            return Err(Error::Protocol(
                "events.query request requires at least one of spaces[] / actors[]".to_owned(),
            ));
        }
        Ok(())
    }

    /// Convert to the underlying [`EventsQuerySelector`] used by transport
    /// helpers. The selector is the `events.subscribe`-compatible parent
    /// shape; this request type is the `events.query`-only narrow view.
    pub fn as_selector(&self) -> EventsQuerySelector {
        EventsQuerySelector {
            spaces: self.spaces.clone(),
            actors: self.actors.clone(),
            from: self.from.clone(),
            until: self.until.clone(),
            direction: Some(self.direction),
            limit: self.limit,
            include_history: None,
        }
    }

    /// Render the request as repeated `?spaces=...&actors=...&from=...`
    /// query pairs for `GET /_cokret/self/events/query`.
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        self.as_selector().to_query_pairs()
    }
}

/// Typed `ck.events.query` response body.
///
/// Downstream agents pattern-match on `events`, then resume with
/// `next_cursor` (forward) / `prev_cursor` (backward). Server returns
/// `limited=true` when the page hit `limit` and more events remain.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventsQueryResBody {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "is_false_default")]
    pub limited: bool,
}

fn is_false_default(v: &bool) -> bool {
    !*v
}

impl From<cokret_core::SyncBackfillResBody> for EventsQueryResBody {
    fn from(r: cokret_core::SyncBackfillResBody) -> Self {
        Self {
            events: r.events,
            next_cursor: r.next_cursor,
            prev_cursor: r.prev_cursor,
            limited: r.limited,
        }
    }
}

impl From<EventsQueryResBody> for cokret_core::SyncBackfillResBody {
    fn from(r: EventsQueryResBody) -> Self {
        Self {
            events: r.events,
            next_cursor: r.next_cursor,
            prev_cursor: r.prev_cursor,
            limited: r.limited,
        }
    }
}

impl EventsQueryDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Backward => "backward",
        }
    }
}
