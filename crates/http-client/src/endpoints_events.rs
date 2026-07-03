//! Event stream / query / submit, snapshot, and authz endpoint methods
//! on [`Client`].

use cokret_core::{
    AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList, Event, EventsSubmitOutcome,
    GrantList, Result, SnapshotManifest, SyncBackfillOutcome,
};
use reqwest::{Method, Response};

use crate::{Client, ClientRequestOptions};

impl Client {
    /// Subscribe to the Event stream for one or more Realms / actors via
    /// `ck.self.events.stream.subscribe` (`GET /_cokret/self/events/subscribe`). The selector is
    /// `realms[]` ∪ `actors[]` repeated query args, and frames use top-level
    /// `kind` with explicit control variants.
    ///
    /// Round C47 (spec e10b6ad): the response Content-Type is now
    /// `application/x-ndjson` (was `text/event-stream`). The client sends an
    /// `Accept: application/x-ndjson` header so old SSE-only servers reject
    /// up front instead of streaming a shape we cannot parse.
    pub async fn events_subscribe_stream(
        &self,
        realm_id: &str,
        after: Option<&str>,
    ) -> Result<Response> {
        // Long-lived NDJSON stream — exempt from the per-request default
        // total timeout (see `DEFAULT_REQUEST_TIMEOUT`).
        let mut builder = self
            .request_unbounded(Method::GET, "/_cokret/self/events/subscribe")?
            .header("accept", "application/x-ndjson")
            .query(&[("realms", realm_id)]);
        if let Some(after) = after {
            builder = builder.query(&[("after", after)]);
        }
        self.send_response(builder).await
    }

    /// Range-read Events via `ck.self.events.query.scan` (`GET /_cokret/self/events`). Pass
    /// `before` to walk older history, `after` to catch up toward newer events,
    /// and `order` to override the default proximity-to-seal ordering.
    pub async fn events_query(
        &self,
        realm_id: &str,
        before: Option<&str>,
        after: Option<&str>,
        order: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SyncBackfillOutcome> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/events")?
            .query(&[("realms", realm_id)]);
        if let Some(before) = before {
            builder = builder.query(&[("before", before)]);
        }
        if let Some(after) = after {
            builder = builder.query(&[("after", after)]);
        }
        if let Some(order) = order {
            builder = builder.query(&[("order", order)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    /// Submit a single signed Event Envelope via `ck.self.events.command.submit`
    /// (`POST /_cokret/self/events`). Wire body is the bare envelope per the OpenAPI
    /// `oneOf` first arm (`event-envelope.schema.json`).
    pub async fn events_submit(&self, event: &Event) -> Result<EventsSubmitOutcome> {
        self.post("/_cokret/self/events", event).await
    }

    /// [`events_submit`](Self::events_submit) with per-request options.
    ///
    /// Attaching an `Idempotency-Key` via
    /// [`ClientRequestOptions::idempotency_key`] makes this POST eligible
    /// for the transparent 5xx/timeout retry gate (the server dedupes on
    /// `event_id` + canonical bytes per operations-sync.md §events.submit,
    /// so a resend is an idempotent no-op returning `duplicate[]`).
    pub async fn events_submit_with_options(
        &self,
        event: &Event,
        options: &ClientRequestOptions,
    ) -> Result<EventsSubmitOutcome> {
        self.post_with_options("/_cokret/self/events", event, options)
            .await
    }

    /// Submit a batch of signed Event Envelopes via `ck.self.events.command.submit`
    /// (`POST /_cokret/self/events`) using the `EventsSubmitBatchRequestBody` body shape.
    pub async fn events_submit_batch(&self, events: &[Event]) -> Result<EventsSubmitOutcome> {
        self.events_submit_batch_with_options(events, &ClientRequestOptions::default())
            .await
    }

    /// [`events_submit_batch`](Self::events_submit_batch) with per-request
    /// options; see [`events_submit_with_options`](Self::events_submit_with_options)
    /// for the retry semantics of an attached `Idempotency-Key`.
    pub async fn events_submit_batch_with_options(
        &self,
        events: &[Event],
        options: &ClientRequestOptions,
    ) -> Result<EventsSubmitOutcome> {
        #[derive(serde::Serialize)]
        struct Batch<'a> {
            events: &'a [Event],
        }
        self.post_with_options("/_cokret/self/events", &Batch { events }, options)
            .await
    }

    pub async fn snapshot_head(&self, realm_id: &str) -> Result<SnapshotManifest> {
        let builder = self
            .request(Method::GET, "/_cokret/self/snapshot/head")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequestBody) -> Result<AuthzCheckOutcome> {
        self.post("/_cokret/self/authz/check", request).await
    }

    pub async fn authz_effective_grants(
        &self,
        realm_id: &str,
        subject: &str,
        at: Option<&str>,
    ) -> Result<GrantList> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/authz/effective-grants")?
            .query(&[("realm_id", realm_id), ("subject", subject)]);
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn authz_invites(
        &self,
        subject: &str,
        realm_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<AuthzInviteList> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/authz/invites")?
            .query(&[("subject", subject)]);
        if let Some(realm_id) = realm_id {
            builder = builder.query(&[("realm_id", realm_id)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }
}
