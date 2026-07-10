//! Event stream / query / submit, snapshot, and authz endpoint methods
//! on [`Client`].

use arkret_core::{
    AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList, CollectionProjectionView,
    DocumentMorphProjectionOutcome, Error, Event, EventsQueryOutcome, EventsSubmitBatchRequestBody,
    EventsSubmitOutcome, EventsSubscribeFrame, GrantList, ProjectionSpaceList,
    ProjectionStrandList, RealmOrganizationRelationshipList, Result, ServiceDescribe,
    SyncBackfillOutcome, ViewProjectionRequestBody,
};
use arkret_state::SnapshotManifest;
use reqwest::{Method, Response};

use crate::{Client, ClientRequestOptions, reject_path_segment};

const MAX_EVENTS_QUERY_PAGES: usize = 100;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventsSubscribeOptions {
    pub realms: Vec<String>,
    pub actors: Vec<String>,
    pub after: Option<String>,
    pub include_history: Option<bool>,
    pub max_duration_ms: Option<u64>,
    pub heartbeat_ms: Option<u64>,
}

impl EventsSubscribeOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn realm(mut self, realm_id: impl Into<String>) -> Self {
        self.realms.push(realm_id.into());
        self
    }

    #[must_use]
    pub fn actor(mut self, actor_id: impl Into<String>) -> Self {
        self.actors.push(actor_id.into());
        self
    }

    #[must_use]
    pub fn after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    #[must_use]
    pub fn include_history(mut self, include_history: bool) -> Self {
        self.include_history = Some(include_history);
        self
    }

    #[must_use]
    pub fn max_duration_ms(mut self, max_duration_ms: u64) -> Self {
        self.max_duration_ms = Some(max_duration_ms);
        self
    }

    #[must_use]
    pub fn heartbeat_ms(mut self, heartbeat_ms: u64) -> Self {
        self.heartbeat_ms = Some(heartbeat_ms);
        self
    }
}

#[cfg(not(target_arch = "wasm32"))]
type BoxEventsSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<EventsSubscribeFrame>> + Send>>;

#[cfg(target_arch = "wasm32")]
type BoxEventsSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<EventsSubscribeFrame>>>>;

pub struct EventsSubscribeFrameStream {
    inner: BoxEventsSubscribeFrameStream,
}

impl EventsSubscribeFrameStream {
    pub async fn next_frame(&mut self) -> Result<Option<EventsSubscribeFrame>> {
        use futures_util::StreamExt;

        self.inner.next().await.transpose()
    }
}

impl Client {
    /// Describe the Event service via `ak.self.events.query.describe`
    /// (`GET /_arkret/self/events/describe`).
    pub async fn events_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/self/events/describe").await
    }

    /// Subscribe to the Event stream for one or more Realms / actors via
    /// `ak.self.events.stream.subscribe` (`GET /_arkret/self/events/subscribe`). The selector is
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
        let mut options = EventsSubscribeOptions::new().realm(realm_id);
        if let Some(after) = after {
            options = options.after(after);
        }
        self.events_subscribe_stream_with_options(&options).await
    }

    pub async fn events_subscribe_stream_with_options(
        &self,
        options: &EventsSubscribeOptions,
    ) -> Result<Response> {
        let builder = self.events_subscribe_request(options)?;
        self.send_response(builder).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn events_subscribe_frames(
        &self,
        options: &EventsSubscribeOptions,
    ) -> Result<EventsSubscribeFrameStream> {
        use futures_util::StreamExt;
        use tokio_util::codec::{FramedRead, LinesCodec};
        use tokio_util::io::StreamReader;

        let response = self.events_subscribe_stream_with_options(options).await?;
        let byte_stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other));
        let reader = StreamReader::new(byte_stream);
        let lines = FramedRead::new(
            reader,
            LinesCodec::new_with_max_length(crate::MAX_SUBSCRIBE_FRAME_BYTES),
        );
        let stream = lines.filter_map(|line_res| async move {
            match line_res {
                Ok(line) => match EventsSubscribeFrame::from_ndjson_line(&line) {
                    Ok(Some(frame)) => Some(Ok(frame)),
                    Ok(None) => None,
                    Err(err) => Some(Err(err)),
                },
                Err(err) => Some(Err(Error::Protocol(format!(
                    "events subscribe line read failed: {err}"
                )))),
            }
        });
        Ok(EventsSubscribeFrameStream {
            inner: Box::pin(stream),
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn events_subscribe_frames(
        &self,
        options: &EventsSubscribeOptions,
    ) -> Result<EventsSubscribeFrameStream> {
        let response = self.events_subscribe_stream_with_options(options).await?;
        let bytes = response
            .bytes()
            .await
            .map_err(crate::client_internals::transport_error)?;
        if bytes.len() > crate::client_internals::MAX_RESPONSE_BODY_BYTES {
            return Err(Error::Protocol(
                "events subscribe buffered response exceeds limit".to_owned(),
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            Error::Protocol(format!("events subscribe response is not UTF-8: {error}"))
        })?;
        let mut frames = Vec::new();
        for line in text.lines() {
            if line.len() > crate::MAX_SUBSCRIBE_FRAME_BYTES {
                return Err(Error::Protocol(
                    "events subscribe frame exceeds limit".to_owned(),
                ));
            }
            if let Some(frame) = EventsSubscribeFrame::from_ndjson_line(line)? {
                frames.push(Ok(frame));
            }
        }
        Ok(EventsSubscribeFrameStream {
            inner: Box::pin(futures_util::stream::iter(frames)),
        })
    }

    fn events_subscribe_request(
        &self,
        options: &EventsSubscribeOptions,
    ) -> Result<reqwest::RequestBuilder> {
        if options.realms.is_empty() && options.actors.is_empty() {
            return Err(Error::Protocol(
                "events subscribe requires at least one realm or actor selector".to_owned(),
            ));
        }

        // Long-lived NDJSON stream — exempt from the per-request default
        // total timeout (see `DEFAULT_REQUEST_TIMEOUT`).
        let mut builder = self
            .request_unbounded(Method::GET, "/_arkret/self/events/subscribe")?
            .header("accept", "application/x-ndjson");
        for realm_id in &options.realms {
            builder = builder.query(&[("realms", realm_id)]);
        }
        for actor_id in &options.actors {
            builder = builder.query(&[("actors", actor_id)]);
        }
        if let Some(after) = options.after.as_deref() {
            builder = builder.query(&[("after", after)]);
        }
        if let Some(include_history) = options.include_history {
            builder = builder.query(&[("include_history", include_history)]);
        }
        if let Some(max_duration_ms) = options.max_duration_ms {
            builder = builder.query(&[("max_duration_ms", max_duration_ms)]);
        }
        if let Some(heartbeat_ms) = options.heartbeat_ms {
            builder = builder.query(&[("heartbeat_ms", heartbeat_ms)]);
        }
        crate::client_internals::validate_request_builder(&builder)?;
        Ok(builder)
    }

    /// Range-read Events via `ak.self.events.query.scan` (`GET /_arkret/self/events`). Pass
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
            .request(Method::GET, "/_arkret/self/events")?
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

    /// Range-read Events via the standard `EventsQueryOutcome` response
    /// shape (`has_more`, `range_completeness`) from `ak.self.events.query.scan`.
    pub async fn events_query_outcome(
        &self,
        realm_id: &str,
        before: Option<&str>,
        after: Option<&str>,
        order: Option<&str>,
        limit: Option<u32>,
        include_completeness: Option<bool>,
    ) -> Result<EventsQueryOutcome> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/events")?
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
        if let Some(include_completeness) = include_completeness {
            builder = builder.query(&[("include_completeness", include_completeness)]);
        }
        self.send_json(builder).await
    }

    /// Walk every page of `ak.self.events.query.scan` for a Realm using
    /// the standard `has_more` / `next_cursor` contract.
    pub async fn events_query_all_pages(&self, realm_id: &str) -> Result<EventsQueryOutcome> {
        let mut combined = self
            .events_query_outcome(realm_id, None, None, None, None, None)
            .await?;
        let mut pages = 1usize;
        let mut last_cursor: Option<String> = None;
        while combined.has_more {
            let Some(next) = combined
                .next_cursor
                .as_deref()
                .map(str::trim)
                .filter(|cursor| !cursor.is_empty())
                .map(ToOwned::to_owned)
            else {
                return Err(Error::Protocol(format!(
                    "events query for realm {realm_id} reported has_more but no next_cursor"
                )));
            };
            if last_cursor.as_deref() == Some(next.as_str()) {
                return Err(Error::Protocol(format!(
                    "events query for realm {realm_id} did not advance next_cursor ({next}); aborting to avoid a pagination loop"
                )));
            }
            if pages >= MAX_EVENTS_QUERY_PAGES {
                return Err(Error::Protocol(format!(
                    "events query for realm {realm_id} exceeded {MAX_EVENTS_QUERY_PAGES} pages; aborting"
                )));
            }
            let page = self
                .events_query_outcome(realm_id, None, Some(&next), None, None, None)
                .await?;
            combined.events.extend(page.events);
            combined.has_more = page.has_more;
            combined.next_cursor = page.next_cursor;
            combined.range_completeness = page.range_completeness;
            last_cursor = Some(next);
            pages += 1;
        }
        Ok(combined)
    }

    /// Submit a single signed Event Envelope via `ak.self.events.command.submit`
    /// (`POST /_arkret/self/events`). Wire body is the bare envelope per the OpenAPI
    /// `oneOf` first arm (`event-envelope.schema.json`).
    pub async fn events_submit(&self, event: &Event) -> Result<EventsSubmitOutcome> {
        self.post("/_arkret/self/events", event).await
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
        self.post_with_options("/_arkret/self/events", event, options)
            .await
    }

    /// Submit a batch of signed Event Envelopes via `ak.self.events.command.submit`
    /// (`POST /_arkret/self/events`) using the `EventsSubmitBatchRequestBody` body shape.
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
        let body = EventsSubmitBatchRequestBody {
            events: events.to_vec(),
            idempotency_key: options.idempotency_key.clone(),
        };
        self.post_with_options("/_arkret/self/events", &body, options)
            .await
    }

    pub async fn snapshot_head(&self, realm_id: &str) -> Result<SnapshotManifest> {
        let builder = self
            .request(Method::GET, "/_arkret/self/snapshot/head")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequestBody) -> Result<AuthzCheckOutcome> {
        self.post("/_arkret/self/authz/check", request).await
    }

    pub async fn authz_effective_grants(
        &self,
        realm_id: &str,
        subject: &str,
        at: Option<&str>,
    ) -> Result<GrantList> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/authz/effective-grants")?
            .query(&[("realm_id", realm_id), ("subject", subject)]);
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn authz_effective_grants_for_subject(
        &self,
        subject: &str,
        at: Option<&str>,
    ) -> Result<GrantList> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/authz/effective-grants")?
            .query(&[("subject", subject)]);
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
            .request(Method::GET, "/_arkret/self/authz/invites")?
            .query(&[("subject", subject)]);
        if let Some(realm_id) = realm_id {
            builder = builder.query(&[("realm_id", realm_id)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }

    pub async fn collection_projection(
        &self,
        view_id: &str,
        request: &ViewProjectionRequestBody,
    ) -> Result<CollectionProjectionView> {
        reject_path_segment(view_id)?;
        let path = format!("/_arkret/self/views/{view_id}/projection");
        self.post(&path, request).await
    }

    pub async fn realm_spaces(&self, realm_id: &str) -> Result<ProjectionSpaceList> {
        reject_path_segment(realm_id)?;
        let path = format!("/_arkret/self/realms/{realm_id}/spaces");
        self.get(&path).await
    }

    pub async fn realm_strands(&self, realm_id: &str) -> Result<ProjectionStrandList> {
        reject_path_segment(realm_id)?;
        let path = format!("/_arkret/self/realms/{realm_id}/strands");
        self.get(&path).await
    }

    pub async fn document_projection(
        &self,
        realm_id: &str,
        morph_id: &str,
    ) -> Result<DocumentMorphProjectionOutcome> {
        reject_path_segment(realm_id)?;
        reject_path_segment(morph_id)?;
        let path = format!("/_arkret/self/realms/{realm_id}/morphs/{morph_id}");
        self.get(&path).await
    }

    pub async fn realm_organizations(
        &self,
        realm_id: &str,
    ) -> Result<RealmOrganizationRelationshipList> {
        reject_path_segment(realm_id)?;
        let path = format!("/_arkret/self/realms/{realm_id}/organizations");
        self.get(&path).await
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use url::Url;

    use super::*;

    fn client() -> Client {
        Client::new(Url::parse("https://alice.example/").unwrap()).unwrap()
    }

    #[test]
    fn events_subscribe_request_serializes_stream_options() {
        let options = EventsSubscribeOptions::new()
            .realm("ak:realm:01904100-0000-7000-8000-000000000001")
            .actor("did:webvh:z6mkfixture:alice.example")
            .after("ak:cursor:stored")
            .include_history(true)
            .max_duration_ms(150)
            .heartbeat_ms(100);

        let built = client()
            .events_subscribe_request(&options)
            .unwrap()
            .build()
            .unwrap();
        let query = built.url().query().unwrap().to_owned();

        assert!(
            query.contains("realms=ak%3Arealm%3A01904100-0000-7000-8000-000000000001"),
            "query: {query}"
        );
        assert!(
            query.contains("actors=did%3Awebvh%3Az6mkfixture%3Aalice.example"),
            "query: {query}"
        );
        assert!(
            query.contains("after=ak%3Acursor%3Astored"),
            "query: {query}"
        );
        assert!(query.contains("include_history=true"), "query: {query}");
        assert!(query.contains("max_duration_ms=150"), "query: {query}");
        assert!(query.contains("heartbeat_ms=100"), "query: {query}");
    }

    #[test]
    fn events_subscribe_request_requires_selector() {
        let error = client()
            .events_subscribe_request(&EventsSubscribeOptions::new())
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("realm or actor")));
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn spawn_chunked_ndjson_server(body_parts: Vec<&'static str>) -> Client {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let body: String = body_parts.iter().copied().collect();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            for part in body_parts {
                socket.write_all(part.as_bytes()).await.unwrap();
                tokio::task::yield_now().await;
            }
            socket.shutdown().await.ok();
        });

        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        Client::builder(base)
            .allow_insecure_localhost()
            .build()
            .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn events_subscribe_frames_yields_one_frame_per_line() {
        let parts = vec![
            "{\"kind\":\"heartbeat\"}\n",
            "{\"kind\":\"catchup_",
            "complete\"}\n",
        ];
        let mut stream = spawn_chunked_ndjson_server(parts)
            .await
            .events_subscribe_frames(
                &EventsSubscribeOptions::new()
                    .realm("ak:realm:01904100-0000-7000-8000-000000000001")
                    .include_history(true)
                    .max_duration_ms(150)
                    .heartbeat_ms(100),
            )
            .await
            .expect("stream init");

        let mut got = Vec::new();
        while let Some(frame) = stream.next_frame().await.expect("frame read") {
            got.push(frame);
        }

        assert_eq!(got.len(), 2, "expected 2 frames, got {got:?}");
        assert_eq!(
            got[0].kind,
            arkret_core::EventsSubscribeFrameKind::Heartbeat
        );
        assert!(got[1].is_catchup_complete());
    }
}
