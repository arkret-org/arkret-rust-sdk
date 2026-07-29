//! Event stream / query / submit, snapshot, and authz endpoint methods
//! on [`Client`].

use arkret_models_collaboration::governance::authorization::{
    AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList, GrantList,
};
use arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList;
use arkret_models_collaboration::http_bodies::{
    EventSealSubmitOutcome, EventView, EventsQueryOutcome, EventsSubmitBatchRequestBody,
    EventsSubmitOutcome, EventsSubscribeFrame, ProjectionSpaceList, ProjectionStrandList,
};
use arkret_models_collaboration::objects::query_projection::{
    CollectionProjectionView, DocumentMorphProjectionOutcome, ViewProjectionRequestBody,
};
use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
use arkret_models_crypto::{
    MaterializedMlsGovernanceProofBundle, MlsGovernanceProofBundle,
    MlsGovernanceProofRequestBodyBody, assemble_mls_governance_proof_chunks,
};
use arkret_models_discovery::ServiceDescribe;
use arkret_state::SnapshotManifest;
use arkret_wire::{
    EventInitialSubmission, Hash, ProposalReceiptIssueOutcome, ProposalReceiptIssueRequest, Seal,
};
use reqwest::{Method, Response};

use crate::{Client, ClientRequestOptions, Error, Result, reject_path_segment};

const MAX_EVENTS_QUERY_PAGES: usize = 100;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventsSubscribeOptions {
    pub realms: Vec<String>,
    pub actors: Vec<String>,
    pub after: Option<String>,
    pub catchup: Option<bool>,
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
    pub fn catchup(mut self, catchup: bool) -> Self {
        self.catchup = Some(catchup);
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
    trace: StreamTraceValidator,
    failed: bool,
}

impl EventsSubscribeFrameStream {
    pub async fn next_frame(&mut self) -> Result<Option<EventsSubscribeFrame>> {
        use futures_util::StreamExt;

        if self.failed {
            return Err(Error::Protocol(
                "events subscribe stream was already rejected".to_owned(),
            ));
        }
        let frame = match self.inner.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(error)) => {
                self.failed = true;
                return Err(error);
            }
            None => {
                self.trace.finish()?;
                return Ok(None);
            }
        };
        self.trace.push(&frame)?;
        Ok(Some(frame))
    }

    pub fn reconnect_cursor(&self) -> Option<&str> {
        self.trace.reconnect_cursor()
    }

    pub const fn is_terminal(&self) -> bool {
        self.trace.is_terminal()
    }
}

impl Client {
    pub async fn issue_control_proposal_receipt(
        &self,
        request: &ProposalReceiptIssueRequest,
    ) -> Result<ProposalReceiptIssueOutcome> {
        request.validate_structural()?;
        let outcome: ProposalReceiptIssueOutcome = self
            .post("/_arkret/self/control-proposal-receipts", request)
            .await?;
        outcome.member_receipt.validate_protocol_bounds()?;
        let event_digest = Hash::new(request.event.event_digest()?)?;
        if outcome.member_receipt.realm_id != request.event.realm_id
            || outcome.member_receipt.proposal_digest != event_digest
        {
            return Err(Error::Protocol(
                "proposal member receipt response changed the Event binding".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Describe the Event service via `ak.self.events.query.describe`
    /// (`GET /_arkret/self/events/describe`).
    pub async fn events_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/self/events/describe").await
    }

    /// Fetch one accepted Event together with its server-visible receipt
    /// objects. B-model recovery uses this after atomic submission to obtain
    /// and validate the generated `ak.schema.event_batch_receipt.v1`.
    pub async fn event_view(&self, event_id: &str) -> Result<EventView> {
        reject_path_segment(event_id)?;
        self.get(&format!("/_arkret/self/events/{event_id}")).await
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
    async fn events_subscribe_stream_with_options(
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
                    Err(err) => Some(Err(err.into())),
                },
                Err(err) => Some(Err(Error::Protocol(format!(
                    "events subscribe line read failed: {err}"
                )))),
            }
        });
        Ok(EventsSubscribeFrameStream {
            inner: Box::pin(stream),
            trace: StreamTraceValidator::new(
                options.catchup.unwrap_or(false),
                options.after.clone(),
            ),
            failed: false,
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
            trace: StreamTraceValidator::new(
                options.catchup.unwrap_or(false),
                options.after.clone(),
            ),
            failed: false,
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
        if let Some(catchup) = options.catchup {
            builder = builder.query(&[("catchup", catchup)]);
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

    /// Fetch a complete accepted-Seal proof for a full-profile MLS
    /// governance binding.
    pub async fn mls_governance_proof(
        &self,
        request: &MlsGovernanceProofRequestBodyBody,
    ) -> Result<MlsGovernanceProofBundle> {
        request.validate()?;
        self.post("/_arkret/self/events/mls-governance-proof", request)
            .await
    }

    /// Fetch and authenticate every chunk of one logical MLS governance proof.
    pub async fn mls_governance_proof_complete(
        &self,
        request: &MlsGovernanceProofRequestBodyBody,
    ) -> Result<MaterializedMlsGovernanceProofBundle> {
        let mut first_request = request.clone();
        first_request.chunk_index = 0;
        first_request.expected_bundle_digest = None;
        let first = self.mls_governance_proof(&first_request).await?;
        let chunk_count = first.chunk_manifest.chunk_count;
        let bundle_digest = first.bundle_digest.clone();
        let mut responses = Vec::with_capacity(chunk_count as usize);
        responses.push(first);
        for chunk_index in 1..chunk_count {
            let mut next_request = first_request.clone();
            next_request.chunk_index = chunk_index;
            next_request.expected_bundle_digest = Some(bundle_digest.clone());
            responses.push(self.mls_governance_proof(&next_request).await?);
        }
        Ok(assemble_mls_governance_proof_chunks(
            &first_request,
            &responses,
        )?)
    }

    /// Submit one initial Event publication via `ak.self.events.command.submit`
    /// (`POST /_arkret/self/events`). Wire body is the first `oneOf` arm of
    /// `EventsSubmitRequestBody`, i.e. `EventInitialSubmission` — the signed
    /// Event plus the publication evidence that bounds it. A bare Event
    /// Envelope is no longer a valid body.
    ///
    /// The caller owns `authorization_lease`. Minting one requires the issuer
    /// signing keys and the authority-set identity of the party that granted
    /// the capability, neither of which this client holds, so the SDK never
    /// fabricates a lease on the caller's behalf.
    pub async fn events_submit(
        &self,
        submission: &EventInitialSubmission,
    ) -> Result<EventsSubmitOutcome> {
        self.post("/_arkret/self/events", submission).await
    }

    /// [`events_submit`](Self::events_submit) with per-request options.
    ///
    /// Attaching an `Idempotency-Key` via
    /// [`ClientRequestOptions::idempotency_key`] makes this POST eligible
    /// for the transparent 5xx/timeout retry gate (the server dedupes on
    /// `event_id` + canonical bytes per operations-sync.md §events.submit,
    /// so a resend is an idempotent no-op returning `duplicate[]`). The key
    /// travels only in the header — it is not a request-body field.
    pub async fn events_submit_with_options(
        &self,
        submission: &EventInitialSubmission,
        options: &ClientRequestOptions,
    ) -> Result<EventsSubmitOutcome> {
        self.post_with_options("/_arkret/self/events", submission, options)
            .await
    }

    /// Submit a batch of initial Event publications via
    /// `ak.self.events.command.submit` (`POST /_arkret/self/events`) using the
    /// `EventsSubmitBatchRequestBody` body shape. Each element carries its own
    /// caller-minted lease; see [`events_submit`](Self::events_submit).
    pub async fn events_submit_batch(
        &self,
        submissions: &[EventInitialSubmission],
    ) -> Result<EventsSubmitOutcome> {
        self.events_submit_batch_with_options(submissions, &ClientRequestOptions::default())
            .await
    }

    /// [`events_submit_batch`](Self::events_submit_batch) with per-request
    /// options; see [`events_submit_with_options`](Self::events_submit_with_options)
    /// for the retry semantics of an attached `Idempotency-Key`.
    pub async fn events_submit_batch_with_options(
        &self,
        submissions: &[EventInitialSubmission],
        options: &ClientRequestOptions,
    ) -> Result<EventsSubmitOutcome> {
        let body = EventsSubmitBatchRequestBody {
            events: submissions.to_vec(),
        };
        self.post_with_options("/_arkret/self/events", &body, options)
            .await
    }

    /// Submit a current-device-signed Seal through the registered self Events
    /// surface. This is the finality step used by B-model principal bootstrap
    /// and recovery; it is not the implementation-private peer Seal rail.
    pub async fn events_submit_seal(&self, seal: &Seal) -> Result<EventSealSubmitOutcome> {
        self.post("/_arkret/self/events/seals", seal).await
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
    #[cfg(not(target_arch = "wasm32"))]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(not(target_arch = "wasm32"))]
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
            .catchup(true)
            .max_duration_ms(30_000)
            .heartbeat_ms(5_000);

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
        assert!(query.contains("catchup=true"), "query: {query}");
        assert!(query.contains("max_duration_ms=30000"), "query: {query}");
        assert!(query.contains("heartbeat_ms=5000"), "query: {query}");
        assert!(!query.contains("include_history"), "query: {query}");
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
            "{\"cursor\":\"ak:cursor:event-1\",\"kind\":\"event\",\"payload\":{}}\n",
            "{\"cursor\":\"ak:cursor:event-1\",\"kind\":\"catchup_",
            "complete\"}\n",
        ];
        let mut stream = spawn_chunked_ndjson_server(parts)
            .await
            .events_subscribe_frames(
                &EventsSubscribeOptions::new()
                    .realm("ak:realm:01904100-0000-7000-8000-000000000001")
                    .catchup(true),
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
            arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind::Event
        );
        assert!(got[1].is_catchup_complete());
        assert_eq!(stream.reconnect_cursor(), Some("ak:cursor:event-1"));
    }
}
