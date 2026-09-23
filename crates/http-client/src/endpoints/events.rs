//! Event submission, stream subscription, resource read, per-stream tail and
//! signed typed snapshot methods on [`Client`].
//!
//! Every coordinate on this surface is per-stream. A producer Event carries no
//! predecessor, order, basis or frontier; ordering and finality come only from
//! the governance Station's `RealmCommit`, and a `RealmCommit` links to the
//! previous Commit of *its own* [`CommitStreamRef`]. So the tail read here is
//! [`Client::scan_commit_stream_tail`], addressed by
//! `(realm_id, stream_ref, after_position)`, and there is no call that returns
//! "the Realm's position": a Realm's Circles and Sidecars are separate streams
//! and a single number could not name a point in all of them.

use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::event_query::CommittedEventView;
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
};
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody,
};
use arkret_models_collaboration::sync_frames::committed_event_subscribe::{
    CommittedEventStreamTrace, CommittedEventSubscribeFrame,
};
use arkret_wire::{
    ActorId, AuthoritySubmitOutcome, CommitStreamRef, EventCommitSubmission, EventId,
    MlsCommitSubmission, RealmId, RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, RequestBuilder, Response};

use crate::{Client, ClientRequestOptions, Error, Result, reject_path_segment};

/// Largest page one stream tail read may request (`stream_scan_request.limit`).
pub const STREAM_SCAN_MAX_LIMIT: u16 = 1000;

/// Largest selector cardinality `ak.self.committed_event.stream.subscribe.v1` accepts
/// for either selector array.
pub const COMMITTED_EVENT_SUBSCRIBE_MAX_SELECTOR_ITEMS: usize = 256;

#[cfg(not(target_arch = "wasm32"))]
type BoxCommittedEventSubscribeFrameStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<CommittedEventSubscribeFrame>> + Send>,
>;

#[cfg(target_arch = "wasm32")]
type BoxCommittedEventSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<CommittedEventSubscribeFrame>>>>;

/// Selector and replay options for `ak.self.committed_event.stream.subscribe.v1`.
///
/// `realm_ids` and `actor_ids` union within themselves and intersect with each
/// other; at least one must be non-empty, because an unscoped subscription has
/// no authorization to evaluate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommittedEventSubscribeOptions {
    realm_ids: Vec<RealmId>,
    actor_ids: Vec<ActorId>,
    after: Option<String>,
    catchup: bool,
}

impl CommittedEventSubscribeOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn realm(mut self, realm_id: RealmId) -> Self {
        self.realm_ids.push(realm_id);
        self
    }

    #[must_use]
    pub fn actor(mut self, actor_id: ActorId) -> Self {
        self.actor_ids.push(actor_id);
        self
    }

    /// Resume exclusively after this subscription cursor.
    #[must_use]
    pub fn after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    /// Replay the bounded range from `after` before going live.
    #[must_use]
    pub const fn catchup(mut self, catchup: bool) -> Self {
        self.catchup = catchup;
        self
    }

    pub const fn catchup_requested(&self) -> bool {
        self.catchup
    }

    pub fn resume_cursor(&self) -> Option<&str> {
        self.after.as_deref()
    }

    /// Reject a selector the operation cannot evaluate before the request is
    /// ever sent.
    pub fn validate(&self) -> Result<()> {
        if self.realm_ids.is_empty() && self.actor_ids.is_empty() {
            return Err(Error::Protocol(
                "committed-event subscribe requires at least one realm_ids or actor_ids selector"
                    .to_owned(),
            ));
        }
        for (label, len) in [
            ("realm_ids", self.realm_ids.len()),
            ("actor_ids", self.actor_ids.len()),
        ] {
            if len > COMMITTED_EVENT_SUBSCRIBE_MAX_SELECTOR_ITEMS {
                return Err(Error::Protocol(format!(
                    "committed-event subscribe {label} exceeds {COMMITTED_EVENT_SUBSCRIBE_MAX_SELECTOR_ITEMS} items"
                )));
            }
        }
        if unique_count(self.realm_ids.iter().map(RealmId::as_str)) != self.realm_ids.len() {
            return Err(Error::Protocol(
                "committed-event subscribe realm_ids must be unique".to_owned(),
            ));
        }
        let encoded_actors = self.encoded_actor_ids()?;
        if unique_count(encoded_actors.iter().map(String::as_str)) != encoded_actors.len() {
            return Err(Error::Protocol(
                "committed-event subscribe actor_ids must be unique".to_owned(),
            ));
        }
        if self.catchup && self.after.is_none() {
            return Err(Error::Protocol(
                "committed-event subscribe catchup requires an after cursor".to_owned(),
            ));
        }
        Ok(())
    }

    /// Each `actor_ids` value is the canonical JSON serialization of one closed
    /// ActorId, never a bare DID: the wire form must keep the Station
    /// coordinate, or two accounts on different Stations would collapse into
    /// one selector entry.
    fn encoded_actor_ids(&self) -> Result<Vec<String>> {
        self.actor_ids
            .iter()
            .map(|actor_id| {
                let bytes = arkret_canonical::canonical_json_bytes(actor_id)?;
                String::from_utf8(bytes).map_err(|error| Error::Protocol(error.to_string()))
            })
            .collect()
    }
}

fn unique_count<'a>(values: impl Iterator<Item = &'a str>) -> usize {
    values.collect::<std::collections::BTreeSet<_>>().len()
}

/// Validated frame stream for `ak.self.committed_event.stream.subscribe.v1`.
///
/// The stream owns an [`CommittedEventStreamTrace`], so frame-order violations (a frame
/// after a terminal one, `catchup_complete` without replayed data, a positional
/// frame without a cursor) are rejected here rather than reaching the caller as
/// silently reordered history.
pub struct CommittedEventSubscribeFrameStream {
    inner: BoxCommittedEventSubscribeFrameStream,
    trace: CommittedEventStreamTrace,
    failed: bool,
}

impl CommittedEventSubscribeFrameStream {
    pub async fn next_frame(&mut self) -> Result<Option<CommittedEventSubscribeFrame>> {
        use futures_util::StreamExt;

        if self.failed {
            return Err(Error::Protocol(
                "committed-event subscribe stream was already rejected".to_owned(),
            ));
        }
        if self.trace.is_terminal() {
            return Ok(None);
        }
        let frame = match self.inner.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(error)) => {
                self.failed = true;
                return Err(error);
            }
            None => {
                self.trace.finish().map_err(|error| {
                    self.failed = true;
                    Error::Protocol(error.to_string())
                })?;
                return Ok(None);
            }
        };
        frame.validate().map_err(|error| {
            self.failed = true;
            Error::Protocol(format!("invalid committed-event subscribe frame: {error}"))
        })?;
        self.trace.push(&frame).map_err(|error| {
            self.failed = true;
            Error::Protocol(error.to_string())
        })?;
        Ok(Some(frame))
    }

    /// Cursor to pass as `after` when reopening this subscription.
    pub fn resume_cursor(&self) -> Option<&str> {
        self.trace.resume_cursor()
    }

    pub const fn is_terminal(&self) -> bool {
        self.trace.is_terminal()
    }
}

impl Client {
    /// Submit one producer-signed Event as `EventCommitSubmission { event }`.
    ///
    /// The Event itself carries no ordering: the returned outcome's
    /// `RealmCommit` is what places it at one `stream_position` of one stream.
    pub async fn submit_event(
        &self,
        submission: &EventCommitSubmission,
    ) -> Result<AuthoritySubmitOutcome> {
        self.submit_event_with_options(submission, &ClientRequestOptions::default())
            .await
    }

    pub async fn submit_event_with_options(
        &self,
        submission: &EventCommitSubmission,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        let request = SelfAuthoritySubmitRequest::Event(submission.clone());
        match self.submit_to_realm_authority(&request, options).await? {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(Error::Protocol(
                "ordinary Event submission returned an aggregate outcome".to_owned(),
            )),
        }
    }

    /// Submit one MLS Commit Event with every Welcome its Add proposals need,
    /// as the atomic `MlsCommitSubmission { commit_event, welcomes,
    /// idempotency_key }`.
    ///
    /// Commit and Welcomes are one unit on purpose: a Commit accepted without
    /// its Welcomes leaves added members unable to join the epoch they were
    /// added in, and no later message can repair that.
    pub async fn submit_mls_commit(
        &self,
        submission: &MlsCommitSubmission,
    ) -> Result<AuthoritySubmitOutcome> {
        self.submit_mls_commit_with_options(submission, &ClientRequestOptions::default())
            .await
    }

    pub async fn submit_mls_commit_with_options(
        &self,
        submission: &MlsCommitSubmission,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        let request = SelfAuthoritySubmitRequest::MlsCommit(submission.clone());
        match self.submit_to_realm_authority(&request, options).await? {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(Error::Protocol(
                "ordinary MLS submission returned an aggregate outcome".to_owned(),
            )),
        }
    }

    /// Read one authorized stream's tail from `after_position` forward.
    ///
    /// `stream_ref` is the closed [`CommitStreamRef`] — `Realm`, `Circle` or
    /// `Sidecar` — so the caller states which stream it is catching up on.
    /// `after_position` of `None` starts at that stream's retained floor.
    pub async fn scan_commit_stream_tail(
        &self,
        realm_id: RealmId,
        stream_ref: CommitStreamRef,
        after_position: Option<u64>,
        limit: u16,
    ) -> Result<StreamScanOutcome> {
        if !(1..=STREAM_SCAN_MAX_LIMIT).contains(&limit) {
            return Err(Error::Protocol(format!(
                "stream tail limit must be 1..={STREAM_SCAN_MAX_LIMIT}"
            )));
        }
        let request = StreamScanRequest {
            realm_id,
            stream_ref,
            direction: arkret_wire::StreamScanDirection::After(after_position),
            limit,
        };
        self.scan_commit_stream(&request).await
    }

    /// Walk one stream's tail to its end, page by page.
    ///
    /// Continuation is by `stream_position` of the last item, never by a
    /// Realm-wide counter: each page's last commit names the exact position the
    /// next page starts after.
    pub async fn scan_commit_stream_to_head(
        &self,
        realm_id: RealmId,
        stream_ref: CommitStreamRef,
        after_position: Option<u64>,
        page_limit: u16,
    ) -> Result<StreamScanOutcome> {
        let mut cursor = after_position;
        let mut collected = StreamScanOutcome {
            committed_events: Vec::new(),
            readable_floor: None,
            truncated: false,
        };
        loop {
            let page = self
                .scan_commit_stream_tail(realm_id.clone(), stream_ref.clone(), cursor, page_limit)
                .await?;
            let last_position = page
                .committed_events
                .last()
                .map(|item| item.commit().stream_position);
            if let Some(floor) = page.readable_floor {
                if collected
                    .readable_floor
                    .as_ref()
                    .is_some_and(|previous| previous != &floor)
                {
                    return Err(Error::Protocol(
                        "stream scan readable floor changed across pages".to_owned(),
                    ));
                }
                collected.readable_floor = Some(floor);
            }
            collected.committed_events.extend(page.committed_events);
            match (page.truncated, last_position) {
                (true, Some(position)) => cursor = Some(position),
                (true, None) => {
                    return Err(Error::Protocol(
                        "stream tail reported truncation without advancing a position".to_owned(),
                    ));
                }
                (false, _) => return Ok(collected),
            }
        }
    }

    /// Read the caller-scoped Event/RealmCommit pair through
    /// `ak.self.committed_event.resource.get.v1`.
    pub async fn committed_event_get(&self, event_id: &EventId) -> Result<CommittedEventView> {
        reject_path_segment(event_id.as_str())?;
        let path = format!("/_arkret/self/committed-events/{}", event_id.as_str());
        self.send_json(self.request(Method::GET, &path)?).await
    }

    /// Fetch the authority-signed typed snapshot manifest for one Realm
    /// (`ak.self.realm_state_snapshot.read.manifest_head.v1`).
    ///
    /// This is the bootstrap materialization: a signed set of typed current
    /// results plus one head per visible stream. It is not a replay container
    /// and proves nothing about streams the requester cannot see — the caller
    /// follows each `visible_stream_heads` entry with
    /// [`Client::scan_commit_stream_tail`] to reach that stream's head.
    pub async fn realm_state_snapshot_head(
        &self,
        realm_id: &RealmId,
    ) -> Result<RealmStateSnapshot> {
        let builder = self
            .request(Method::GET, "/_arkret/self/realm-state-snapshot/head")?
            .query(&[("realm_id", realm_id.as_str())]);
        let snapshot: RealmStateSnapshot = self.send_json(builder).await?;
        if &snapshot.realm_id != realm_id {
            return Err(Error::Protocol(
                "realm state snapshot head answered for a different Realm".to_owned(),
            ));
        }
        if snapshot.visible_stream_heads.is_empty() {
            return Err(Error::Protocol(
                "realm state snapshot head carries no visible stream head".to_owned(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for head in &snapshot.visible_stream_heads {
            if !seen.insert(&head.stream_ref) {
                return Err(Error::Protocol(
                    "realm state snapshot head repeats a commit stream".to_owned(),
                ));
            }
        }
        Ok(snapshot)
    }

    /// Read one exact watch cell from the governing Station's durable typed
    /// reducer. A written clear returns `Current` with `value: Cleared(())`,
    /// distinct from `NeverWritten`.
    pub async fn strand_watch_current(
        &self,
        request: &StrandWatchCurrentRequestBody,
    ) -> Result<StrandWatchCurrentOutcome> {
        let outcome: StrandWatchCurrentOutcome = self
            .post("/_arkret/self/strands/watch/current", request)
            .await?;
        outcome
            .validate_for_request(request)
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        Ok(outcome)
    }

    /// Read one exact Relation primary-domain or moderation-target current
    /// result from the governing Station's durable reducer cut.
    pub async fn exact_current_result(
        &self,
        request: &ExactCurrentResultsReadRequestBody,
        expected_governance_generation: u64,
    ) -> Result<ExactCurrentResultsReadOutcome> {
        request
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let outcome: ExactCurrentResultsReadOutcome = self
            .post("/_arkret/self/current-results/exact", request)
            .await?;
        outcome
            .validate_for_request(request, expected_governance_generation)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(outcome)
    }

    fn committed_event_subscribe_request(
        &self,
        options: &CommittedEventSubscribeOptions,
    ) -> Result<RequestBuilder> {
        options.validate()?;
        // `headers` replaces rather than appends, so the client-wide
        // `Accept: application/json` default does not survive alongside it.
        // A request advertising both would let an NDJSON-unaware server answer
        // with a single JSON document this rail cannot parse.
        let mut accept = reqwest::header::HeaderMap::new();
        accept.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/x-ndjson"),
        );
        let mut builder = self
            .request_unbounded(Method::GET, "/_arkret/self/committed-events/subscribe")?
            .headers(accept);
        for realm_id in &options.realm_ids {
            builder = builder.query(&[("realm_ids", realm_id.as_str())]);
        }
        for actor_id in options.encoded_actor_ids()? {
            builder = builder.query(&[("actor_ids", actor_id)]);
        }
        if let Some(after) = options.after.as_deref() {
            builder = builder.query(&[("after", after)]);
        }
        if options.catchup {
            builder = builder.query(&[("catchup", true)]);
        }
        crate::client_internals::validate_request_builder(&builder)?;
        Ok(builder)
    }

    async fn committed_event_subscribe_response(
        &self,
        options: &CommittedEventSubscribeOptions,
        request_options: &ClientRequestOptions,
    ) -> Result<Response> {
        let builder = self.committed_event_subscribe_request(options)?;
        let response = self
            .send_response(self.apply_request_options(builder, request_options)?)
            .await?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.contains("application/x-ndjson") {
            return Err(Error::Protocol(
                "committed-event subscribe requires application/x-ndjson".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Open the long-lived NDJSON Event subscription.
    pub async fn committed_event_subscribe_frames(
        &self,
        options: &CommittedEventSubscribeOptions,
    ) -> Result<CommittedEventSubscribeFrameStream> {
        self.committed_event_subscribe_frames_with_options(
            options,
            &ClientRequestOptions::default(),
        )
        .await
    }

    pub async fn committed_event_subscribe_frames_with_options(
        &self,
        options: &CommittedEventSubscribeOptions,
        request_options: &ClientRequestOptions,
    ) -> Result<CommittedEventSubscribeFrameStream> {
        use futures_util::StreamExt;

        let response = self
            .committed_event_subscribe_response(options, request_options)
            .await?;
        let inner: BoxCommittedEventSubscribeFrameStream =
            if crate::subscribe_body::streaming_bodies_available() {
                Box::pin(
                    crate::subscribe_body::ndjson_lines(response.bytes_stream()).map(|line| {
                        line.and_then(|line| {
                            serde_json::from_str::<CommittedEventSubscribeFrame>(&line)
                                .map_err(Error::from)
                        })
                    }),
                )
            } else {
                let frames = crate::subscribe_body::bounded_response_lines(response)
                    .await?
                    .into_iter()
                    .map(|line| {
                        serde_json::from_str::<CommittedEventSubscribeFrame>(&line)
                            .map_err(Error::from)
                    })
                    .collect::<Vec<_>>();
                Box::pin(futures_util::stream::iter(frames))
            };
        Ok(CommittedEventSubscribeFrameStream {
            inner,
            trace: CommittedEventStreamTrace::new(options.catchup, options.after.clone()),
            failed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind;
    use arkret_wire::EventId;
    use url::Url;

    use super::*;

    fn client() -> Client {
        Client::new(Url::parse("https://alice.example/").unwrap()).unwrap()
    }

    fn realm(seed: u8) -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [seed; 32]))
    }

    #[test]
    fn subscribe_without_a_selector_is_refused() {
        let error = CommittedEventSubscribeOptions::new()
            .validate()
            .unwrap_err();
        assert!(error.to_string().contains("at least one"));
    }

    #[test]
    fn duplicate_realm_selectors_are_refused() {
        let options = CommittedEventSubscribeOptions::new()
            .realm(realm(1))
            .realm(realm(1));
        assert!(
            options
                .validate()
                .unwrap_err()
                .to_string()
                .contains("unique")
        );
    }

    #[test]
    fn catchup_without_a_cursor_is_refused() {
        let options = CommittedEventSubscribeOptions::new()
            .realm(realm(1))
            .catchup(true);
        assert!(
            options
                .validate()
                .unwrap_err()
                .to_string()
                .contains("catchup requires an after cursor")
        );
    }

    #[test]
    fn subscribe_request_carries_the_ndjson_selector_query() {
        let options = CommittedEventSubscribeOptions::new()
            .realm(realm(1))
            .realm(realm(2))
            .after("ak:cursor:abc")
            .catchup(true);
        let request = client()
            .committed_event_subscribe_request(&options)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.url().path(),
            "/_arkret/self/committed-events/subscribe"
        );
        let query = request.url().query().unwrap();
        assert_eq!(query.matches("realm_ids=").count(), 2);
        assert!(query.contains("after=ak%3Acursor%3Aabc"));
        assert!(query.contains("catchup=true"));
        assert_eq!(
            request.headers().get("accept").unwrap(),
            "application/x-ndjson"
        );
    }

    #[tokio::test]
    async fn stream_tail_limit_is_bounded() {
        // The bound is checked before the request is built, so an
        // out-of-range page size never reaches the network.
        for limit in [0, STREAM_SCAN_MAX_LIMIT + 1] {
            let error = client()
                .scan_commit_stream_tail(
                    realm(1),
                    CommitStreamRef::Realm { realm_id: realm(1) },
                    None,
                    limit,
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("limit must be 1..=1000"));
        }
    }

    #[tokio::test]
    async fn terminal_frame_stops_local_iteration() {
        let frames = vec![
            Ok(CommittedEventSubscribeFrame {
                kind: CommittedEventSubscribeFrameKind::Heartbeat,
                realm_id: None,
                cursor: None,
                payload: None,
                reconnect_after_ms: None,
            }),
            Ok(CommittedEventSubscribeFrame {
                kind: CommittedEventSubscribeFrameKind::ResyncRequired,
                realm_id: None,
                cursor: None,
                payload: None,
                reconnect_after_ms: Some(1_000),
            }),
            Ok(CommittedEventSubscribeFrame {
                kind: CommittedEventSubscribeFrameKind::Heartbeat,
                realm_id: None,
                cursor: None,
                payload: None,
                reconnect_after_ms: None,
            }),
        ];
        let mut stream = CommittedEventSubscribeFrameStream {
            inner: Box::pin(futures_util::stream::iter(frames)),
            trace: CommittedEventStreamTrace::new(false, None),
            failed: false,
        };
        assert_eq!(
            stream.next_frame().await.unwrap().unwrap().kind,
            CommittedEventSubscribeFrameKind::Heartbeat
        );
        assert_eq!(
            stream.next_frame().await.unwrap().unwrap().kind,
            CommittedEventSubscribeFrameKind::ResyncRequired
        );
        assert!(stream.is_terminal());
        assert!(stream.next_frame().await.unwrap().is_none());
        // resync_required clears the resume cursor: there is nothing to
        // resume from, only a re-bootstrap.
        assert!(stream.resume_cursor().is_none());
    }
}
