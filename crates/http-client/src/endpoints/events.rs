//! Event stream / query / submit, snapshot, and authz endpoint methods
//! on [`Client`].

use std::collections::BTreeSet;

use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::event_query::{
    EventsDescribeRequestBody, EventsFrontierRequestBody, EventsQueryPostRequestBody,
    SealFrontierRequestBody,
};
use arkret_models_collaboration::event_sync::{
    EventsFrontierSelector, EventsFrontierState, SealFrontierState,
};
use arkret_models_collaboration::governance::authorization::{
    AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList, GrantList,
};
use arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependencyResolveOutcome, SealAvailabilityReceiptIssueOutcome,
    SealAvailabilityReceiptIssueRequest, SelfGovernanceDependencyResolveRequest,
};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventSealSubmitOutcome,
    EventsQueryOutcome, EventsRangeCompleteness, EventsResolveOutcome, EventsResolveRequestBody,
    EventsSubmitOutcome, EventsSubscribeFrame, ProjectionSpaceList, ProjectionStrandList,
    SealResolveOutcome, SelfSealResolveRequestBody,
};
use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
use arkret_models_crypto::{MlsGovernanceProofBundle, MlsGovernanceProofRequestBody};
use arkret_models_discovery::ServiceDescribe;
use arkret_schema::PreparedStandardEvent;
use arkret_state::SnapshotManifest;
use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    AuthorizationLeaseIssueRequestBody, ControlProposalAck, ControlProposalAckIssueOutcome,
    ControlProposalAckIssueRequest, ControlProposalDecisionPolicy,
    ControlProposalDecisionReadOutcome, ControlProposalDecisionReadRequestBody,
    ControlProposalDecisionSubmitOutcome, ControlProposalDecisionSubmitRequestBody, Cursor,
    DidCoreId, Event, EventInitialSubmission, EventSubmitContext, EventsSubmitBatchRequestBody,
    Hash, RealmId, Seal,
};
use reqwest::{Method, RequestBuilder, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Client, ClientRequestOptions, Error, Result, reject_path_segment};

const MAX_EVENTS_QUERY_PAGES: usize = 100;

fn query_method() -> Method {
    Method::from_bytes(b"QUERY").expect("QUERY is a valid registered HTTP method")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventsSubscribeOptions {
    pub realm_ids: Vec<RealmId>,
    pub actor_ids: Vec<DidCoreId>,
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
    pub fn realm(mut self, realm_id: RealmId) -> Self {
        self.realm_ids.push(realm_id);
        self
    }

    #[must_use]
    pub fn actor(mut self, actor_id: DidCoreId) -> Self {
        self.actor_ids.push(actor_id);
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
    /// Persist one complete signed defer/reject against its durable proposal
    /// and immutable Control Proposal Ack.
    pub async fn submit_control_proposal_decision(
        &self,
        request: &ControlProposalDecisionSubmitRequestBody,
    ) -> Result<ControlProposalDecisionSubmitOutcome> {
        request.validate_structural()?;
        let outcome: ControlProposalDecisionSubmitOutcome = self
            .post_protocol_replay_safe("/_arkret/self/control-proposal-decisions", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read the exact durable Ack/decision/Seal state for one proposal.
    pub async fn read_control_proposal_decision(
        &self,
        request: &ControlProposalDecisionReadRequestBody,
    ) -> Result<ControlProposalDecisionReadOutcome> {
        let outcome: ControlProposalDecisionReadOutcome = self
            .post("/_arkret/self/control-proposal-decisions/query", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    async fn events_read_query<T, B>(&self, path: &str, body: &B) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let query = self.canonical_json_body(self.request(query_method(), path)?, body)?;
        self.send_json(query).await
    }

    /// Fetch a selector-bound Event frontier and fail closed when the service
    /// returns a different union variant or scope.
    pub async fn events_frontier(
        &self,
        selector: &EventsFrontierSelector,
    ) -> Result<EventsFrontierState> {
        let body = match selector {
            EventsFrontierSelector::RealmActor { realm_id, actor_id } => {
                EventsFrontierRequestBody {
                    actor_id: actor_id.clone(),
                    realm_id: Some(realm_id.clone()),
                }
            }
            EventsFrontierSelector::ActorAggregate { actor_id } => EventsFrontierRequestBody {
                actor_id: actor_id.clone(),
                realm_id: None,
            },
        };
        let state: EventsFrontierState = self
            .events_read_query("/_arkret/self/events/frontier", &body)
            .await?;
        selector.validate_response(&state.frontier)?;
        Ok(state)
    }

    /// Fetch the complete accepted Realm Seal antichain from its sole self
    /// discovery surface.
    pub async fn seals_frontier(&self, realm_id: RealmId) -> Result<SealFrontierState> {
        let state: SealFrontierState = self
            .events_read_query(
                "/_arkret/self/seals/frontier",
                &SealFrontierRequestBody {
                    realm_id: realm_id.clone(),
                },
            )
            .await?;
        if state.frontier.realm_id != realm_id {
            return Err(Error::Protocol(
                "Seal frontier response does not match the requested realm_id".to_owned(),
            ));
        }
        state.frontier.validate_protocol_bounds()?;
        Ok(state)
    }

    pub async fn issue_authorization_leases(
        &self,
        request: &AuthorizationLeaseIssueRequestBody,
        digest_suites: &[arkret_canonical::DigestSuite],
        options: &ClientRequestOptions,
    ) -> Result<arkret_wire::AuthorizationLeaseIssueOutcome> {
        request.validate_structural()?;
        let outcome: arkret_wire::AuthorizationLeaseIssueOutcome = self
            .post_with_options("/_arkret/self/authorization-leases", request, options)
            .await?;
        outcome.validate_against_request(request, digest_suites)?;
        Ok(outcome)
    }

    /// Prepare the default submission path for an ordered Event unit.
    ///
    /// Ordinary Events use online admission without a prefetched lease. A
    /// closed anchor unit has no accepted authority yet, so this method obtains
    /// the complete anchor-unit lease set that lets the admitting Principal
    /// Server issue the genesis Control Proposal Acks atomically.
    pub async fn prepare_initial_submissions(
        &self,
        events: &[Event],
        digest_suites: &[arkret_canonical::DigestSuite],
    ) -> Result<Vec<EventInitialSubmission>> {
        if events.len() != digest_suites.len() {
            return Err(Error::Protocol(
                "initial Event and digest-suite cardinality must match".to_owned(),
            ));
        }
        let submit_context = initial_submission_context(events)?;
        if submit_context == EventSubmitContext::AnchorUnit {
            // Realm genesis has no accepted authority from which a caller can
            // pre-collect a Control Proposal Ack. The admitting Principal Server
            // mints those receipts atomically after it has pre-admitted the
            // complete lease-bound unit. A device re-anchor, by contrast,
            // already has an accepted recovery authority and must arrive with
            // its receipts.
            let first = events.first();
            let collect_anchor_receipts = anchor_unit_requires_precollected_receipts(
                first.map(|event| &event.kind),
                first.is_some_and(|event| {
                    event
                        .executed_by
                        .as_ref()
                        .is_some_and(|executor| executor != &event.actor_id)
                }),
            )?;
            return self
                .prepare_initial_submissions_with_collector(
                    events,
                    digest_suites,
                    None,
                    collect_anchor_receipts,
                )
                .await;
        }
        events
            .iter()
            .cloned()
            .zip(digest_suites.iter().copied())
            .map(|(event, digest_suite)| {
                let submission = EventInitialSubmission::online(event);
                submission.validate_structural_in_context(submit_context, digest_suite)?;
                Ok(submission)
            })
            .collect()
    }

    async fn prepare_initial_submissions_with_collector(
        &self,
        events: &[Event],
        digest_suites: &[arkret_canonical::DigestSuite],
        collector: Option<(&[Client], &NotaryValue, ControlProposalDecisionPolicy)>,
        collect_anchor_receipts: bool,
    ) -> Result<Vec<EventInitialSubmission>> {
        let submit_context = initial_submission_context(events)?;
        let anchor_unit = submit_context == EventSubmitContext::AnchorUnit;
        let request = AuthorizationLeaseIssueRequestBody {
            events: events.to_vec(),
            intents: Vec::new(),
        };
        let request_key = arkret_wire::new_prefixed_uuid7("lease-");
        let options = ClientRequestOptions::new()
            .request_id(request_key.clone())
            .idempotency_key(request_key);
        let outcome = self
            .issue_authorization_leases(&request, digest_suites, &options)
            .await?;
        let mut submissions = Vec::with_capacity(events.len());
        for ((event, digest_suite), lease) in events
            .iter()
            .zip(digest_suites.iter().copied())
            .zip(outcome.authorization_leases)
        {
            let mut submission = EventInitialSubmission {
                event: event.clone(),
                authorization_lease: Some(lease),
                cba_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            };
            let is_control_move = event.kind.is_control_plane();
            if is_control_move && (!anchor_unit || collect_anchor_receipts) {
                let request = ControlProposalAckIssueRequest {
                    event: event.clone(),
                    authorization_lease: submission
                        .authorization_lease
                        .clone()
                        .expect("delayed submission was constructed with a lease"),
                    cba_proof_bundles: Vec::new(),
                };
                submission.control_proposal_ack = Some(
                    if let Some((authority_clients, notary, policy)) = collector {
                        self.collect_control_proposal_ack(
                            &request,
                            digest_suite,
                            authority_clients,
                            notary,
                            policy,
                        )
                        .await?
                    } else {
                        let outcome = self
                            .issue_control_proposal_ack(&request, digest_suite)
                            .await?;
                        ControlProposalAck::from_authority_acks_protocol_bounds(vec![
                            outcome.authority_ack,
                        ])?
                    },
                );
            }
            submission.validate_structural_in_context(submit_context, digest_suite)?;
            submissions.push(submission);
        }
        Ok(submissions)
    }

    /// Collect and assemble one canonical Control Proposal Ack set from independent
    /// current authority transports.
    pub async fn collect_control_proposal_ack(
        &self,
        request: &ControlProposalAckIssueRequest,
        digest_suite: arkret_canonical::DigestSuite,
        authority_clients: &[Client],
        notary: &NotaryValue,
        policy: ControlProposalDecisionPolicy,
    ) -> Result<ControlProposalAck> {
        request.validate_structural()?;
        if authority_clients.is_empty() {
            return Err(Error::Protocol(
                "proposal authority client set must not be empty".to_owned(),
            ));
        }
        let mut members = Vec::with_capacity(authority_clients.len());
        for authority in authority_clients {
            members.push(
                authority
                    .issue_control_proposal_ack(request, digest_suite)
                    .await?
                    .authority_ack,
            );
        }
        ControlProposalAck::from_authority_acks_for_notary(members, policy, notary)
            .map_err(Into::into)
    }

    /// Single-Event convenience wrapper around
    /// [`prepare_initial_submissions`](Self::prepare_initial_submissions).
    pub async fn prepare_initial_submission(
        &self,
        event: &Event,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<EventInitialSubmission> {
        let prepared = PreparedStandardEvent::try_from(event.clone())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        self.prepare_initial_standard_submission(&prepared, digest_suite)
            .await
    }

    /// Prepare one schema-validated, non-anchor Event for first publication.
    ///
    /// Callers that author Events should prefer this API: possession of the
    /// wrapper proves the Event has one valid ordinary CBA plane and prevents
    /// mutation between validation and publication-evidence issuance.
    pub async fn prepare_initial_standard_submission(
        &self,
        prepared: &PreparedStandardEvent,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<EventInitialSubmission> {
        let submissions = self
            .prepare_initial_submissions(
                std::slice::from_ref(prepared.event()),
                std::slice::from_ref(&digest_suite),
            )
            .await?;
        submissions.into_iter().next().ok_or_else(|| {
            Error::Protocol("authorization issuer returned no initial submission".to_owned())
        })
    }

    pub async fn issue_control_proposal_ack(
        &self,
        request: &ControlProposalAckIssueRequest,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<ControlProposalAckIssueOutcome> {
        request.validate_structural()?;
        let outcome: ControlProposalAckIssueOutcome = self
            .post("/_arkret/self/control-proposal-acks", request)
            .await?;
        outcome.authority_ack.validate_protocol_bounds()?;
        let event_digest = Hash::new(request.event.event_digest_with_digest_suite(digest_suite)?)?;
        if outcome.authority_ack.realm_id != request.event.realm_id
            || outcome.authority_ack.proposal_digest != event_digest
        {
            return Err(Error::Protocol(
                "proposal authority Ack response changed the Event binding".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Describe the Event service via `ak.self.events.read.describe.v1`.
    ///
    /// HTTP QUERY with an empty JSON object is the sole binding.
    pub async fn events_describe(&self) -> Result<ServiceDescribe> {
        self.events_describe_with_request(&EventsDescribeRequestBody::default())
            .await
    }

    /// Describe an actor- or Realm-scoped Event service capability view.
    pub async fn events_describe_with_request(
        &self,
        request: &EventsDescribeRequestBody,
    ) -> Result<ServiceDescribe> {
        self.events_read_query("/_arkret/self/events/describe", request)
            .await
    }

    /// Subscribe to the Event stream for one or more Realms / actors via
    /// `ak.self.events.stream.subscribe.v1` (`GET /_arkret/self/events/subscribe`). The selector is
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

    /// Open the bounded NDJSON Event stream.
    ///
    /// The response is read incrementally where the transport exposes the body
    /// and after close where it does not — see `subscribe_body`. Both
    /// are the same conformant bounded response; the choice only decides how
    /// soon a frame reaches the caller, and the caller's reconnect loop is
    /// unchanged either way.
    pub async fn events_subscribe_frames(
        &self,
        options: &EventsSubscribeOptions,
    ) -> Result<EventsSubscribeFrameStream> {
        use futures_util::StreamExt;

        let response = self.events_subscribe_stream_with_options(options).await?;
        let inner: BoxEventsSubscribeFrameStream =
            if crate::subscribe_body::streaming_bodies_available() {
                Box::pin(
                    crate::subscribe_body::ndjson_lines(response.bytes_stream()).filter_map(
                        |line| async move {
                            match line.and_then(|line| {
                                EventsSubscribeFrame::from_ndjson_line(&line).map_err(Error::from)
                            }) {
                                Ok(Some(frame)) => Some(Ok(frame)),
                                Ok(None) => None,
                                Err(error) => Some(Err(error)),
                            }
                        },
                    ),
                )
            } else {
                let mut frames = Vec::new();
                for line in crate::subscribe_body::bounded_response_lines(response).await? {
                    if let Some(frame) = EventsSubscribeFrame::from_ndjson_line(&line)? {
                        frames.push(Ok(frame));
                    }
                }
                Box::pin(futures_util::stream::iter(frames))
            };
        Ok(EventsSubscribeFrameStream {
            inner,
            trace: StreamTraceValidator::new(
                options.catchup.unwrap_or(false),
                options.after.clone(),
            ),
            failed: false,
        })
    }

    fn events_subscribe_request(&self, options: &EventsSubscribeOptions) -> Result<RequestBuilder> {
        if options.realm_ids.is_empty() && options.actor_ids.is_empty() {
            return Err(Error::Protocol(
                "events subscribe requires at least one realm or actor selector".to_owned(),
            ));
        }

        // Long-lived NDJSON stream — exempt from the per-request default
        // total timeout (see `DEFAULT_REQUEST_TIMEOUT`).
        let mut builder = self
            .request_unbounded(Method::GET, "/_arkret/self/events/subscribe")?
            .header("accept", "application/x-ndjson");
        for realm_id in &options.realm_ids {
            builder = builder.query(&[("realm_ids", realm_id.as_str())]);
        }
        for actor_id in &options.actor_ids {
            builder = builder.query(&[("actor_ids", actor_id.as_str())]);
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

    /// Resolve the exact canonical Events identified by the closed selector
    /// set accepted by `ak.self.events.read.resolve.v1`.
    pub async fn events_resolve(
        &self,
        request: &EventsResolveRequestBody,
    ) -> Result<EventsResolveOutcome> {
        request.validate()?;
        self.events_read_query("/_arkret/self/events/resolve", request)
            .await
    }

    /// Resolve every-and-only canonical Seal named by the self selector.
    pub async fn seals_resolve(
        &self,
        request: &SelfSealResolveRequestBody,
    ) -> Result<SealResolveOutcome> {
        request.validate()?;
        let outcome: SealResolveOutcome = self
            .events_read_query("/_arkret/self/seals/resolve", request)
            .await?;
        outcome.validate_structural()?;
        let requested = request.seal_refs.iter().cloned().collect::<BTreeSet<_>>();
        let returned = outcome
            .seals
            .iter()
            .map(|seal| seal.id.clone())
            .chain(outcome.missing_seal_refs.iter().cloned())
            .collect::<BTreeSet<_>>();
        if returned != requested
            || outcome
                .seals
                .iter()
                .any(|seal| seal.realm_id != request.realm_id)
        {
            return Err(Error::Protocol(
                "Seal resolve outcome is cross-Realm or not every-and-only the request".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Range-read Events via canonical `ak.self.events.read.scan.v1` HTTP QUERY.
    pub async fn events_read(
        &self,
        request: &EventsQueryPostRequestBody,
    ) -> Result<EventsQueryOutcome> {
        if request.realm_ids.is_empty() && request.actor_ids.is_empty() {
            return Err(Error::Protocol(
                "events read requires at least one realm or actor selector".to_owned(),
            ));
        }
        if request.limit == Some(0) {
            return Err(Error::Protocol(
                "events read limit must be greater than zero".to_owned(),
            ));
        }

        self.events_read_query("/_arkret/self/events", request)
            .await
    }

    /// Convenience wrapper for one Realm using the standard outcome shape.
    pub async fn events_read_outcome(
        &self,
        realm_id: &str,
        before: Option<&str>,
        after: Option<&str>,
        order: Option<&str>,
        limit: Option<u32>,
        include_completeness: Option<bool>,
    ) -> Result<EventsQueryOutcome> {
        let request = EventsQueryPostRequestBody {
            realm_ids: vec![RealmId::new(realm_id)?],
            actor_ids: Vec::new(),
            before: before.map(Cursor::new).transpose()?,
            after: after.map(Cursor::new).transpose()?,
            order: order.map(ToOwned::to_owned),
            limit,
            filters: None,
            include_completeness,
        };
        self.events_read(&request).await
    }

    /// Walk every page of `ak.self.events.read.scan.v1` for a Realm using
    /// the standard `has_more` / `next_cursor` contract.
    pub async fn events_read_all_pages(&self, realm_id: &str) -> Result<EventsQueryOutcome> {
        self.events_read_all_pages_inner(
            vec![RealmId::new(realm_id)?],
            Vec::new(),
            false,
            format!("realm {realm_id}"),
        )
        .await
    }

    /// Walk every durable Event page for one actor.
    ///
    /// Actor-scoped reads are required when a caller must reproduce a complete
    /// principal control history. Realm-scoped projection scans can omit
    /// canonical anchor Events that do not have an independently visible
    /// projection row.
    pub async fn events_read_all_pages_for_actor(
        &self,
        actor_id: &DidCoreId,
    ) -> Result<EventsQueryOutcome> {
        self.events_read_all_pages_inner(
            Vec::new(),
            vec![actor_id.clone()],
            false,
            format!("actor {actor_id}"),
        )
        .await
    }

    /// Walk every page and request range-completeness evidence for each page.
    ///
    /// Inline attestations and references are unioned by id across pages. An
    /// absent `range_completeness` response remains absence, rather than an
    /// error, because feature negotiation decides whether the service supports
    /// this optional query extension.
    pub async fn events_read_all_pages_with_completeness(
        &self,
        realm_id: &str,
    ) -> Result<EventsQueryOutcome> {
        self.events_read_all_pages_inner(
            vec![RealmId::new(realm_id)?],
            Vec::new(),
            true,
            format!("realm {realm_id}"),
        )
        .await
    }

    async fn events_read_all_pages_inner(
        &self,
        realms: Vec<RealmId>,
        actors: Vec<DidCoreId>,
        include_completeness: bool,
        selector_label: String,
    ) -> Result<EventsQueryOutcome> {
        let mut combined = self
            .events_read(&EventsQueryPostRequestBody {
                realm_ids: realms.clone(),
                actor_ids: actors.clone(),
                before: None,
                after: None,
                order: None,
                limit: None,
                filters: None,
                include_completeness: include_completeness.then_some(true),
            })
            .await?;
        let mut completeness = combined.range_completeness.take();
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
                    "events query for {selector_label} reported has_more but no next_cursor"
                )));
            };
            if last_cursor.as_deref() == Some(next.as_str()) {
                return Err(Error::Protocol(format!(
                    "events query for {selector_label} did not advance next_cursor ({next}); aborting to avoid a pagination loop"
                )));
            }
            if pages >= MAX_EVENTS_QUERY_PAGES {
                return Err(Error::Protocol(format!(
                    "events query for {selector_label} exceeded {MAX_EVENTS_QUERY_PAGES} pages; aborting"
                )));
            }
            let page = self
                .events_read(&EventsQueryPostRequestBody {
                    realm_ids: realms.clone(),
                    actor_ids: actors.clone(),
                    before: None,
                    after: Some(Cursor::new(next.clone())?),
                    order: None,
                    limit: None,
                    filters: None,
                    include_completeness: include_completeness.then_some(true),
                })
                .await?;
            combined.events.extend(page.events);
            combined.has_more = page.has_more;
            combined.next_cursor = page.next_cursor;
            merge_range_completeness(&mut completeness, page.range_completeness)?;
            last_cursor = Some(next);
            pages += 1;
        }
        combined.range_completeness = completeness;
        Ok(combined)
    }

    /// Fetch one complete near-current MLS group-security-frontier proof.
    pub async fn mls_governance_proof(
        &self,
        request: &MlsGovernanceProofRequestBody,
    ) -> Result<MlsGovernanceProofBundle> {
        request.validate()?;
        let outcome: MlsGovernanceProofBundle = self
            .post("/_arkret/self/seals/mls-governance-proof", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Resolve one exact same-service governance dependency selector set.
    /// Missing selectors are a hard failure for replay consumers.
    pub async fn governance_dependencies_resolve(
        &self,
        request: &SelfGovernanceDependencyResolveRequest,
    ) -> Result<GovernanceDependencyResolveOutcome> {
        request.validate()?;
        let outcome: GovernanceDependencyResolveOutcome = self
            .post("/_arkret/self/seals/governance-dependencies", request)
            .await?;
        outcome.validate_for_self_request(request)?;
        if !outcome.missing_selectors.is_empty() {
            return Err(Error::Protocol(
                "governance dependency resolution is incomplete".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Ask the create-locked Principal Server holder to issue and persist the
    /// exact availability dependency closure before a device signs a PCR
    /// successor Seal.
    pub async fn seal_availability_receipts_issue(
        &self,
        request: &SealAvailabilityReceiptIssueRequest,
    ) -> Result<SealAvailabilityReceiptIssueOutcome> {
        request.validate()?;
        let outcome: SealAvailabilityReceiptIssueOutcome = self
            .post("/_arkret/self/seals/availability-receipts", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read the complete durable Realm fanout target set for one visible Event.
    ///
    /// Target identifiers are opaque. A target service id is present only
    /// when the server confirms the caller can currently read a contributing
    /// member delivery binding. This QUERY never triggers route resolution or
    /// a delivery retry.
    pub async fn event_delivery_status(
        &self,
        request: &EventDeliveryStatusRequestBody,
    ) -> Result<EventDeliveryStatusOutcome> {
        let outcome: EventDeliveryStatusOutcome = self
            .events_read_query("/_arkret/self/events/delivery-status", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Submit one initial Event publication via `ak.self.events.command.submit.v1`
    /// (`POST /_arkret/self/events`). Wire body is `EventInitialSubmission` —
    /// the signed Event plus the publication evidence that bounds it. A bare
    /// Event Envelope is no longer a valid body.
    ///
    /// Callers that do not already hold a wrapper should use
    /// [`prepare_initial_submission`](Self::prepare_initial_submission) so the
    /// authenticated Principal Server performs read-only admission and signs
    /// the lease. The SDK never fabricates a lease locally.
    pub async fn events_submit(
        &self,
        submission: &EventInitialSubmission,
    ) -> Result<EventsSubmitOutcome> {
        let outcome: EventsSubmitOutcome = self.post("/_arkret/self/events", submission).await?;
        outcome.validate_delivery_invariants()?;
        Ok(outcome)
    }

    /// Submit a batch of initial Event publications via
    /// `ak.self.events.command.submit.v1` (`POST /_arkret/self/events`) using the
    /// `EventsSubmitBatchRequestBody` body shape. Each element carries its own
    /// authority-issued lease; see [`events_submit`](Self::events_submit).
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
        let outcome: EventsSubmitOutcome = self
            .post_with_options("/_arkret/self/events", &body, options)
            .await?;
        outcome.validate_delivery_invariants()?;
        Ok(outcome)
    }

    /// Submit the registered caller-authored Direct Conversation founding unit.
    ///
    /// Its idempotency key is part of the closed body contract. Retrying this exact value returns
    /// the stored byte-identical acceptance receipt; callers must never re-author another unit
    /// after an ambiguous network result.
    pub async fn direct_conversation_founding_submit(
        &self,
        submission: &DirectConversationFoundingUnitSubmission,
    ) -> Result<DirectConversationFoundingAcceptanceOutcome> {
        self.post("/_arkret/self/events", submission).await
    }

    /// Submit a current-device-signed Seal (`ak.self.seals.command.submit.v1`).
    /// This is the finality step used by B-model principal bootstrap and
    /// recovery; it is not the implementation-private peer Seal rail.
    ///
    /// A Seal is not an Event: the registered path is `/_arkret/self/seals`,
    /// never a child of the Events surface.
    pub async fn events_submit_seal(&self, seal: &Seal) -> Result<EventSealSubmitOutcome> {
        self.post("/_arkret/self/seals", seal).await
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
        realm_id: &RealmId,
        subject: &DidCoreId,
        subject_principal_server_id: &DidCoreId,
        at: Option<&str>,
    ) -> Result<GrantList> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/authz/effective-grants")?
            .query(&[
                ("realm_id", realm_id.as_str()),
                ("subject", subject.as_str()),
                (
                    "subject_principal_server_id",
                    subject_principal_server_id.as_str(),
                ),
            ]);
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

    pub async fn realm_organizations(
        &self,
        realm_id: &str,
    ) -> Result<RealmOrganizationRelationshipList> {
        reject_path_segment(realm_id)?;
        let path = format!("/_arkret/self/realms/{realm_id}/organizations");
        self.get(&path).await
    }
}

/// Classify the publication unit before making any network request and run
/// the wire-level submit gate in the matching CBA context.
///
/// A missing DataEvent basis must never be inferred to mean "anchor unit".
/// The latter is a closed protocol exception and is recognizable by its first
/// Event kind; treating every all-empty CBA tuple as an anchor lets malformed
/// ordinary Events reach the authorization issuer.
fn initial_submission_context(events: &[Event]) -> Result<EventSubmitContext> {
    Ok(arkret_wire::classify_event_submit_context(events)?)
}

fn anchor_unit_requires_precollected_receipts(
    first_kind: Option<&arkret_wire::EventKind>,
    delegated_genesis: bool,
) -> Result<bool> {
    if first_kind == Some(&arkret_wire::EventKind::RealmCreate) && delegated_genesis {
        return Err(Error::Protocol(
            "delegated Realm genesis requires an explicit local proposal authority".to_owned(),
        ));
    }
    Ok(first_kind.is_some_and(|kind| kind != &arkret_wire::EventKind::RealmCreate))
}

#[cfg(test)]
mod initial_submission_tests {
    use super::anchor_unit_requires_precollected_receipts;

    #[test]
    fn realm_genesis_receipts_are_minted_during_atomic_ingress() {
        assert!(
            !anchor_unit_requires_precollected_receipts(
                Some(&arkret_wire::EventKind::RealmCreate),
                false,
            )
            .unwrap()
        );
        assert!(
            anchor_unit_requires_precollected_receipts(
                Some(&arkret_wire::EventKind::DeviceReanchor),
                false,
            )
            .unwrap()
        );
        assert!(
            anchor_unit_requires_precollected_receipts(
                Some(&arkret_wire::EventKind::RealmCreate),
                true,
            )
            .is_err(),
            "managed genesis must select an explicit controller receipt signer"
        );
    }
}

fn merge_range_completeness(
    combined: &mut Option<EventsRangeCompleteness>,
    page: Option<EventsRangeCompleteness>,
) -> Result<()> {
    let Some(page) = page else {
        return Ok(());
    };
    let combined = combined.get_or_insert_with(|| EventsRangeCompleteness {
        attestation_refs: Vec::new(),
        attestations: Vec::new(),
    });
    for reference in page.attestation_refs {
        if !combined.attestation_refs.contains(&reference) {
            combined.attestation_refs.push(reference);
        }
    }
    for attestation in page.attestations {
        if let Some(existing) = combined
            .attestations
            .iter()
            .find(|candidate| candidate.event_id == attestation.event_id)
        {
            if existing != &attestation {
                return Err(Error::Protocol(format!(
                    "duplicate_conflict: range-completeness Event {} changed across query pages",
                    attestation.event_id
                )));
            }
        } else {
            combined.attestations.push(attestation);
        }
    }
    combined
        .attestation_refs
        .sort_by(|left, right| left.as_str().cmp(right.as_str()));
    combined
        .attestations
        .sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(not(target_arch = "wasm32"))]
    use tokio::net::TcpListener;
    use url::Url;

    use super::*;

    fn basis_free_message_event() -> Event {
        arkret_wire::test_support::raw_event(
            "ak.message.create",
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            0,
            arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({
                "strand_id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        )
        .unwrap()
    }

    fn client() -> Client {
        Client::new(Url::parse("https://alice.example/").unwrap()).unwrap()
    }

    #[test]
    fn events_subscribe_request_serializes_stream_options() {
        let options = EventsSubscribeOptions::new()
            .realm(RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap())
            .actor(DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap())
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
            query.contains("realm_ids=ak%3Arealm%3AAdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
            "query: {query}"
        );
        assert!(
            query.contains("actor_ids=ak%3Adid_core%3Awebvh%3Az6mkfixture%3Aalice.example"),
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

    #[test]
    fn initial_submission_rejects_basis_free_message_before_network() {
        let error = initial_submission_context(&[basis_free_message_event()]).unwrap_err();
        assert!(error.to_string().contains("basis-free publication unit"));
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
                    .realm(
                        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                            .unwrap(),
                    )
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
            got[0].kind(),
            arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind::Event
        );
        assert!(got[1].is_catchup_complete());
        assert_eq!(stream.reconnect_cursor(), Some("ak:cursor:event-1"));
    }
}
