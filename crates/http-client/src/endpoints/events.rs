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
    GovernanceDependencyResolveOutcome, SealPrepareOutcome, SealPrepareRequest,
    SelfGovernanceDependencyResolveRequest,
};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventSealSubmitOutcome,
    EventsQueryOutcome, EventsResolveOutcome, EventsResolveRequestBody, EventsSubmitOutcome,
    EventsSubscribeFrame, ProjectionSpaceList, ProjectionStrandList, SealResolveOutcome,
    SelfSealResolveRequestBody,
};
use arkret_models_collaboration::sync_frames::realm_state_snapshot::RealmStateSnapshotBootstrap;
use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
use arkret_models_crypto::{MlsGovernanceProofBundle, MlsGovernanceProofRequestBody};
use arkret_models_discovery::ServiceDescribe;
use arkret_schema::PreparedStandardEvent;
use arkret_state::{
    RealmStateSnapshotManifest, RealmStateSnapshotRestore, RealmStateSnapshotVerifyOptions,
    realm_state_snapshot_bootstrap_binds_manifest, restore_realm_state_snapshot,
};
use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    AccountId, ActorId, AuthorizationLeaseIssueRequestBody, ControlProposalAck,
    ControlProposalAckIssueOutcome, ControlProposalAckIssueRequest, ControlProposalDecisionPolicy,
    ControlProposalDecisionReadOutcome, ControlProposalDecisionReadRequestBody,
    ControlProposalDecisionSubmitOutcome, ControlProposalDecisionSubmitRequestBody, Cursor, Event,
    EventInitialSubmission, EventSubmitContext, EventsSubmitBatchRequestBody, Hash, RealmId, Seal,
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
    pub actor_ids: Vec<ActorId>,
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
    pub fn actor(mut self, actor_id: ActorId) -> Self {
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
    /// the complete anchor-unit lease set that lets the admitting Station issue the genesis Control
    /// Proposal Acks atomically.
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
            // pre-collect a Control Proposal Ack. The admitting Station
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
                cbs_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            };
            let is_control_move = event.kind.is_control_plane();
            if is_control_move && (!anchor_unit || collect_anchor_receipts) {
                let request = ControlProposalAckIssueRequest {
                    event: event.clone(),
                    publication_mode: arkret_wire::ControlProposalPublicationMode::Delayed,
                    authorization_lease: Some(
                        submission
                            .authorization_lease
                            .clone()
                            .expect("delayed submission was constructed with a lease"),
                    ),
                    cbs_proof_bundles: Vec::new(),
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
    /// wrapper proves the Event has one valid ordinary CBS plane and prevents
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
        if options.realm_ids.len() > 256
            || options.actor_ids.len() > 256
            || options.realm_ids.iter().collect::<BTreeSet<_>>().len() != options.realm_ids.len()
            || options.actor_ids.iter().collect::<BTreeSet<_>>().len() != options.actor_ids.len()
        {
            return Err(Error::Protocol(
                "events subscribe selectors must be unique and bounded to 256".to_owned(),
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
            builder = builder.query(&[("actor_ids", actor_id.canonical_key()?)]);
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
    ) -> Result<EventsQueryOutcome> {
        let request = EventsQueryPostRequestBody {
            realm_ids: vec![RealmId::new(realm_id)?],
            actor_ids: Vec::new(),
            before: before.map(Cursor::new).transpose()?,
            after: after.map(Cursor::new).transpose()?,
            order: order.map(ToOwned::to_owned),
            limit,
            filters: None,
        };
        self.events_read(&request).await
    }

    /// Walk every page of `ak.self.events.read.scan.v1` for a Realm using
    /// the standard older-history `has_more` / `prev_cursor` contract.
    pub async fn events_read_all_pages(&self, realm_id: &str) -> Result<EventsQueryOutcome> {
        self.events_read_all_pages_inner(
            vec![RealmId::new(realm_id)?],
            Vec::new(),
            format!("realm {realm_id}"),
        )
        .await
    }

    /// Walk every durable Event page for one actor.
    ///
    /// Actor-scoped reads are required when a caller must reproduce a complete
    /// principal control history (service-http-binding.md section 3.3.1.1).
    /// Realm scans also use the canonical log, but apply Realm history/scope
    /// visibility; they are not the authorized full actor-history contract.
    pub async fn events_read_all_pages_for_actor(
        &self,
        actor_id: &ActorId,
    ) -> Result<EventsQueryOutcome> {
        self.events_read_all_pages_inner(
            Vec::new(),
            vec![actor_id.clone()],
            format!("actor {actor_id}"),
        )
        .await
    }

    async fn events_read_all_pages_inner(
        &self,
        realms: Vec<RealmId>,
        actors: Vec<ActorId>,
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
            })
            .await?;
        let mut pages = 1usize;
        let mut last_cursor: Option<String> = None;
        while combined.has_more {
            let Some(previous) = combined
                .prev_cursor
                .as_deref()
                .map(str::trim)
                .filter(|cursor| !cursor.is_empty())
                .map(ToOwned::to_owned)
            else {
                return Err(Error::Protocol(format!(
                    "events query for {selector_label} reported has_more but no prev_cursor"
                )));
            };
            if last_cursor.as_deref() == Some(previous.as_str()) {
                return Err(Error::Protocol(format!(
                    "events query for {selector_label} did not advance prev_cursor ({previous}); aborting to avoid a pagination loop"
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
                    before: Some(Cursor::new(previous.clone())?),
                    after: None,
                    order: None,
                    limit: None,
                    filters: None,
                })
                .await?;
            combined.events.extend(page.events);
            combined.has_more = page.has_more;
            combined.prev_cursor = page.prev_cursor;
            last_cursor = Some(previous);
            pages += 1;
        }
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
    /// Returns the validated partition of available and missing selectors.
    /// Replay consumers must require their selected dependency closure in full.
    pub async fn governance_dependencies_resolve(
        &self,
        request: &SelfGovernanceDependencyResolveRequest,
    ) -> Result<GovernanceDependencyResolveOutcome> {
        request.validate()?;
        let outcome: GovernanceDependencyResolveOutcome = self
            .post("/_arkret/self/seals/governance-dependencies", request)
            .await?;
        outcome.validate_for_self_request(request)?;
        Ok(outcome)
    }

    /// Read pending digests without scanning or replaying PCR history.
    pub async fn pcr_pending_control(
        &self,
        request: &arkret_models_collaboration::governance_dependencies::PcrPendingControlRequest,
    ) -> Result<arkret_models_collaboration::governance_dependencies::PcrPendingControlOutcome>
    {
        request.validate()?;
        let outcome: arkret_models_collaboration::governance_dependencies::PcrPendingControlOutcome = self.events_read_query("/_arkret/self/seals/pending-control", request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Request the exact Station-validated body for a device-signed PCR Seal.
    pub async fn seals_prepare(&self, request: &SealPrepareRequest) -> Result<SealPrepareOutcome> {
        request.validate()?;
        let outcome: SealPrepareOutcome = self.post("/_arkret/self/seals/prepare", request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read the complete durable Realm fanout target set for one visible Event.
    ///
    /// Target identifiers are opaque. A target service id is present only
    /// when the server confirms the caller can currently read a contributing
    /// joined-member ActorId routing projection. This QUERY never triggers
    /// route resolution or a delivery retry.
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
    /// authenticated Station performs read-only admission and signs
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

    /// The Realm's head snapshot manifest, as served.
    ///
    /// Nothing is verified here — `realm-state-snapshot-schema.md` §5 puts the
    /// transcript check before the chunks, and both belong to
    /// [`Self::restore_realm_state_snapshot_head`]. A caller that only wants to
    /// compare a `state_digest` or read the frontier can use this; a caller
    /// that wants state MUST NOT.
    pub async fn realm_state_snapshot_head(
        &self,
        realm_id: &str,
    ) -> Result<RealmStateSnapshotManifest> {
        let builder = self
            .request(Method::GET, "/_arkret/self/realm-state-snapshot/head")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    /// Fetch the Realm's head snapshot, verify it, and materialize it.
    ///
    /// The whole §5 consumer path in one call: manifest, every chunk recovered
    /// from its content-addressed `chunk_ref`, the transcript signature through
    /// `verify_issuer_jws`, and the `state_digest` recomputed from the
    /// delivered chunks rather than believed.
    ///
    /// The result carries a [`CoveredEventSet`] that answers §3's covered-set
    /// question with `Unknown` until the caller feeds it the committed index or
    /// an inclusion proof. That is deliberate: a restored client that answered
    /// «not covered» from ignorance would revive superseded writes on the next
    /// late-branch merge.
    pub async fn restore_realm_state_snapshot_head<F>(
        &self,
        realm_id: &str,
        options: &RealmStateSnapshotVerifyOptions,
        verify_issuer_jws: F,
    ) -> Result<RealmStateSnapshotRestore>
    where
        F: FnOnce(&arkret_wire::DidUrl, &[u8], &str) -> std::result::Result<(), String>,
    {
        let manifest = self.realm_state_snapshot_head(realm_id).await?;
        self.restore_realm_state_snapshot(&manifest, options, verify_issuer_jws)
            .await
    }

    /// Restore the snapshot a `realm_state_snapshot_bootstrap` hint named.
    ///
    /// The hint and the manifest arrive in two different responses, so the
    /// manifest is bound to the hint before any chunk is fetched: a server that
    /// advertised one snapshot on the events query and served another on the
    /// head route is rejected rather than silently accelerated on.
    pub async fn restore_realm_state_snapshot_for_bootstrap<F>(
        &self,
        realm_id: &str,
        bootstrap: &RealmStateSnapshotBootstrap,
        options: &RealmStateSnapshotVerifyOptions,
        verify_issuer_jws: F,
    ) -> Result<RealmStateSnapshotRestore>
    where
        F: FnOnce(&arkret_wire::DidUrl, &[u8], &str) -> std::result::Result<(), String>,
    {
        let manifest = self.realm_state_snapshot_head(realm_id).await?;
        realm_state_snapshot_bootstrap_binds_manifest(bootstrap, &manifest)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        self.restore_realm_state_snapshot(&manifest, options, verify_issuer_jws)
            .await
    }

    /// Restore a manifest the caller already holds.
    ///
    /// Split from [`Self::restore_realm_state_snapshot_head`] so a client that
    /// received a `realm_state_snapshot_bootstrap` hint can bind the manifest to
    /// that hint before spending the chunk downloads.
    pub async fn restore_realm_state_snapshot<F>(
        &self,
        manifest: &RealmStateSnapshotManifest,
        options: &RealmStateSnapshotVerifyOptions,
        verify_issuer_jws: F,
    ) -> Result<RealmStateSnapshotRestore>
    where
        F: FnOnce(&arkret_wire::DidUrl, &[u8], &str) -> std::result::Result<(), String>,
    {
        let mut chunk_bytes = Vec::with_capacity(manifest.chunks.len());
        for descriptor in &manifest.chunks {
            chunk_bytes.push(self.blob_download(&descriptor.chunk_ref, None).await?);
        }
        restore_realm_state_snapshot(manifest, &chunk_bytes, options, verify_issuer_jws)
            .map_err(|error| Error::Protocol(error.to_string()))
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequestBody) -> Result<AuthzCheckOutcome> {
        self.post("/_arkret/self/authz/check", request).await
    }

    pub async fn authz_effective_grants(
        &self,
        realm_id: &RealmId,
        subject: &ActorId,
        at: Option<&str>,
    ) -> Result<GrantList> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/authz/effective-grants")?
            .query(&[
                ("realm_id", realm_id.as_str()),
                ("subject_actor_id", subject.to_string().as_str()),
            ]);
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn authz_invites(
        &self,
        subject: &AccountId,
        realm_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<AuthzInviteList> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/authz/invites")?
            .query(&[
                ("subject", subject.principal_id.as_str()),
                ("subject_station_id", subject.station_id.as_str()),
            ]);
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
/// the wire-level submit gate in the matching CBS context.
///
/// A missing DataEvent basis must never be inferred to mean "anchor unit".
/// The latter is a closed protocol exception and is recognizable by its first
/// Event kind; treating every all-empty CBS tuple as an anchor lets malformed
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

#[cfg(test)]
mod tests {
    use arkret_wire::DidCoreId;
    #[cfg(not(target_arch = "wasm32"))]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(not(target_arch = "wasm32"))]
    use tokio::net::{TcpListener, TcpStream};
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
            .actor(ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )))
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
            query.contains("actor_ids=%7B%22account_id%22"),
            "query: {query}"
        );
        assert!(!query.contains("realms="), "query: {query}");
        assert!(!query.contains("actors="), "query: {query}");
        let actor_values = built
            .url()
            .query_pairs()
            .filter(|(name, _)| name == "actor_ids")
            .map(|(_, value)| value.into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            actor_values,
            vec![options.actor_ids[0].canonical_key().unwrap()]
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
    async fn spawn_chunked_ndjson_server(body_parts: Vec<String>) -> Client {
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

            let body = body_parts.concat();
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
    async fn read_http_request(socket: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = socket.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn spawn_json_sequence_server(
        response_bodies: Vec<&'static str>,
    ) -> (Client, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(response_bodies.len());
            for body in response_bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                requests.push(read_http_request(&mut socket).await);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.ok();
            }
            requests
        });
        let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        (client, server)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn events_read_all_pages_walks_older_history_with_prev_cursor() {
        let (client, server) = spawn_json_sequence_server(vec![
            r#"{"events":[],"prev_cursor":"ak:cursor:older","next_cursor":"ak:cursor:newest-edge","has_more":true}"#,
            r#"{"events":[],"next_cursor":"ak:cursor:page-two-newer","has_more":false}"#,
        ])
        .await;

        let outcome = client
            .events_read_all_pages_for_actor(&ActorId::service(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            ))
            .await
            .unwrap();
        let requests = server.await.unwrap();
        let second_body = requests[1]
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap();
        let second_body: serde_json::Value = serde_json::from_str(second_body).unwrap();

        assert_eq!(second_body["before"], "ak:cursor:older");
        assert!(second_body.get("after").is_none());
        assert_eq!(
            outcome.next_cursor.as_deref(),
            Some("ak:cursor:newest-edge")
        );
        assert_eq!(outcome.prev_cursor, None);
        assert!(!outcome.has_more);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn events_subscribe_frames_yields_one_frame_per_line() {
        let event_frame = serde_json::json!({
            "cursor": "ak:cursor:event-1",
            "kind": "event",
            "payload": basis_free_message_event(),
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        });
        let parts = vec![
            String::from_utf8(arkret_canonical::canonical_json_bytes(&event_frame).unwrap())
                .unwrap()
                + "\n",
            "{\"cursor\":\"ak:cursor:event-1\",\"kind\":\"catchup_".to_owned(),
            "complete\"}\n".to_owned(),
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
