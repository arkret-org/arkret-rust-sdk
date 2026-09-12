//! First cross-station Realm join intake
//! (`realm-join-intake.schema.json`, `sync/federation.md` sections 5.3 to
//! 5.3.4).
//!
//! Three faces share one carrier family here:
//!
//! - the bounded bootstrap an existing member Station serves to an applicant's Station that holds
//!   no accepted state for the Realm;
//! - the own-Station preparation that freezes the exact bytes a client signs;
//! - the restricted application outcome both the applicant's Station and the applicant may read
//!   before membership exists.
//!
//! The pre-join preview half of the same schema file composes
//! `realm_preview`, so it lives with the Directory shapes in
//! `arkret-models-discovery`; nothing is duplicated across the two, because
//! `realm_join_intent`, `realm_join_governance_facts` and
//! `realm_join_realm_state` are only reachable from the faces below.
//!
//! None of these carriers is authorization. Bootstrap material grants no
//! general roster, message or key read; preparation is not admission, and
//! submit re-checks current authority, freshness and basis.

use std::collections::BTreeSet;
use std::fmt;

use arkret_canonical::DigestSuite;
use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, ActorId, CellRef, ControlProposalDecisionReadOutcome, ControlProposalState,
    EncryptionProfile, Event, EventId, Hash, InviteId, JoinRule, Precondition, RealmId, RequestId,
    Result, SchemaId, SealBasis, SealId, WireError, canonical, event_kind_str,
    framed_request_digest, validate_invite_token,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::membership_invite::{
    InviteAcceptPayload, JoinGateProof, MembershipPayload, MembershipPayloadState,
};

/// Domain-separation label of `peer_bootstrap_outcome.request_digest`.
pub const REALM_JOIN_BOOTSTRAP_REQUEST_DIGEST_LABEL: &str = "ak.realm-join-bootstrap-request-v1";

/// Domain-separation label of `self_prepare_outcome.request_digest`.
pub const REALM_JOIN_PREPARE_REQUEST_DIGEST_LABEL: &str = "ak.realm-join-prepare-request-v1";

/// `realm_join_member_join_intent.gate_proofs` bound.
pub const MAX_REALM_JOIN_GATE_PROOFS: usize = 16;

/// `peer_bootstrap_outcome.applicant_predecessor_events` bound.
pub const MAX_REALM_JOIN_PREDECESSOR_EVENTS: usize = 64;

/// Enforce one carrier's registered `x-arkret-max-canonical-bytes`.
///
/// The per-member bounds do not imply it: a bootstrap outcome may carry 64
/// dependency bundles, and each bundle's own cap is the whole outcome's cap,
/// so only an aggregate check keeps the registered budget.
fn validate_canonical_bytes(value: &impl Serialize, limit: usize, what: &str) -> Result<()> {
    if canonical::canonical_json_bytes(value)?.len() > limit {
        return Err(WireError::Protocol(format!(
            "{what} exceeds {limit} canonical bytes"
        )));
    }
    Ok(())
}

fn validate_window(
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    what: &str,
) -> Result<()> {
    if expires_at <= observed_at {
        return Err(WireError::Protocol(format!(
            "{what} expires_at must follow observed_at"
        )));
    }
    Ok(())
}

/// Closed join intent. v1 registers exactly three branches; `restricted_join`
/// and application receipts have no registered payload or precondition branch,
/// so a caller that wants one gets `unsupported_feature` from the service
/// rather than a silent mapping onto `member_join`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmJoinIntent {
    /// Acceptance of one exact directed invite. `invite_token` is the
    /// holder-private locator delivered through `ak.account.invite_delivery`
    /// and is the applicant possession proof for this attempt.
    InviteAccept {
        invite_id: InviteId,
        invite_token: String,
    },
    /// Self-authored join under the Realm join policy. `gate_proofs` are
    /// applicant-supplied; gates the reducer replays from accepted state never
    /// appear here.
    MemberJoin {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        #[cfg_attr(
            feature = "openapi",
            salvo(schema(value_type = Vec<serde_json::Value>))
        )]
        gate_proofs: Vec<JoinGateProof>,
    },
    /// Public join-intent signal only. v1 carries no application text, so the
    /// knock path cannot become an external spam channel.
    Knock {},
}

/// `invite_token` is holder-private and MUST NOT be logged, so the derived
/// `Debug` that would print it is replaced rather than relied on to be unused.
impl fmt::Debug for RealmJoinIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InviteAccept { invite_id, .. } => formatter
                .debug_struct("RealmJoinIntent::InviteAccept")
                .field("invite_id", invite_id)
                .field("invite_token", &"<redacted>")
                .finish(),
            Self::MemberJoin { gate_proofs } => formatter
                .debug_struct("RealmJoinIntent::MemberJoin")
                .field("gate_proofs", gate_proofs)
                .finish(),
            Self::Knock {} => formatter.write_str("RealmJoinIntent::Knock"),
        }
    }
}

impl RealmJoinIntent {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InviteAccept { invite_token, .. } => {
                validate_invite_token("Realm join intent", invite_token)
            }
            Self::MemberJoin { gate_proofs } => {
                if gate_proofs.len() > MAX_REALM_JOIN_GATE_PROOFS {
                    return Err(WireError::Protocol(format!(
                        "Realm join intent carries more than {MAX_REALM_JOIN_GATE_PROOFS} gate proofs"
                    )));
                }
                let mut seen = BTreeSet::new();
                for proof in gate_proofs {
                    if !seen.insert(canonical::canonical_json_bytes(proof)?) {
                        return Err(WireError::Protocol(
                            "Realm join intent gate proofs must be duplicate-free".to_owned(),
                        ));
                    }
                }
                Ok(())
            }
            Self::Knock {} => Ok(()),
        }
    }

    /// Event kind this intent authors.
    pub fn event_kind(&self) -> &'static str {
        match self {
            Self::InviteAccept { .. } => event_kind_str::INVITE_ACCEPT,
            Self::MemberJoin { .. } | Self::Knock {} => event_kind_str::MEMBER_STATE,
        }
    }
}

/// The exact governance-dependent authoring inputs a not-yet-joined applicant
/// cannot derive locally.
///
/// The holder Station reports them from its own accepted projection; the
/// requesting Station verifies them against the accompanying dependency
/// closure before reusing them. A `ak.schema.realm_join_candidate.v1` is never
/// a substitute: the same members on a candidate are the issuer's observation,
/// good for candidate selection and staleness detection only.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinGovernanceFacts {
    /// Effective `ak.realm.join_rule` value under the accepted projection of
    /// `seal_basis`.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub join_rule: JoinRule,
    /// Complete current accepted Seal frontier of the holder service: exactly
    /// one leaf for `single_signer` and `threshold`, the complete canonical
    /// duplicate-free non-quarantined antichain for `open_set`. A compressed
    /// head is never a substitute.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub seal_basis: SealBasis,
    /// Live Realm digest suite from the verified joined projection of the
    /// complete `seal_basis`.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub digest_algorithm: DigestSuite,
    /// Effective Realm `encryption_profile` under the same projection, so the
    /// applicant device can apply the pre-join recovery-material gate without
    /// any membership-gated history read.
    pub encryption_profile: EncryptionProfile,
}

impl RealmJoinGovernanceFacts {
    pub fn validate(&self) -> Result<()> {
        self.seal_basis.validate_protocol_bounds()
    }
}

/// Typed transition used while constructing a complete join Event.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_kind", deny_unknown_fields)]
pub enum RealmJoinTransition {
    #[serde(rename = "ak.invite.accept")]
    InviteAccept {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        payload: InviteAcceptPayload,
        /// Exact pre-state predicates for this Move under the returned
        /// `seal_basis`. An `ak.invite.accept` carrying `invitee_account_id`
        /// MUST carry the `head_eq` the client cannot derive.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        preconditions: Vec<Precondition>,
    },
    #[serde(rename = "ak.member.state")]
    MemberState {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        payload: MembershipPayload,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        preconditions: Vec<Precondition>,
    },
}

impl RealmJoinTransition {
    pub fn event_kind(&self) -> &'static str {
        match self {
            Self::InviteAccept { .. } => event_kind_str::INVITE_ACCEPT,
            Self::MemberState { .. } => event_kind_str::MEMBER_STATE,
        }
    }

    pub fn preconditions(&self) -> &[Precondition] {
        match self {
            Self::InviteAccept { preconditions, .. } | Self::MemberState { preconditions, .. } => {
                preconditions
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InviteAccept {
                payload,
                preconditions,
            } => {
                payload.validate()?;
                // `governance-objects.md` section 5.3 makes the directed form
                // the only one whose live-target write is derivable from the
                // Event, and it is exactly the form that needs a frozen
                // `head_eq`. A prepared transition without one would ask the client
                // to derive the predicate it was told never to derive.
                if payload.invitee_account_id.is_some() && preconditions.is_empty() {
                    return Err(WireError::Protocol(
                        "prepared directed ak.invite.accept requires frozen preconditions"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            Self::MemberState { payload, .. } => {
                if !matches!(
                    payload.membership,
                    MembershipPayloadState::Join | MembershipPayloadState::Knock
                ) {
                    return Err(WireError::Protocol(
                        "prepared ak.member.state must author a join or knock transition"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// The intent this transition is a legal preparation of.
    fn matches_intent(&self, intent: &RealmJoinIntent) -> bool {
        match (self, intent) {
            (
                Self::InviteAccept { payload, .. },
                RealmJoinIntent::InviteAccept { invite_id, .. },
            ) => payload.invite_id == *invite_id,
            (Self::MemberState { payload, .. }, RealmJoinIntent::MemberJoin { .. }) => {
                payload.membership == MembershipPayloadState::Join
            }
            (Self::MemberState { payload, .. }, RealmJoinIntent::Knock {}) => {
                payload.membership == MembershipPayloadState::Knock
            }
            _ => false,
        }
    }
}

/// Closed payload branches for a prepared Realm join; serialization preserves
/// the Event payload object without adding a second wire discriminator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmJoinPayload {
    InviteAccept(InviteAcceptPayload),
    MemberState(MembershipPayload),
}

/// Complete closed Event body returned before the producer attaches its proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinUnsignedEvent {
    pub event_id: EventId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: arkret_wire::EventKind,
    pub realm_id: RealmId,
    pub scope_ref: arkret_wire::ScopeRef,
    pub actor_id: ActorId,
    pub actor_seq: u64,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<arkret_wire::Hlc>,
    pub prev_refs: Vec<EventId>,
    pub seal_basis: SealBasis,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub payload: RealmJoinPayload,
    pub preconditions: Vec<Precondition>,
}

impl RealmJoinUnsignedEvent {
    pub fn prepare(
        request: &RealmJoinPrepareRequestBody,
        frontier: &crate::event_sync::RealmActorFrontierView,
        seal_basis: SealBasis,
        transition: RealmJoinTransition,
        digest_suite: DigestSuite,
    ) -> Result<Self> {
        transition.validate()?;
        let payload = match &transition {
            RealmJoinTransition::InviteAccept { payload, .. } => {
                RealmJoinPayload::InviteAccept(payload.clone())
            }
            RealmJoinTransition::MemberState { payload, .. } => {
                RealmJoinPayload::MemberState(payload.clone())
            }
        };
        let mut event = Self {
            event_id: EventId::from_digest(digest_suite, [0; 32]),
            kind: arkret_wire::EventKind::from(transition.event_kind()),
            realm_id: request.realm_id.clone(),
            scope_ref: arkret_wire::ScopeRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            actor_id: ActorId::account(request.account_id.clone()),
            actor_seq: frontier.next_actor_seq,
            created_at: request.created_at,
            hlc: request.hlc.clone(),
            prev_refs: frontier.frontier_event_ids.clone(),
            seal_basis,
            payload,
            preconditions: transition.preconditions().to_vec(),
        };
        let mut envelope = event.to_event()?;
        envelope.refresh_content_bound_identity_with_digest_suite(digest_suite)?;
        event.event_id = envelope.event_id;
        Ok(event)
    }

    pub fn transition(&self) -> Result<RealmJoinTransition> {
        match (self.kind.as_str(), &self.payload) {
            (event_kind_str::INVITE_ACCEPT, RealmJoinPayload::InviteAccept(payload)) => {
                Ok(RealmJoinTransition::InviteAccept {
                    payload: payload.clone(),
                    preconditions: self.preconditions.clone(),
                })
            }
            (event_kind_str::MEMBER_STATE, RealmJoinPayload::MemberState(payload)) => {
                Ok(RealmJoinTransition::MemberState {
                    payload: payload.clone(),
                    preconditions: self.preconditions.clone(),
                })
            }
            _ => Err(WireError::Protocol(
                "prepared join event kind and payload disagree".to_owned(),
            )),
        }
    }

    pub fn to_event(&self) -> Result<Event> {
        Ok(Event {
            event_id: self.event_id.clone(),
            kind: self.kind.clone(),
            realm_id: self.realm_id.clone(),
            scope_ref: self.scope_ref.clone(),
            actor_id: self.actor_id.clone(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_seq: self.actor_seq,
            created_at: self.created_at,
            hlc: self.hlc.clone(),
            prev_refs: self.prev_refs.clone(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: self.preconditions.clone(),
            seal_ref: None,
            auth_context: None,
            seal_basis: Some(self.seal_basis.clone()),
            payload: serde_json::from_value(serde_json::to_value(&self.payload)?)?,
            unsigned: Default::default(),
            proofs: Vec::new(),
            requirements: Default::default(),
        })
    }
}

/// Authenticated account request to prepare exactly one join attempt.
///
/// It never carries a candidate endpoint, a self-reported `seal_basis` or any
/// caller-declared governance fact: those are precisely what the Station is
/// asked to establish.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPrepareRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    /// Canonical Realm id the user selected, normally taken from a preview
    /// outcome.
    pub realm_id: RealmId,
    pub intent: RealmJoinIntent,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<arkret_wire::Hlc>,
}

impl RealmJoinPrepareRequestBody {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_PREPARE_REQUEST_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.intent.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "Realm join preparation request",
        )
    }

    /// `SHA-256(UTF8(label) || 0x00 || JCS(exact request body))`.
    pub fn request_digest(&self) -> Result<Hash> {
        self.validate()?;
        framed_request_digest(REALM_JOIN_PREPARE_REQUEST_DIGEST_LABEL, self)
    }
}

/// Own-Station validated preparation of one join attempt.
///
/// Preparing the same canonical request again inside the retention window
/// returns byte-identical material.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPrepareOutcome {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    /// Binds this preparation to the exact declared intent, including the
    /// protected invite credential that is never echoed.
    pub request_digest: Hash,
    pub governance_facts: RealmJoinGovernanceFacts,
    pub unsigned_event: RealmJoinUnsignedEvent,
    pub accepted_actor_frontier: crate::event_sync::RealmActorFrontierView,
    pub authoring_device_generation_ref: u64,
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    /// Instant after which the client MUST prepare again instead of signing
    /// this material.
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl RealmJoinPrepareOutcome {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_PREPARE_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 262_144;

    pub fn validate_structural(&self) -> Result<()> {
        self.account_id.validate()?;
        self.governance_facts.validate()?;
        self.unsigned_event.transition()?.validate()?;
        self.accepted_actor_frontier
            .validate_with_suite(self.governance_facts.digest_algorithm)?;
        let event = &self.unsigned_event;
        let frontier = &self.accepted_actor_frontier;
        if self.authoring_device_generation_ref == 0
            || frontier.realm_id != self.realm_id
            || frontier.actor_id != ActorId::account(self.account_id.clone())
            || event.realm_id != self.realm_id
            || event.actor_id != frontier.actor_id
            || event.scope_ref
                != (arkret_wire::ScopeRef::Realm {
                    realm_id: self.realm_id.clone(),
                })
            || event.actor_seq != frontier.next_actor_seq
            || event.prev_refs != frontier.frontier_event_ids
            || event.seal_basis != self.governance_facts.seal_basis
        {
            return Err(WireError::Protocol(
                "prepared join differs from accepted frontier or authority".to_owned(),
            ));
        }
        event
            .to_event()?
            .verify_event_id_matches_content_with_digest_suite(
                self.governance_facts.digest_algorithm,
            )?;
        validate_canonical_bytes(self, Self::MAX_CANONICAL_BYTES, "Realm join preparation")?;
        validate_window(self.observed_at, self.expires_at, "Realm join preparation")
    }

    /// Everything a client is allowed to check: target, purpose, request
    /// binding, and that the bytes it is about to sign are the ones this
    /// request asked for. It deliberately proves nothing about remote
    /// governance — that is the Station's job, and re-deriving it here is the
    /// client history replay the protocol removed.
    pub fn validate_for_request(&self, request: &RealmJoinPrepareRequestBody) -> Result<()> {
        self.validate_structural()?;
        if self.request_id != request.request_id
            || self.account_id != request.account_id
            || self.realm_id != request.realm_id
        {
            return Err(WireError::Protocol(
                "Realm join preparation does not echo the request identity".to_owned(),
            ));
        }
        if self.request_digest != request.request_digest()? {
            return Err(WireError::Protocol(
                "Realm join preparation request_digest does not cover this request".to_owned(),
            ));
        }
        if self.unsigned_event.created_at != request.created_at
            || self.unsigned_event.hlc != request.hlc
            || self.unsigned_event.kind.as_str() != request.intent.event_kind()
            || !self
                .unsigned_event
                .transition()?
                .matches_intent(&request.intent)
        {
            return Err(WireError::Protocol(
                "Realm join preparation prepares a different intent than requested".to_owned(),
            ));
        }
        let actor = ActorId::account(request.account_id.clone());
        let (expected_payload, expected_cell, expected_invite_value) = match &request.intent {
            RealmJoinIntent::InviteAccept { invite_id, .. } => {
                let subject =
                    arkret_wire::composite_subject(&[request.account_id.canonical_key()?])?;
                (
                    serde_json::to_value(InviteAcceptPayload::directed(
                        invite_id.clone(),
                        request.account_id.clone(),
                    ))?,
                    CellRef::new(format!(
                        "ak:cell:ak.component.invite.live_target.v1:{subject}"
                    ))?,
                    Some(serde_json::to_value(invite_id.event_id())?),
                )
            }
            RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
                let (membership, gate_proofs) = match &request.intent {
                    RealmJoinIntent::MemberJoin { gate_proofs } => {
                        (MembershipPayloadState::Join, gate_proofs.clone())
                    }
                    _ => (MembershipPayloadState::Knock, Vec::new()),
                };
                let subject = arkret_wire::composite_subject(&[actor.canonical_key()?])?;
                (
                    serde_json::to_value(MembershipPayload {
                        strand_id: None,
                        realm_id: Some(request.realm_id.clone()),
                        member_id: actor,
                        membership,
                        gate_proofs,
                        reason: None,
                        membership_cause: None,
                        agent_controller_binding: None,
                        invite_ref: None,
                    })?,
                    CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))?,
                    None,
                )
            }
        };
        if serde_json::to_value(&self.unsigned_event.payload)? != expected_payload {
            return Err(WireError::Protocol(
                "prepared join payload or refs adds unrequested semantics".to_owned(),
            ));
        }
        let [precondition] = self.unsigned_event.preconditions.as_slice() else {
            return Err(WireError::Protocol(
                "prepared join requires exactly one scoped head_eq precondition".to_owned(),
            ));
        };
        let predicate = &precondition.predicate;
        let valid_value = match expected_invite_value {
            Some(expected) => predicate.value.as_ref() == Some(&expected),
            None => predicate.value.as_ref().is_some_and(|value| {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|state| matches!(state, "join" | "knock" | "leave" | "ban"))
            }),
        };
        if precondition.cell_id != expected_cell
            || predicate.op != arkret_wire::PredicateOp::HeadEq
            || predicate.values.is_some()
            || predicate.predicate_id.is_some()
            || !valid_value
        {
            return Err(WireError::Protocol(
                "prepared join precondition changes the target cell, operator or legal state"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// State of one join application as observed by the receiving Realm member
/// Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinRealmState {
    /// The byte-identical Event was durably accepted for forwarding but is not
    /// yet an Ack-bearing proposal.
    Received,
    AuthorityPending,
    Deferred,
    Overdue,
    Rejected,
    Sealed,
}

impl RealmJoinRealmState {
    /// The registered one-to-one mapping onto
    /// `control_proposal_decision_read_outcome.proposal_state`. `received`
    /// precedes any proposal, so it maps to nothing.
    pub fn proposal_state(self) -> Option<ControlProposalState> {
        match self {
            Self::Received => None,
            Self::AuthorityPending => Some(ControlProposalState::Pending),
            Self::Deferred => Some(ControlProposalState::Deferred),
            Self::Overdue => Some(ControlProposalState::Overdue),
            Self::Rejected => Some(ControlProposalState::Rejected),
            Self::Sealed => Some(ControlProposalState::Sealed),
        }
    }

    pub fn from_proposal_state(state: ControlProposalState) -> Self {
        match state {
            ControlProposalState::Pending => Self::AuthorityPending,
            ControlProposalState::Deferred => Self::Deferred,
            ControlProposalState::Overdue => Self::Overdue,
            ControlProposalState::Rejected => Self::Rejected,
            ControlProposalState::Sealed => Self::Sealed,
        }
    }
}

/// Forwarding state held by the applicant's own Station. It is never Realm
/// acceptance.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinOriginState {
    /// Durably queued.
    Pending,
    /// One bounded candidate accepted the byte-identical Event.
    Forwarded,
    /// Every bounded candidate currently fails closed or is expired; the
    /// attempt stays retryable.
    Unreachable,
}

/// Authenticated service-to-service request from the applicant's own Station
/// for the bounded material required to author and verify exactly one join
/// attempt.
///
/// A caller-declared intent is never authorization: the holder verifies
/// `applicant_account_id.station_id` against the authenticated
/// `Source-Service-ID` and evaluates the intent against its own accepted state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinBootstrapRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    /// Complete applicant AccountId. A bare principal, a handle or an inferred
    /// Station is never accepted.
    pub applicant_account_id: AccountId,
    pub intent: RealmJoinIntent,
}

impl RealmJoinBootstrapRequestBody {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_BOOTSTRAP_REQUEST_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate(&self) -> Result<()> {
        self.applicant_account_id.validate()?;
        self.intent.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "Realm join bootstrap request",
        )
    }

    pub fn request_digest_for_canonical(bytes: &[u8]) -> Result<Hash> {
        let request: Self = arkret_canonical::from_canonical_json_slice(bytes)?;
        request.validate()?;
        let mut framed = REALM_JOIN_BOOTSTRAP_REQUEST_DIGEST_LABEL
            .as_bytes()
            .to_vec();
        framed.push(0);
        framed.extend_from_slice(bytes);
        Ok(Hash::new(arkret_canonical::sha256_digest(&framed))?)
    }

    pub fn request_digest(&self) -> Result<Hash> {
        self.validate()?;
        framed_request_digest(REALM_JOIN_BOOTSTRAP_REQUEST_DIGEST_LABEL, self)
    }
}

pub use super::realm_join_bootstrap::RealmJoinBootstrapOutcome;

/// Authenticated service-to-service read of the restricted outcome of exactly
/// one forwarded join application.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPeerApplicationStatusRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub applicant_account_id: AccountId,
    /// Exact join Event the applicant's Station forwarded. Any other Event of
    /// the same Realm shares the non-enumerating `not_found` outcome.
    pub event_id: EventId,
}

impl RealmJoinPeerApplicationStatusRequestBody {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_PEER_APPLICATION_STATUS_REQUEST_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate(&self) -> Result<()> {
        self.applicant_account_id.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "Realm join application status request",
        )
    }
}

/// Restricted outcome of exactly one join application: no roster, no unrelated
/// proposals, no Realm history, no general governance read.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPeerApplicationStatusOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub applicant_account_id: AccountId,
    pub event_id: EventId,
    pub realm_state: RealmJoinRealmState,
    /// Durable proposal observation for this exact application, present for
    /// every `realm_state` other than `received`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<ControlProposalDecisionReadOutcome>,
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
}

impl RealmJoinPeerApplicationStatusOutcome {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_PEER_APPLICATION_STATUS_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 262_144;

    pub fn validate_structural(&self) -> Result<()> {
        self.applicant_account_id.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "Realm join application status",
        )?;
        match (self.realm_state.proposal_state(), &self.decision) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(WireError::Protocol(
                "a received Realm join application has no proposal decision yet".to_owned(),
            )),
            (Some(_), None) => Err(WireError::Protocol(
                "an adjudicated Realm join application requires its proposal decision".to_owned(),
            )),
            (Some(expected), Some(decision)) => {
                if decision.proposal_state != expected {
                    return Err(WireError::Protocol(
                        "Realm join realm_state and proposal_state disagree".to_owned(),
                    ));
                }
                if decision.realm_id != self.realm_id {
                    return Err(WireError::Protocol(
                        "Realm join application decision belongs to another Realm".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    pub fn validate_for_request(
        &self,
        request: &RealmJoinPeerApplicationStatusRequestBody,
    ) -> Result<()> {
        request.validate()?;
        self.validate_structural()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.applicant_account_id != request.applicant_account_id
            || self.event_id != request.event_id
        {
            return Err(WireError::Protocol(
                "Realm join application status does not echo the request identity".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authenticated account read of one own join application before membership
/// exists.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinSelfApplicationStatusRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    /// Exact join Event this account submitted through its own Station.
    pub event_id: EventId,
}

impl RealmJoinSelfApplicationStatusRequestBody {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_SELF_APPLICATION_STATUS_REQUEST_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "Realm join application status request",
        )
    }
}

/// Own-Station validated progress of one join application.
///
/// It carries no Ack, no authority set, no authority signature and no covering
/// Seal bytes: the client learns whether it has joined, not a second
/// governance read surface. Once `sealed`, the account is a member and
/// continues through the ordinary member federation and sync surfaces.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinSelfApplicationStatusOutcome {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub origin_state: RealmJoinOriginState,
    /// Present exactly when a bounded candidate has answered for this
    /// application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_state: Option<RealmJoinRealmState>,
    /// Present exactly when `realm_state` is `sealed` and the own Station has
    /// itself verified and accepted that covering Seal. It is an acceptance
    /// observation, never an authoring `seal_basis`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_seal_id: Option<SealId>,
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
}

impl RealmJoinSelfApplicationStatusOutcome {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_SELF_APPLICATION_STATUS_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 65_536;

    pub fn validate_structural(&self) -> Result<()> {
        self.account_id.validate()?;
        validate_canonical_bytes(
            self,
            Self::MAX_CANONICAL_BYTES,
            "Realm join application status",
        )?;
        if self.origin_state != RealmJoinOriginState::Forwarded && self.realm_state.is_some() {
            return Err(WireError::Protocol(
                "a Realm join application that was never forwarded has no Realm state".to_owned(),
            ));
        }
        let sealed = self.realm_state == Some(RealmJoinRealmState::Sealed);
        if sealed != self.accepted_seal_id.is_some() {
            return Err(WireError::Protocol(
                "accepted_seal_id is present exactly when the Realm state is sealed".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_request(
        &self,
        request: &RealmJoinSelfApplicationStatusRequestBody,
    ) -> Result<()> {
        request.validate()?;
        self.validate_structural()?;
        if self.request_id != request.request_id
            || self.account_id != request.account_id
            || self.realm_id != request.realm_id
            || self.event_id != request.event_id
        {
            return Err(WireError::Protocol(
                "Realm join application status does not echo the request identity".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::seal::{NotarySig, Seal, SealSignature};
    use arkret_wire::{
        ActorId, CellRef, ControlProposalAuthorityKind, DidCoreId, DidUrl, Predicate, PredicateOp,
    };
    use serde_json::json;

    use super::*;
    use crate::governance::membership_invite::MembershipInviteRef;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).expect("hash")
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").expect("realm id")
    }

    fn account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:applicant.example").expect("principal"),
            DidCoreId::new("ak:did_core:web:origin.example").expect("station"),
        )
    }

    fn request_id() -> RequestId {
        RequestId::new("ak:request:01970000-0000-7000-8000-000000000031").expect("request id")
    }

    fn invite_id() -> InviteId {
        InviteId::new("ak:invite:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").expect("invite id")
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2").expect("event id")
    }

    fn seal() -> Seal {
        seal_with('1')
    }

    fn seal_with(delta_byte: char) -> Seal {
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).expect("seal id"),
            realm_id: realm_id(),
            predecessor_refs: Vec::new(),
            delta: vec![hash(delta_byte)],
            control_event_set_root: hash('2'),
            state_root: hash('3'),
            completeness_root: hash('4'),
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(SealSignature {
                verification_method: DidUrl::new("did:web:notary.example#key-1").expect("method"),
                payload_digest: hash('5'),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }),
            sealed_at: "2026-09-10T08:00:00Z".parse().expect("timestamp"),
            hlc: arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").expect("hlc"),
        };
        seal.id = seal
            .derive_id(DigestSuite::Sha256)
            .expect("derived seal id");
        seal
    }

    fn governance_facts(basis: SealBasis) -> RealmJoinGovernanceFacts {
        RealmJoinGovernanceFacts {
            join_rule: JoinRule::Invite,
            seal_basis: basis,
            digest_algorithm: DigestSuite::Sha256,
            encryption_profile: EncryptionProfile::MlsRfc9420,
        }
    }

    fn observed_at() -> DateTime<Utc> {
        "2026-09-10T08:00:00Z".parse().expect("timestamp")
    }

    fn expires_at() -> DateTime<Utc> {
        "2026-09-10T08:05:00Z".parse().expect("timestamp")
    }

    fn invite_intent() -> RealmJoinIntent {
        RealmJoinIntent::InviteAccept {
            invite_id: invite_id(),
            invite_token: "srv-01HYZ8Z000000000000000".to_owned(),
        }
    }

    fn prepare_request() -> RealmJoinPrepareRequestBody {
        RealmJoinPrepareRequestBody {
            request_id: request_id(),
            account_id: account_id(),
            realm_id: realm_id(),
            intent: invite_intent(),
            created_at: observed_at(),
            hlc: Some(arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap()),
        }
    }

    fn head_eq_precondition() -> Precondition {
        Precondition {
            cell_id: CellRef::new(format!(
                "ak:cell:ak.component.invite.live_target.v1:{}",
                arkret_wire::composite_subject(&[account_id().canonical_key().unwrap()]).unwrap()
            ))
            .expect("cell ref"),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!(invite_id().event_id())),
                values: None,
                predicate_id: None,
            },
        }
    }

    fn prepare_outcome(request: &RealmJoinPrepareRequestBody) -> RealmJoinPrepareOutcome {
        let frontier = crate::event_sync::RealmActorFrontierView::new(
            request.realm_id.clone(),
            ActorId::account(request.account_id.clone()),
            0,
            Vec::new(),
            DigestSuite::Sha256,
        )
        .unwrap();
        let unsigned_event = RealmJoinUnsignedEvent::prepare(
            request,
            &frontier,
            SealBasis {
                leaves: vec![seal().id],
            },
            RealmJoinTransition::InviteAccept {
                payload: InviteAcceptPayload::directed(invite_id(), account_id()),
                preconditions: vec![head_eq_precondition()],
            },
            DigestSuite::Sha256,
        )
        .unwrap();
        RealmJoinPrepareOutcome {
            request_id: request.request_id.clone(),
            account_id: request.account_id.clone(),
            realm_id: request.realm_id.clone(),
            request_digest: request.request_digest().expect("digest"),
            governance_facts: governance_facts(SealBasis {
                leaves: vec![seal().id],
            }),
            unsigned_event,
            accepted_actor_frontier: frontier,
            authoring_device_generation_ref: 1,
            observed_at: observed_at(),
            expires_at: expires_at(),
        }
    }

    #[test]
    fn an_intent_round_trips_through_its_wire_tag() {
        let value = serde_json::to_value(invite_intent()).expect("serialize");
        assert_eq!(value["intent"], json!("invite_accept"));
        let restored: RealmJoinIntent = serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored, invite_intent());

        let knock = serde_json::to_value(RealmJoinIntent::Knock {}).expect("serialize");
        assert_eq!(knock, json!({"intent": "knock"}));
        let restored: RealmJoinIntent = serde_json::from_value(knock).unwrap();
        assert_eq!(restored, RealmJoinIntent::Knock {});
        for unrequested in ["gate_proofs", "application_text", "x_unrequested"] {
            let mut value = json!({"intent": "knock"});
            value[unrequested] = json!([]);
            assert!(serde_json::from_value::<RealmJoinIntent>(value).is_err());
        }
    }

    #[test]
    fn an_unregistered_intent_branch_has_no_representation() {
        // `restricted_join` and application receipts are the two branches the
        // service must answer with `unsupported_feature`; the point of the
        // closed union is that a caller cannot even encode them.
        assert!(
            serde_json::from_value::<RealmJoinIntent>(json!({"intent": "restricted_join"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<RealmJoinIntent>(json!({"intent": "application"})).is_err()
        );
    }

    #[test]
    fn debug_output_never_carries_the_invite_token() {
        let rendered = format!("{:?}", prepare_request());
        assert!(
            !rendered.contains("srv-01HYZ8Z000000000000000"),
            "{rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn an_empty_invite_token_is_rejected() {
        let mut request = prepare_request();
        request.intent = RealmJoinIntent::InviteAccept {
            invite_id: invite_id(),
            invite_token: String::new(),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn the_request_digest_covers_the_protected_credential() {
        let request = prepare_request();
        let mut other = prepare_request();
        other.intent = RealmJoinIntent::InviteAccept {
            invite_id: invite_id(),
            invite_token: "srv-01HYZ8Z000000000000001".to_owned(),
        };
        assert_ne!(
            request.request_digest().expect("digest"),
            other.request_digest().expect("digest"),
            "a second token on the same invite must not reuse the first preparation"
        );
    }

    #[test]
    fn a_preparation_binds_its_own_request() {
        let request = prepare_request();
        let outcome = prepare_outcome(&request);
        outcome
            .validate_for_request(&request)
            .expect("the preparation answers this request");

        let mut replayed = prepare_request();
        replayed.realm_id =
            RealmId::new("ak:realm:AZ0iBOTdEfBLcM7WT9SFbSOJU7EYIkPMPtXcLcZ5UjRT").expect("realm");
        assert!(outcome.validate_for_request(&replayed).is_err());
    }

    #[test]
    fn a_preparation_may_not_switch_the_intent() {
        let request = prepare_request();
        let mut outcome = prepare_outcome(&request);
        let bad_transition = RealmJoinTransition::MemberState {
            payload: MembershipPayload {
                strand_id: None,
                realm_id: Some(realm_id()),
                member_id: ActorId::account(account_id()),
                membership: MembershipPayloadState::Join,
                gate_proofs: Vec::new(),
                reason: None,
                membership_cause: None,
                agent_controller_binding: None,
                invite_ref: Some(MembershipInviteRef::Invite(invite_id())),
            },
            preconditions: Vec::new(),
        };
        outcome.unsigned_event = RealmJoinUnsignedEvent::prepare(
            &request,
            &outcome.accepted_actor_frontier,
            outcome.governance_facts.seal_basis.clone(),
            bad_transition,
            DigestSuite::Sha256,
        )
        .unwrap();
        let error = outcome
            .validate_for_request(&request)
            .expect_err("an invite acceptance may not come back as a self-authored join");
        assert!(error.to_string().contains("different intent"), "{error}");
    }

    fn rehash_prepared_event(outcome: &mut RealmJoinPrepareOutcome) {
        let mut event = outcome.unsigned_event.to_event().unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(
                outcome.governance_facts.digest_algorithm,
            )
            .unwrap();
        outcome.unsigned_event.event_id = event.event_id;
    }

    #[test]
    fn prepared_join_rejects_rehashed_extra_payload_refs_and_predicates() {
        let request = prepare_request();
        let baseline = prepare_outcome(&request);
        baseline.validate_for_request(&request).unwrap();
        let mut variants = Vec::new();
        let mut extra = serde_json::to_value(&baseline).unwrap();
        extra["unsigned_event"]["payload"]["x_unrequested"] = json!("injected");
        variants.push(serde_json::from_value(extra).unwrap());
        let mut referenced = serde_json::to_value(&baseline).unwrap();
        referenced["unsigned_event"]["refs"] = json!([{
            "id": invite_id().event_id(), "role": "related", "critical": true,
        }]);
        assert!(serde_json::from_value::<RealmJoinPrepareOutcome>(referenced).is_err());
        let mut wrong_subject = baseline.clone();
        wrong_subject.unsigned_event.preconditions[0].cell_id =
            CellRef::new("ak:cell:ak.component.invite.live_target.v1:another-account").unwrap();
        variants.push(wrong_subject);
        let mut wrong_invite = baseline.clone();
        wrong_invite.unsigned_event.preconditions[0].predicate.value = Some(json!(null));
        variants.push(wrong_invite);
        let mut extra_predicate = baseline.clone();
        extra_predicate
            .unsigned_event
            .preconditions
            .push(head_eq_precondition());
        variants.push(extra_predicate);
        let mut wrong_operator = baseline.clone();
        wrong_operator.unsigned_event.preconditions[0].predicate.op = PredicateOp::Contains;
        variants.push(wrong_operator);
        for mut tampered in variants {
            rehash_prepared_event(&mut tampered);
            assert!(tampered.validate_for_request(&request).is_err());
        }
    }

    #[test]
    fn prepared_member_join_and_knock_cannot_smuggle_strand_or_invite_semantics() {
        for intent in [
            RealmJoinIntent::MemberJoin {
                gate_proofs: Vec::new(),
            },
            RealmJoinIntent::Knock {},
        ] {
            let mut request = prepare_request();
            request.intent = intent;
            let mut outcome = prepare_outcome(&request);
            let actor = ActorId::account(request.account_id.clone());
            let subject =
                arkret_wire::composite_subject(&[actor.canonical_key().unwrap()]).unwrap();
            let transition = RealmJoinTransition::MemberState {
                payload: MembershipPayload {
                    strand_id: None,
                    realm_id: Some(request.realm_id.clone()),
                    member_id: actor,
                    membership: if matches!(request.intent, RealmJoinIntent::Knock {}) {
                        MembershipPayloadState::Knock
                    } else {
                        MembershipPayloadState::Join
                    },
                    gate_proofs: Vec::new(),
                    reason: None,
                    membership_cause: None,
                    agent_controller_binding: None,
                    invite_ref: None,
                },
                preconditions: vec![Precondition {
                    cell_id: CellRef::new(format!(
                        "ak:cell:ak.component.member.state.v1:{subject}"
                    ))
                    .unwrap(),
                    predicate: Predicate {
                        op: PredicateOp::HeadEq,
                        value: Some(json!(null)),
                        values: None,
                        predicate_id: None,
                    },
                }],
            };
            outcome.unsigned_event = RealmJoinUnsignedEvent::prepare(
                &request,
                &outcome.accepted_actor_frontier,
                outcome.governance_facts.seal_basis.clone(),
                transition,
                DigestSuite::Sha256,
            )
            .unwrap();
            outcome.validate_for_request(&request).unwrap();
            let mut value = serde_json::to_value(&outcome).unwrap();
            value["unsigned_event"]["payload"]["invite_ref"] = json!(invite_id());
            let mut injected = serde_json::from_value(value).unwrap();
            rehash_prepared_event(&mut injected);
            assert!(injected.validate_for_request(&request).is_err());
            let mut value = serde_json::to_value(&outcome).unwrap();
            value["unsigned_event"]["payload"]["strand_id"] =
                json!("ak:strand:AXA352XtBodUhnMN_nDxOloEHVn0_yAotxiYxbyU38Df");
            let mut injected = serde_json::from_value(value).unwrap();
            rehash_prepared_event(&mut injected);
            assert!(injected.validate_for_request(&request).is_err());
        }
    }

    #[test]
    fn rejoin_uses_accepted_chain_and_rejects_timestamp_or_zero_sequence_rewrite() {
        let request = prepare_request();
        let mut outcome = prepare_outcome(&request);
        outcome.accepted_actor_frontier = crate::event_sync::RealmActorFrontierView::new(
            request.realm_id.clone(),
            ActorId::account(request.account_id.clone()),
            8,
            vec![EventId::from_digest(DigestSuite::Sha256, [7; 32])],
            DigestSuite::Sha256,
        )
        .unwrap();
        outcome.unsigned_event = RealmJoinUnsignedEvent::prepare(
            &request,
            &outcome.accepted_actor_frontier,
            outcome.governance_facts.seal_basis.clone(),
            outcome.unsigned_event.transition().unwrap(),
            DigestSuite::Sha256,
        )
        .unwrap();
        outcome.validate_for_request(&request).unwrap();
        outcome.unsigned_event.actor_seq = 0;
        assert!(outcome.validate_for_request(&request).is_err());
        outcome.unsigned_event.actor_seq = 8;
        outcome.unsigned_event.created_at += chrono::Duration::seconds(1);
        assert!(outcome.validate_for_request(&request).is_err());
    }

    #[test]
    fn a_directed_invite_acceptance_requires_frozen_preconditions() {
        let request = prepare_request();
        let mut outcome = prepare_outcome(&request);
        outcome.unsigned_event.preconditions.clear();
        let error = outcome
            .validate_structural()
            .expect_err("the client cannot derive head_eq itself");
        assert!(error.to_string().contains("preconditions"), "{error}");
    }

    #[test]
    fn typed_join_transition_preserves_the_event_kind() {
        let request = prepare_request();
        let value = serde_json::to_value(
            prepare_outcome(&request)
                .unsigned_event
                .transition()
                .unwrap(),
        )
        .expect("serialize");
        assert_eq!(value["event_kind"], json!("ak.invite.accept"));
        assert!(value["payload"]["invite_id"].is_string());
        let restored: RealmJoinTransition = serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored.event_kind(), event_kind_str::INVITE_ACCEPT);
    }

    #[test]
    fn a_membership_payload_cannot_ride_the_invite_accept_branch() {
        assert!(
            serde_json::from_value::<RealmJoinTransition>(json!({
                "event_kind": "ak.invite.accept",
                "payload": {
                    "member_id": {"kind": "account", "account_id": {
                        "principal_id": "ak:did_core:web:applicant.example",
                        "station_id": "ak:did_core:web:origin.example"}},
                    "membership": "join"
                }
            }))
            .is_err()
        );
    }

    fn bootstrap_request() -> RealmJoinBootstrapRequestBody {
        RealmJoinBootstrapRequestBody {
            request_id: request_id(),
            realm_id: realm_id(),
            applicant_account_id: account_id(),
            intent: invite_intent(),
        }
    }

    fn bootstrap_outcome(request: &RealmJoinBootstrapRequestBody) -> RealmJoinBootstrapOutcome {
        RealmJoinBootstrapOutcome {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            applicant_account_id: request.applicant_account_id.clone(),
            request_digest: request.request_digest().unwrap(),
            governance_facts: governance_facts(SealBasis {
                leaves: vec![seal().id],
            }),
            page_index: 0,
            records: vec![],
            next_cursor: None,
            observed_at: observed_at(),
            expires_at: expires_at(),
        }
    }

    #[test]
    fn bootstrap_pages_preserve_context_and_reject_gaps_and_false_completion() {
        use super::super::realm_join_bootstrap::RealmJoinBootstrapAssembly;
        let request = bootstrap_request();
        let mut first = bootstrap_outcome(&request);
        first.next_cursor = Some("opaque-first".into());
        let mut assembly = RealmJoinBootstrapAssembly::new(first.clone(), &request).unwrap();
        assert!(assembly.finish(observed_at()).is_err());
        let mut next = first.clone();
        next.page_index = 2;
        next.next_cursor = None;
        assert!(assembly.append(next.clone(), &request).is_err());
        next.page_index = 1;
        next.governance_facts.join_rule = JoinRule::Public;
        assert!(assembly.append(next.clone(), &request).is_err());
        next.governance_facts = first.governance_facts.clone();
        assembly.append(next.clone(), &request).unwrap();
        assembly.finish(observed_at()).unwrap();
        assert!(assembly.validate_closure_coordinates().is_err());
        assert!(assembly.append(next, &request).is_err());
        assert!(assembly.finish(expires_at()).is_err());
    }

    #[test]
    fn bootstrap_wire_rejects_old_proof_fields_and_missing_terminal_cursor() {
        use super::super::realm_join_bootstrap::RealmJoinBootstrapReadRequest;
        let request = bootstrap_request();
        let mut page = serde_json::to_value(bootstrap_outcome(&request)).unwrap();
        page.as_object_mut().unwrap().remove("next_cursor");
        assert!(serde_json::from_value::<RealmJoinBootstrapOutcome>(page.clone()).is_err());
        page["next_cursor"] = serde_json::Value::Null;
        page["precondition_evidence"] = json!({});
        assert!(serde_json::from_value::<RealmJoinBootstrapOutcome>(page).is_err());
        assert!(
            serde_json::from_value::<RealmJoinBootstrapReadRequest>(
                json!({"cursor":"opaque", "realm_id":realm_id()})
            )
            .is_err()
        );
    }

    #[test]
    fn bootstrap_pages_can_exceed_eight_mib_in_total_without_accepting_foreign_actor() {
        use super::super::realm_join_bootstrap::{
            RealmJoinBootstrapAssembly, RealmJoinBootstrapRecord,
        };
        let request = bootstrap_request();
        let mut assembly = None;
        for page_index in 0..2 {
            let mut page = bootstrap_outcome(&request);
            page.page_index = page_index;
            page.next_cursor = (page_index == 0).then(|| "opaque-next".into());
            for index in 0..32 {
                let mut event = prepare_outcome(&prepare_request())
                    .unsigned_event
                    .to_event()
                    .unwrap();
                event.kind = arkret_wire::EventKind::MessageCreate;
                event.event_id = EventId::from_digest(
                    DigestSuite::Sha256,
                    [(page_index * 32 + index) as u8; 32],
                );
                event.payload = serde_json::from_value(json!({"strand_id":"ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19", "track_name":"discussion", "content":{"kind":"ak.content.text","body":"x".repeat(180_000)}})).unwrap();
                page.records
                    .push(RealmJoinBootstrapRecord::ApplicantPredecessor { event });
            }
            page.validate_for_request(&request).unwrap();
            if page_index == 0 {
                assembly = Some(RealmJoinBootstrapAssembly::new(page, &request).unwrap());
            } else {
                assembly.as_mut().unwrap().append(page, &request).unwrap();
            }
        }
        let assembly = assembly.unwrap();
        assert!(
            arkret_canonical::canonical_json_bytes(&assembly.records)
                .unwrap()
                .len()
                > 8 * 1024 * 1024
        );
        assembly.finish(observed_at()).unwrap();
        let mut foreign = assembly.records[0].clone();
        if let RealmJoinBootstrapRecord::ApplicantPredecessor { event } = &mut foreign {
            event.realm_id =
                RealmId::new("ak:realm:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N").unwrap();
        }
        assert!(
            foreign
                .validate_scope(&request.realm_id, &request.applicant_account_id)
                .is_err()
        );
    }

    fn decision(state: ControlProposalState) -> ControlProposalDecisionReadOutcome {
        ControlProposalDecisionReadOutcome {
            realm_id: realm_id(),
            proposal_digest: hash('6'),
            proposal_event_kind: event_kind_str::INVITE_ACCEPT.to_owned(),
            proposal_authority_kind: ControlProposalAuthorityKind::ControlProposalAck,
            proposal_state: state,
            control_proposal_ack: None,
            defer_decisions: None,
            terminal_reject: None,
            fault_reason: None,
            accepted_seal_id: None,
        }
    }

    fn peer_status_request() -> RealmJoinPeerApplicationStatusRequestBody {
        RealmJoinPeerApplicationStatusRequestBody {
            request_id: request_id(),
            realm_id: realm_id(),
            applicant_account_id: account_id(),
            event_id: event_id(),
        }
    }

    fn peer_status_outcome(
        realm_state: RealmJoinRealmState,
        decision: Option<ControlProposalDecisionReadOutcome>,
    ) -> RealmJoinPeerApplicationStatusOutcome {
        RealmJoinPeerApplicationStatusOutcome {
            request_id: request_id(),
            realm_id: realm_id(),
            applicant_account_id: account_id(),
            event_id: event_id(),
            realm_state,
            decision,
            observed_at: observed_at(),
        }
    }

    #[test]
    fn every_realm_state_but_received_carries_its_decision() {
        for state in [
            RealmJoinRealmState::AuthorityPending,
            RealmJoinRealmState::Deferred,
            RealmJoinRealmState::Overdue,
            RealmJoinRealmState::Rejected,
            RealmJoinRealmState::Sealed,
        ] {
            let mapped = state.proposal_state().expect("an adjudicated state maps");
            assert_eq!(RealmJoinRealmState::from_proposal_state(mapped), state);
            peer_status_outcome(state, Some(decision(mapped)))
                .validate_for_request(&peer_status_request())
                .expect("the registered mapping holds");
            assert!(
                peer_status_outcome(state, None)
                    .validate_structural()
                    .is_err()
            );
        }

        peer_status_outcome(RealmJoinRealmState::Received, None)
            .validate_for_request(&peer_status_request())
            .expect("a received application has no proposal yet");
        assert!(
            peer_status_outcome(
                RealmJoinRealmState::Received,
                Some(decision(ControlProposalState::Pending))
            )
            .validate_structural()
            .is_err()
        );
    }

    #[test]
    fn a_disagreeing_proposal_state_is_rejected() {
        let error = peer_status_outcome(
            RealmJoinRealmState::Sealed,
            Some(decision(ControlProposalState::Pending)),
        )
        .validate_structural()
        .expect_err("sealed and pending cannot both be true");
        assert!(error.to_string().contains("disagree"), "{error}");
    }

    fn self_status_request() -> RealmJoinSelfApplicationStatusRequestBody {
        RealmJoinSelfApplicationStatusRequestBody {
            request_id: request_id(),
            account_id: account_id(),
            realm_id: realm_id(),
            event_id: event_id(),
        }
    }

    fn self_status_outcome(
        origin_state: RealmJoinOriginState,
        realm_state: Option<RealmJoinRealmState>,
        accepted_seal_id: Option<SealId>,
    ) -> RealmJoinSelfApplicationStatusOutcome {
        RealmJoinSelfApplicationStatusOutcome {
            request_id: request_id(),
            account_id: account_id(),
            realm_id: realm_id(),
            event_id: event_id(),
            origin_state,
            realm_state,
            accepted_seal_id,
            observed_at: observed_at(),
        }
    }

    #[test]
    fn a_realm_state_requires_a_forwarded_application() {
        self_status_outcome(RealmJoinOriginState::Pending, None, None)
            .validate_for_request(&self_status_request())
            .expect("a queued application has no Realm answer");
        assert!(
            self_status_outcome(
                RealmJoinOriginState::Unreachable,
                Some(RealmJoinRealmState::Received),
                None
            )
            .validate_structural()
            .is_err()
        );
    }

    #[test]
    fn an_accepted_seal_appears_exactly_when_sealed() {
        let seal_id = seal().id;
        self_status_outcome(
            RealmJoinOriginState::Forwarded,
            Some(RealmJoinRealmState::Sealed),
            Some(seal_id.clone()),
        )
        .validate_for_request(&self_status_request())
        .expect("a sealed application reports the Seal its Station accepted");

        assert!(
            self_status_outcome(
                RealmJoinOriginState::Forwarded,
                Some(RealmJoinRealmState::Sealed),
                None
            )
            .validate_structural()
            .is_err()
        );
        assert!(
            self_status_outcome(
                RealmJoinOriginState::Forwarded,
                Some(RealmJoinRealmState::Rejected),
                Some(seal_id)
            )
            .validate_structural()
            .is_err()
        );
    }

    #[test]
    fn the_self_outcome_has_no_authority_surface() {
        let value = serde_json::to_value(self_status_outcome(
            RealmJoinOriginState::Forwarded,
            Some(RealmJoinRealmState::Sealed),
            Some(seal().id),
        ))
        .expect("serialize");
        let members = value.as_object().expect("object");
        for forbidden in [
            "decision",
            "control_proposal_ack",
            "authority_set",
            "authority_signature",
            "seal",
        ] {
            assert!(!members.contains_key(forbidden), "{forbidden} leaked");
        }
    }

    /// Field-set parity with `realm-join-intake.schema.json`.
    ///
    /// A schema member the carrier cannot hold is a binding this SDK cannot
    /// express; a carrier member the schema does not declare is one no
    /// conforming peer will accept. The comparison runs in both directions
    /// against fully populated instances, because `skip_serializing_if` hides
    /// an absent optional from the serialized form.
    mod schema_parity {
        use std::collections::BTreeSet;

        use arkret_wire::{ActorId, ControlProposalState, PayloadProof};
        use serde::Serialize;
        use serde_json::Value;

        use super::*;
        use crate::governance::membership_invite::{JoinGateProof, JoinGateProofKind};
        use crate::governance::realm_join_intake::{
            RealmJoinIntent, RealmJoinOriginState, RealmJoinRealmState,
        };

        const INTAKE: &str = "schemas/realm-join-intake.schema.json";

        fn definition(name: &str) -> Value {
            let schema = arkret_schema_conformance::spec_json_artifact(INTAKE)
                .unwrap_or_else(|error| panic!("embedded {INTAKE} failed to load: {error}"));
            schema["$defs"][name].clone()
        }

        fn assert_matches_schema<T: Serialize>(name: &str, fully_populated: &T) {
            let declared: BTreeSet<String> = definition(name)["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("$defs/{name}/properties is missing"))
                .keys()
                .cloned()
                .collect();
            let carried: BTreeSet<String> = serde_json::to_value(fully_populated)
                .expect("carrier serializes")
                .as_object()
                .expect("carrier serializes to an object")
                .keys()
                .cloned()
                .collect();
            assert_eq!(declared, carried, "$defs/{name} and its carrier differ");
        }

        fn assert_enum_values<T: Serialize>(name: &str, all: &[T]) {
            let declared: BTreeSet<String> = definition(name)["enum"]
                .as_array()
                .unwrap_or_else(|| panic!("$defs/{name}/enum is missing"))
                .iter()
                .map(|value| value.as_str().expect("enum value is a string").to_owned())
                .collect();
            let carried: BTreeSet<String> = all
                .iter()
                .map(|value| {
                    serde_json::to_value(value)
                        .expect("enum serializes")
                        .as_str()
                        .expect("enum serializes to a string")
                        .to_owned()
                })
                .collect();
            assert_eq!(declared, carried, "$defs/{name} and its enum differ");
        }

        fn gate_proof() -> JoinGateProof {
            JoinGateProof {
                gate_id: "gate-1".to_owned(),
                kind: JoinGateProofKind::ChallengeResponse,
                realm_id: realm_id(),
                applicant_actor_id: ActorId::account(account_id()),
                policy_digest: hash('8'),
                created_at: observed_at(),
                challenge_kind: None,
                challenge_id: None,
                issuer_id: None,
                claims: None,
                proofs: Vec::<PayloadProof>::new(),
            }
        }

        #[test]
        fn every_intake_body_carries_exactly_its_declared_members() {
            let prepare_request = prepare_request();
            let prepare_outcome = prepare_outcome(&prepare_request);
            assert_matches_schema("self_prepare_request_body", &prepare_request);
            assert_matches_schema("self_prepare_outcome", &prepare_outcome);
            assert_matches_schema(
                "realm_join_governance_facts",
                &prepare_outcome.governance_facts,
            );
            assert_matches_schema("realm_join_unsigned_event", &prepare_outcome.unsigned_event);

            let bootstrap_request = bootstrap_request();
            let bootstrap_outcome = bootstrap_outcome(&bootstrap_request);
            assert_matches_schema("peer_bootstrap_initial_request_body", &bootstrap_request);
            assert_matches_schema("peer_bootstrap_outcome", &bootstrap_outcome);

            assert_matches_schema(
                "peer_application_status_request_body",
                &peer_status_request(),
            );
            assert_matches_schema(
                "peer_application_status_outcome",
                &peer_status_outcome(
                    RealmJoinRealmState::Sealed,
                    Some(decision(ControlProposalState::Sealed)),
                ),
            );

            assert_matches_schema(
                "self_application_status_request_body",
                &self_status_request(),
            );
            assert_matches_schema(
                "self_application_status_outcome",
                &self_status_outcome(
                    RealmJoinOriginState::Forwarded,
                    Some(RealmJoinRealmState::Sealed),
                    Some(seal().id),
                ),
            );
        }

        #[test]
        fn every_intent_branch_carries_exactly_its_declared_members() {
            assert_matches_schema(
                "realm_join_invite_accept_intent",
                &RealmJoinIntent::InviteAccept {
                    invite_id: invite_id(),
                    invite_token: "srv-01HYZ8Z000000000000000".to_owned(),
                },
            );
            assert_matches_schema(
                "realm_join_member_join_intent",
                &RealmJoinIntent::MemberJoin {
                    gate_proofs: vec![gate_proof()],
                },
            );
            assert_matches_schema("realm_join_knock_intent", &RealmJoinIntent::Knock {});
        }

        #[test]
        fn every_registered_canonical_byte_cap_is_pinned() {
            for (name, declared) in [
                (
                    "self_prepare_request_body",
                    RealmJoinPrepareRequestBody::MAX_CANONICAL_BYTES,
                ),
                (
                    "self_prepare_outcome",
                    RealmJoinPrepareOutcome::MAX_CANONICAL_BYTES,
                ),
                (
                    "peer_bootstrap_request_body",
                    RealmJoinBootstrapRequestBody::MAX_CANONICAL_BYTES,
                ),
                (
                    "peer_bootstrap_outcome",
                    RealmJoinBootstrapOutcome::MAX_CANONICAL_BYTES,
                ),
                (
                    "peer_application_status_request_body",
                    RealmJoinPeerApplicationStatusRequestBody::MAX_CANONICAL_BYTES,
                ),
                (
                    "peer_application_status_outcome",
                    RealmJoinPeerApplicationStatusOutcome::MAX_CANONICAL_BYTES,
                ),
                (
                    "self_application_status_request_body",
                    RealmJoinSelfApplicationStatusRequestBody::MAX_CANONICAL_BYTES,
                ),
                (
                    "self_application_status_outcome",
                    RealmJoinSelfApplicationStatusOutcome::MAX_CANONICAL_BYTES,
                ),
            ] {
                assert_eq!(
                    definition(name)["x-arkret-max-canonical-bytes"].as_u64(),
                    Some(declared as u64),
                    "$defs/{name} budget drifted from its Rust constant"
                );
            }
        }

        #[test]
        fn the_aggregate_budget_check_actually_rejects() {
            // Each dependency bundle's own cap equals the whole bootstrap
            // outcome's cap, so 64 individually legal bundles can be 64 times
            // the registered budget. Exercised directly rather than by
            // building an 8 MiB fixture.
            let request = bootstrap_request();
            let outcome = bootstrap_outcome(&request);
            validate_canonical_bytes(&outcome, usize::MAX, "test")
                .expect("a carrier inside its budget passes");
            let error = validate_canonical_bytes(&outcome, 8, "test")
                .expect_err("a carrier over its budget is rejected");
            assert!(error.to_string().contains("canonical bytes"), "{error}");
        }

        #[test]
        fn the_closed_state_vocabularies_match_the_registry() {
            assert_enum_values(
                "realm_join_realm_state",
                &[
                    RealmJoinRealmState::Received,
                    RealmJoinRealmState::AuthorityPending,
                    RealmJoinRealmState::Deferred,
                    RealmJoinRealmState::Overdue,
                    RealmJoinRealmState::Rejected,
                    RealmJoinRealmState::Sealed,
                ],
            );
            assert_enum_values(
                "realm_join_origin_state",
                &[
                    RealmJoinOriginState::Pending,
                    RealmJoinOriginState::Forwarded,
                    RealmJoinOriginState::Unreachable,
                ],
            );
            // The mapping table is closed only if it round-trips in both
            // directions for every adjudicated proposal state.
            for state in [
                ControlProposalState::Pending,
                ControlProposalState::Deferred,
                ControlProposalState::Overdue,
                ControlProposalState::Rejected,
                ControlProposalState::Sealed,
            ] {
                assert_eq!(
                    RealmJoinRealmState::from_proposal_state(state).proposal_state(),
                    Some(state)
                );
            }
        }
    }
}
