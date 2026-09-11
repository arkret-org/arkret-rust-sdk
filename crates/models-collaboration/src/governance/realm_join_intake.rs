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
//! roster, message, MLS or governance read; preparation is not admission, and
//! submit re-checks current authority, freshness and basis.

use std::collections::BTreeSet;
use std::fmt;

use arkret_canonical::DigestSuite;
use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, ActorId, CbsProofBundle, CellRef, ControlProposalDecisionReadOutcome,
    ControlProposalState, EncryptionProfile, Event, EventId, Hash, InviteId, JoinRule,
    Precondition, RealmId, RequestId, Result, SchemaId, SealBasis, SealId, SemanticRefProof,
    SemanticRefProofRootField, WireError, canonical, event_kind_str, framed_request_digest,
    validate_invite_token,
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

/// `peer_bootstrap_outcome.dependency_bundles` bound; it also equals the
/// `seal_basis` leaf bound, because the array is one bundle per leaf.
pub const MAX_REALM_JOIN_DEPENDENCY_BUNDLES: usize = 64;

/// `realm_join_cell_state_proofs` bound. It is the same bound for the same
/// reason: the array is one proof per `seal_basis` leaf.
pub const MAX_REALM_JOIN_CELL_STATE_PROOFS: usize = 64;

/// `realm_join_cell_state_proof.neighbors` bound. A sorted-neighbor
/// non-membership proof needs at most the two leaves that bracket `cell_id`.
pub const MAX_REALM_JOIN_ABSENCE_NEIGHBORS: usize = 2;

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

/// Whether one control cell is written under one `seal_basis` leaf.
///
/// `absent` is the never-written case, and it is what makes the `null` join
/// result derivable at all: a Station that simply omitted the proof would be
/// indistinguishable from one that could not build it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCellPresence {
    Present,
    Absent,
}

/// Value-or-absence proof for one control cell against exactly one
/// `seal_basis` leaf.
///
/// Nothing here is authoritative. `present` carries the audit path of the
/// cell's `state_root` leaf, so the verifier reads the exact state object out
/// of `leaf_canonical_preimage_b64u` instead of trusting a declared value;
/// `absent` carries the sorted-neighbor non-membership proof for the same
/// `cell_id` under the same root. Both forms MUST recompute the `state_root`
/// the verifier itself derived for `seal_ref`, which is a step this structural
/// check deliberately does not perform.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinCellStateProof {
    /// Exact cell this proof decides. The requesting Station derives it from
    /// the applicant's own complete `AccountId` or account `ActorId`; a
    /// holder-declared subject is never a source.
    pub cell_id: CellRef,
    /// Exact `seal_basis` leaf this proof is evaluated against.
    pub seal_ref: SealId,
    pub presence: RealmJoinCellPresence,
    /// Present exactly when `presence` is `present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion: Option<SemanticRefProof>,
    /// Present exactly when `presence` is `absent`. Zero items assert the
    /// empty-tree root, one item is a boundary neighbour, and two items MUST
    /// carry adjacent `leaf_index` values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub neighbors: Option<Vec<SemanticRefProof>>,
}

impl RealmJoinCellStateProof {
    pub fn validate_structural(&self) -> Result<()> {
        match (self.presence, &self.inclusion, &self.neighbors) {
            (RealmJoinCellPresence::Present, Some(inclusion), None) => {
                inclusion.validate_structural()?;
                if inclusion.root_field != SemanticRefProofRootField::StateRoot {
                    return Err(WireError::Protocol(
                        "Realm join cell inclusion proof must resolve against state_root"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            (RealmJoinCellPresence::Absent, None, Some(neighbors)) => {
                if neighbors.len() > MAX_REALM_JOIN_ABSENCE_NEIGHBORS {
                    return Err(WireError::Protocol(format!(
                        "Realm join cell absence proof carries more than {MAX_REALM_JOIN_ABSENCE_NEIGHBORS} neighbors"
                    )));
                }
                for neighbor in neighbors {
                    neighbor.validate_structural()?;
                    if neighbor.root_field != SemanticRefProofRootField::StateRoot {
                        return Err(WireError::Protocol(
                            "Realm join cell absence proof must resolve against state_root"
                                .to_owned(),
                        ));
                    }
                }
                if let [left, right] = neighbors.as_slice() {
                    if left == right {
                        return Err(WireError::Protocol(
                            "Realm join cell absence proof repeats one neighbor".to_owned(),
                        ));
                    }
                    // Two neighbours only bracket `cell_id` if nothing can sit
                    // between them, and a pair that disagrees about the tree
                    // size is not a pair of neighbours in one tree at all.
                    if left.leaf_count != right.leaf_count
                        || right.leaf_index != left.leaf_index.saturating_add(1)
                    {
                        return Err(WireError::Protocol(
                            "Realm join cell absence neighbors must be adjacent leaves of one tree"
                                .to_owned(),
                        ));
                    }
                }
                if let [only] = neighbors.as_slice() {
                    // A single neighbour asserts that `cell_id` falls outside
                    // the tree, so it MUST be a boundary leaf; an interior leaf
                    // leaves both sides unproven.
                    if only.leaf_index != 0 && only.leaf_index + 1 != only.leaf_count {
                        return Err(WireError::Protocol(
                            "a single Realm join absence neighbor must be a boundary leaf"
                                .to_owned(),
                        ));
                    }
                }
                Ok(())
            }
            (RealmJoinCellPresence::Present, ..) => Err(WireError::Protocol(
                "a present Realm join cell proof requires an inclusion path and no neighbors"
                    .to_owned(),
            )),
            (RealmJoinCellPresence::Absent, ..) => Err(WireError::Protocol(
                "an absent Realm join cell proof requires neighbors and no inclusion path"
                    .to_owned(),
            )),
        }
    }
}

/// Exactly one [`RealmJoinCellStateProof`] per `seal_basis` leaf, for one and
/// the same `cell_id`, in the same canonical leaf order as `seal_basis.leaves`
/// and `dependency_bundles`.
///
/// A missing leaf, a repeated leaf, a leaf outside the returned basis or a
/// second `cell_id` is a schema violation: the requesting Station joins the
/// per-leaf results under the registered lattice rules for that cell and never
/// accepts one leaf as the whole basis.
fn validate_cell_state_proofs(
    proofs: &[RealmJoinCellStateProof],
    leaves: &[SealId],
    what: &str,
) -> Result<()> {
    if proofs.is_empty() || proofs.len() > MAX_REALM_JOIN_CELL_STATE_PROOFS {
        return Err(WireError::Protocol(format!(
            "{what} requires 1..={MAX_REALM_JOIN_CELL_STATE_PROOFS} cell state proofs"
        )));
    }
    if proofs.len() != leaves.len() {
        return Err(WireError::Protocol(format!(
            "{what} requires one cell state proof per seal_basis leaf"
        )));
    }
    let cell_id = &proofs[0].cell_id;
    for (proof, leaf) in proofs.iter().zip(leaves) {
        if proof.seal_ref != *leaf {
            return Err(WireError::Protocol(format!(
                "{what} cell state proofs are not in canonical leaf order"
            )));
        }
        if proof.cell_id != *cell_id {
            return Err(WireError::Protocol(format!(
                "{what} cell state proofs must all decide one cell"
            )));
        }
        proof.validate_structural()?;
    }
    Ok(())
}

/// Exact `live_target` material for one directed invite.
///
/// The slot subject is the single-component composite of the applicant's
/// complete `AccountId`, so an occupied slot is by construction a live direct
/// invite for exactly this applicant and no other.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinInviteAcceptPrecondition {
    /// Proofs for the `ak.component.invite.live_target.v1` cell. An absent or
    /// `Bottom` joined slot is not a usable pre-state and fails rather than
    /// being defaulted.
    pub live_target_proofs: Vec<RealmJoinCellStateProof>,
    /// Proofs for the `ak.component.invite.lifecycle.v1` cell of the invite
    /// that occupies the slot; any joined state other than `pending` or
    /// `claimed` is rejected.
    pub invite_lifecycle_proofs: Vec<RealmJoinCellStateProof>,
    /// Exact accepted `ak.invite.create` Control Move that occupies the slot.
    /// Its content-bound `event_id` MUST equal the joined `live_target` value,
    /// which is what authenticates it, so it carries no separate coverage
    /// proof.
    pub invite_move: Event,
}

/// Exact `member.state` material for a self-authored join or knock.
///
/// The requesting Station derives the `head_eq` value from the joined per-leaf
/// results: a never-written cell yields `null`, a written cell yields its exact
/// `fsm` state, and a joined `Bottom` fails closed instead of being rewritten
/// as `null`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinMemberStatePrecondition {
    /// Proofs for the `ak.component.member.state.v1` cell whose subject is the
    /// applicant's complete account `ActorId`.
    pub member_state_proofs: Vec<RealmJoinCellStateProof>,
}

/// Closed exact-precondition material for the requested join intent.
///
/// It proves the value or the never-written absence of exactly the one control
/// cell the prepared Event will bind, evaluated against the complete returned
/// `seal_basis`, and it discloses nothing else. The schema registers two
/// payload branches; the wire tag is the same closed `intent` vocabulary as
/// [`RealmJoinIntent`], because the `member_state` branch answers both
/// `member_join` and `knock`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "snake_case")]
pub enum RealmJoinPreconditionEvidence {
    InviteAccept(RealmJoinInviteAcceptPrecondition),
    MemberJoin(RealmJoinMemberStatePrecondition),
    Knock(RealmJoinMemberStatePrecondition),
}

impl RealmJoinPreconditionEvidence {
    /// Shape and per-leaf coverage against the exact basis the same outcome
    /// returned. Recomputing each `state_root` and joining the per-leaf results
    /// is the requesting Station's step, not this one.
    pub fn validate_structural(&self, seal_basis: &SealBasis) -> Result<()> {
        let leaves = &seal_basis.leaves;
        match self {
            Self::InviteAccept(evidence) => {
                validate_cell_state_proofs(
                    &evidence.live_target_proofs,
                    leaves,
                    "Realm join invite live_target",
                )?;
                validate_cell_state_proofs(
                    &evidence.invite_lifecycle_proofs,
                    leaves,
                    "Realm join invite lifecycle",
                )
            }
            Self::MemberJoin(evidence) | Self::Knock(evidence) => validate_cell_state_proofs(
                &evidence.member_state_proofs,
                leaves,
                "Realm join member state",
            ),
        }
    }

    /// The branch MUST agree with the requested intent: precondition material
    /// for another intent decides another cell.
    pub fn matches_intent(&self, intent: &RealmJoinIntent) -> bool {
        matches!(
            (self, intent),
            (Self::InviteAccept(_), RealmJoinIntent::InviteAccept { .. })
                | (Self::MemberJoin(_), RealmJoinIntent::MemberJoin { .. })
                | (Self::Knock(_), RealmJoinIntent::Knock {})
        )
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

    pub fn request_digest(&self) -> Result<Hash> {
        self.validate()?;
        framed_request_digest(REALM_JOIN_BOOTSTRAP_REQUEST_DIGEST_LABEL, self)
    }
}

/// Bounded join bootstrap material for exactly the requested applicant, Realm
/// and intent.
///
/// It authorizes nothing: no membership, no roster, message, MLS or general
/// governance read, and it expires.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinBootstrapOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub applicant_account_id: AccountId,
    /// Binds the outcome to this request. It is not an authentication proof
    /// against a malicious holder — the dependency closure is.
    pub request_digest: Hash,
    pub governance_facts: RealmJoinGovernanceFacts,
    /// Exactly one receiver-relative dependency bundle per `seal_basis` leaf,
    /// in the same canonical leaf order. It is the minimum closure the
    /// requesting Station needs to verify the returned facts itself; it is not
    /// authoritative.
    pub dependency_bundles: Vec<CbsProofBundle>,
    /// Exact-precondition material for the declared intent, evaluated against
    /// the same complete `seal_basis` and verified independently by the
    /// requesting Station.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub precondition_evidence: RealmJoinPreconditionEvidence,
    /// Unverified authoring input: the applicant's own accepted Events at the
    /// highest actor sequence the holder observes for exactly this `realm_id`
    /// and account `ActorId`, sorted bytewise by `event_id` without duplicates.
    ///
    /// An empty array is only the holder observing none. It proves neither an
    /// empty chain nor completeness, and it never lowers or overrides history
    /// the requesting Station has already verified.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub applicant_predecessor_events: Vec<Event>,
    /// Instant the holder observed the returned accepted projection.
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    /// Instant after which the requesting Station MUST re-run bootstrap
    /// instead of authoring from this material.
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl RealmJoinBootstrapOutcome {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_BOOTSTRAP_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 8 * 1024 * 1024;

    pub fn validate_structural(&self) -> Result<()> {
        self.applicant_account_id.validate()?;
        validate_canonical_bytes(self, Self::MAX_CANONICAL_BYTES, "Realm join bootstrap")?;
        self.governance_facts.validate()?;
        let leaves = &self.governance_facts.seal_basis.leaves;
        if self.dependency_bundles.is_empty()
            || self.dependency_bundles.len() > MAX_REALM_JOIN_DEPENDENCY_BUNDLES
        {
            return Err(WireError::Protocol(format!(
                "Realm join bootstrap requires 1..={MAX_REALM_JOIN_DEPENDENCY_BUNDLES} dependency bundles"
            )));
        }
        if self.dependency_bundles.len() != leaves.len() {
            return Err(WireError::Protocol(
                "Realm join bootstrap requires one dependency bundle per seal_basis leaf"
                    .to_owned(),
            ));
        }
        for (bundle, leaf) in self.dependency_bundles.iter().zip(leaves) {
            bundle.validate_structural()?;
            if bundle.target_seal_ref != *leaf {
                return Err(WireError::Protocol(
                    "Realm join bootstrap dependency bundles are not in canonical leaf order"
                        .to_owned(),
                ));
            }
        }
        self.precondition_evidence
            .validate_structural(&self.governance_facts.seal_basis)?;
        self.validate_predecessor_events()?;
        validate_window(self.observed_at, self.expires_at, "Realm join bootstrap")
    }

    /// Scope and ordering of `applicant_predecessor_events`.
    ///
    /// These Events are authoring input, so the only thing decidable here is
    /// that they are the applicant's own, for this Realm, and canonically
    /// ordered. Producer proof, station admission proof, signer regime and
    /// sequence continuity are re-run by the requesting Station under the
    /// ordinary Event acceptance rules before any of them enters a prepare
    /// context.
    fn validate_predecessor_events(&self) -> Result<()> {
        if self.applicant_predecessor_events.len() > MAX_REALM_JOIN_PREDECESSOR_EVENTS {
            return Err(WireError::Protocol(format!(
                "Realm join bootstrap carries more than {MAX_REALM_JOIN_PREDECESSOR_EVENTS} applicant predecessor events"
            )));
        }
        let applicant = ActorId::account(self.applicant_account_id.clone());
        for event in &self.applicant_predecessor_events {
            if event.realm_id != self.realm_id || event.actor_id != applicant {
                return Err(WireError::Protocol(
                    "Realm join bootstrap predecessor events must all be the applicant's own for this Realm"
                        .to_owned(),
                ));
            }
        }
        if self
            .applicant_predecessor_events
            .windows(2)
            .any(|pair| pair[0].event_id.as_str() >= pair[1].event_id.as_str())
        {
            return Err(WireError::Protocol(
                "Realm join bootstrap predecessor events must be bytewise sorted and unique"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &RealmJoinBootstrapRequestBody) -> Result<()> {
        self.validate_structural()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.applicant_account_id != request.applicant_account_id
        {
            return Err(WireError::Protocol(
                "Realm join bootstrap does not echo the request identity".to_owned(),
            ));
        }
        if self.request_digest != request.request_digest()? {
            return Err(WireError::Protocol(
                "Realm join bootstrap request_digest does not cover this request".to_owned(),
            ));
        }
        if !self.precondition_evidence.matches_intent(&request.intent) {
            return Err(WireError::Protocol(
                "Realm join bootstrap precondition evidence answers another intent".to_owned(),
            ));
        }
        Ok(())
    }
}

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

    fn live_target_cell() -> CellRef {
        CellRef::new(format!(
            "ak:cell:ak.component.invite.live_target.v1:{}",
            arkret_wire::composite_subject(&[account_id().canonical_key().unwrap()]).unwrap()
        ))
        .expect("cell ref")
    }

    fn invite_lifecycle_cell() -> CellRef {
        CellRef::new(format!(
            "ak:cell:ak.component.invite.lifecycle.v1:{}",
            invite_id().as_str()
        ))
        .expect("cell ref")
    }

    fn member_state_cell() -> CellRef {
        CellRef::new(format!(
            "ak:cell:ak.component.member.state.v1:{}",
            arkret_wire::composite_subject(&[ActorId::account(account_id())
                .canonical_key()
                .unwrap()])
            .unwrap()
        ))
        .expect("cell ref")
    }

    fn state_root_proof(leaf_index: u64, leaf_count: u64) -> SemanticRefProof {
        SemanticRefProof {
            kind: arkret_wire::SemanticRefProofKind::Rfc6962Merkle,
            root_field: SemanticRefProofRootField::StateRoot,
            root_digest: hash('3'),
            leaf_canonical_preimage_b64u: arkret_wire::Base64UrlString::new(format!(
                "cGF0aA{leaf_index}"
            ))
            .expect("preimage"),
            leaf_digest: hash('9'),
            audit_path: vec![hash('a')],
            leaf_index,
            leaf_count,
        }
    }

    fn present_proof(cell_id: CellRef, seal_ref: SealId) -> RealmJoinCellStateProof {
        RealmJoinCellStateProof {
            cell_id,
            seal_ref,
            presence: RealmJoinCellPresence::Present,
            inclusion: Some(state_root_proof(0, 1)),
            neighbors: None,
        }
    }

    fn absent_proof(
        cell_id: CellRef,
        seal_ref: SealId,
        neighbors: Vec<SemanticRefProof>,
    ) -> RealmJoinCellStateProof {
        RealmJoinCellStateProof {
            cell_id,
            seal_ref,
            presence: RealmJoinCellPresence::Absent,
            inclusion: None,
            neighbors: Some(neighbors),
        }
    }

    /// An Event that really is the applicant's own, for this Realm, with a
    /// content-bound id derived from its own bytes.
    fn applicant_event(actor_seq: u64) -> Event {
        let mut event = prepare_outcome(&prepare_request())
            .unsigned_event
            .to_event()
            .expect("envelope");
        event.actor_seq = actor_seq;
        event
            .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
            .expect("derived id");
        event
    }

    fn invite_move() -> Event {
        let mut event = applicant_event(0);
        event.kind = arkret_wire::EventKind::from("ak.invite.create");
        event
            .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
            .expect("derived id");
        event
    }

    fn invite_accept_evidence(leaves: &[SealId]) -> RealmJoinPreconditionEvidence {
        RealmJoinPreconditionEvidence::InviteAccept(RealmJoinInviteAcceptPrecondition {
            live_target_proofs: leaves
                .iter()
                .map(|leaf| present_proof(live_target_cell(), leaf.clone()))
                .collect(),
            invite_lifecycle_proofs: leaves
                .iter()
                .map(|leaf| present_proof(invite_lifecycle_cell(), leaf.clone()))
                .collect(),
            invite_move: invite_move(),
        })
    }

    fn member_state_evidence(leaves: &[SealId]) -> RealmJoinPreconditionEvidence {
        RealmJoinPreconditionEvidence::MemberJoin(RealmJoinMemberStatePrecondition {
            member_state_proofs: leaves
                .iter()
                .map(|leaf| absent_proof(member_state_cell(), leaf.clone(), Vec::new()))
                .collect(),
        })
    }

    fn bootstrap_outcome(request: &RealmJoinBootstrapRequestBody) -> RealmJoinBootstrapOutcome {
        let seal = seal();
        RealmJoinBootstrapOutcome {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            applicant_account_id: request.applicant_account_id.clone(),
            request_digest: request.request_digest().expect("digest"),
            governance_facts: governance_facts(SealBasis {
                leaves: vec![seal.id.clone()],
            }),
            dependency_bundles: vec![CbsProofBundle {
                target_seal_ref: seal.id.clone(),
                seals: vec![seal.clone()],
                control_moves: Vec::new(),
                inclusion_proofs: Vec::new(),
                availability_proofs: Vec::new(),
            }],
            precondition_evidence: invite_accept_evidence(&[seal.id.clone()]),
            applicant_predecessor_events: Vec::new(),
            observed_at: observed_at(),
            expires_at: expires_at(),
        }
    }

    fn sorted_predecessors(count: usize) -> Vec<Event> {
        let mut events: Vec<Event> = (0..count).map(|seq| applicant_event(seq as u64)).collect();
        events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
        events
    }

    #[test]
    fn precondition_evidence_needs_one_proof_per_basis_leaf() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        outcome
            .validate_structural()
            .expect("one proof per leaf for each cell");

        let RealmJoinPreconditionEvidence::InviteAccept(evidence) =
            &mut outcome.precondition_evidence
        else {
            panic!("the invite fixture is an invite_accept branch");
        };
        evidence.live_target_proofs.clear();
        let error = outcome
            .validate_structural()
            .expect_err("a cell with no proof at all decides nothing");
        assert!(error.to_string().contains("cell state proofs"), "{error}");
    }

    #[test]
    fn precondition_proofs_follow_the_canonical_leaf_order() {
        // Two real leaves, two real bundles, two real proofs per cell. Only the
        // proof order is wrong, so without the order rule each leaf would be
        // decided against another leaf's recomputed state_root.
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        let mut seals = vec![seal_with('1'), seal_with('7')];
        seals.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        let leaves: Vec<SealId> = seals.iter().map(|seal| seal.id.clone()).collect();
        outcome.governance_facts.seal_basis = SealBasis {
            leaves: leaves.clone(),
        };
        outcome.dependency_bundles = seals
            .iter()
            .map(|seal| CbsProofBundle {
                target_seal_ref: seal.id.clone(),
                seals: vec![seal.clone()],
                control_moves: Vec::new(),
                inclusion_proofs: Vec::new(),
                availability_proofs: Vec::new(),
            })
            .collect();
        outcome.precondition_evidence = invite_accept_evidence(&leaves);
        outcome
            .validate_structural()
            .expect("one proof per leaf, in leaf order");

        let RealmJoinPreconditionEvidence::InviteAccept(evidence) =
            &mut outcome.precondition_evidence
        else {
            panic!("the invite fixture is an invite_accept branch");
        };
        evidence.invite_lifecycle_proofs.reverse();
        let error = outcome
            .validate_structural()
            .expect_err("a proof for another leaf proves nothing about this one");
        assert!(
            error.to_string().contains("canonical leaf order"),
            "{error}"
        );
    }

    #[test]
    fn one_proof_group_decides_exactly_one_cell() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        let mut seals = vec![seal_with('1'), seal_with('7')];
        seals.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        let leaves: Vec<SealId> = seals.iter().map(|seal| seal.id.clone()).collect();
        outcome.governance_facts.seal_basis = SealBasis {
            leaves: leaves.clone(),
        };
        outcome.dependency_bundles = seals
            .iter()
            .map(|seal| CbsProofBundle {
                target_seal_ref: seal.id.clone(),
                seals: vec![seal.clone()],
                control_moves: Vec::new(),
                inclusion_proofs: Vec::new(),
                availability_proofs: Vec::new(),
            })
            .collect();
        outcome.precondition_evidence = invite_accept_evidence(&leaves);

        let RealmJoinPreconditionEvidence::InviteAccept(evidence) =
            &mut outcome.precondition_evidence
        else {
            panic!("the invite fixture is an invite_accept branch");
        };
        // A second cell inside one group would let a holder answer about a cell
        // the requesting Station never derived.
        evidence.live_target_proofs[1].cell_id = member_state_cell();
        let error = outcome
            .validate_structural()
            .expect_err("one group decides one cell");
        assert!(error.to_string().contains("one cell"), "{error}");
    }

    #[test]
    fn a_present_cell_proof_carries_only_a_state_root_inclusion_path() {
        let leaf = seal().id;
        present_proof(live_target_cell(), leaf.clone())
            .validate_structural()
            .expect("an inclusion path under state_root");

        let mut wrong_root = present_proof(live_target_cell(), leaf.clone());
        wrong_root.inclusion.as_mut().expect("inclusion").root_field =
            SemanticRefProofRootField::ControlEventSetRoot;
        let error = wrong_root
            .validate_structural()
            .expect_err("the covered-event tree is not the governance state tree");
        assert!(error.to_string().contains("state_root"), "{error}");

        let mut both = present_proof(live_target_cell(), leaf.clone());
        both.neighbors = Some(Vec::new());
        assert!(both.validate_structural().is_err());

        let mut neither = present_proof(live_target_cell(), leaf);
        neither.inclusion = None;
        assert!(neither.validate_structural().is_err());
    }

    #[test]
    fn an_absent_cell_proof_carries_a_bounded_sorted_neighbor_set() {
        let leaf = seal().id;
        // Zero neighbours: the empty-tree root.
        absent_proof(member_state_cell(), leaf.clone(), Vec::new())
            .validate_structural()
            .expect("the empty-tree root needs no neighbor");
        // One boundary neighbour.
        absent_proof(
            member_state_cell(),
            leaf.clone(),
            vec![state_root_proof(0, 4)],
        )
        .validate_structural()
        .expect("a boundary neighbor bounds one side");
        // Two adjacent neighbours bracket the cell.
        absent_proof(
            member_state_cell(),
            leaf.clone(),
            vec![state_root_proof(1, 4), state_root_proof(2, 4)],
        )
        .validate_structural()
        .expect("adjacent leaves leave no room for the cell");

        let interior = absent_proof(
            member_state_cell(),
            leaf.clone(),
            vec![state_root_proof(1, 4)],
        );
        assert!(
            interior.validate_structural().is_err(),
            "an interior leaf leaves both sides unproven"
        );

        let gap = absent_proof(
            member_state_cell(),
            leaf.clone(),
            vec![state_root_proof(0, 4), state_root_proof(2, 4)],
        );
        assert!(
            gap.validate_structural().is_err(),
            "a gap between neighbors is exactly where the cell could sit"
        );

        let three = absent_proof(
            member_state_cell(),
            leaf.clone(),
            vec![
                state_root_proof(0, 4),
                state_root_proof(1, 4),
                state_root_proof(2, 4),
            ],
        );
        assert!(three.validate_structural().is_err());

        let mut wrong_root = state_root_proof(0, 4);
        wrong_root.root_field = SemanticRefProofRootField::ControlEventSetRoot;
        assert!(
            absent_proof(member_state_cell(), leaf.clone(), vec![wrong_root])
                .validate_structural()
                .is_err()
        );

        let mut with_inclusion = absent_proof(member_state_cell(), leaf, Vec::new());
        with_inclusion.inclusion = Some(state_root_proof(0, 1));
        assert!(with_inclusion.validate_structural().is_err());
    }

    #[test]
    fn precondition_evidence_answers_the_requested_intent() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        outcome
            .validate_for_request(&request)
            .expect("invite evidence for an invite request");

        outcome.precondition_evidence =
            member_state_evidence(&outcome.governance_facts.seal_basis.leaves);
        let error = outcome
            .validate_for_request(&request)
            .expect_err("member.state material decides another cell than live_target");
        assert!(error.to_string().contains("another intent"), "{error}");

        let mut member_request = bootstrap_request();
        member_request.intent = RealmJoinIntent::MemberJoin {
            gate_proofs: Vec::new(),
        };
        outcome.request_digest = member_request.request_digest().expect("digest");
        outcome
            .validate_for_request(&member_request)
            .expect("member.state material for a member_join request");

        let mut knock_request = bootstrap_request();
        knock_request.intent = RealmJoinIntent::Knock {};
        outcome.request_digest = knock_request.request_digest().expect("digest");
        assert!(
            outcome.validate_for_request(&knock_request).is_err(),
            "a member_join branch is not a knock branch"
        );
    }

    #[test]
    fn precondition_evidence_round_trips_through_its_wire_tag() {
        let leaves = vec![seal().id];
        let value = serde_json::to_value(invite_accept_evidence(&leaves)).expect("serialize");
        assert_eq!(value["intent"], json!("invite_accept"));
        assert!(value.get("live_target_proofs").is_some());
        let restored: RealmJoinPreconditionEvidence =
            serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored, invite_accept_evidence(&leaves));

        let knock = RealmJoinPreconditionEvidence::Knock(RealmJoinMemberStatePrecondition {
            member_state_proofs: vec![absent_proof(
                member_state_cell(),
                leaves[0].clone(),
                Vec::new(),
            )],
        });
        let value = serde_json::to_value(&knock).expect("serialize");
        assert_eq!(value["intent"], json!("knock"));
        assert_eq!(
            serde_json::from_value::<RealmJoinPreconditionEvidence>(value).expect("deserialize"),
            knock
        );

        assert!(
            serde_json::from_value::<RealmJoinPreconditionEvidence>(
                json!({"intent": "restricted_join", "member_state_proofs": []})
            )
            .is_err()
        );
    }

    #[test]
    fn predecessor_events_are_the_applicants_own_for_this_realm() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        outcome.applicant_predecessor_events = sorted_predecessors(2);
        outcome
            .validate_structural()
            .expect("the applicant's own siblings");

        let mut foreign_realm = outcome.clone();
        foreign_realm.applicant_predecessor_events[0].realm_id =
            RealmId::new("ak:realm:AZ0iBOTdEfBLcM7WT9SFbSOJU7EYIkPMPtXcLcZ5UjRT").expect("realm");
        let error = foreign_realm
            .validate_structural()
            .expect_err("another Realm's Event is not a predecessor here");
        assert!(error.to_string().contains("applicant's own"), "{error}");

        let mut foreign_actor = outcome.clone();
        foreign_actor.applicant_predecessor_events[0].actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:other.example").expect("principal"),
            DidCoreId::new("ak:did_core:web:origin.example").expect("station"),
        ));
        assert!(
            foreign_actor.validate_structural().is_err(),
            "another actor's Event never enters this actor's chain"
        );
    }

    #[test]
    fn predecessor_events_are_bytewise_sorted_and_duplicate_free() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        outcome.applicant_predecessor_events = sorted_predecessors(3);
        outcome.validate_structural().expect("canonical order");

        let mut reversed = outcome.clone();
        reversed.applicant_predecessor_events.reverse();
        let error = reversed
            .validate_structural()
            .expect_err("an unordered sibling set has no canonical form");
        assert!(error.to_string().contains("bytewise sorted"), "{error}");

        let mut duplicated = outcome.clone();
        duplicated.applicant_predecessor_events =
            vec![outcome.applicant_predecessor_events[0].clone(); 2];
        assert!(duplicated.validate_structural().is_err());
    }

    #[test]
    fn predecessor_events_stay_inside_the_registered_bound() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        let events = sorted_predecessors(MAX_REALM_JOIN_PREDECESSOR_EVENTS + 1);
        outcome.applicant_predecessor_events = events[..MAX_REALM_JOIN_PREDECESSOR_EVENTS].to_vec();
        outcome
            .validate_structural()
            .expect("the registered bound is reachable");

        outcome.applicant_predecessor_events = events;
        let error = outcome
            .validate_structural()
            .expect_err("a closure that does not fit is limit_exceeded, never truncated");
        assert!(error.to_string().contains("predecessor events"), "{error}");
    }

    #[test]
    fn bootstrap_material_answers_exactly_one_request() {
        let request = bootstrap_request();
        let outcome = bootstrap_outcome(&request);
        outcome
            .validate_for_request(&request)
            .expect("the bundle set matches the returned basis");
    }

    #[test]
    fn a_bootstrap_bundle_must_exist_for_every_basis_leaf() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        let second = SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).expect("seal id");
        outcome.governance_facts.seal_basis = SealBasis {
            leaves: vec![
                outcome.governance_facts.seal_basis.leaves[0].clone(),
                second,
            ],
        };
        let error = outcome
            .validate_structural()
            .expect_err("one leaf without a closure cannot be verified");
        assert!(
            error.to_string().contains("one dependency bundle"),
            "{error}"
        );
    }

    #[test]
    fn bootstrap_bundles_follow_the_canonical_leaf_order() {
        // Two well-formed bundles for two real leaves. Only their order is
        // wrong, so nothing else can be what rejects this: without the order
        // rule the requesting Station would verify each leaf against another
        // leaf's closure.
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        let mut seals = vec![seal_with('1'), seal_with('7')];
        seals.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        outcome.governance_facts.seal_basis = SealBasis {
            leaves: seals.iter().map(|seal| seal.id.clone()).collect(),
        };
        outcome.dependency_bundles = seals
            .iter()
            .map(|seal| CbsProofBundle {
                target_seal_ref: seal.id.clone(),
                seals: vec![seal.clone()],
                control_moves: Vec::new(),
                inclusion_proofs: Vec::new(),
                availability_proofs: Vec::new(),
            })
            .collect();
        outcome.precondition_evidence =
            invite_accept_evidence(&outcome.governance_facts.seal_basis.leaves);
        outcome
            .validate_structural()
            .expect("one bundle per leaf, in leaf order");

        outcome.dependency_bundles.reverse();
        let error = outcome
            .validate_structural()
            .expect_err("a bundle for another leaf proves nothing about this one");
        assert!(
            error.to_string().contains("canonical leaf order"),
            "{error}"
        );
    }

    #[test]
    fn expired_bootstrap_material_is_not_a_window() {
        let request = bootstrap_request();
        let mut outcome = bootstrap_outcome(&request);
        outcome.expires_at = outcome.observed_at;
        assert!(outcome.validate_structural().is_err());
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
            assert_matches_schema("peer_bootstrap_request_body", &bootstrap_request);
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
        fn every_precondition_branch_carries_exactly_its_declared_members() {
            let leaves = vec![seal().id];
            assert_matches_schema(
                "realm_join_invite_accept_precondition",
                &invite_accept_evidence(&leaves),
            );
            assert_matches_schema(
                "realm_join_member_state_precondition",
                &member_state_evidence(&leaves),
            );
        }

        #[test]
        fn a_cell_state_proof_covers_both_of_its_exclusive_shapes() {
            // `inclusion` and `neighbors` are mutually exclusive, so no single
            // instance is "fully populated"; parity has to be checked against
            // the union of the two legal shapes.
            let declared: BTreeSet<String> =
                definition("realm_join_cell_state_proof")["properties"]
                    .as_object()
                    .expect("$defs/realm_join_cell_state_proof/properties is missing")
                    .keys()
                    .cloned()
                    .collect();
            let leaf = seal().id;
            let mut carried = BTreeSet::new();
            for shape in [
                present_proof(live_target_cell(), leaf.clone()),
                absent_proof(member_state_cell(), leaf, vec![state_root_proof(0, 4)]),
            ] {
                carried.extend(
                    serde_json::to_value(&shape)
                        .expect("carrier serializes")
                        .as_object()
                        .expect("carrier serializes to an object")
                        .keys()
                        .cloned(),
                );
            }
            assert_eq!(declared, carried);
        }

        #[test]
        fn the_cell_presence_vocabulary_matches_the_registry() {
            let declared: BTreeSet<String> =
                definition("realm_join_cell_state_proof")["properties"]["presence"]["enum"]
                    .as_array()
                    .expect("presence enum is missing")
                    .iter()
                    .map(|value| value.as_str().expect("enum value is a string").to_owned())
                    .collect();
            let carried: BTreeSet<String> = [
                RealmJoinCellPresence::Present,
                RealmJoinCellPresence::Absent,
            ]
            .iter()
            .map(|value| {
                serde_json::to_value(value)
                    .expect("enum serializes")
                    .as_str()
                    .expect("enum serializes to a string")
                    .to_owned()
            })
            .collect();
            assert_eq!(declared, carried);
        }

        #[test]
        fn every_registered_proof_array_bound_is_pinned() {
            let intake = arkret_schema_conformance::spec_json_artifact(INTAKE)
                .unwrap_or_else(|error| panic!("embedded {INTAKE} failed to load: {error}"));
            assert_eq!(
                intake["$defs"]["realm_join_cell_state_proofs"]["maxItems"].as_u64(),
                Some(MAX_REALM_JOIN_CELL_STATE_PROOFS as u64)
            );
            assert_eq!(
                intake["$defs"]["realm_join_cell_state_proof"]["properties"]["neighbors"]
                    ["maxItems"]
                    .as_u64(),
                Some(MAX_REALM_JOIN_ABSENCE_NEIGHBORS as u64)
            );
            assert_eq!(
                intake["$defs"]["peer_bootstrap_outcome"]["properties"]
                    ["applicant_predecessor_events"]["maxItems"]
                    .as_u64(),
                Some(MAX_REALM_JOIN_PREDECESSOR_EVENTS as u64)
            );
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
            super::super::validate_canonical_bytes(&outcome, usize::MAX, "test")
                .expect("a carrier inside its budget passes");
            let error = super::super::validate_canonical_bytes(&outcome, 8, "test")
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
