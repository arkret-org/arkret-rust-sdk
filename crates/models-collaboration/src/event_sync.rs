//! Event frontier, submission, subscription, and snapshot wire models.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.
//! Generated reducer-profile digests are owned by `arkret-policy`.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_wire::{
    CbaProofBundle, ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalReceipt,
    Did, Error, Event, EventFederationSubmission, EventId, FederatedDeviceSigningKeyEvidence, Hash,
    Hlc, RealmId, Result, SchemaId, Seal, SealBasis, SealId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_signer_evidence::{AgentSignerEvidence, AgentSignerEvidenceBundle};

// ── EventsFrontier 3-way split ──────────────────────────────────────────

/// `/events/frontier` peer-role selector. The account-client and
/// anonymous-health responses are shape-discriminated; the federation-peer
/// response follows the single canonical
/// [`EventsFrontierFederationPeerState`] shape defined by the spec
/// artifacts (`service-operation-dtos.schema.json`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontierPeerRole {
    AccountClient,
    FederationPeer,
    AnonymousHealth,
}

/// `ak.self.events.query.frontier` account-client response
/// (`service-operation-dtos.schema.json#/$defs/EventsFrontierAccountClientState`,
/// SPEC-SOL-003 resolution): a single `frontier` object whose shape follows
/// the request selector — actor (`{actor_id, actor_seq, event_id}`) or Realm
/// Seal view (`{realm_id, seal_id, control_event_set_root, state_root,
/// hlc?}`) — plus optional receipts. The Realm Seal view is the registered
/// account-client source for minting a single-leaf Control Move `seal_basis`
/// and a DataEvent `seal_ref`. When accepted managed Agent PCR Events are
/// ahead of their accepted Seal, the view remains that signed predecessor and
/// `receipts` carries the full `ak.managed_agent_pcr.seal_head.v1` Seal needed
/// by the controller device to author its successor.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsFrontierAccountClientState {
    pub frontier: EventsFrontierView,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ManagedAgentPcrSealHeadReceipt>,
}

/// Typed, closed receipt carrying the last accepted controller-device-signed
/// Seal for a managed Agent PCR whose Event log is ahead of Seal coverage.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAgentPcrSealHeadReceipt {
    pub kind: ManagedAgentPcrSealHeadReceiptKind,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub seal: Seal,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedAgentPcrSealHeadReceiptKind {
    #[serde(rename = "ak.managed_agent_pcr.seal_head.v1")]
    ManagedAgentPcrSealHeadV1,
}

/// Maximum accepted siblings represented by one Realm-scoped actor frontier.
/// This aliases the single v1 cumulative same-height limit from the Event
/// envelope artifact implementation.
pub use arkret_wire::MAX_ACTOR_SEQ_TOTAL_SIBLINGS as MAX_ACTOR_FRONTIER_EVENT_IDS;

/// Domain separator for the canonical Realm actor frontier digest transcript.
pub const REALM_ACTOR_FRONTIER_DIGEST_DOMAIN: &[u8] = b"ak-realm-actor-frontier-v1\0";

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealmActorFrontierKind {
    #[serde(rename = "realm_actor")]
    RealmActor,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealmSealFrontierKind {
    #[serde(rename = "realm_seal")]
    RealmSeal,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorAggregateFrontierKind {
    #[serde(rename = "actor_aggregate")]
    ActorAggregate,
}

/// Typed selector for `GET /_arkret/self/events/frontier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventsFrontierSelector {
    RealmActor { realm_id: RealmId, actor_id: Did },
    RealmSeal { realm_id: RealmId },
    ActorAggregate { actor_id: Did },
}

impl EventsFrontierSelector {
    /// Query pairs for an HTTP client. Callers should pass these through their
    /// URL library rather than hand-building or escaping a query string.
    pub fn query_pairs(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::RealmActor { realm_id, actor_id } => vec![
                ("realm_id", realm_id.as_str().to_owned()),
                ("actor_id", actor_id.as_str().to_owned()),
            ],
            Self::RealmSeal { realm_id } => {
                vec![("realm_id", realm_id.as_str().to_owned())]
            }
            Self::ActorAggregate { actor_id } => {
                vec![("actor_id", actor_id.as_str().to_owned())]
            }
        }
    }

    /// Validate that a response is the exact variant and scope selected by
    /// this request. Mismatches fail closed before authoring.
    pub fn validate_response(&self, response: &EventsFrontierView) -> Result<()> {
        match (self, response) {
            (Self::RealmActor { realm_id, actor_id }, EventsFrontierView::RealmActor(frontier))
                if &frontier.realm_id == realm_id && &frontier.actor_id == actor_id =>
            {
                frontier.validate()
            }
            (Self::RealmSeal { realm_id }, EventsFrontierView::RealmSeal(frontier))
                if &frontier.realm_id == realm_id =>
            {
                frontier.validate_protocol_bounds()
            }
            (Self::ActorAggregate { actor_id }, EventsFrontierView::ActorAggregate(frontier))
                if &frontier.actor_id == actor_id =>
            {
                frontier.validate()
            }
            _ => Err(Error::Protocol(
                "events frontier response does not match the requested selector".to_owned(),
            )),
        }
    }
}

/// Selector-dependent, closed and wire-discriminated frontier union.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventsFrontierView {
    RealmActor(RealmActorFrontierView),
    RealmSeal(RealmSealFrontierView),
    ActorAggregate(ActorAggregateFrontierView),
}

#[derive(Serialize)]
struct RealmActorFrontierDigestTranscript<'a> {
    kind: &'static str,
    realm_id: &'a RealmId,
    actor_id: &'a Did,
    next_actor_seq: u64,
    frontier_event_ids: &'a [EventId],
}

/// Deterministic authoring frontier for one `(realm_id, actor_id)` chain.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorFrontierView {
    pub kind: RealmActorFrontierKind,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub next_actor_seq: u64,
    pub frontier_event_ids: Vec<EventId>,
    pub frontier_digest: Hash,
}

impl RealmActorFrontierView {
    pub fn new(
        realm_id: RealmId,
        actor_id: Did,
        next_actor_seq: u64,
        frontier_event_ids: Vec<EventId>,
        digest_suite: DigestSuite,
    ) -> Result<Self> {
        let frontier_digest = Self::compute_digest(
            &realm_id,
            &actor_id,
            next_actor_seq,
            &frontier_event_ids,
            digest_suite,
        )?;
        let frontier = Self {
            kind: RealmActorFrontierKind::RealmActor,
            realm_id,
            actor_id,
            next_actor_seq,
            frontier_event_ids,
            frontier_digest,
        };
        frontier.validate_with_suite(digest_suite)?;
        Ok(frontier)
    }

    pub fn compute_digest(
        realm_id: &RealmId,
        actor_id: &Did,
        next_actor_seq: u64,
        frontier_event_ids: &[EventId],
        digest_suite: DigestSuite,
    ) -> Result<Hash> {
        let transcript = RealmActorFrontierDigestTranscript {
            kind: "realm_actor",
            realm_id,
            actor_id,
            next_actor_seq,
            frontier_event_ids,
        };
        let canonical = arkret_canonical::canonical_json_bytes(&transcript)
            .map_err(|error| Error::Protocol(format!("frontier transcript: {error}")))?;
        let mut bytes =
            Vec::with_capacity(REALM_ACTOR_FRONTIER_DIGEST_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(REALM_ACTOR_FRONTIER_DIGEST_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Hash::new(arkret_canonical::digest(digest_suite, bytes))?)
    }

    pub fn validate(&self) -> Result<()> {
        let suite_name = self
            .frontier_digest
            .as_str()
            .split_once(':')
            .map(|(suite, _)| suite)
            .ok_or_else(|| Error::Protocol("frontier_digest has no suite prefix".to_owned()))?;
        let suite = arkret_canonical::digest_suite(suite_name)?;
        self.validate_with_suite(suite)
    }

    pub fn validate_with_suite(&self, digest_suite: DigestSuite) -> Result<()> {
        if self.frontier_event_ids.len() > MAX_ACTOR_FRONTIER_EVENT_IDS {
            return Err(Error::Protocol(
                "realm actor frontier exceeds the v1 sibling limit".to_owned(),
            ));
        }
        if self.next_actor_seq == 0 && !self.frontier_event_ids.is_empty() {
            return Err(Error::Protocol(
                "empty realm actor frontier must not contain event ids".to_owned(),
            ));
        }
        if self.next_actor_seq > 0 && self.frontier_event_ids.is_empty() {
            return Err(Error::Protocol(
                "non-empty realm actor frontier must contain event ids".to_owned(),
            ));
        }
        if self
            .frontier_event_ids
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(Error::Protocol(
                "frontier_event_ids must be bytewise sorted and unique".to_owned(),
            ));
        }
        let expected = Self::compute_digest(
            &self.realm_id,
            &self.actor_id,
            self.next_actor_seq,
            &self.frontier_event_ids,
            digest_suite,
        )?;
        if expected != self.frontier_digest {
            return Err(Error::Protocol(
                "realm actor frontier digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Read-only actor aggregate. It deliberately exposes no authoring helper.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorAggregateFrontierView {
    pub kind: ActorAggregateFrontierKind,
    pub actor_id: Did,
    pub realms: Vec<RealmActorFrontierView>,
}

/// Closed `error.details` for an explicit actor-chain CAS conflict.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsActorCasConflictProblem {
    pub accepted: bool,
    pub current_frontier: RealmActorFrontierView,
}

impl EventsActorCasConflictProblem {
    pub fn validate(&self) -> Result<()> {
        if self.accepted {
            return Err(Error::Protocol(
                "actor CAS conflict details must assert accepted=false".to_owned(),
            ));
        }
        self.current_frontier.validate()
    }
}

impl ActorAggregateFrontierView {
    pub fn validate(&self) -> Result<()> {
        for frontier in &self.realms {
            if frontier.actor_id != self.actor_id {
                return Err(Error::Protocol(
                    "actor aggregate contains a different actor_id".to_owned(),
                ));
            }
            frontier.validate()?;
        }
        if self
            .realms
            .windows(2)
            .any(|pair| pair[0].realm_id.as_str() >= pair[1].realm_id.as_str())
        {
            return Err(Error::Protocol(
                "actor aggregate realms must be sorted and unique".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Realm Seal view shape of the account-client frontier: the current
/// accepted Seal head of the Realm. `seal_basis()` mints the single-leaf
/// Control Move basis (`leaves=[seal_id]`); `seal_id` alone is the DataEvent
/// `seal_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlGovernanceHealthStatus {
    Healthy,
    Degraded,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlProposalDecisionState {
    Pending,
    Deferred,
    Overdue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingControlProposal {
    pub proposal_digest: Hash,
    pub receipt: ControlProposalReceipt,
    pub decisions: Vec<ControlProposalDecision>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub current_decision_due_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub absolute_due_at: DateTime<Utc>,
    pub defer_count: u8,
    pub decision_state: ControlProposalDecisionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_reason: Option<ControlProposalFaultReason>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlProposalFaultReason {
    ControlProposalDecisionOverdue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlGovernanceHealth {
    pub status: ControlGovernanceHealthStatus,
    pub pending_proposals: Vec<PendingControlProposal>,
    pub retained_faults: Vec<RetainedControlProposalFault>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedControlProposalFault {
    pub proposal_digest: Hash,
    pub receipt: ControlProposalReceipt,
    pub decisions: Vec<ControlProposalDecision>,
    pub accepted_seal_id: SealId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub fault_reason: ControlProposalFaultReason,
}

impl ControlGovernanceHealth {
    pub const MAX_PENDING_PROPOSALS: usize = 128;

    pub fn healthy() -> Self {
        Self {
            status: ControlGovernanceHealthStatus::Healthy,
            pending_proposals: Vec::new(),
            retained_faults: Vec::new(),
        }
    }

    pub fn validate_with_policy(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        self.validate_common(Some(policy))
    }

    pub fn validate_protocol_bounds(&self) -> Result<()> {
        self.validate_common(None)
    }

    fn validate_common(&self, policy: Option<ControlProposalDecisionPolicy>) -> Result<()> {
        if self.pending_proposals.len() > Self::MAX_PENDING_PROPOSALS {
            return Err(Error::Protocol(
                "control governance health exceeds 128 pending proposals".to_owned(),
            ));
        }
        if self.retained_faults.len() > Self::MAX_PENDING_PROPOSALS {
            return Err(Error::Protocol(
                "control governance health exceeds 128 retained faults".to_owned(),
            ));
        }
        let mut previous_key: Option<(DateTime<Utc>, &str)> = None;
        let mut has_overdue = false;
        for pending in &self.pending_proposals {
            if let Some(policy) = policy {
                pending.receipt.validate_structural(policy)?;
            } else {
                pending.receipt.validate_protocol_bounds()?;
            }
            if pending.proposal_digest != pending.receipt.proposal_digest
                || pending.absolute_due_at != pending.receipt.absolute_due_at
                || usize::from(pending.defer_count) != pending.decisions.len()
            {
                return Err(Error::Protocol(
                    "pending control proposal does not preserve receipt/decision binding"
                        .to_owned(),
                ));
            }
            let mut verified_defers = Vec::with_capacity(pending.decisions.len());
            for decision in &pending.decisions {
                if decision.is_reject() {
                    return Err(Error::Protocol(
                        "terminal signed_reject cannot remain pending".to_owned(),
                    ));
                }
                if let Some(policy) = policy {
                    decision.validate_chain(&pending.receipt, &verified_defers, policy)?;
                } else {
                    decision.validate_chain_protocol_bounds(&pending.receipt, &verified_defers)?;
                }
                verified_defers.push(decision.clone());
            }
            let expected_due_at = verified_defers
                .last()
                .map(ControlProposalDecision::decision_due_at)
                .unwrap_or(pending.receipt.decision_due_at);
            if pending.current_decision_due_at != expected_due_at {
                return Err(Error::Protocol(
                    "pending proposal current_decision_due_at does not match its decision chain"
                        .to_owned(),
                ));
            }
            let overdue = pending.decision_state == ControlProposalDecisionState::Overdue;
            if overdue
                != (pending.fault_reason
                    == Some(ControlProposalFaultReason::ControlProposalDecisionOverdue))
            {
                return Err(Error::Protocol(
                    "overdue proposal must carry the stable overdue fault reason".to_owned(),
                ));
            }
            let expected_non_fault_state = if pending.decisions.is_empty() {
                ControlProposalDecisionState::Pending
            } else {
                ControlProposalDecisionState::Deferred
            };
            if !overdue && pending.decision_state != expected_non_fault_state {
                return Err(Error::Protocol(
                    "pending proposal decision_state does not match its decision chain".to_owned(),
                ));
            }
            has_overdue |= overdue;
            let key = (pending.absolute_due_at, pending.proposal_digest.as_str());
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(Error::Protocol(
                    "pending proposals are not in canonical deadline/digest order".to_owned(),
                ));
            }
            previous_key = Some(key);
        }
        let mut previous_fault_key: Option<(DateTime<Utc>, &str)> = None;
        for fault in &self.retained_faults {
            if let Some(policy) = policy {
                fault.receipt.validate_structural(policy)?;
            } else {
                fault.receipt.validate_protocol_bounds()?;
            }
            if fault.proposal_digest != fault.receipt.proposal_digest
                || fault.fault_reason != ControlProposalFaultReason::ControlProposalDecisionOverdue
            {
                return Err(Error::Protocol(
                    "retained control proposal fault does not preserve its receipt binding"
                        .to_owned(),
                ));
            }
            let mut verified_defers = Vec::with_capacity(fault.decisions.len());
            let mut previous_due_at = fault.receipt.decision_due_at;
            let mut missed_deadline = false;
            for decision in &fault.decisions {
                if decision.is_reject() {
                    return Err(Error::Protocol(
                        "signed_reject cannot precede an accepted Seal".to_owned(),
                    ));
                }
                if let Some(policy) = policy {
                    decision.validate_chain(&fault.receipt, &verified_defers, policy)?;
                } else {
                    decision.validate_chain_protocol_bounds(&fault.receipt, &verified_defers)?;
                }
                missed_deadline |= !decision.satisfied_current_deadline(previous_due_at);
                previous_due_at = decision.decision_due_at();
                verified_defers.push(decision.clone());
            }
            missed_deadline |= fault.accepted_at > previous_due_at;
            if !missed_deadline {
                return Err(Error::Protocol(
                    "retained proposal fault has no missed signed deadline".to_owned(),
                ));
            }
            let key = (fault.accepted_at, fault.proposal_digest.as_str());
            if previous_fault_key.is_some_and(|previous| previous >= key) {
                return Err(Error::Protocol(
                    "retained proposal faults are not in canonical accepted-at/digest order"
                        .to_owned(),
                ));
            }
            previous_fault_key = Some(key);
        }
        let expected_status = if has_overdue || !self.retained_faults.is_empty() {
            ControlGovernanceHealthStatus::Degraded
        } else {
            ControlGovernanceHealthStatus::Healthy
        };
        if self.status != expected_status {
            return Err(Error::Protocol(
                "control governance status does not match pending proposal faults".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSealFrontierView {
    pub kind: RealmSealFrontierKind,
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub governance_health: ControlGovernanceHealth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
}

impl RealmSealFrontierView {
    pub fn new(
        realm_id: RealmId,
        seal_id: SealId,
        control_event_set_root: Hash,
        state_root: Hash,
        governance_health: ControlGovernanceHealth,
        hlc: Option<Hlc>,
    ) -> Self {
        Self {
            kind: RealmSealFrontierKind::RealmSeal,
            realm_id,
            seal_id,
            control_event_set_root,
            state_root,
            governance_health,
            hlc,
        }
    }

    /// Single-leaf Control Move `seal_basis` under this view.
    pub fn seal_basis(&self) -> SealBasis {
        SealBasis {
            leaves: vec![self.seal_id.clone()],
        }
    }

    pub fn validate_protocol_bounds(&self) -> Result<()> {
        self.governance_health.validate_protocol_bounds()
    }

    pub fn validate_with_policy(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        self.governance_health.validate_with_policy(policy)
    }
}

/// `ak.peer.events.query.frontier` federation-peer response
/// (`service-operation-dtos.schema.json#/$defs/EventsFrontierFederationPeerState`).
/// Returned to an authorized federation peer over signed S2S trust-domain
/// headers: the realm's federation-visible head Event IDs, the
/// `frontier_root` hash commitment, per-actor sequence upper bounds, and a
/// service signature over the observed frontier. This is the single
/// canonical shape shared by the spec artifacts, the producing service, and
/// every consumer.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsFrontierFederationPeerState {
    pub realm_id: RealmId,
    /// Current federation-visible head Event IDs for the realm.
    pub heads: Vec<EventId>,
    /// Maximum HLC observed by the issuer at this frontier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hlc: Option<String>,
    /// Hash commitment returned to an authorized federation peer.
    pub frontier_root: Hash,
    /// Per-actor sequence upper bounds returned to an authorized peer.
    #[serde(default)]
    pub actor_seq_upper_bounds: BTreeMap<Did, u64>,
    /// Optional witness / receipt-service attestations over the frontier.
    #[serde(default)]
    pub witness_receipts: Vec<BTreeMap<String, Value>>,
    /// RFC 3339 (`Z`-suffixed) instant the issuer observed this frontier.
    pub observed_at: String,
    pub issuer: Did,
    /// Service signature object over the peer frontier response.
    pub signature: BTreeMap<String, Value>,
}

/// Round 4 — anonymous-health variant. Used by public health checks
/// (`peer_role=anonymous_health`); the wire shape MUST NOT carry
/// receipts, signatures, or actor_seq_upper_bounds. Type system
/// enforces this (no such fields).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsFrontierAnonymousHealthState {
    pub peer_role: FrontierPeerRole,
    pub service_id: Did,
    pub healthy: bool,
    /// Wall-clock instant the frontier snapshot was generated. Used for
    /// staleness detection only — not signed.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub generated_at: DateTime<Utc>,
}

/// Round 4 — discriminated `/events/frontier` response.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventsFrontierState {
    AccountClient(EventsFrontierAccountClientState),
    FederationPeer(EventsFrontierFederationPeerState),
    AnonymousHealth(EventsFrontierAnonymousHealthState),
}

// ── FederationServiceBindingRef ─────────────────────────────────────────

/// Typed binding reference for federation transport. Carried inside
/// `ak.self.events.command.submit` (federation variant) and the
/// `events/frontier` federation-peer response so a receiver can verify
/// the request is bound to the sender's policy and delivery frontiers.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub realm_policy_digest: Hash,
    pub membership_frontier: Vec<EventId>,
    pub delivery_binding_frontier: Vec<EventId>,
    pub destination_service_kind: String,
}

// ── EventsSubmit variants ───────────────────────────────────────────────

// `EventsSubmitBatchRequestBody` lives in this crate's `http_bodies`
// module (re-exported here for the historic flat path).
pub use crate::http_bodies::EventsSubmitBatchRequestBody;

pub const MAX_FEDERATED_EVENT_SIGNER_EVIDENCE: usize = 64;
pub const MAX_FEDERATED_EVENTS: usize = 500;

/// Round 4 — federation `/events/submit` request. Used when a remote
/// service forwards events from another principal server. MUST carry
/// the full [`FederationServiceBindingRef`] so the receiver can verify
/// origin policy and delivery state. The reducer profile is resolved from
/// each Event's authenticated CBA and is never declared by the transport.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitFederationRequestBody {
    pub service_binding_ref: FederationServiceBindingRef,
    /// Each transported Event travels with the lease and the original ingress
    /// receipts that authorized its first publication.
    pub events: Vec<EventFederationSubmission>,
    /// Receiver-relative CBA dependency bundles rooted at the transported
    /// Events' `seal_ref` or `seal_basis` leaves.
    ///
    /// These are transport prerequisites, not Events and not an alternate
    /// federation write rail. A bundle MAY be a bounded verifiable superset;
    /// receivers independently verify every embedded object and project a
    /// Seal only after its covered Control Events are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub signer_key_evidence: Vec<FederatedDeviceSigningKeyEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub agent_signer_evidence_bundle: Option<AgentSignerEvidenceBundle>,
}

impl EventsSubmitFederationRequestBody {
    /// The transported Events, without their publication evidence.
    pub fn transported_events(&self) -> impl Iterator<Item = &Event> {
        self.events.iter().map(|submission| &submission.event)
    }

    /// Every Seal disclosed by the request's CBA proof bundles.
    ///
    /// Bundles are receiver-relative and MAY overlap, so the same Seal may be
    /// listed by more than one bundle. It is disclosed once here; the
    /// duplicate-id check below then applies to the deduplicated set.
    fn transported_seals(&self) -> Result<Vec<&Seal>> {
        let mut seen = BTreeSet::new();
        let mut seals = Vec::new();
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
            for seal in &bundle.seals {
                if seen.insert(seal.id.clone()) {
                    seals.push(seal);
                }
            }
        }
        Ok(seals)
    }

    /// Validate the request-level federation transport contract.
    ///
    /// This is intentionally independent of receiver-local persistence. A
    /// receiver must additionally establish that every omitted predecessor is
    /// already accepted locally before it projects a transported Seal.
    pub fn validate_federation_transport(&self) -> Result<()> {
        if self.events.is_empty() || self.events.len() > MAX_FEDERATED_EVENTS {
            return Err(Error::Protocol(
                "federation events must contain between 1 and 500 items".to_owned(),
            ));
        }
        let events = self
            .events
            .iter()
            .map(|submission| submission.event.clone())
            .collect::<Vec<_>>();
        let submit_context = arkret_wire::classify_event_submit_context(&events)?;
        if submit_context == arkret_wire::EventSubmitContext::AnchorUnit {
            let leases = self
                .events
                .iter()
                .filter_map(|submission| submission.authorization_lease.clone())
                .collect::<Vec<_>>();
            if !leases.is_empty() {
                if leases.len() != self.events.len() {
                    return Err(Error::Protocol(
                        "an anchor unit cannot mix online and delayed submissions".to_owned(),
                    ));
                }
                arkret_wire::validate_anchor_unit_lease_bindings(&events, &leases)?;
            }
        }
        for submission in &self.events {
            submission.validate_structural_in_context(submit_context)?;
        }
        if self.cba_proof_bundles.len() > arkret_wire::event_submission::MAX_SUBMISSION_CBA_BUNDLES
        {
            return Err(Error::Protocol(format!(
                "federation request exceeds {} CBA proof bundles",
                arkret_wire::event_submission::MAX_SUBMISSION_CBA_BUNDLES
            )));
        }
        let required_targets = self
            .transported_events()
            .flat_map(|event| {
                event.seal_ref.iter().chain(
                    event
                        .seal_basis
                        .iter()
                        .flat_map(|basis| basis.leaves.iter()),
                )
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut previous_target: Option<&str> = None;
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
            if previous_target.is_some_and(|previous| previous >= bundle.target_seal_ref.as_str()) {
                return Err(Error::Protocol(
                    "federation CBA proof bundles must be strictly sorted by target_seal_ref"
                        .to_owned(),
                ));
            }
            previous_target = Some(bundle.target_seal_ref.as_str());
            if !required_targets.contains(&bundle.target_seal_ref) {
                return Err(Error::Protocol(
                    "federation CBA proof bundle target is unrelated to transported Events"
                        .to_owned(),
                ));
            }
        }
        let seals = self.transported_seals()?;
        let mut saw_data_event = false;
        for event in self.transported_events() {
            if event.realm_id != self.service_binding_ref.realm_id {
                return Err(Error::Protocol(
                    "federation Event belongs to another Realm".to_owned(),
                ));
            }
            match event
                .kind
                .descriptor()
                .and_then(|descriptor| descriptor.plane)
            {
                Some("control") => {
                    if saw_data_event {
                        return Err(Error::Protocol(
                            "federation Control Events must precede DataEvents".to_owned(),
                        ));
                    }
                }
                Some("data") => saw_data_event = true,
                _ => {
                    return Err(Error::Protocol(
                        "federation Event kind has no registered CBA plane".to_owned(),
                    ));
                }
            }
        }

        let mut seal_ids = BTreeSet::new();
        for seal in &seals {
            if !seal_ids.insert(seal.id.clone()) {
                return Err(Error::Protocol(
                    "federation CBA proof bundles contain a duplicate Seal id".to_owned(),
                ));
            }
            seal.validate_id()?;
            seal.validate_structural()?;
            if seal.realm_id != self.service_binding_ref.realm_id {
                return Err(Error::Protocol(
                    "federation Seal prerequisite belongs to another Realm".to_owned(),
                ));
            }
        }

        // Reject disclosure that is not reachable from a transported
        // DataEvent seal_ref or Control Event seal_basis leaf. Receiver-local
        // predecessors may be omitted.
        let transported_by_id = seals
            .iter()
            .map(|seal| (seal.id.clone(), *seal))
            .collect::<BTreeMap<_, _>>();
        let mut pending = Vec::new();
        for event in self.transported_events() {
            if let Some(seal_ref) = &event.seal_ref
                && transported_by_id.contains_key(seal_ref)
            {
                pending.push(seal_ref.clone());
            }
            if let Some(seal_basis) = &event.seal_basis {
                pending.extend(
                    seal_basis
                        .leaves
                        .iter()
                        .filter(|seal_id| transported_by_id.contains_key(*seal_id))
                        .cloned(),
                );
            }
        }
        let mut reachable = BTreeSet::new();
        while let Some(seal_id) = pending.pop() {
            if !reachable.insert(seal_id.clone()) {
                continue;
            }
            if let Some(seal) = transported_by_id.get(&seal_id) {
                pending.extend(
                    seal.predecessor_refs
                        .iter()
                        .filter(|predecessor| transported_by_id.contains_key(*predecessor))
                        .cloned(),
                );
            }
        }
        if reachable.len() != seals.len() {
            return Err(Error::Protocol(
                "federation CBA proof bundles contain Seals unrelated to transported Events"
                    .to_owned(),
            ));
        }

        // Build the in-request Event/Seal prerequisite graph and require it to
        // be acyclic. External dependencies are deliberately absent: the
        // receiver resolves those from accepted local state. A cycle wholly
        // represented by this request can never be repaired by retry and is a
        // permanent schema violation, including cycles longer than the direct
        // Event -> Seal -> same Event case.
        let event_nodes_by_digest = self
            .transported_events()
            .map(|event| {
                let digest = Hash::new(event.event_digest()?).map_err(|error| {
                    Error::Protocol(format!("federation Event digest is not canonical: {error}"))
                })?;
                Ok((digest, format!("event:{}", event.event_id)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        for event in self.transported_events() {
            let node = format!("event:{}", event.event_id);
            let event_dependencies = dependencies.entry(node).or_default();
            if let Some(seal_ref) = &event.seal_ref
                && transported_by_id.contains_key(seal_ref)
            {
                event_dependencies.insert(format!("seal:{seal_ref}"));
            }
            if let Some(seal_basis) = &event.seal_basis {
                event_dependencies.extend(
                    seal_basis
                        .leaves
                        .iter()
                        .filter(|seal_id| transported_by_id.contains_key(*seal_id))
                        .map(|seal_id| format!("seal:{seal_id}")),
                );
            }
        }
        for seal in &seals {
            let node = format!("seal:{}", seal.id);
            let seal_dependencies = dependencies.entry(node).or_default();
            seal_dependencies.extend(
                seal.predecessor_refs
                    .iter()
                    .filter(|seal_id| transported_by_id.contains_key(*seal_id))
                    .map(|seal_id| format!("seal:{seal_id}")),
            );
            seal_dependencies.extend(
                seal.delta
                    .iter()
                    .chain(&seal.covered_event_digests)
                    .filter_map(|digest| event_nodes_by_digest.get(digest).cloned()),
            );
        }
        let mut remaining_dependencies = dependencies
            .iter()
            .map(|(node, required)| (node.clone(), required.len()))
            .collect::<BTreeMap<_, _>>();
        let mut dependents = BTreeMap::<String, Vec<String>>::new();
        for (node, required) in &dependencies {
            for dependency in required {
                dependents
                    .entry(dependency.clone())
                    .or_default()
                    .push(node.clone());
            }
        }
        let mut ready = remaining_dependencies
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(node, _)| node.clone())
            .collect::<Vec<_>>();
        let mut resolved = 0usize;
        while let Some(node) = ready.pop() {
            resolved += 1;
            for dependent in dependents.get(&node).into_iter().flatten() {
                let count = remaining_dependencies
                    .get_mut(dependent)
                    .expect("every dependent is a graph node");
                *count -= 1;
                if *count == 0 {
                    ready.push(dependent.clone());
                }
            }
        }
        if resolved != dependencies.len() {
            return Err(Error::Protocol(
                "federation Event/Seal prerequisite graph contains a cycle".to_owned(),
            ));
        }

        if self.signer_key_evidence.len() > MAX_FEDERATED_EVENT_SIGNER_EVIDENCE {
            return Err(Error::Protocol(
                "federation signer_key_evidence exceeds the v1 limit".to_owned(),
            ));
        }
        for evidence in &self.signer_key_evidence {
            evidence.validate_shape()?;
            if !self
                .transported_events()
                .any(|event| evidence.matches_event_proof(event, &evidence.verification_method))
            {
                return Err(Error::Protocol(
                    "federation signer evidence does not match a transported Event proof"
                        .to_owned(),
                ));
            }
        }
        if let Some(bundle) = &self.agent_signer_evidence_bundle {
            if bundle.schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_BUNDLE_V1
                || bundle.evidence.len() > 256
            {
                return Err(Error::Protocol(
                    "federation agent_signer_evidence_bundle is invalid".to_owned(),
                ));
            }
            for evidence in &bundle.evidence {
                let AgentSignerEvidence::HistoricalEvent {
                    admission_evidence,
                    event_admission_receipt,
                    ..
                } = evidence
                else {
                    return Err(Error::Protocol(
                        "federation Event transport requires historical Agent signer evidence"
                            .to_owned(),
                    ));
                };
                let binding = &admission_evidence
                    .agent_authority_snapshot
                    .core
                    .signing_key_binding;
                let matches_event = self.transported_events().any(|event| {
                    if event.applet_id.is_some() {
                        return false;
                    }
                    let signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
                    if signer != &binding.agent_id
                        || !event.proofs.iter().any(|proof| {
                            proof.verification_method == binding.verification_method.as_str()
                        })
                    {
                        return false;
                    }
                    event_admission_receipt.event_id == event.event_id
                        && event_admission_receipt.agent_id == binding.agent_id
                        && event_admission_receipt.verification_method
                            == binding.verification_method
                        && event_admission_receipt.agent_key_authorize_event_id
                            == binding.agent_key_authorize_event_id
                });
                if !matches_event {
                    return Err(Error::Protocol(
                        "federation Agent signer evidence does not match a transported Event proof and admission receipt"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// `SnapshotBootstrap` migrated to `sync_frames::snapshot`. It reaches the
// `arkret::SnapshotBootstrap` path via the `artifacts::sync`
// re-export, so no shim is needed here.

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId,
        ControlProposalReceiptKind, DeviceId, DidKey, DidUrl, Hash, IngressReceipt, LeaseBasisRef,
        NotarySig, PayloadProof, PayloadSignature, ReceiptId, RiskTier, ScopeRef, SealKind,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn realm_actor_frontier_distinguishes_empty_and_seq_zero_histories() {
        let actor_id = Did::new("did:web:alice.example").unwrap();
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        RealmActorFrontierView::new(
            realm_id.clone(),
            actor_id.clone(),
            0,
            Vec::new(),
            DigestSuite::Sha256,
        )
        .unwrap();
        RealmActorFrontierView::new(
            realm_id.clone(),
            actor_id.clone(),
            1,
            vec![EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap()],
            DigestSuite::Sha256,
        )
        .unwrap();

        assert!(
            RealmActorFrontierView::new(realm_id, actor_id, 1, Vec::new(), DigestSuite::Sha256)
                .is_err()
        );
    }

    #[test]
    fn realm_actor_frontier_digest_matches_the_spec_vector() {
        let frontier = RealmActorFrontierView::new(
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            43,
            vec![
                EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap(),
                EventId::new("ak:event:01904100-0000-7000-8000-000000000002").unwrap(),
            ],
            DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(
            frontier.frontier_digest.as_str(),
            "sha256:4f928af58951a0a04f532b272fe6c45b371d33e932d0a15a8df84725a5efe1cf"
        );
    }

    /// A well-formed reducer-input DataEvent: `ak.message.create` is registered
    /// on the data plane, so the envelope must carry `seal_ref` + `auth_context`
    /// and no `seal_basis`.
    fn event_with_device_proof() -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001"
            },
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-21T08:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "seal_ref": format!("ak:seal:sha256:{}", "e".repeat(64)),
            "auth_context": {
                "did": "did:web:alice.example",
                "key_id": "ak:device:01904100-0000-7000-8000-000000000002",
                "key_epoch": 1
            },
            "payload": {},
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000002",
                "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "created_at": "2026-07-21T08:00:00.000Z",
                "jws": "header..signature"
            }]
        }))
        .unwrap()
    }

    fn evidence() -> FederatedDeviceSigningKeyEvidence {
        let device_authorize_event = serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000004",
            "kind": "ak.device.authorize",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000004",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000004"
            },
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-21T07:00:00.000Z",
            "hlc": "01970e589d21-0000-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "principal_id": "did:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000002",
                "device_public_key": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:web:auth.example",
                    "authorization_ref": "did:web:alice.example#device-enrollment"
                }
            },
            "executed_by": "did:web:auth.example",
            "authorization_ref": "did:web:alice.example#device-enrollment",
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": "did:web:auth.example#enrollment",
                "event_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-21T07:00:00.000Z",
                "jws": "header..signature"
            }]
        }))
        .unwrap();
        FederatedDeviceSigningKeyEvidence {
            actor_id: Did::new("did:web:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
            verification_method: DidUrl::new(
                "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000002",
            )
            .unwrap(),
            device_signing_key: DidKey::new(
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
            )
            .unwrap(),
            authorization_accepted_at: "2026-07-21T07:00:01.000Z".parse().unwrap(),
            device_authorize_event: Box::new(device_authorize_event),
        }
    }

    #[test]
    fn signer_evidence_matches_only_the_exact_event_proof() {
        let event = event_with_device_proof();
        let evidence = evidence();
        assert!(evidence.matches_event_proof(&event, &evidence.verification_method));

        let mut wrong_actor = evidence;
        wrong_actor.actor_id = Did::new("did:web:mallory.example").unwrap();
        assert!(!wrong_actor.matches_event_proof(&event, &wrong_actor.verification_method));
    }

    #[test]
    fn federation_request_rejects_unrelated_signer_evidence() {
        let event = event_with_device_proof();
        let mut unrelated = evidence();
        unrelated.verification_method = DidUrl::new(format!(
            "{}#{}",
            unrelated.actor_id,
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000003").unwrap()
        ))
        .unwrap();
        unrelated.device_id =
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000003").unwrap();
        let request = EventsSubmitFederationRequestBody {
            service_binding_ref: FederationServiceBindingRef {
                realm_id: event.realm_id.clone(),
                realm_policy_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                membership_frontier: vec![event.event_id.clone()],
                delivery_binding_frontier: vec![event.event_id.clone()],
                destination_service_kind: "principal_server".to_owned(),
            },
            events: vec![federation_submission(event)],
            cba_proof_bundles: Vec::new(),
            signer_key_evidence: vec![unrelated],
            agent_signer_evidence_bundle: None,
        };
        assert!(request.validate_federation_transport().is_err());
    }

    fn publication_proof(
        verification_method: &DidUrl,
        payload_digest: Hash,
        created_at: DateTime<Utc>,
    ) -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }
    }

    /// Wrap a transported Event in the publication evidence the federation rail
    /// now requires: the basis-bound lease that authorized it and the ingress
    /// receipt that recorded its first publication inside the lease window.
    fn federation_submission(event: Event) -> EventFederationSubmission {
        let issued_at: DateTime<Utc> = "2026-07-21T08:00:00.000Z".parse().unwrap();
        let authority_set_policy = AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: event.scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: "ak:event:01904100-0000-7000-8000-111111111111".to_owned(),
                source_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec![event.kind.as_str().to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new("did:web:authority.example#key-1").unwrap(),
                }],
                threshold: 1,
            }],
        };
        let authority_set_ref = AuthoritySetRef {
            authority_set_id: authority_set_policy.authority_set_id.clone(),
            authority_set_digest: authority_set_policy.digest().unwrap(),
        };
        let control_proposal_receipt = event
            .seal_basis
            .as_ref()
            .map(|_| proposal_receipt_for(&event, &authority_set_ref, issued_at));
        let mut authorization_lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: event.actor_id.clone(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
            scope_ref: event.scope_ref.clone(),
            action: event.kind.as_str().to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::Low,
            issued_at,
            expires_at: issued_at + chrono::Duration::hours(1),
            authority_set_ref: authority_set_ref.clone(),
            authority_set_policy,
            proofs: Vec::new(),
        };
        let lease_digest = authorization_lease.lease_digest().unwrap();
        authorization_lease.proofs = vec![publication_proof(
            &DidUrl::new("did:web:authority.example#key-1").unwrap(),
            lease_digest,
            issued_at,
        )];

        let mut receipt = IngressReceipt {
            receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-cccccccccccc").unwrap(),
            event_digest: Hash::new(event.event_digest().unwrap()).unwrap(),
            authorization_lease_id: authorization_lease.authorization_lease_id.clone(),
            received_at: issued_at,
            service_id: Did::new("did:web:ingress.example").unwrap(),
            authority_set_ref,
            proofs: Vec::new(),
        };
        let receipt_digest = receipt.receipt_digest().unwrap();
        receipt.proofs = vec![publication_proof(
            &DidUrl::new("did:web:ingress.example#key-1").unwrap(),
            receipt_digest,
            issued_at,
        )];

        EventFederationSubmission {
            event,
            authorization_lease: Some(authorization_lease),
            ingress_receipts: vec![receipt],
            control_proposal_receipt,
            membership_compensation_evidence: None,
        }
    }

    fn proposal_receipt_for(
        event: &Event,
        authority_set_ref: &AuthoritySetRef,
        received_at: DateTime<Utc>,
    ) -> ControlProposalReceipt {
        let proposal_digest = Hash::new(event.event_digest().unwrap()).unwrap();
        let authority_set_digest = authority_set_ref.authority_set_digest.clone();
        let mut member_receipt = arkret_wire::ProposalMemberReceipt {
            realm_id: event.realm_id.clone(),
            proposal_digest: proposal_digest.clone(),
            received_at,
            decision_due_at: received_at + chrono::Duration::seconds(30),
            absolute_due_at: received_at + chrono::Duration::seconds(90),
            authority_set_ref: authority_set_digest.clone(),
            signature: PayloadSignature {
                verification_method: DidUrl::new("did:web:authority.example#key-1").unwrap(),
                extra: Default::default(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: received_at,
                jws: "a..b".to_owned(),
            },
        };
        member_receipt.signature.payload_digest = member_receipt.member_receipt_digest().unwrap();
        ControlProposalReceipt {
            kind: ControlProposalReceiptKind::ProposalReceipt,
            realm_id: event.realm_id.clone(),
            proposal_digest,
            received_at,
            decision_due_at: received_at + chrono::Duration::seconds(30),
            absolute_due_at: received_at + chrono::Duration::seconds(90),
            defer_count: 0,
            authority_set_ref: authority_set_digest,
            member_receipts: vec![member_receipt],
        }
    }

    #[test]
    fn realm_seal_frontier_distinguishes_protocol_bounds_from_exact_policy() {
        let event = control_move_over(&federation_prerequisite_seal());
        let submission = federation_submission(event.clone());
        let received_at = DateTime::parse_from_rfc3339("2026-07-29T20:57:46.276Z")
            .unwrap()
            .with_timezone(&Utc);
        let receipt = proposal_receipt_for(
            &event,
            &submission
                .authorization_lease
                .as_ref()
                .expect("fixture uses delayed federation")
                .authority_set_ref,
            received_at,
        );
        let health = ControlGovernanceHealth {
            status: ControlGovernanceHealthStatus::Healthy,
            pending_proposals: vec![PendingControlProposal {
                proposal_digest: receipt.proposal_digest.clone(),
                current_decision_due_at: receipt.decision_due_at,
                absolute_due_at: receipt.absolute_due_at,
                defer_count: 0,
                decision_state: ControlProposalDecisionState::Pending,
                fault_reason: None,
                receipt,
                decisions: Vec::new(),
            }],
            retained_faults: Vec::new(),
        };
        let frontier = RealmSealFrontierView::new(
            event.realm_id,
            SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap(),
            Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            health,
            None,
        );

        frontier
            .validate_protocol_bounds()
            .expect("a 30s/90s Realm frontier is inside protocol ceilings");
        frontier
            .validate_with_policy(ControlProposalDecisionPolicy::default())
            .expect("the same frontier matches the effective default Realm policy");
        assert!(
            frontier
                .validate_with_policy(ControlProposalDecisionPolicy::protocol_maximum())
                .is_err(),
            "protocol ceilings must not masquerade as the exact Realm policy"
        );
    }

    fn federation_request(events: Vec<Event>) -> EventsSubmitFederationRequestBody {
        let realm_id = events[0].realm_id.clone();
        EventsSubmitFederationRequestBody {
            service_binding_ref: FederationServiceBindingRef {
                realm_id,
                realm_policy_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                membership_frontier: Vec::new(),
                delivery_binding_frontier: Vec::new(),
                destination_service_kind: "principal_server".to_owned(),
            },
            events: events.into_iter().map(federation_submission).collect(),
            cba_proof_bundles: Vec::new(),
            signer_key_evidence: Vec::new(),
            agent_signer_evidence_bundle: None,
        }
    }

    /// Turn the DataEvent fixture into a Control Move: registered control-plane
    /// kinds carry `seal_basis` and MUST NOT carry `seal_ref`/`auth_context`.
    fn control_move_over(basis_seal: &Seal) -> Event {
        let mut control = event_with_device_proof();
        control.kind = "ak.capability.grant".into();
        control.seal_ref = None;
        control.auth_context = None;
        control.seal_basis = Some(basis_seal.seal_basis());
        control
    }

    fn federation_prerequisite_seal() -> Seal {
        let hash =
            |byte: char| Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap();
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            predecessor_refs: Vec::new(),
            delta: vec![Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap()],
            control_event_set_root: hash('2'),
            state_root: hash('3'),
            completeness_root: hash('4'),
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(PayloadSignature {
                verification_method: DidUrl::new("did:web:notary.example#key-1").unwrap(),
                extra: Default::default(),
                payload_digest: hash('5'),
                created_at: "2026-07-21T08:00:00Z".parse().unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }),
            sealed_at: "2026-07-21T08:00:00Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            kind: SealKind::Normal,
        };
        seal.id = seal.derive_id().unwrap();
        seal
    }

    #[test]
    fn federation_transport_is_single_realm_and_control_first() {
        let data = event_with_device_proof();
        let mut other_realm = data.clone();
        let foreign_realm = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000099").unwrap();
        other_realm.realm_id = foreign_realm.clone();
        // The signed scope has to move with the envelope Realm, otherwise the
        // envelope is rejected for an inconsistent scope before the transport
        // single-Realm rule is ever reached.
        other_realm.scope_ref = ScopeRef::Realm {
            realm_id: foreign_realm,
        };
        assert!(
            federation_request(vec![data.clone(), other_realm])
                .validate_federation_transport()
                .is_err()
        );

        let control = control_move_over(&federation_prerequisite_seal());
        assert!(
            federation_request(vec![data, control])
                .validate_federation_transport()
                .is_err()
        );
    }

    #[test]
    fn federation_transport_enforces_event_limit_and_header_only_idempotency() {
        let event = event_with_device_proof();
        let mut empty = federation_request(vec![event.clone()]);
        empty.events.clear();
        assert!(empty.validate_federation_transport().is_err());
        assert!(
            federation_request(vec![event.clone(); MAX_FEDERATED_EVENTS + 1])
                .validate_federation_transport()
                .is_err()
        );

        let request = federation_request(vec![event]);
        let value = serde_json::to_value(&request).unwrap();
        assert!(value.get("idempotency_key").is_none());
        let mut value = value;
        value
            .as_object_mut()
            .unwrap()
            .insert("idempotency_key".to_owned(), json!("header-only"));
        assert!(serde_json::from_value::<EventsSubmitFederationRequestBody>(value).is_err());
    }

    #[test]
    fn federation_transport_seal_closure_is_rooted_at_control_basis_leaves() {
        // The federation body no longer carries a bare `seals[]`: CBA
        // prerequisites travel inside `cba_proof_bundles`, and the closure rule
        // is unchanged — every disclosed Seal must be reachable from a
        // transported DataEvent `seal_ref` or Control Move `seal_basis` leaf.
        let seal = federation_prerequisite_seal();
        let control = control_move_over(&seal);

        let mut request = federation_request(vec![control]);
        request.cba_proof_bundles = vec![CbaProofBundle {
            target_seal_ref: seal.id.clone(),
            seals: vec![seal],
            control_moves: Vec::new(),
            inclusion_proofs: Vec::new(),
            availability_proofs: Vec::new(),
        }];
        request
            .validate_federation_transport()
            .expect("a Control Event may transport its non-local Seal basis");
    }

    #[test]
    fn federation_transport_rejects_a_seal_no_transported_event_roots() {
        // Same closure rule, negative direction: a bundle whose Seal is not
        // reachable from any transported Event is unrelated disclosure.
        let seal = federation_prerequisite_seal();
        let mut request = federation_request(vec![event_with_device_proof()]);
        request.cba_proof_bundles = vec![CbaProofBundle {
            target_seal_ref: seal.id.clone(),
            seals: vec![seal],
            control_moves: Vec::new(),
            inclusion_proofs: Vec::new(),
            availability_proofs: Vec::new(),
        }];
        let error = request.validate_federation_transport().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unrelated to transported Events"),
            "{error}"
        );
    }

    #[test]
    fn federation_transport_requires_publication_evidence_bound_to_each_event() {
        // `events[]` is no longer a bare Event array. Each transported Event
        // travels with the lease that authorized it and at least one ingress
        // receipt binding that exact Event digest inside the lease window.
        let request = federation_request(vec![event_with_device_proof()]);
        request
            .validate_federation_transport()
            .expect("an Event with its lease and ingress receipt is transportable");

        let mut without_receipt = request.clone();
        without_receipt.events[0].ingress_receipts.clear();
        assert!(without_receipt.validate_federation_transport().is_err());

        let mut foreign_digest = request.clone();
        foreign_digest.events[0].ingress_receipts[0].event_digest =
            Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert!(foreign_digest.validate_federation_transport().is_err());

        let mut foreign_actor = request;
        foreign_actor.events[0]
            .authorization_lease
            .as_mut()
            .expect("fixture uses delayed federation")
            .actor_id = Did::new("did:web:mallory.example").unwrap();
        assert!(foreign_actor.validate_federation_transport().is_err());
    }
}
