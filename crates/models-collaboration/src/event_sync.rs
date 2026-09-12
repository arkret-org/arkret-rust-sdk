//! Event frontier, submission, subscription, and snapshot wire models.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.
//! Generated reducer-profile digests are owned by `arkret-policy`.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_wire::{
    ActorId, CbsEffectPlane, CbsProofBundle, ControlProposalAck, ControlProposalDecision,
    ControlProposalDecisionPolicy, DidCoreId, Event, EventFederationSubmission, EventId, Hash,
    MAX_ACTOR_SEQ_TOTAL_SIBLINGS, RealmId, Result, Seal, SealBasis, SealId, WireError,
};
#[cfg(test)]
use arkret_wire::{Did, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── EventsFrontier 3-way split ──────────────────────────────────────────

/// `ak.self.events.read.frontier.v1` account-client response
/// (`service-operation-dtos.schema.json#/$defs/EventsFrontierState`). Realm
/// Seal discovery is exclusively `ak.self.seals.read.frontier.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsFrontierState {
    pub frontier: EventsFrontierView,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealFrontierState {
    pub frontier: RealmSealFrontierView,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<AgentPcrSealHeadReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSealFrontierState {
    pub frontier: RealmSealFrontierView,
    pub service_proof: arkret_wire::PayloadProof,
}

/// Typed, closed receipt carrying the last accepted controller-device-signed
/// Seal for a Agent PCR whose Event log is ahead of Seal coverage.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPcrSealHeadReceipt {
    pub kind: AgentPcrSealHeadReceiptKind,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub seal: Seal,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPcrSealHeadReceiptKind {
    #[serde(rename = "ak.agent_pcr.seal_head.v1")]
    AgentPcrSealHeadV1,
}

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

/// Typed selector for canonical `QUERY /_arkret/self/events/frontier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventsFrontierSelector {
    RealmActor {
        realm_id: RealmId,
        actor_id: ActorId,
    },
    ActorAggregate {
        actor_id: ActorId,
    },
}

impl EventsFrontierSelector {
    /// Query pairs for an HTTP client. Callers should pass these through their
    /// URL library rather than hand-building or escaping a query string.
    pub fn query_pairs(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::RealmActor { realm_id, actor_id } => vec![
                ("realm_id", realm_id.as_str().to_owned()),
                (
                    "actor_id",
                    actor_id.canonical_key().expect("validated ActorId"),
                ),
            ],
            Self::ActorAggregate { actor_id } => {
                vec![(
                    "actor_id",
                    actor_id.canonical_key().expect("validated ActorId"),
                )]
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
            (Self::ActorAggregate { actor_id }, EventsFrontierView::ActorAggregate(frontier))
                if &frontier.actor_id == actor_id =>
            {
                frontier.validate()
            }
            _ => Err(WireError::Protocol(
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
    ActorAggregate(ActorAggregateFrontierView),
}

#[derive(Serialize)]
struct RealmActorFrontierDigestTranscript<'a> {
    kind: &'static str,
    realm_id: &'a RealmId,
    actor_id: &'a ActorId,
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
    pub actor_id: ActorId,
    pub next_actor_seq: u64,
    pub frontier_event_ids: Vec<EventId>,
    pub frontier_digest: Hash,
}

impl RealmActorFrontierView {
    pub fn new(
        realm_id: RealmId,
        actor_id: ActorId,
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
        actor_id: &ActorId,
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
            .map_err(|error| WireError::Protocol(format!("frontier transcript: {error}")))?;
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
            .ok_or_else(|| WireError::Protocol("frontier_digest has no suite prefix".to_owned()))?;
        let suite = arkret_canonical::digest_suite(suite_name)?;
        self.validate_with_suite(suite)
    }

    pub fn validate_with_suite(&self, digest_suite: DigestSuite) -> Result<()> {
        if self.frontier_event_ids.len() > MAX_ACTOR_SEQ_TOTAL_SIBLINGS {
            return Err(WireError::Protocol(
                "realm actor frontier exceeds the v1 sibling limit".to_owned(),
            ));
        }
        if self.next_actor_seq == 0 && !self.frontier_event_ids.is_empty() {
            return Err(WireError::Protocol(
                "empty realm actor frontier must not contain event ids".to_owned(),
            ));
        }
        if self.next_actor_seq > 0 && self.frontier_event_ids.is_empty() {
            return Err(WireError::Protocol(
                "non-empty realm actor frontier must contain event ids".to_owned(),
            ));
        }
        if self
            .frontier_event_ids
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "realm actor frontier digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Read-only actor aggregate. It deliberately exposes no authoring helper.
/// `service-operation-dtos.schema.json#/$defs/ActorAggregateFrontierView`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorAggregateFrontierView {
    pub kind: ActorAggregateFrontierKind,
    pub actor_id: ActorId,
    pub frontiers: Vec<RealmActorFrontierView>,
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
            return Err(WireError::Protocol(
                "actor CAS conflict details must assert accepted=false".to_owned(),
            ));
        }
        self.current_frontier.validate()
    }
}

impl ActorAggregateFrontierView {
    pub fn validate(&self) -> Result<()> {
        for frontier in &self.frontiers {
            if frontier.actor_id != self.actor_id {
                return Err(WireError::Protocol(
                    "actor aggregate contains a different actor_id".to_owned(),
                ));
            }
            frontier.validate()?;
        }
        if self
            .frontiers
            .windows(2)
            .any(|pair| pair[0].realm_id.as_str() >= pair[1].realm_id.as_str())
        {
            return Err(WireError::Protocol(
                "actor aggregate realms must be sorted and unique".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Realm Seal view shape of the account-client frontier: the current
/// accepted Seal head of the Realm. `seal_basis()` mints the single-leaf
/// Control Move basis (`leaves=[seal_id]`).
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
    pub control_proposal_ack: ControlProposalAck,
    pub decisions: Vec<ControlProposalDecision>,
    pub decision_state: ControlProposalDecisionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_reason: Option<ControlProposalFaultReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_revocation_state: Option<arkret_wire::DeviceRevocationPendingState>,
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
    pub pending_proposals_complete: bool,
}

impl ControlGovernanceHealth {
    pub const MAX_PENDING_PROPOSALS: usize = 128;

    pub fn healthy() -> Self {
        Self {
            status: ControlGovernanceHealthStatus::Healthy,
            pending_proposals: Vec::new(),
            pending_proposals_complete: true,
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
            return Err(WireError::Protocol(
                "control governance health exceeds 128 pending proposals".to_owned(),
            ));
        }
        let mut previous_key: Option<(DateTime<Utc>, &str)> = None;
        let mut has_overdue = false;
        for pending in &self.pending_proposals {
            if let Some(revocation) = &pending.device_revocation_state {
                revocation.validate()?;
                let decision_state = match revocation.decision_state {
                    arkret_wire::DeviceRevocationDecisionState::Pending => {
                        ControlProposalDecisionState::Pending
                    }
                    arkret_wire::DeviceRevocationDecisionState::Deferred => {
                        ControlProposalDecisionState::Deferred
                    }
                    arkret_wire::DeviceRevocationDecisionState::Overdue => {
                        ControlProposalDecisionState::Overdue
                    }
                };
                if revocation.control_proposal_ack != pending.control_proposal_ack
                    || revocation.decisions.as_deref().unwrap_or_default() != pending.decisions
                    || decision_state != pending.decision_state
                {
                    return Err(WireError::Protocol(
                        "pending device revocation must match its enclosing proposal".to_owned(),
                    ));
                }
            }
            if let Some(policy) = policy {
                pending.control_proposal_ack.validate_structural(policy)?;
            } else {
                pending.control_proposal_ack.validate_protocol_bounds()?;
            }
            let mut verified_defers = Vec::with_capacity(pending.decisions.len());
            for decision in &pending.decisions {
                if decision.is_reject() {
                    return Err(WireError::Protocol(
                        "terminal signed_reject cannot remain pending".to_owned(),
                    ));
                }
                if let Some(policy) = policy {
                    decision.validate_chain(
                        &pending.control_proposal_ack,
                        &verified_defers,
                        policy,
                    )?;
                } else {
                    decision.validate_chain_protocol_bounds(
                        &pending.control_proposal_ack,
                        &verified_defers,
                    )?;
                }
                verified_defers.push(decision.clone());
            }
            let overdue = pending.decision_state == ControlProposalDecisionState::Overdue;
            if overdue
                != (pending.fault_reason
                    == Some(ControlProposalFaultReason::ControlProposalDecisionOverdue))
            {
                return Err(WireError::Protocol(
                    "overdue proposal must carry the stable overdue fault reason".to_owned(),
                ));
            }
            let expected_non_fault_state = if pending.decisions.is_empty() {
                ControlProposalDecisionState::Pending
            } else {
                ControlProposalDecisionState::Deferred
            };
            if !overdue && pending.decision_state != expected_non_fault_state {
                return Err(WireError::Protocol(
                    "pending proposal decision_state does not match its decision chain".to_owned(),
                ));
            }
            has_overdue |= overdue;
            let key = (
                pending.control_proposal_ack.absolute_due_at,
                pending.control_proposal_ack.proposal_digest.as_str(),
            );
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(WireError::Protocol(
                    "pending proposals are not in canonical deadline/digest order".to_owned(),
                ));
            }
            previous_key = Some(key);
        }
        let expected_status = if has_overdue || !self.pending_proposals_complete {
            ControlGovernanceHealthStatus::Degraded
        } else {
            ControlGovernanceHealthStatus::Healthy
        };
        if self.status != expected_status {
            return Err(WireError::Protocol(
                "control governance status does not match pending proposal faults".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/service-operation-dtos.schema.json#/$defs/RealmSealFrontierView`
/// `observation_coordinate`.
///
/// `current` names this service's verified durable view at this coordinate; it
/// is never a claim about a global wall-clock latest state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSealFrontierObservationCoordinate {
    pub service_id: DidCoreId,
    pub sequence: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/service-operation-dtos.schema.json#/$defs/RealmSealFrontierView`.
///
/// `seal_basis.leaves[]` is the complete canonical non-quarantined accepted
/// Seal leaf frontier: exactly one confirmed leaf under quorum notary
/// authority. Self clients consume
/// their authenticated Account Station result without replaying history; peer
/// servers independently verify foreign governance. The live digest suite is
/// the effective suite at exactly this accepted basis.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSealFrontierView {
    pub kind: RealmSealFrontierKind,
    pub realm_id: RealmId,
    pub seal_basis: SealBasis,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub live_digest_suite: DigestSuite,
    pub governance_health: ControlGovernanceHealth,
    pub observation_coordinate: RealmSealFrontierObservationCoordinate,
}

impl RealmSealFrontierView {
    pub fn new(
        realm_id: RealmId,
        seal_basis: SealBasis,
        live_digest_suite: DigestSuite,
        governance_health: ControlGovernanceHealth,
        observation_coordinate: RealmSealFrontierObservationCoordinate,
    ) -> Self {
        Self {
            kind: RealmSealFrontierKind::RealmSeal,
            realm_id,
            seal_basis,
            live_digest_suite,
            governance_health,
            observation_coordinate,
        }
    }

    /// The complete accepted leaf antichain a newly authored Control Move may
    /// cite after binding the authenticated Account Station result to its intent.
    pub fn seal_basis(&self) -> SealBasis {
        self.seal_basis.clone()
    }

    /// The unique accepted leaf of the quorum-confirmed Realm history.
    pub fn sole_leaf(&self) -> Result<&SealId> {
        match self.seal_basis.leaves.as_slice() {
            [leaf] => Ok(leaf),
            _ => Err(WireError::Protocol(
                "Realm Seal frontier is not a single-leaf accepted antichain".to_owned(),
            )),
        }
    }

    pub fn validate_protocol_bounds(&self) -> Result<()> {
        self.seal_basis.validate_protocol_bounds()?;
        self.governance_health.validate_protocol_bounds()
    }

    pub fn validate_with_policy(&self, policy: ControlProposalDecisionPolicy) -> Result<()> {
        self.governance_health.validate_with_policy(policy)
    }
}

/// `ak.peer.events.read.frontier.v1` federation-peer response
/// (`service-operation-dtos.schema.json#/$defs/EventsFrontierFederationPeerState`).
/// Returned to an authorized federation peer over signed S2S trust-domain
/// headers: the realm's federation-visible head Event IDs, the
/// `frontier_root` hash commitment, optional actor-scoped authorization roots,
/// per-actor sequence upper bounds, and a service signature over the observed
/// frontier. This is the single
/// canonical shape shared by the spec artifacts, the producing service, and
/// every consumer.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsFrontierFederationPeerState {
    pub realm_id: RealmId,
    /// Current federation-visible head Event IDs for the realm.
    pub head_ids: Vec<EventId>,
    /// Maximum HLC observed by the issuer at this frontier, when available.
    #[serde(
        default,
        deserialize_with = "deserialize_frontier_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_hlc: Option<String>,
    /// Hash commitment returned to an authorized federation peer.
    pub frontier_root: Hash,
    /// Issuer-local authorization-state commitment for `request.actor_id`.
    #[serde(
        default,
        deserialize_with = "deserialize_frontier_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_state_root: Option<Hash>,
    /// Filtered policy-cell state root for the requested Realm.
    #[serde(
        default,
        deserialize_with = "deserialize_frontier_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_frontier_root: Option<Hash>,
    /// Filtered membership/role state root for `request.actor_id`.
    #[serde(
        default,
        deserialize_with = "deserialize_frontier_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub membership_frontier_root: Option<Hash>,
    /// Per-actor sequence upper bounds returned to an authorized peer. JSON
    /// object keys are the exact RFC 8785 canonical JSON text of each ActorId.
    #[serde(default, with = "actor_sequence_bounds_map")]
    pub actor_seq_upper_bounds: BTreeMap<ActorId, u64>,
    /// Optional witness / receipt-service attestations over the frontier.
    #[serde(default)]
    pub witness_receipts: Vec<BTreeMap<String, Value>>,
    /// RFC 3339 (`Z`-suffixed) instant the issuer observed this frontier.
    pub observed_at: String,
    pub issuer_id: DidCoreId,
    /// Service signature object over the peer frontier response.
    pub signature: BTreeMap<String, Value>,
}

fn deserialize_frontier_optional<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl EventsFrontierFederationPeerState {
    /// Rebuild the signed object from the response, never from an untrusted
    /// `signature.signed_payload` mirror. Optional commitments always use null.
    pub fn signature_payload(&self) -> Result<Value> {
        let roots = [
            self.auth_state_root.as_ref(),
            self.policy_frontier_root.as_ref(),
            self.membership_frontier_root.as_ref(),
        ];
        if roots.iter().any(Option::is_some) && roots.iter().any(Option::is_none) {
            return Err(WireError::Protocol(
                "partial actor frontier roots".to_owned(),
            ));
        }
        let observed = DateTime::parse_from_rfc3339(&self.observed_at)
            .map_err(|error| WireError::Protocol(format!("frontier observed_at: {error}")))?;
        if arkret_canonical::format_timestamp_canonical(observed.with_timezone(&Utc))
            != self.observed_at
        {
            return Err(WireError::Protocol(
                "noncanonical frontier observed_at".to_owned(),
            ));
        }
        Ok(serde_json::json!({
            "domain": arkret_wire::DomainSeparationId::EVENTS_FRONTIER_SIGNATURE_V1,
            "frontier_root": self.frontier_root,
            "auth_state_root": self.auth_state_root,
            "policy_frontier_root": self.policy_frontier_root,
            "membership_frontier_root": self.membership_frontier_root,
            "realm_id": self.realm_id,
            "issuer_id": self.issuer_id,
            "max_hlc": self.max_hlc,
            "observed_at": self.observed_at,
        }))
    }

    /// Validate envelope metadata and freshness before cryptographic verification.
    /// The caller must also recompute the frontier root and resolve the issuer's
    /// currently authorized verification method; this method does not verify JWS.
    pub fn signature_binding_bytes(&self, now: DateTime<Utc>) -> Result<Vec<u8>> {
        const FIELDS: [&str; 7] = [
            "typ",
            "scheme",
            "verification_method",
            "payload_digest",
            "created_at",
            "jws",
            "signed_payload",
        ];
        if self.signature.len() != FIELDS.len()
            || FIELDS
                .iter()
                .any(|field| !self.signature.contains_key(*field))
        {
            return Err(WireError::Protocol(
                "invalid frontier signature envelope".to_owned(),
            ));
        }
        let payload = self.signature_payload()?;
        let bytes = arkret_canonical::canonical_json_bytes(&payload)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if self.signature["typ"] != arkret_wire::DomainSeparationId::EVENTS_FRONTIER_SIGNATURE_V1
            || self.signature["scheme"] != "ed25519-detached-jws"
            || self.signature["created_at"] != self.observed_at
            || self.signature["signed_payload"] != payload
            || self.signature["payload_digest"] != arkret_canonical::sha256_digest(&bytes)
            || self.signature["jws"].as_str().is_none_or(str::is_empty)
        {
            return Err(WireError::Protocol(
                "frontier signature binding mismatch".to_owned(),
            ));
        }
        let method = self.signature["verification_method"]
            .as_str()
            .ok_or_else(|| {
                WireError::Protocol("frontier verification_method missing".to_owned())
            })?;
        arkret_wire::DidUrl::new(method.to_owned())
            .map_err(|error| WireError::Protocol(error.to_owned()))?;
        let observed = DateTime::parse_from_rfc3339(&self.observed_at)
            .map_err(|error| WireError::Protocol(error.to_string()))?
            .with_timezone(&Utc);
        if (now - observed).num_milliseconds().unsigned_abs() > 300_000 {
            return Err(WireError::Protocol("frontier signature expired".to_owned()));
        }
        Ok(bytes)
    }
}

pub(crate) mod actor_sequence_bounds_map {
    use std::collections::BTreeMap;
    use std::fmt;
    use std::marker::PhantomData;

    use arkret_wire::ActorId;
    use serde::de::{Error, MapAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S, T>(
        bounds: &BTreeMap<ActorId, T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        let mut encoded = BTreeMap::new();
        for (actor, upper_bound) in bounds {
            actor.validate().map_err(serde::ser::Error::custom)?;
            let key = actor.canonical_key().map_err(serde::ser::Error::custom)?;
            encoded.insert(key, upper_bound);
        }
        encoded.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D, T>(deserializer: D) -> Result<BTreeMap<ActorId, T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        struct BoundsVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundsVisitor<T> {
            type Value = BTreeMap<ActorId, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object keyed by canonical ActorId JSON strings")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut bounds = BTreeMap::new();
                while let Some((key, upper_bound)) = map.next_entry::<String, T>()? {
                    let value =
                        arkret_canonical::parse_json_rejecting_duplicate_keys(key.as_bytes())
                            .map_err(M::Error::custom)?;
                    let actor = ActorId::deserialize(value).map_err(M::Error::custom)?;
                    actor.validate().map_err(M::Error::custom)?;
                    if actor.canonical_key().map_err(M::Error::custom)? != key {
                        return Err(M::Error::custom(
                            "actor sequence map key is not canonical ActorId JSON",
                        ));
                    }
                    if bounds.insert(actor, upper_bound).is_some() {
                        return Err(M::Error::custom("duplicate actor sequence map key"));
                    }
                }
                Ok(bounds)
            }
        }

        deserializer.deserialize_map(BoundsVisitor(PhantomData))
    }
}

/// Canonical, globally ordered leaf data for the federation frontier commitment
/// (`federation.md` §4.5.1). Feed these bytes into the Seal Merkle family, not
/// the snapshot tree. The Actor remains an object inside its leaf; only the
/// response map key and the actor leaf's sorting key encode it as JSON text.
pub fn federation_frontier_leaf_data(
    head_ids: &[EventId],
    actor_upper_bounds: &BTreeMap<ActorId, u64>,
) -> Result<Vec<Vec<u8>>> {
    #[derive(Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum FrontierLeaf<'a> {
        Head {
            event_digest: Hash,
        },
        ActorSeqUpperBound {
            actor_id: &'a ActorId,
            actor_seq_upper_bound: u64,
        },
    }

    let mut leaves = Vec::new();
    for event_id in head_ids.iter().collect::<BTreeSet<_>>() {
        let digest = event_id.event_digest();
        leaves.push((
            format!("head:{digest}"),
            FrontierLeaf::Head {
                event_digest: digest,
            },
        ));
    }
    for (actor, upper_bound) in actor_upper_bounds {
        actor.validate()?;
        leaves.push((
            format!("actor:{}", actor.canonical_key()?),
            FrontierLeaf::ActorSeqUpperBound {
                actor_id: actor,
                actor_seq_upper_bound: *upper_bound,
            },
        ));
    }
    leaves.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    leaves
        .into_iter()
        .map(|(_, leaf)| arkret_canonical::canonical_json_bytes(&leaf).map_err(Into::into))
        .collect()
}

// ── FederationServiceBindingRef ─────────────────────────────────────────

/// Typed binding reference for federation transport. Carried inside
/// `ak.self.events.command.submit.v1` (federation variant) and the
/// `events/frontier` federation-peer response so a receiver can verify
/// the request is bound to the sender's policy and delivery frontiers.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub realm_policy_digest: Hash,
    pub membership_frontier: Vec<EventId>,
    pub destination_kind: String,
}

// ── EventsSubmit variants ───────────────────────────────────────────────

pub const MAX_FEDERATED_EVENTS: usize = 500;

/// Federation `/events/submit` request. Used when a remote
/// service forwards events from another Station. MUST carry
/// the full [`FederationServiceBindingRef`] so the receiver can verify
/// origin policy and delivery state. The reducer profile is resolved from
/// each Event's authenticated CBS and is never declared by the transport.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitFederationBatchRequestBody {
    pub service_binding_ref: FederationServiceBindingRef,
    /// Each transported Event travels with the lease and the original ingress
    /// receipts that authorized its first publication.
    pub events: Vec<EventFederationSubmission>,
    /// Receiver-relative CBS dependency bundles rooted at the transported
    /// Events' authority refs or `seal_basis` leaves.
    ///
    /// These are transport prerequisites, not Events and not an alternate
    /// federation write rail. A bundle MAY be a bounded verifiable superset;
    /// receivers independently verify every embedded object and project a
    /// Seal only after its covered Control Events are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cbs_proof_bundles: Vec<CbsProofBundle>,
}

impl EventsSubmitFederationBatchRequestBody {
    /// The transported Events, without their publication evidence.
    pub fn transported_events(&self) -> impl Iterator<Item = &Event> {
        self.events.iter().map(|submission| &submission.event)
    }

    /// Every Seal disclosed by the request's CBS proof bundles.
    ///
    /// Bundles are receiver-relative and MAY overlap, so the same Seal may be
    /// listed by more than one bundle. It is disclosed once here; the
    /// duplicate-id check below then applies to the deduplicated set.
    fn transported_seals(&self) -> Result<Vec<&Seal>> {
        let mut seen = BTreeSet::new();
        let mut seals = Vec::new();
        for bundle in &self.cbs_proof_bundles {
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
    pub fn validate_federation_transport(&self, digest_suites: &[DigestSuite]) -> Result<()> {
        if self.events.is_empty() || self.events.len() > MAX_FEDERATED_EVENTS {
            return Err(WireError::Protocol(
                "federation events must contain between 1 and 500 items".to_owned(),
            ));
        }
        let events = self
            .events
            .iter()
            .map(|submission| submission.event.clone())
            .collect::<Vec<_>>();
        if events.len() != digest_suites.len() {
            return Err(WireError::Protocol(
                "federation Event and digest-suite cardinality must match".to_owned(),
            ));
        }
        let submit_context =
            arkret_wire::classify_federated_event_submit_context(&events, digest_suites)?;
        if submit_context == arkret_wire::EventSubmitContext::AnchorUnit {
            let leases = self
                .events
                .iter()
                .filter_map(|submission| submission.authorization_lease.clone())
                .collect::<Vec<_>>();
            if !leases.is_empty() {
                if leases.len() != self.events.len() {
                    return Err(WireError::Protocol(
                        "an anchor unit cannot mix online and delayed submissions".to_owned(),
                    ));
                }
                arkret_wire::validate_anchor_unit_lease_bindings(&events, &leases, digest_suites)?;
            }
        }
        for (submission, digest_suite) in self.events.iter().zip(digest_suites.iter().copied()) {
            submission.validate_structural_in_context(submit_context, digest_suite)?;
        }
        if self.cbs_proof_bundles.len() > arkret_wire::event_submission::MAX_SUBMISSION_CBS_BUNDLES
        {
            return Err(WireError::Protocol(format!(
                "federation request exceeds {} CBS proof bundles",
                arkret_wire::event_submission::MAX_SUBMISSION_CBS_BUNDLES
            )));
        }
        let required_targets = self
            .transported_events()
            .flat_map(|event| {
                event
                    .auth_context
                    .iter()
                    .flat_map(|context| context.authority_refs.iter())
                    .chain(
                        event
                            .seal_basis
                            .iter()
                            .flat_map(|basis| basis.leaves.iter()),
                    )
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut previous_target: Option<&str> = None;
        for bundle in &self.cbs_proof_bundles {
            bundle.validate_structural()?;
            if previous_target.is_some_and(|previous| previous >= bundle.target_seal_ref.as_str()) {
                return Err(WireError::Protocol(
                    "federation CBS proof bundles must be strictly sorted by target_seal_ref"
                        .to_owned(),
                ));
            }
            previous_target = Some(bundle.target_seal_ref.as_str());
            if !required_targets.contains(&bundle.target_seal_ref) {
                return Err(WireError::Protocol(
                    "federation CBS proof bundle target is unrelated to transported Events"
                        .to_owned(),
                ));
            }
        }
        let seals = self.transported_seals()?;
        let mut saw_ordinary_event = false;
        for event in self.transported_events() {
            if event.realm_id != self.service_binding_ref.realm_id {
                return Err(WireError::Protocol(
                    "federation Event belongs to another Realm".to_owned(),
                ));
            }
            match event.kind.cbs_plane() {
                Some(CbsEffectPlane::Control) => {
                    if saw_ordinary_event {
                        return Err(WireError::Protocol(
                            "federation Control Events must precede ordinary Events".to_owned(),
                        ));
                    }
                }
                Some(CbsEffectPlane::Data) => saw_ordinary_event = true,
                _ => {
                    return Err(WireError::Protocol(
                        "federation Event kind has no registered CBS plane".to_owned(),
                    ));
                }
            }
        }

        let mut seal_ids = BTreeSet::new();
        for seal in &seals {
            if !seal_ids.insert(seal.id.clone()) {
                return Err(WireError::Protocol(
                    "federation CBS proof bundles contain a duplicate Seal id".to_owned(),
                ));
            }
            seal.validate_structural()?;
            if seal.realm_id != self.service_binding_ref.realm_id {
                return Err(WireError::Protocol(
                    "federation Seal prerequisite belongs to another Realm".to_owned(),
                ));
            }
        }

        // Reject disclosure that is not reachable from a transported
        // ordinary Event authority ref or Control Event seal_basis leaf. Receiver-local
        // predecessors may be omitted.
        let transported_by_id = seals
            .iter()
            .map(|seal| (seal.id.clone(), *seal))
            .collect::<BTreeMap<_, _>>();
        let mut pending = Vec::new();
        for event in self.transported_events() {
            if let Some(auth_context) = &event.auth_context {
                pending.extend(
                    auth_context
                        .authority_refs
                        .iter()
                        .filter(|seal_id| transported_by_id.contains_key(*seal_id))
                        .cloned(),
                );
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
                    seal.predecessor_ref
                        .iter()
                        .filter(|predecessor| transported_by_id.contains_key(*predecessor))
                        .cloned(),
                );
            }
        }
        if reachable.len() != seals.len() {
            return Err(WireError::Protocol(
                "federation CBS proof bundles contain Seals unrelated to transported Events"
                    .to_owned(),
            ));
        }

        // Build the in-request Event/Seal prerequisite graph and require it to
        // be acyclic. External dependencies are deliberately absent: the
        // receiver resolves those from accepted local state. A cycle wholly
        // represented by this request can never be repaired by retry and is a
        // permanent schema violation, including cycles longer than the direct
        // Event -> Seal -> same Event case.
        let submitted_digest_by_id = self
            .events
            .iter()
            .zip(digest_suites.iter().copied())
            .map(|(submission, digest_suite)| {
                Ok((
                    submission.event.event_id.clone(),
                    Hash::new(
                        submission
                            .event
                            .event_digest_with_digest_suite(digest_suite)?,
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let covered_digests = seals
            .iter()
            .flat_map(|seal| seal.delta.iter().chain(&seal.covered_event_digests))
            .collect::<BTreeSet<_>>();
        let event_nodes_by_digest = self
            .transported_events()
            .map(|event| {
                let digest = if let Some(digest) = submitted_digest_by_id.get(&event.event_id) {
                    digest.clone()
                } else {
                    let mut matches = covered_digests.iter().filter_map(|expected| {
                        let suite = expected.digest_suite().ok()?;
                        let actual =
                            Hash::new(event.event_digest_with_digest_suite(suite).ok()?).ok()?;
                        (actual == **expected).then_some(actual)
                    });
                    let Some(digest) = matches.next() else {
                        return Err(WireError::Protocol(
                            "federation Control Move is not bound by transported Seal coverage"
                                .to_owned(),
                        ));
                    };
                    if matches.next().is_some() {
                        return Err(WireError::Protocol(
                            "federation Control Move has ambiguous digest-suite coverage"
                                .to_owned(),
                        ));
                    }
                    digest
                };
                Ok((digest, format!("event:{}", event.event_id)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        for event in self.transported_events() {
            let node = format!("event:{}", event.event_id);
            let event_dependencies = dependencies.entry(node).or_default();
            if let Some(auth_context) = &event.auth_context {
                event_dependencies.extend(
                    auth_context
                        .authority_refs
                        .iter()
                        .filter(|seal_id| transported_by_id.contains_key(*seal_id))
                        .map(|seal_id| format!("seal:{seal_id}")),
                );
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
                seal.predecessor_ref
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
            return Err(WireError::Protocol(
                "federation Event/Seal prerequisite graph contains a cycle".to_owned(),
            ));
        }

        Ok(())
    }
}

/// Closed request union for `ak.peer.events.command.submit.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventsSubmitFederationRequestBody {
    Batch(EventsSubmitFederationBatchRequestBody),
    DirectConversationFounding(
        crate::direct_conversation_ops::DirectConversationFoundingFederationSubmission,
    ),
    AgentMembershipCascade(
        crate::governance::agent_membership_cascade::AgentMembershipCascadeFederationSubmission,
    ),
}

impl<'de> Deserialize<'de> for EventsSubmitFederationRequestBody {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value.get("unit_kind").and_then(Value::as_str) {
            None => serde_json::from_value(value)
                .map(Self::Batch)
                .map_err(serde::de::Error::custom),
            Some("direct_conversation_founding") => serde_json::from_value(value)
                .map(Self::DirectConversationFounding)
                .map_err(serde::de::Error::custom),
            Some("agent_membership_cascade") => serde_json::from_value(value)
                .map(Self::AgentMembershipCascade)
                .map_err(serde::de::Error::custom),
            Some(unit_kind) => Err(serde::de::Error::custom(format!(
                "unsupported federation submit unit_kind '{unit_kind}'"
            ))),
        }
    }
}

// `RealmStateSnapshotBootstrap` lives in `sync_frames::realm_state_snapshot` and reaches
// the `arkret::RealmStateSnapshotBootstrap` path via the `artifacts::sync` re-export.

#[cfg(test)]
#[path = "event_sync/tests.rs"]
mod tests;
