//! Event frontier, submission, subscription, and snapshot wire models.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.
//! Generated reducer-profile digests are owned by `arkret-policy`.

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_wire::{
    Did, Error, Event, EventId, FederatedDeviceSigningKeyEvidence, Hash, Hlc, RealmId, Result,
    Seal, SealBasis, SealId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_signer_evidence::{
    AGENT_SIGNER_EVIDENCE_BUNDLE_SCHEMA, AgentAuthorizationAdmission, AgentSignerEvidenceBundle,
};

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
                Ok(())
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSealFrontierView {
    pub kind: RealmSealFrontierKind,
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
}

impl RealmSealFrontierView {
    pub fn new(
        realm_id: RealmId,
        seal_id: SealId,
        control_event_set_root: Hash,
        state_root: Hash,
        hlc: Option<Hlc>,
    ) -> Self {
        Self {
            kind: RealmSealFrontierKind::RealmSeal,
            realm_id,
            seal_id,
            control_event_set_root,
            state_root,
            hlc,
        }
    }

    /// Single-leaf Control Move `seal_basis` under this view.
    pub fn seal_basis(&self) -> SealBasis {
        SealBasis {
            leaves: vec![self.seal_id.clone()],
            control_event_set_root: self.control_event_set_root.clone(),
            state_root: self.state_root.clone(),
        }
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
    /// Maximum HLC observed by the issuer at this frontier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hlc: Option<String>,
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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

/// Round 4 (commit 7446832) — typed binding reference for federation
/// transport. All six fields REQUIRED. Carried inside
/// `ak.self.events.command.submit` (federation variant) and the
/// `events/frontier` federation-peer response so a receiver can verify
/// the request is bound to the sender's current reducer state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub realm_policy_digest: Hash,
    pub membership_frontier: Vec<EventId>,
    pub delivery_binding_frontier: Vec<EventId>,
    pub destination_service_kind: String,
    pub reducer_profile_digest: Hash,
}

// ── EventsSubmit variants ───────────────────────────────────────────────

// `EventsSubmitBatchRequestBody` lives in this crate's `http_bodies`
// module (re-exported here for the historic flat path).
pub use crate::http_bodies::EventsSubmitBatchRequestBody;

pub const MAX_FEDERATED_EVENT_SIGNER_EVIDENCE: usize = 64;
pub const MAX_FEDERATED_SEAL_PREREQUISITES: usize = 4096;

/// Round 4 — federation `/events/submit` request. Used when a remote
/// service forwards events from another principal server. MUST carry
/// the full [`FederationServiceBindingRef`] so the receiver can verify
/// origin reducer state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsSubmitFederationRequestBody {
    pub service_binding_ref: FederationServiceBindingRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<Event>,
    /// Signed Seal ancestry required to verify `events[].seal_ref`.
    ///
    /// These are transport prerequisites, not Events and not an alternate
    /// federation write rail. Receivers independently verify and project each
    /// Seal only after its covered Control Events are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub seals: Vec<Seal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub signer_key_evidence: Vec<FederatedDeviceSigningKeyEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub agent_signer_evidence_bundle: Option<AgentSignerEvidenceBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl EventsSubmitFederationRequestBody {
    pub fn validate_signer_key_evidence(&self) -> Result<()> {
        if self.seals.len() > MAX_FEDERATED_SEAL_PREREQUISITES {
            return Err(Error::Protocol(
                "federation seals exceeds the v1 limit".to_owned(),
            ));
        }
        for seal in &self.seals {
            seal.validate_id()?;
            seal.validate_structural()?;
            if seal.realm_id != self.service_binding_ref.realm_id {
                return Err(Error::Protocol(
                    "federation Seal prerequisite belongs to another Realm".to_owned(),
                ));
            }
        }
        if self.signer_key_evidence.len() > MAX_FEDERATED_EVENT_SIGNER_EVIDENCE {
            return Err(Error::Protocol(
                "federation signer_key_evidence exceeds the v1 limit".to_owned(),
            ));
        }
        for evidence in &self.signer_key_evidence {
            evidence.validate_shape()?;
            if !self
                .events
                .iter()
                .any(|event| evidence.matches_event_proof(event, &evidence.verification_method))
            {
                return Err(Error::Protocol(
                    "federation signer evidence does not match a transported Event proof"
                        .to_owned(),
                ));
            }
        }
        if let Some(bundle) = &self.agent_signer_evidence_bundle {
            if bundle.schema.as_str() != AGENT_SIGNER_EVIDENCE_BUNDLE_SCHEMA
                || bundle.evidence.len() > 256
            {
                return Err(Error::Protocol(
                    "federation agent_signer_evidence_bundle is invalid".to_owned(),
                ));
            }
            for evidence in &bundle.evidence {
                let binding = &evidence.signing_key_binding;
                let matches_event = self.events.iter().any(|event| {
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
                    event
                        .unsigned
                        .get("agent_authorization_admission")
                        .cloned()
                        .and_then(|value| {
                            serde_json::from_value::<AgentAuthorizationAdmission>(value).ok()
                        })
                        .is_some_and(|admission| {
                            admission.agent_id == binding.agent_id
                                && admission.verification_method == binding.verification_method
                                && admission.authorization_event_id
                                    == binding.agent_key_authorize_event_id
                        })
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
    use arkret_wire::{DeviceId, DidKey};
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

    fn event_with_device_proof() -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-21T08:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
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
                "alg": "EdDSA",
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
            verification_method:
                "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
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
        unrelated.verification_method = format!(
            "{}#{}",
            unrelated.actor_id,
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000003").unwrap()
        );
        unrelated.device_id =
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000003").unwrap();
        let request = EventsSubmitFederationRequestBody {
            service_binding_ref: FederationServiceBindingRef {
                realm_id: event.realm_id.clone(),
                realm_policy_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                membership_frontier: vec![event.event_id.clone()],
                delivery_binding_frontier: vec![event.event_id.clone()],
                destination_service_kind: "principal_server".to_owned(),
                reducer_profile_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            },
            events: vec![event],
            seals: Vec::new(),
            signer_key_evidence: vec![unrelated],
            agent_signer_evidence_bundle: None,
            idempotency_key: None,
        };
        assert!(request.validate_signer_key_evidence().is_err());
    }
}
