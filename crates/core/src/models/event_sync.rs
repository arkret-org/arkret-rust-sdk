//! Event frontier, submission, subscription, and snapshot wire models.

use super::*;
use crate::{SealBasis, canonical};

// ── EventsFrontier 3-way split ──────────────────────────────────────────

/// `/events/frontier` peer-role selector. The account-client and
/// anonymous-health responses are shape-discriminated; the federation-peer
/// response follows the single canonical
/// [`EventsFrontierFederationPeerState`] shape defined by the spec
/// artifacts (`service-operation-dtos.schema.json`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
/// and a DataEvent `seal_ref`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAccountClientState {
    pub frontier: EventsFrontierView,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

/// Selector-dependent `frontier` object of
/// [`EventsFrontierAccountClientState`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum EventsFrontierView {
    RealmSealView(RealmSealFrontierView),
    Actor(ActorFrontierView),
}

/// Realm Seal view shape of the account-client frontier: the current
/// accepted Seal head of the Realm. `seal_basis()` mints the single-leaf
/// Control Move basis (`leaves=[seal_id]`); `seal_id` alone is the DataEvent
/// `seal_ref`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmSealFrontierView {
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
}

impl RealmSealFrontierView {
    /// Single-leaf Control Move `seal_basis` under this view.
    pub fn seal_basis(&self) -> SealBasis {
        SealBasis {
            leaves: vec![self.seal_id.clone()],
            control_event_set_root: self.control_event_set_root.clone(),
            state_root: self.state_root.clone(),
        }
    }
}

/// Actor shape of the account-client frontier: highest accepted `actor_seq`
/// visible to the caller. An empty visible history is represented by
/// `actor_seq == 0` and no `event_id`; non-empty frontiers carry both a
/// positive sequence and its Event id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorFrontierView {
    pub actor_id: Did,
    pub actor_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
}

impl ActorFrontierView {
    /// Enforce the registered empty/non-empty actor frontier invariant.
    pub fn validate(&self) -> Result<()> {
        match (self.actor_seq, self.event_id.is_some()) {
            (0, false) | (1.., true) => Ok(()),
            (0, true) => Err(Error::Protocol(
                "empty actor frontier must not include event_id".to_owned(),
            )),
            (_, false) => Err(Error::Protocol(
                "non-empty actor frontier must include event_id".to_owned(),
            )),
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub witness_receipts: Vec<Value>,
    /// RFC 3339 (`Z`-suffixed) instant the issuer observed this frontier.
    pub observed_at: String,
    pub issuer: Did,
    /// Service signature object over the peer frontier response.
    pub signature: Value,
    /// Maximum HLC observed by the issuer at this frontier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hlc: Option<String>,
}

/// Round 4 — anonymous-health variant. Used by public health checks
/// (`peer_role=anonymous_health`); the wire shape MUST NOT carry
/// receipts, signatures, or actor_seq_upper_bounds. Type system
/// enforces this (no such fields).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAnonymousHealthState {
    pub peer_role: FrontierPeerRole,
    pub service_id: Did,
    pub healthy: bool,
    /// Wall-clock instant the frontier snapshot was generated. Used for
    /// staleness detection only — not signed.
    pub generated_at: DateTime<Utc>,
}

/// Round 4 — discriminated `/events/frontier` response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub realm_policy_digest: Hash,
    pub membership_frontier: Vec<EventId>,
    pub delivery_binding_frontier: Vec<EventId>,
    pub destination_service_type: String,
    pub reducer_profile_digest: Hash,
}

pub const FEDERATION_MINIMAL_PROFILE_ID: &str = "ak.profile.federation_minimal.v1";
pub const FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST: &str =
    "sha256:f275d2e5dd588758bd9a77254cbfa72fa187cc098e7f61a63c3d13609c34a09c";

pub fn federation_minimal_reducer_profile_digest() -> &'static str {
    FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST
}

// ── EventsSubmit variants ───────────────────────────────────────────────

/// Round 4 — batch `/events/submit` request. Multiple envelopes
/// submitted in a single round trip. The receiver MUST process each
/// envelope independently; partial-success returns the per-envelope
/// rejected list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitBatchRequestBody {
    pub events: Vec<Event>,
    /// Optional idempotency key for the entire batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Round 4 — federation `/events/submit` request. Used when a remote
/// service forwards events from another principal server. MUST carry
/// the full [`FederationServiceBindingRef`] so the receiver can verify
/// origin reducer state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitFederationRequestBody {
    pub service_binding_ref: FederationServiceBindingRef,
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

// ── EventsSubscribe NDJSON frame discriminator ──────────────────────────

/// Round 4 — typed `/events/subscribe` NDJSON frame body.
///
/// Wire-breaking: replaces the pre-round-4 untyped string frames. The
/// `Dropped` variant MUST carry a cursor so receivers can resume; an
/// implementation that emits `Dropped` without cursor MUST downgrade
/// to `ResyncRequired`.
pub type EventsSubscribeFrameBody = crate::http::EventsSubscribeFrame;

// ── SnapshotBootstrap ───────────────────────────────────────────────────

/// Round 4 — chunked snapshot delivery envelope.
///
/// The signature binds the canonical bootstrap header:
/// `domain`, `state_digest`, `snapshot_frontier`, and a deterministic digest
/// root over the ordered chunk digests. Consumers still fetch and verify each
/// chunk by its declared digest before applying the snapshot.
///
/// Dev-only shape. Current production snapshot bootstrap uses
/// `ak.schema.snapshot.v1` [`crate::SnapshotManifest`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotBootstrap {
    /// Signature over [`SnapshotBootstrap::signing_payload_digest`].
    pub signature: SnapshotBootstrapSignature,
    /// Canonical state root over the snapshot's projected state.
    pub state_digest: Hash,
    /// Frontier the snapshot was generated against.
    pub snapshot_frontier: Vec<EventId>,
    /// Ordered chunk digests. Consumers MUST verify each chunk's bytes
    /// match the declared digest before applying.
    pub chunks: Vec<SnapshotBootstrapChunk>,
}

/// Dev-only bootstrap signature for [`SnapshotBootstrap`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotBootstrapSignature {
    pub alg: String,
    pub verification_method: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

impl SnapshotBootstrap {
    pub const SIGNING_DOMAIN: &'static str = "ak.snapshot.bootstrap.v1";

    pub fn chunk_digest_root(&self) -> Result<Hash> {
        let digests: Vec<&str> = self
            .chunks
            .iter()
            .map(|chunk| chunk.digest.as_str())
            .collect();
        let digest = canonical::canonical_sha256(&serde_json::json!({
            "domain": Self::SIGNING_DOMAIN,
            "chunk_digests": digests,
        }))?;
        Hash::new(digest).map_err(Into::into)
    }

    pub fn signing_payload(&self) -> Result<Value> {
        Ok(serde_json::json!({
            "domain": Self::SIGNING_DOMAIN,
            "state_digest": self.state_digest.as_str(),
            "snapshot_frontier": self
                .snapshot_frontier
                .iter()
                .map(EventId::as_str)
                .collect::<Vec<_>>(),
            "chunk_digest_root": self.chunk_digest_root()?.as_str(),
        }))
    }

    pub fn signing_payload_digest(&self) -> Result<Hash> {
        let digest = canonical::canonical_sha256(&self.signing_payload()?)?;
        Hash::new(digest).map_err(Into::into)
    }

    pub fn validate_signature_binding(&self) -> Result<()> {
        let expected = self.signing_payload_digest()?;
        if self.signature.payload_digest != expected {
            return Err(Error::Protocol(
                "snapshot bootstrap signature payload_digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Dev-only bootstrap chunk descriptor for [`SnapshotBootstrap`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotBootstrapChunk {
    pub chunk_id: String,
    pub digest: Hash,
    pub size_bytes: u64,
    /// HTTP URL or `ak:blob:` reference where the chunk bytes can be
    /// fetched.
    pub fetch_ref: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_minimal_reducer_profile_digest_is_well_formed() {
        assert_eq!(
            FEDERATION_MINIMAL_PROFILE_ID,
            "ak.profile.federation_minimal.v1"
        );
        assert_eq!(
            federation_minimal_reducer_profile_digest(),
            FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST
        );
        assert_eq!(
            Hash::new(FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST)
                .unwrap()
                .as_str(),
            FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST
        );
    }

    #[test]
    fn actor_frontier_distinguishes_empty_and_non_empty_histories() {
        let actor_id = Did::new("did:web:alice.example").unwrap();
        ActorFrontierView {
            actor_id: actor_id.clone(),
            actor_seq: 0,
            event_id: None,
        }
        .validate()
        .unwrap();
        ActorFrontierView {
            actor_id: actor_id.clone(),
            actor_seq: 1,
            event_id: Some(EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap()),
        }
        .validate()
        .unwrap();

        assert!(
            ActorFrontierView {
                actor_id,
                actor_seq: 1,
                event_id: None,
            }
            .validate()
            .is_err()
        );
    }
}
