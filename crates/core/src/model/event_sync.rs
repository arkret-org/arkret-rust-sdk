//! Event frontier, submission, subscription, and snapshot wire models.

use super::*;
use crate::canonical;

// ── EventsFrontier 3-way split ──────────────────────────────────────────

/// Round 4 (commit f9bd7eb) — peer role discriminator for the
/// `/events/frontier` endpoint. The pre-round-4 single-shape response
/// is wire-broken; receivers MUST route by `peer_role` and produce one
/// of three discriminated response variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FrontierPeerRole {
    AccountClient,
    FederationPeer,
    AnonymousHealth,
}

/// Round 4 — account-client variant of the `/events/frontier` response.
/// Used by signed-in clients; the SDK does NOT include `frontier_root`
/// or transport signatures here (client UI does not need them).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAccountClientResponse {
    pub peer_role: FrontierPeerRole,
    pub frontier: BTreeMap<SpaceId, Vec<EventId>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor_seq_upper_bounds: BTreeMap<Did, u64>,
}

/// Round 4 — federation-peer variant of `/events/frontier`. Carries
/// `frontier_root` + transport receipts + `service_binding_ref` so a
/// remote peer can verify the response binds to the producing service.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierFederationPeerResponse {
    pub peer_role: FrontierPeerRole,
    pub frontier: BTreeMap<SpaceId, Vec<EventId>>,
    pub frontier_root: Hash,
    pub service_binding_ref: FederationServiceBindingRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor_seq_upper_bounds: BTreeMap<Did, u64>,
}

/// Round 4 — anonymous-health variant. Used by public health checks
/// (`peer_role=anonymous_health`); the wire shape MUST NOT carry
/// receipts, signatures, or actor_seq_upper_bounds. Type system
/// enforces this (no such fields).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAnonymousHealthResponse {
    pub peer_role: FrontierPeerRole,
    pub service_did: Did,
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
pub enum EventsFrontierResponse {
    AccountClient(EventsFrontierAccountClientResponse),
    FederationPeer(EventsFrontierFederationPeerResponse),
    AnonymousHealth(EventsFrontierAnonymousHealthResponse),
}

// ── FederationServiceBindingRef ─────────────────────────────────────────

/// Round 4 (commit 7446832) — typed binding reference for federation
/// transport. All six fields REQUIRED. Carried inside
/// `cx.events.submit` (federation variant) and the
/// `events/frontier` federation-peer response so a receiver can verify
/// the request is bound to the sender's current reducer state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub space_policy_hash: Hash,
    pub membership_frontier: Vec<EventId>,
    pub delivery_binding_frontier: Vec<EventId>,
    pub destination_service_type: String,
    pub reducer_profile_digest: Hash,
}

// ── EventsSubmit variants ───────────────────────────────────────────────

/// Round 4 — batch `/events/submit` request. Multiple envelopes
/// submitted in a single round trip. The receiver MUST process each
/// envelope independently; partial-success returns the per-envelope
/// rejected list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitBatchRequest {
    pub events: Vec<Value>,
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
pub struct EventsSubmitFederationRequest {
    pub service_binding_ref: FederationServiceBindingRef,
    pub events: Vec<Value>,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventsSubscribeFrameBody {
    Event {
        event: Value,
    },
    Frontier {
        frontier: Value,
    },
    Heartbeat {
        /// Server time the heartbeat was emitted (staleness guard).
        emitted_at: DateTime<Utc>,
    },
    CatchupComplete,
    EpochRotation {
        epoch: u64,
    },
    Dropped {
        /// REQUIRED resume cursor; absence MUST be treated as
        /// `ResyncRequired` by the implementation that produced the
        /// frame.
        cursor: Cursor,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
    },
    ResyncRequired {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
    },
    Unauthorized {
        reason: String,
    },
}

// ── SnapshotBootstrap ───────────────────────────────────────────────────

/// Round 4 — chunked snapshot delivery envelope.
///
/// The signature binds the canonical bootstrap header:
/// `domain`, `state_digest`, `snapshot_frontier`, and a deterministic digest
/// root over the ordered chunk digests. Consumers still fetch and verify each
/// chunk by its declared digest before applying the snapshot.
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
    pub const SIGNING_DOMAIN: &'static str = "cx.snapshot.bootstrap.v1";

    pub fn chunk_digest_root(&self) -> Result<Hash> {
        let digests: Vec<&str> = self.chunks.iter().map(|chunk| chunk.digest.as_str()).collect();
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotBootstrapChunk {
    pub chunk_id: String,
    pub digest: Hash,
    pub size_bytes: u64,
    /// HTTP URL or `cx:blob:` reference where the chunk bytes can be
    /// fetched.
    pub fetch_ref: String,
}
