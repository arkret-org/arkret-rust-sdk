//! Event frontier, submission, subscription, and snapshot wire models.
//!
//! Migrated from `arkret-core` (`models/event_sync.rs`); a shim there
//! re-exports these shapes to preserve the `arkret_core::` path. The
//! `federation_minimal` reducer-profile digest constant/fn stay in
//! `arkret-core` because they resolve against `arkret_policy::generated`
//! (a higher layer than this data crate).

use std::collections::BTreeMap;

use arkret_wire::{
    Did, Error, Event, EventId, FederatedDeviceSigningKeyEvidence, Hash, Hlc, RealmId, Result,
    Seal, SealBasis, SealId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── EventsFrontier 3-way split ──────────────────────────────────────────

/// `/events/frontier` peer-role selector. The account-client and
/// anonymous-health responses are shape-discriminated; the federation-peer
/// response follows the single canonical
/// [`EventsFrontierFederationPeerState`] shape defined by the spec
/// artifacts (`service-operation-dtos.schema.json`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAccountClientState {
    pub frontier: EventsFrontierView,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ManagedAgentPcrSealHeadReceipt>,
}

/// Typed, closed receipt carrying the last accepted controller-device-signed
/// Seal for a managed Agent PCR whose Event log is ahead of Seal coverage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ManagedAgentPcrSealHeadReceipt {
    pub kind: ManagedAgentPcrSealHeadReceiptKind,
    pub seal: Seal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum ManagedAgentPcrSealHeadReceiptKind {
    #[serde(rename = "ak.managed_agent_pcr.seal_head.v1")]
    ManagedAgentPcrSealHeadV1,
}

/// Selector-dependent `frontier` object of
/// [`EventsFrontierAccountClientState`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub realm_policy_digest: Hash,
    pub membership_frontier: Vec<EventId>,
    pub delivery_binding_frontier: Vec<EventId>,
    pub destination_service_type: String,
    pub reducer_profile_digest: Hash,
}

// ── EventsSubmit variants ───────────────────────────────────────────────

// `EventsSubmitBatchRequestBody` lives in this crate's `http_bodies`
// module (re-exported here for the historic flat path).
pub use crate::http_bodies::EventsSubmitBatchRequestBody;

pub const MAX_FEDERATED_EVENT_SIGNER_EVIDENCE: usize = 64;

/// Round 4 — federation `/events/submit` request. Used when a remote
/// service forwards events from another principal server. MUST carry
/// the full [`FederationServiceBindingRef`] so the receiver can verify
/// origin reducer state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitFederationRequestBody {
    pub service_binding_ref: FederationServiceBindingRef,
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signer_key_evidence: Vec<FederatedDeviceSigningKeyEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl EventsSubmitFederationRequestBody {
    pub fn validate_signer_key_evidence(&self) -> Result<()> {
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
        Ok(())
    }
}

// `SnapshotBootstrap` migrated to `sync_frames::snapshot`. It reaches the
// `arkret_core::SnapshotBootstrap` path via the `artifacts::sync`
// re-export, so no shim is needed here.

#[cfg(test)]
mod tests {
    use arkret_wire::{DeviceId, DidKey};
    use serde_json::json;

    use super::*;

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
                destination_service_type: "principal_server".to_owned(),
                reducer_profile_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            },
            events: vec![event],
            signer_key_evidence: vec![unrelated],
            idempotency_key: None,
        };
        assert!(request.validate_signer_key_evidence().is_err());
    }
}
