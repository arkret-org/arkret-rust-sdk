//! Space Host typed model (spec Phase 4 §3.3 / §13).
//!
//! Hub-writer Spaces have a single canonical Space Host (a service DID)
//! that endorses every durable state event with a `host_endorsement`
//! proof. This module provides typed payloads for the two host-related
//! event kinds:
//!
//! - `cx.space.host` — singleton state event declaring the current
//!   `host_did`, optional `standby_hosts`, `activation_timeout_ms`, and
//!   the host's HTTP endpoint for clients to submit events through.
//! - `cx.space.host.transfer` — per_subject (by `transfer_id`) ceremony
//!   moving the host role between service DIDs. Two modes:
//!   `smooth` requires dual-signature from current and new host;
//!   `emergency` requires a governance quorum proof from
//!   `Space.owning_organizations` after `activation_timeout_ms` of host
//!   inactivity.

use contrix_core::{Did, EventId, Hash, Proof};
use serde::{Deserialize, Serialize};

/// Stable kind for the singleton host declaration state event.
pub const SPACE_HOST_KIND: &str = "cx.space.host";
/// Stable kind for the host transfer ceremony state event.
pub const SPACE_HOST_TRANSFER_KIND: &str = "cx.space.host.transfer";

/// Default activation timeout when a `cx.space.host` event omits the
/// field — 24 hours, in line with the spec schema default.
pub const DEFAULT_ACTIVATION_TIMEOUT_MS: u64 = 86_400_000;

/// Endorsement signing method advertised by the host. v1 only registers
/// detached JWS over canonical event bytes; future profiles may extend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EndorsementMethod {
    #[default]
    ServiceProofJws,
}

/// Payload of `cx.space.host`.
///
/// State slot is keyed by `(space_id, "cx.space.host")` (singleton). The
/// reducer maintains the current host_did from the latest accepted event
/// in this slot. host_did itself MUST NOT be replaced by a plain
/// `cx.space.host` update — use [`SpaceHostTransferPayload`] for that.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceHostPayload {
    /// Service DID of the canonical Space Host.
    pub host_did: Did,
    /// Pre-declared failover candidates eligible to assume host role
    /// via emergency transfer after `activation_timeout_ms` of host
    /// inactivity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standby_hosts: Vec<Did>,
    /// Milliseconds without host endorsement activity required before
    /// standby_hosts may initiate emergency transfer. Default 24h.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_timeout_ms: Option<u64>,
    /// Signature method this host uses to endorse durable state events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endorsement_method: Option<EndorsementMethod>,
    /// HTTP endpoint clients submit events to for host endorsement.
    /// Resolved against host_did's DID Document service entries when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_endpoint: Option<String>,
}

impl SpaceHostPayload {
    /// Convenience constructor — sets only the required `host_did`.
    pub fn new(host_did: Did) -> Self {
        Self {
            host_did,
            standby_hosts: Vec::new(),
            activation_timeout_ms: None,
            endorsement_method: None,
            host_endpoint: None,
        }
    }

    /// Effective activation timeout, falling back to
    /// [`DEFAULT_ACTIVATION_TIMEOUT_MS`].
    pub fn effective_activation_timeout_ms(&self) -> u64 {
        self.activation_timeout_ms.unwrap_or(DEFAULT_ACTIVATION_TIMEOUT_MS)
    }
}

/// Mode of a host transfer ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    /// Current host + new host both sign — graceful handover.
    Smooth,
    /// Host has been unreachable past `activation_timeout_ms` (or its
    /// service DID has been revoked / its control proof lost). A majority
    /// of `Space.owning_organizations` signs the transfer instead.
    Emergency,
}

/// Both-host signed evidence carried on `mode = smooth` transfers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SmoothDualSignature {
    pub previous_host_proof: Proof,
    pub new_host_proof: Proof,
}

/// Governance-quorum evidence carried on `mode = emergency` transfers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceQuorumProof {
    pub policy_version: String,
    pub signers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<Hash>,
}

/// Payload of `cx.space.host.transfer`.
///
/// State slot is per_subject keyed by `payload.transfer_id`; retries
/// within the same ceremony coalesce on the same slot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceHostTransferPayload {
    pub transfer_id: String,
    pub mode: TransferMode,
    pub previous_host: Did,
    pub new_host: Did,
    /// Causal frontier (event refs) at which the new host's
    /// endorsements become authoritative. State events with
    /// `prev_refs` preceding `activation_frontier` accept old host
    /// endorsement; events at or after require new host endorsement.
    pub activation_frontier: Vec<EventId>,
    /// Required when `mode == Emergency` — references the incident /
    /// governance proceeding that triggered the transfer. MUST NOT be
    /// the empty string `"emergency"`; must be an auditable id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_ref: Option<String>,
    /// Required when `mode == Emergency` — proof that ≥ majority of
    /// `Space.owning_organizations` endorsed the transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_quorum_proof: Option<GovernanceQuorumProof>,
    /// Required when `mode == Smooth` — both current and new host
    /// proofs over the canonical transfer payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smooth_dual_signature: Option<SmoothDualSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SpaceHostTransferPayload {
    /// Validate the mode-conditional invariants required by
    /// `event-payload.schema.json` (Phase 4 spec).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.activation_frontier.is_empty() {
            return Err("host transfer requires non-empty activation_frontier");
        }
        match self.mode {
            TransferMode::Smooth => {
                if self.smooth_dual_signature.is_none() {
                    return Err("smooth host transfer requires smooth_dual_signature");
                }
                Ok(())
            }
            TransferMode::Emergency => {
                if self.incident_ref.is_none() {
                    return Err("emergency host transfer requires incident_ref");
                }
                if self.governance_quorum_proof.is_none() {
                    return Err("emergency host transfer requires governance_quorum_proof");
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_core::EventId;

    fn did(s: &str) -> Did {
        Did::new(s).unwrap()
    }

    fn event_ref() -> EventId {
        EventId::new("cx:event:01js0xfy0000000000000000000").unwrap()
    }

    #[test]
    fn space_host_payload_round_trip() {
        let payload = SpaceHostPayload::new(did("did:web:host1.example"));
        let json = serde_json::to_string(&payload).unwrap();
        let round: SpaceHostPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(round, payload);
    }

    #[test]
    fn effective_activation_timeout_falls_back_to_default() {
        let payload = SpaceHostPayload::new(did("did:web:host1.example"));
        assert_eq!(payload.effective_activation_timeout_ms(), DEFAULT_ACTIVATION_TIMEOUT_MS);
        let mut explicit = payload.clone();
        explicit.activation_timeout_ms = Some(60_000);
        assert_eq!(explicit.effective_activation_timeout_ms(), 60_000);
    }

    #[test]
    fn emergency_transfer_requires_incident_and_quorum() {
        let bad = SpaceHostTransferPayload {
            transfer_id: "t1".to_owned(),
            mode: TransferMode::Emergency,
            previous_host: did("did:web:host1.example"),
            new_host: did("did:web:standby.example"),
            activation_frontier: vec![event_ref()],
            incident_ref: None,
            governance_quorum_proof: None,
            smooth_dual_signature: None,
            reason: None,
        };
        assert!(bad.validate().is_err());

        let good = SpaceHostTransferPayload {
            incident_ref: Some("incident:host_unreachable_72h".to_owned()),
            governance_quorum_proof: Some(GovernanceQuorumProof {
                policy_version: "cx.governance.v1".to_owned(),
                signers: vec![did("did:web:org1.example"), did("did:web:org2.example")],
                decision_id: None,
                audit_digest: None,
            }),
            ..bad
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn smooth_transfer_requires_dual_signature() {
        let bad = SpaceHostTransferPayload {
            transfer_id: "t1".to_owned(),
            mode: TransferMode::Smooth,
            previous_host: did("did:web:host1.example"),
            new_host: did("did:web:host2.example"),
            activation_frontier: vec![event_ref()],
            incident_ref: None,
            governance_quorum_proof: None,
            smooth_dual_signature: None,
            reason: None,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn empty_activation_frontier_is_rejected() {
        let bad = SpaceHostTransferPayload {
            transfer_id: "t1".to_owned(),
            mode: TransferMode::Smooth,
            previous_host: did("did:web:host1.example"),
            new_host: did("did:web:host2.example"),
            activation_frontier: vec![],
            incident_ref: None,
            governance_quorum_proof: None,
            smooth_dual_signature: None,
            reason: None,
        };
        assert!(bad.validate().is_err());
    }
}
