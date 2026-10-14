//! Closed business/audit unit and its first-admission producer closures.

use arkret_wire::ScopeRef;

use super::*;
use crate::events_payloads::audit::{AuditAccessedKind, AuditAccessedPayload};
use crate::events_payloads::circle::CircleMemberStatePayload;
use crate::events_payloads::strand::{StrandWatchLevel, StrandWatchSetPayload};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditPairedEventUnitKind {
    #[serde(rename = "audit_paired_event")]
    AuditPairedEvent,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPairedEventUnitSubmission {
    pub unit_kind: AuditPairedEventUnitKind,
    pub events: [EventAdmissionSubmission; 2],
}

fn pair_refusal(message: &str) -> WireError {
    WireError::ProtocolCode {
        code: ErrorCode::FailedPrecondition,
        message: message.to_owned(),
    }
}

impl AuditPairedEventUnitSubmission {
    /// Validate immutable bindings. Current authority, signatures, capabilities,
    /// approvals and CAS still require the accepting transaction.
    pub fn validate(&self) -> Result<()> {
        for slot in &self.events {
            slot.validate()?;
            slot.event
                .verify_event_id_matches_content_with_digest_suite(
                    arkret_canonical::DigestSuite::Sha256,
                )?;
            slot.event
                .verify_producer_proof_self_consistency(arkret_canonical::DigestSuite::Sha256)?;
        }
        let business = &self.events[0].event;
        let audit = &self.events[1].event;
        let (access_kind, target, target_ref) = match business.kind {
            EventKind::StrandWatchSet => {
                let payload: StrandWatchSetPayload =
                    serde_json::from_value(serde_json::to_value(&business.payload)?)?;
                if !matches!(
                    payload.level,
                    Some(
                        StrandWatchLevel::MentionsOnly
                            | StrandWatchLevel::Participating
                            | StrandWatchLevel::All
                    )
                ) || payload.level_public == Some(true)
                {
                    return Err(pair_refusal(
                        "Watch others cannot clear, mute or publicly expose the target",
                    ));
                }
                (
                    AuditAccessedKind::WatchSetOthers,
                    payload.watcher_actor_id,
                    payload.strand_id.to_string(),
                )
            }
            EventKind::CircleMemberState => {
                let payload: CircleMemberStatePayload =
                    serde_json::from_value(serde_json::to_value(&business.payload)?)?;
                payload.validate()?;
                if !matches!(&business.scope_ref, ScopeRef::Circle { circle_id, .. } if circle_id == &payload.circle_id)
                {
                    return Err(pair_refusal(
                        "Circle membership pair must use the target Circle stream",
                    ));
                }
                (
                    AuditAccessedKind::CircleMemberSetOthers,
                    payload.member_id,
                    payload.circle_id.to_string(),
                )
            }
            _ => return Err(pair_refusal("unregistered business kind for an audit pair")),
        };
        if audit.kind != EventKind::AuditAccessed {
            return Err(pair_refusal(
                "the second audit pair slot must be audit.accessed",
            ));
        }
        let payload: AuditAccessedPayload =
            serde_json::from_value(serde_json::to_value(&audit.payload)?)?;
        let business_method = business
            .producer_proof
            .as_ref()
            .map(|p| &p.verification_method);
        let audit_method = audit
            .producer_proof
            .as_ref()
            .map(|p| &p.verification_method);
        let refs: Vec<_> = audit
            .semantic_refs
            .iter()
            .filter(|r| r.role == "audit_pair")
            .collect();
        if !matches!(
            business.scope_ref,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        ) {
            return Err(pair_refusal("audit pair requires a Realm or Circle stream"));
        }
        if target == business.actor_id
            || business.event_id == audit.event_id
            || business.realm_id != audit.realm_id
            || business.scope_ref != audit.scope_ref
            || business.actor_id != audit.actor_id
            || business.actual_signer() != audit.actual_signer()
            || business_method.is_none()
            || business_method != audit_method
            || payload.access_kind != access_kind
            || payload.writer_actor_id != business.actor_id
            || payload.target_actor_id.as_ref() != Some(&target)
            || payload.target_ref.to_string() != target_ref
            || payload.paired_event_id.as_ref() != Some(&business.event_id)
            || refs.len() != 1
            || !refs[0].critical
            || refs[0].id != business.event_id.as_str()
            || business
                .semantic_refs
                .iter()
                .any(|r| r.id == audit.event_id.as_str() || r.role == "audit_pair")
        {
            return Err(pair_refusal(
                "audit pair must bind its exact business, writer, target, scope and producer",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "Closed schema variants retain existing producer types."
)]
pub enum AtomicSlotProducerEvidence {
    Device {
        producer_device_evidence: ForwardAccountDeviceSignerEvidence,
    },
    Agent {
        producer_agent_evidence: AgentProducerEvidence,
    },
    Service {},
}

impl AtomicSlotProducerEvidence {
    pub fn device(&self) -> Option<&ForwardAccountDeviceSignerEvidence> {
        match self {
            Self::Device {
                producer_device_evidence,
            } => Some(producer_device_evidence),
            _ => None,
        }
    }
    pub fn agent(&self) -> Option<&AgentProducerEvidence> {
        match self {
            Self::Agent {
                producer_agent_evidence,
            } => Some(producer_agent_evidence),
            _ => None,
        }
    }
    pub fn validate_for_event(&self, event: &Event) -> Result<()> {
        let human = validate_producer_device_evidence_presence(event, self.device())?;
        if let (Some(human), Some(device)) = (human, self.device()) {
            device.validate_binding(&human.account_id, &human.device_id)?;
            if event
                .producer_proof
                .as_ref()
                .map(|proof| &proof.verification_method)
                != Some(
                    &device
                        .device_projection_attestation
                        .attestation
                        .event_authorization
                        .verification_method,
                )
            {
                return Err(pair_refusal(
                    "atomic Device authorization names another producer key",
                ));
            }
        }
        validate_producer_agent_evidence_presence(event, self.agent())?;
        if matches!(self, Self::Service {})
            && !matches!(event.actual_signer(), ActorId::Service { .. })
        {
            return Err(pair_refusal(
                "empty atomic producer evidence is only for a Service producer",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthorityForwardAtomicRequest {
    pub branch: AuthorityForwardBranch,
    pub atomic_submission: AuditPairedEventUnitSubmission,
    pub atomic_producer_evidence: [AtomicSlotProducerEvidence; 2],
}

impl PeerAuthorityForwardAtomicRequest {
    pub fn validate(&self) -> Result<()> {
        self.atomic_submission.validate()?;
        let digest = authority_forward_body_digest(self)?;
        for (slot, evidence) in self
            .atomic_submission
            .events
            .iter()
            .zip(&self.atomic_producer_evidence)
        {
            evidence.validate_for_event(&slot.event)?;
            if let Some(device) = evidence.device() {
                let source = &device
                    .device_projection_attestation
                    .attestation
                    .event_authorization;
                if source.event_id != slot.event.event_id || source.forward_body_digest != digest {
                    return Err(pair_refusal(
                        "atomic Device authorization must bind its own Event and the whole unit body",
                    ));
                }
            }
        }
        match &self.atomic_producer_evidence {
            [
                AtomicSlotProducerEvidence::Device {
                    producer_device_evidence: first,
                },
                AtomicSlotProducerEvidence::Device {
                    producer_device_evidence: second,
                },
            ] => {
                let first = &first.device_projection_attestation.attestation;
                let mut second = second.device_projection_attestation.attestation.clone();
                second.event_authorization.event_id = first.event_authorization.event_id.clone();
                if first != &second {
                    return Err(pair_refusal(
                        "atomic Device slots must share one exact origin cut",
                    ));
                }
            }
            [
                AtomicSlotProducerEvidence::Agent {
                    producer_agent_evidence: first,
                },
                AtomicSlotProducerEvidence::Agent {
                    producer_agent_evidence: second,
                },
            ] => {
                if first != second {
                    return Err(pair_refusal(
                        "atomic Agent slots must share one exact origin cut",
                    ));
                }
            }
            [
                AtomicSlotProducerEvidence::Service {},
                AtomicSlotProducerEvidence::Service {},
            ] => {}
            _ => {
                return Err(pair_refusal(
                    "atomic producer slots have different source kinds",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPairedEventAcceptanceOutcome {
    pub unit_kind: AuditPairedEventUnitKind,
    pub status: AggregateAcceptanceStatus,
    pub commits: [RealmCommit; 2],
}

impl AuditPairedEventAcceptanceOutcome {
    pub fn validate(&self) -> Result<()> {
        for commit in &self.commits {
            commit.validate_shape()?;
        }
        let [business, audit] = &self.commits;
        if business.realm_id != audit.realm_id
            || business.stream_ref != audit.stream_ref
            || business.governance_generation != audit.governance_generation
            || business.authority_ref != audit.authority_ref
            || business.stream_position.checked_add(1) != Some(audit.stream_position)
            || audit.previous_commit_ref.as_ref() != Some(&business.commit_id)
        {
            return Err(pair_refusal(
                "audit pair Commits must form one consecutive governing stream",
            ));
        }
        Ok(())
    }
    pub fn validate_for_request(&self, request: &AuditPairedEventUnitSubmission) -> Result<()> {
        self.validate()?;
        for (slot, commit) in request.events.iter().zip(&self.commits) {
            arkret_wire::CommittedEventFullView {
                event: slot.event.clone(),
                commit: commit.clone(),
            }
            .validate_shape()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPairedEventFederationSubmission {
    pub unit_kind: AuditPairedEventUnitKind,
    pub committed_events: [CommittedEventSubmission; 2],
}

impl AuditPairedEventFederationSubmission {
    pub fn validate(&self) -> Result<()> {
        for slot in &self.committed_events {
            slot.validate()?;
        }
        let request = AuditPairedEventUnitSubmission {
            unit_kind: self.unit_kind,
            events: self
                .committed_events
                .each_ref()
                .map(|slot| slot.event_submission.clone()),
        };
        request.validate()?;
        AuditPairedEventAcceptanceOutcome {
            unit_kind: self.unit_kind,
            status: AggregateAcceptanceStatus::Committed,
            commits: self
                .committed_events
                .each_ref()
                .map(|slot| slot.source_commit.clone()),
        }
        .validate_for_request(&request)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[expect(
    clippy::large_enum_variant,
    reason = "Closed outcome branches retain their existing Commit types."
)]
pub enum PeerAuthorityForwardOutcomeValue {
    Ordinary(arkret_wire::AuthoritySubmitOutcome),
    AuditPairedEvent(AuditPairedEventAcceptanceOutcome),
}

impl PeerAuthorityForwardOutcomeValue {
    pub fn validate_shape(&self) -> Result<()> {
        match self {
            Self::Ordinary(value) => value.validate_shape(),
            Self::AuditPairedEvent(value) => value.validate(),
        }
    }
}

/// Classify slots that cannot be copied through an ordinary replication item.
pub fn is_audit_paired_event_slot(event: &Event) -> Result<bool> {
    Ok(match event.kind {
        EventKind::StrandWatchSet => {
            let payload: StrandWatchSetPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            payload.watcher_actor_id != event.actor_id
        }
        EventKind::CircleMemberState => {
            let payload: CircleMemberStatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            payload.member_id != event.actor_id
        }
        EventKind::AuditAccessed => {
            let payload: AuditAccessedPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            matches!(
                payload.access_kind,
                AuditAccessedKind::WatchSetOthers | AuditAccessedKind::CircleMemberSetOthers
            )
        }
        _ => false,
    })
}
