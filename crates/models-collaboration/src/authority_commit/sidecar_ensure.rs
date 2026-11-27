//! First-admission federation for one controller's new personal Sidecar.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarEnsureUnitKind {
    SidecarEnsure,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarEnsureUnitSubmission {
    pub unit_kind: SidecarEnsureUnitKind,
    pub events: [EventAdmissionSubmission; 2],
}

fn invalid(message: &str) -> WireError {
    WireError::ProtocolCode {
        code: ErrorCode::FailedPrecondition,
        message: message.into(),
    }
}

impl SidecarEnsureUnitSubmission {
    pub fn validate(&self) -> Result<()> {
        for slot in &self.events {
            slot.validate()?;
            if slot.approval_signatures.is_some()
                || slot.event.executed_by.is_some()
                || slot.event.applet_id.is_some()
            {
                return Err(invalid(
                    "Sidecar ensure needs two original controller Device Events",
                ));
            }
            slot.event
                .verify_event_id_matches_content_with_digest_suite(
                    arkret_canonical::DigestSuite::Sha256,
                )?;
            slot.event
                .verify_producer_proof_self_consistency(arkret_canonical::DigestSuite::Sha256)?;
        }
        let create = &self.events[0].event;
        let attach = &self.events[1].event;
        let sidecar = arkret_wire::SidecarId::from_event_id(&create.event_id);
        let device = create
            .account_device_producer()?
            .ok_or_else(|| invalid("Sidecar ensure requires a Device"))?;
        if create.kind != EventKind::SidecarCreate
            || !create.payload.is_empty()
            || attach.kind != EventKind::SidecarContextAttach
            || create.realm_id != attach.realm_id
            || create.actor_id.as_account_id() != Some(&device.account_id)
            || create.actor_id != attach.actor_id
            || attach.account_device_producer()?.as_ref() != Some(&device)
            || create.scope_ref
                != (arkret_wire::ScopeRef::Realm {
                    realm_id: create.realm_id.clone(),
                })
            || attach.scope_ref
                != (arkret_wire::ScopeRef::Sidecar {
                    realm_id: create.realm_id.clone(),
                    sidecar_id: sidecar.clone(),
                })
        {
            return Err(invalid(
                "Sidecar creation and first context bindings differ",
            ));
        }
        let mut after = attach
            .semantic_refs
            .iter()
            .filter(|reference| reference.role == "after");
        if !after
            .next()
            .is_some_and(|reference| reference.critical && reference.id == create.event_id.as_str())
            || after.next().is_some()
        {
            return Err(invalid(
                "Sidecar first context must cite its exact creation Event",
            ));
        }
        let payload: crate::events_payloads::sidecar::SidecarContextAttachPayload =
            serde_json::from_value(serde_json::to_value(&attach.payload)?)?;
        if payload.sidecar_id != sidecar
            || payload.version != 1
            || payload.predecessor_event_ref.is_some()
        {
            return Err(invalid("Sidecar first context does not bind the new scope"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSidecarEnsureForwardRequestBody {
    pub branch: AuthorityForwardBranch,
    pub atomic_submission: SidecarEnsureUnitSubmission,
    pub atomic_producer_evidence: [AtomicSlotProducerEvidence; 2],
}

impl PeerSidecarEnsureForwardRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.atomic_submission.validate()?;
        let digest = authority_forward_body_digest(self)?;
        for (slot, proof) in self
            .atomic_submission
            .events
            .iter()
            .zip(&self.atomic_producer_evidence)
        {
            proof.validate_for_event(&slot.event)?;
            let proof = proof
                .device()
                .ok_or_else(|| invalid("Sidecar ensure requires a Device attestation per slot"))?;
            let source = &proof
                .device_projection_attestation
                .attestation
                .event_authorization;
            if source.forward_body_digest != digest || source.event_id != slot.event.event_id {
                return Err(invalid(
                    "Sidecar Device evidence must cover the individual Event and both submissions",
                ));
            }
        }
        let first = &self.atomic_producer_evidence[0]
            .device()
            .unwrap()
            .device_projection_attestation
            .attestation;
        let mut second = self.atomic_producer_evidence[1]
            .device()
            .unwrap()
            .device_projection_attestation
            .attestation
            .clone();
        second.event_authorization.event_id = first.event_authorization.event_id.clone();
        if first != &second {
            return Err(invalid("Sidecar Device slots require the same origin cut"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarEnsureAcceptanceOutcome {
    pub unit_kind: SidecarEnsureUnitKind,
    pub status: AggregateAcceptanceStatus,
    pub commits: [RealmCommit; 2],
}
impl SidecarEnsureAcceptanceOutcome {
    pub fn validate(&self) -> Result<()> {
        let [create, attach] = &self.commits;
        create.validate_shape()?;
        attach.validate_shape()?;
        if create.realm_id != attach.realm_id
            || create.governance_generation != attach.governance_generation
            || create.authority_ref != attach.authority_ref
            || attach.stream_position != 0
            || attach.previous_commit_ref.is_some()
            || create.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: create.realm_id.clone(),
                })
            || attach.stream_ref
                != (CommitStreamRef::Sidecar {
                    realm_id: create.realm_id.clone(),
                    sidecar_id: arkret_wire::SidecarId::from_event_id(&create.event_ref),
                })
        {
            return Err(invalid(
                "Sidecar ensure requires both governing Commits on their own streams",
            ));
        }
        Ok(())
    }

    pub fn validate_for_request(&self, unit: &SidecarEnsureUnitSubmission) -> Result<()> {
        self.validate()?;
        for (slot, commit) in unit.events.iter().zip(&self.commits) {
            arkret_wire::CommittedEventFullView {
                event: slot.event.clone(),
                commit: commit.clone(),
            }
            .validate_shape()?;
        }
        Ok(())
    }
}
