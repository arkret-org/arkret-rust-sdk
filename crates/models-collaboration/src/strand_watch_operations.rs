//! Exact, non-enumerating watch current read from the governing Station.

use arkret_wire::{ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, RealmId, StrandId};
use serde::{Deserialize, Serialize};

use crate::events_payloads::strand::StrandWatchExpectedValue;

/// Canonical body budget shared by the self and signed peer operations.
pub const STRAND_WATCH_CURRENT_MAX_BYTES: usize = 16 * 1024;
pub const PEER_STRAND_WATCH_CURRENT_PATH: &str = "/_arkret/peer/strands/watch/current";

/// Shared self/peer request; neither operation enumerates other watchers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchCurrentRequestBody {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub watcher_actor_id: ActorId,
}

impl StrandWatchCurrentRequestBody {
    pub fn validate(&self) -> Result<(), arkret_wire::WireError> {
        if arkret_canonical::canonical_json_bytes(self)
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
            .len()
            > STRAND_WATCH_CURRENT_MAX_BYTES
        {
            return Err(arkret_wire::WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::PayloadTooLarge,
                message: "watch-current request exceeds its canonical budget".to_owned(),
            });
        }
        Ok(())
    }
}

/// Closed selector returned with both watch-current outcome branches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchCurrentSelector {
    pub kind: StrandWatchSelectorKind,
    pub strand_id: StrandId,
    pub watcher_actor_id: ActorId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrandWatchSelectorKind {
    StrandWatch,
}

/// A written watch cell has a revision even when it was cleared to `null`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentStrandWatch {
    pub selector: StrandWatchCurrentSelector,
    /// Exact stream of the covering RealmCommit named by `revision.commit_id`.
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    /// Required on the wire, including when explicitly cleared to JSON `null`.
    pub value: StrandWatchValue,
}

/// Unlike `Option<T>`, this field does not silently accept an omitted `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StrandWatchValue {
    Set(StrandWatchExpectedValue),
    Cleared(()),
}

impl StrandWatchValue {
    pub const fn as_option(&self) -> Option<&StrandWatchExpectedValue> {
        match self {
            Self::Set(value) => Some(value),
            Self::Cleared(()) => None,
        }
    }
}

/// Absence is an explicit Station-confirmed fact, never inferred from a
/// missing snapshot entry or local raw Event order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrandWatchCurrentResponseBody {
    NeverWritten {
        realm_id: RealmId,
        #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
        governance_generation: u64,
        stream_head: CommitStreamHead,
        selector: StrandWatchCurrentSelector,
    },
    Current {
        realm_id: RealmId,
        #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
        governance_generation: u64,
        stream_head: CommitStreamHead,
        current_state: CurrentStrandWatch,
    },
}

impl StrandWatchCurrentResponseBody {
    pub const fn governance_generation(&self) -> u64 {
        match self {
            Self::NeverWritten {
                governance_generation,
                ..
            }
            | Self::Current {
                governance_generation,
                ..
            } => *governance_generation,
        }
    }

    /// The Account Station supplies its fresh nonce-bound verified authority.
    pub fn validate_for_generation(
        &self,
        request: &StrandWatchCurrentRequestBody,
        generation: u64,
    ) -> Result<(), &'static str> {
        self.validate_for_request(request)?;
        if self.governance_generation() != generation {
            return Err("watch-current response differs from the verified governing generation");
        }
        Ok(())
    }

    /// Reject a validly shaped response for a different requested cell or
    /// Realm. Authorization and current authority verification stay server-side.
    pub fn validate_for_request(
        &self,
        request: &StrandWatchCurrentRequestBody,
    ) -> Result<(), &'static str> {
        if arkret_canonical::canonical_json_bytes(self)
            .map_err(|_| "watch-current response is not canonical JSON")?
            .len()
            > STRAND_WATCH_CURRENT_MAX_BYTES
        {
            return Err("watch-current response exceeds its canonical budget");
        }
        let (realm_id, head, selector, source) = match self {
            Self::NeverWritten {
                realm_id,
                stream_head,
                selector,
                ..
            } => (realm_id, stream_head, selector, None),
            Self::Current {
                realm_id,
                stream_head,
                current_state,
                ..
            } => (
                realm_id,
                stream_head,
                &current_state.selector,
                Some((&current_state.source_stream_ref, &current_state.revision)),
            ),
        };
        if !matches!(
            &head.stream_ref,
            CommitStreamRef::Realm { .. } | CommitStreamRef::Circle { .. }
        ) {
            return Err("watch-current head is not a Realm or Circle namespace");
        }
        if realm_id != &request.realm_id || head.stream_ref.realm_id() != &request.realm_id {
            return Err("watch-current response Realm differs from request");
        }
        if selector.strand_id != request.strand_id
            || selector.watcher_actor_id != request.watcher_actor_id
        {
            return Err("watch-current response selector differs from request");
        }
        if let Some((source_stream_ref, revision)) = source {
            // The revision position is only comparable on its own covering
            // stream; a row from another stream cannot be bounded by this head.
            if source_stream_ref != &head.stream_ref {
                return Err("watch-current source stream differs from the confirmed stream head");
            }
            if revision.stream_position > head.stream_position
                || (revision.stream_position == head.stream_position
                    && revision.commit_id != head.commit_id)
            {
                return Err("watch-current revision is not bounded by the confirmed stream head");
            }
        }
        Ok(())
    }
}

/// Audited reads commit one audit Event and freeze a private observation.
pub const STRAND_WATCH_AUDIT_MAX_BYTES: usize = 1024 * 1024;
pub const SELF_STRAND_WATCH_AUDIT_PATH: &str = "/_arkret/self/strands/watch/audit-read";
pub const PEER_STRAND_WATCH_AUDIT_PATH: &str = "/_arkret/peer/strands/watch/audit-read";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchAuditReadRequestBody {
    pub audit_submission: arkret_wire::EventAdmissionSubmission,
}

impl WatchAuditReadRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        use crate::events_payloads::audit::{AuditAccessedKind, AuditAccessedPayload};
        let event = &self.audit_submission.event;
        self.audit_submission.validate()?;
        event.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )?;
        event.verify_producer_proof_self_consistency(arkret_canonical::DigestSuite::Sha256)?;
        let payload: AuditAccessedPayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        if event.kind != arkret_wire::EventKind::AuditAccessed
            || payload.access_kind != AuditAccessedKind::WatchAuditRead
            || payload.writer_actor_id != event.actor_id
            || event.actor_id.as_account_id().is_none()
            || event.actual_signer().as_account_id().is_none()
            || payload.target_actor_id.is_none()
            || payload.paired_event_id.is_some()
            || payload.late_recovery_original_event_id.is_some()
        {
            return Err(arkret_wire::WireError::Protocol(
                "audited read requires one exact Account-produced Watch audit intent".to_owned(),
            ));
        }
        if !matches!(
            event.scope_ref,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        ) {
            return Err(arkret_wire::WireError::Protocol(
                "audited read requires a Realm or Circle stream".to_owned(),
            ));
        }
        self.selector()?;
        validate_audit_budget(self)
    }

    pub fn selector(&self) -> arkret_wire::Result<StrandWatchCurrentRequestBody> {
        let payload: crate::events_payloads::audit::AuditAccessedPayload =
            serde_json::from_value(serde_json::to_value(&self.audit_submission.event.payload)?)?;
        Ok(StrandWatchCurrentRequestBody {
            realm_id: self.audit_submission.event.realm_id.clone(),
            strand_id: payload.target_ref.to_string().parse()?,
            watcher_actor_id: payload.target_actor_id.ok_or_else(|| {
                arkret_wire::WireError::Protocol("audited read lacks its exact target".to_owned())
            })?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerWatchAuditReadRequestBody {
    pub audit_submission: arkret_wire::EventAdmissionSubmission,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub producer_device_evidence:
        Option<arkret_models_identity::ForwardAccountDeviceSignerEvidence>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub producer_agent_evidence: Option<arkret_models_identity::AgentProducerEvidence>,
}

impl PeerWatchAuditReadRequestBody {
    pub fn validate_carrier_shape(&self) -> arkret_wire::Result<()> {
        if self.producer_device_evidence.is_some() == self.producer_agent_evidence.is_some() {
            return Err(arkret_wire::WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::SchemaViolation,
                message: "peer audit requires exactly one producer evidence member".to_owned(),
            });
        }
        validate_audit_budget(self)
    }
    pub fn logical_request(&self) -> WatchAuditReadRequestBody {
        WatchAuditReadRequestBody {
            audit_submission: self.audit_submission.clone(),
        }
    }
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.logical_request().validate()?;
        if self.producer_device_evidence.is_some() == self.producer_agent_evidence.is_some() {
            return Err(arkret_wire::WireError::Protocol(
                "peer audited read requires exactly one actual-producer closure".to_owned(),
            ));
        }
        crate::authority_commit::validate_producer_device_evidence_presence(
            &self.audit_submission.event,
            self.producer_device_evidence.as_ref(),
        )?;
        crate::authority_commit::validate_producer_agent_evidence_presence(
            &self.audit_submission.event,
            self.producer_agent_evidence.as_ref(),
        )?;
        if let Some(device) = &self.producer_device_evidence {
            let source = &device
                .device_projection_attestation
                .attestation
                .event_authorization;
            if source.event_id != self.audit_submission.event.event_id
                || source.forward_body_digest
                    != crate::authority_commit::authority_forward_body_digest(self)?
            {
                return Err(arkret_wire::WireError::Protocol(
                    "audited read producer authorization must bind its exact audit and body"
                        .to_owned(),
                ));
            }
        }
        validate_audit_budget(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchAuditReadResponseBody {
    pub audit_commit: arkret_wire::RealmCommit,
    pub current: StrandWatchCurrentResponseBody,
}

impl WatchAuditReadResponseBody {
    pub fn validate_for_request(
        &self,
        request: &WatchAuditReadRequestBody,
        generation: u64,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        validate_audit_budget(self)?;
        self.audit_commit.validate_shape()?;
        let event = &request.audit_submission.event;
        arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: self.audit_commit.clone(),
        }
        .validate_shape()?;
        self.current
            .validate_for_generation(&request.selector()?, generation)
            .map_err(|detail| arkret_wire::WireError::Protocol(detail.to_owned()))?;
        let head = match &self.current {
            StrandWatchCurrentResponseBody::NeverWritten { stream_head, .. }
            | StrandWatchCurrentResponseBody::Current { stream_head, .. } => stream_head,
        };
        if self.audit_commit.governance_generation != generation
            || head.commit_id != self.audit_commit.commit_id
            || head.stream_position != self.audit_commit.stream_position
            || head.stream_ref != self.audit_commit.stream_ref
        {
            return Err(arkret_wire::WireError::Protocol(
                "audited read observation must bind the exact audit Commit cut".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_audit_budget(value: &impl Serialize) -> arkret_wire::Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > STRAND_WATCH_AUDIT_MAX_BYTES {
        return Err(arkret_wire::WireError::ProtocolCode {
            code: arkret_wire::ErrorCode::PayloadTooLarge,
            message: "Watch audited read exceeds its canonical body budget".to_owned(),
        });
    }
    Ok(())
}
