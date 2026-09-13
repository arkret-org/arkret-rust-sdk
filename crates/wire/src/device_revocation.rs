//! Durable device-revocation state and the service-to-service gate contract.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AcceptedDevicePossessionProof, AccountId, ControlProposalAck, ControlProposalDecision,
    DeviceId, EventId, Hash, Result, SealId, WireError,
};

pub const MAX_DEVICE_REVOCATION_GATE_RECORDS: usize = 128;
pub const MAX_DEVICE_REVOCATION_RECEIPT_LIFETIME: Duration = Duration::seconds(30);

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevocationStateSchema {
    #[serde(rename = "ak.schema.device_revocation_state.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationDecisionState {
    Pending,
    Deferred,
    Overdue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationFaultReason {
    ControlProposalDecisionOverdue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationDeniedAction {
    SessionGrantIssueOrRefresh,
    KeypackageClaim,
    ToDeviceWrite,
    EventWrite,
}

pub const DEVICE_REVOCATION_DENIED_ACTIONS: [DeviceRevocationDeniedAction; 4] = [
    DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
    DeviceRevocationDeniedAction::KeypackageClaim,
    DeviceRevocationDeniedAction::ToDeviceWrite,
    DeviceRevocationDeniedAction::EventWrite,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevocationPendingStatus {
    #[serde(rename = "revocation_pending")]
    RevocationPending,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevokedStatus {
    #[serde(rename = "revoked")]
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevocationRejectedStatus {
    #[serde(rename = "revocation_rejected")]
    RevocationRejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationPendingState {
    pub schema: DeviceRevocationStateSchema,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    pub proposal_event_id: EventId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: ControlProposalAck,
    pub status: DeviceRevocationPendingStatus,
    pub decision_state: DeviceRevocationDecisionState,
    pub denied_actions: [DeviceRevocationDeniedAction; 4],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<Vec<ControlProposalDecision>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_reason: Option<DeviceRevocationFaultReason>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokedState {
    pub schema: DeviceRevocationStateSchema,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    pub proposal_event_id: EventId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: ControlProposalAck,
    pub status: DeviceRevokedStatus,
    pub covering_seal_id: SealId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
}

/// A rejected revocation clears only the pending gate for this exact proposal.
/// Its rejection reason is authenticated by the deciding Seal command result.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationRejectedState {
    pub schema: DeviceRevocationStateSchema,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    pub proposal_event_id: EventId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: ControlProposalAck,
    pub status: DeviceRevocationRejectedStatus,
    pub deciding_seal_id: SealId,
}

impl DeviceRevocationRejectedState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.account_id,
            self.target_device_generation_ref,
            &self.proposal_event_id,
            self.acceptance_seq,
            &self.control_proposal_ack,
        )
    }

    /// The caller authenticates the Seal and the proposal's original device
    /// binding. This check binds its unique rejected unit result to this record.
    pub fn validate_deciding_seal(&self, seal: &crate::Seal) -> Result<()> {
        self.validate()?;
        seal.validate_structural()?;
        let digest = self.proposal_event_id.event_digest();
        let mut matching = seal
            .command_results
            .iter()
            .filter(|result| result.unit_event_digests.contains(&digest));
        let result = matching.next();
        if self.deciding_seal_id != seal.id
            || self.control_proposal_ack.realm_id != seal.realm_id
            || !result.is_some_and(|result| result.outcome == crate::CommandOutcome::Rejected)
            || matching.next().is_some()
        {
            return Err(WireError::Protocol("device revocation rejection must bind one rejected command result in its deciding Seal".to_owned()));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceRevocationGateRecord {
    Pending(DeviceRevocationPendingState),
    Revoked(DeviceRevokedState),
}

fn validate_record_common(
    account_id: &AccountId,
    target_device_generation_ref: u64,
    proposal_event_id: &EventId,
    acceptance_seq: u64,
    ack: &ControlProposalAck,
) -> Result<()> {
    account_id.validate()?;
    if target_device_generation_ref == 0 || acceptance_seq == 0 {
        return Err(WireError::Protocol(
            "device revocation generation and acceptance_seq must be positive".to_owned(),
        ));
    }
    ack.validate_protocol_bounds()?;
    if ack.proposal_digest != proposal_event_id.event_digest() {
        return Err(WireError::Protocol(
            "device revocation record proposal Event ID does not match its Ack".to_owned(),
        ));
    }
    Ok(())
}

impl DeviceRevocationPendingState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.account_id,
            self.target_device_generation_ref,
            &self.proposal_event_id,
            self.acceptance_seq,
            &self.control_proposal_ack,
        )?;
        if self.denied_actions != DEVICE_REVOCATION_DENIED_ACTIONS {
            return Err(WireError::Protocol(
                "device revocation denied_actions must equal the canonical four-action list"
                    .to_owned(),
            ));
        }
        let decisions = self.decisions.as_deref().unwrap_or_default();
        if decisions.len() > 2 {
            return Err(WireError::Protocol(
                "pending revocation decisions must contain at most two signed defers".to_owned(),
            ));
        }
        match self.decision_state {
            DeviceRevocationDecisionState::Pending
                if self.decisions.is_none() && self.fault_reason.is_none() => {}
            DeviceRevocationDecisionState::Deferred
                if !decisions.is_empty() && self.fault_reason.is_none() => {}
            DeviceRevocationDecisionState::Overdue
                if self.fault_reason
                    == Some(DeviceRevocationFaultReason::ControlProposalDecisionOverdue) => {}
            _ => {
                return Err(WireError::Protocol(
                    "device revocation pending decision_state fields are inconsistent".to_owned(),
                ));
            }
        }
        for (index, decision) in decisions.iter().enumerate() {
            decision
                .validate_chain_protocol_bounds(&self.control_proposal_ack, &decisions[..index])?;
        }
        Ok(())
    }
}

impl DeviceRevokedState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.account_id,
            self.target_device_generation_ref,
            &self.proposal_event_id,
            self.acceptance_seq,
            &self.control_proposal_ack,
        )?;
        if self.sealed_at < self.accepted_at {
            return Err(WireError::Protocol(
                "device revocation sealed_at precedes accepted_at".to_owned(),
            ));
        }
        Ok(())
    }
}

impl DeviceRevocationGateRecord {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Pending(state) => state.validate(),
            Self::Revoked(state) => state.validate(),
        }
    }

    pub fn acceptance_seq(&self) -> u64 {
        match self {
            Self::Pending(state) => state.acceptance_seq,
            Self::Revoked(state) => state.acceptance_seq,
        }
    }

    pub fn proposal_event_id(&self) -> &EventId {
        match self {
            Self::Pending(state) => &state.proposal_event_id,
            Self::Revoked(state) => &state.proposal_event_id,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked(_))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationGateActionClass {
    SessionGrantIssue,
    ReturningSessionGrantIssue,
    SessionGrantRefresh,
    KeypackageClaim,
    ToDeviceWrite,
    EventWrite,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationGateCheckRequestBody {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    /// Issuer-held verified binding, never a client-supplied value. Present
    /// together with `expected_device_generation_ref` or not at all, and only
    /// omittable only for initial registration/recovery `SessionGrantIssue`
    /// and returning account-handoff `ReturningSessionGrantIssue`; both learn
    /// the current binding from the origin-signed allow receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_generation_ref: Option<u64>,
    pub action_class: DeviceRevocationGateActionClass,
    pub intent_digest: Hash,
    /// Full accepted-device proof verified by the origin in the same
    /// linearization as the current authorization decision. Required only for
    /// returning account-handoff issue and human refresh; initial
    /// registration/recovery issue and unrelated actions must not carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_device_possession_proof: Option<AcceptedDevicePossessionProof>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
}

impl DeviceRevocationGateCheckRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        match (&self.action_class, &self.accepted_device_possession_proof) {
            (
                DeviceRevocationGateActionClass::ReturningSessionGrantIssue,
                Some(AcceptedDevicePossessionProof::Issue(proof)),
            ) => {
                AcceptedDevicePossessionProof::Issue(proof.clone()).validate()?;
            }
            (
                DeviceRevocationGateActionClass::SessionGrantRefresh,
                Some(AcceptedDevicePossessionProof::Refresh(proof)),
            ) => {
                AcceptedDevicePossessionProof::Refresh(proof.clone()).validate()?;
            }
            (
                DeviceRevocationGateActionClass::ReturningSessionGrantIssue
                | DeviceRevocationGateActionClass::SessionGrantRefresh,
                _,
            ) => {
                return Err(WireError::Protocol(
                    "session grant gate action requires its matching accepted-device proof"
                        .to_owned(),
                ));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(WireError::Protocol(
                    "accepted-device proof is forbidden for this gate action".to_owned(),
                ));
            }
        }
        if let Some(proof) = &self.accepted_device_possession_proof
            && (proof.account_id() != &self.account_id
                || proof.device_id() != &self.device_id
                || proof.session_intent_digest() != &self.intent_digest)
        {
            return Err(WireError::Protocol(
                "accepted-device proof does not bind the gate principal, device and intent"
                    .to_owned(),
            ));
        }
        match (
            &self.expected_device_authorize_event_id,
            self.expected_device_generation_ref,
        ) {
            (Some(_), Some(generation)) => {
                if generation == 0 {
                    return Err(WireError::Protocol(
                        "device revocation gate generation must be positive".to_owned(),
                    ));
                }
            }
            (None, None) => {
                if !matches!(
                    self.action_class,
                    DeviceRevocationGateActionClass::SessionGrantIssue
                        | DeviceRevocationGateActionClass::ReturningSessionGrantIssue
                ) {
                    return Err(WireError::Protocol(
                        "device revocation gate expected binding is required outside initial or returning session issue"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(WireError::Protocol(
                    "device revocation gate expected binding must carry both the authorization Event and the generation"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationGateDecision {
    Allow,
    RevocationPending,
    Revoked,
    AuthorityMismatch,
    GenerationMismatch,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-revocation-state.schema.json#/$defs/
/// device_revocation_gate_decision_receipt`.
///
/// The outcome travels only on the registered deployment-internal
/// authenticated channel between the account's bound Account Authority and
/// this exact origin Station, so that channel — not a detached signature —
/// supplies authenticity and integrity. The shape is closed in both
/// directions: `deny_unknown_fields` makes a receipt carrying `proof` or
/// `verification_method` fail to deserialize at all, and a consumer MUST NOT
/// accept a receipt that did not arrive over that authenticated channel.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationGateDecisionReceipt {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    /// Origin-derived current binding. Present only for
    /// [`DeviceRevocationGateDecision::Allow`], where it is the sole source
    /// for the issued grant's device binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_generation_ref: Option<u64>,
    pub action_class: DeviceRevocationGateActionClass,
    pub intent_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_device_possession_proof_digest: Option<Hash>,
    pub decision: DeviceRevocationGateDecision,
    pub linearization_seq: u64,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub linearized_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_proposal_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covering_seal_id: Option<SealId>,
}

/// Only `allow` discloses the origin-derived binding; withholding it from
/// `generation_mismatch` is what stops a refresh from being re-issued at a
/// replaced generation.
fn validate_gate_decision_witness(
    decision: DeviceRevocationGateDecision,
    target_device_authorize_event_id: Option<&EventId>,
    target_device_generation_ref: Option<u64>,
    blocking_proposal_digest: Option<&Hash>,
    covering_seal_id: Option<&SealId>,
) -> Result<()> {
    let derived_binding = match (
        target_device_authorize_event_id,
        target_device_generation_ref,
    ) {
        (Some(_), Some(generation)) if generation > 0 => true,
        (None, None) => false,
        _ => {
            return Err(WireError::Protocol(
                "device revocation gate receipt derived binding must carry both the authorization Event and a positive generation"
                    .to_owned(),
            ));
        }
    };
    if derived_binding != matches!(decision, DeviceRevocationGateDecision::Allow) {
        return Err(WireError::Protocol(
            "device revocation gate receipt discloses the derived binding for exactly the allow decision"
                .to_owned(),
        ));
    }
    match decision {
        DeviceRevocationGateDecision::RevocationPending
            if blocking_proposal_digest.is_some() && covering_seal_id.is_none() => {}
        DeviceRevocationGateDecision::Revoked
            if covering_seal_id.is_some() && blocking_proposal_digest.is_none() => {}
        DeviceRevocationGateDecision::Allow
        | DeviceRevocationGateDecision::AuthorityMismatch
        | DeviceRevocationGateDecision::GenerationMismatch
            if blocking_proposal_digest.is_none() && covering_seal_id.is_none() => {}
        _ => {
            return Err(WireError::Protocol(
                "device revocation gate receipt decision witness is inconsistent".to_owned(),
            ));
        }
    }
    Ok(())
}

impl DeviceRevocationGateDecisionReceipt {
    /// Every wire invariant the receipt owns on its own, independent of the
    /// request it answered. Authenticity and integrity come from the
    /// deployment-internal authenticated channel, so there is nothing
    /// cryptographic left for this type to check.
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        validate_possession_verification_presence(
            self.action_class,
            self.accepted_device_possession_proof_digest.as_ref(),
        )?;
        if self.linearization_seq == 0
            || self.expires_at <= self.linearized_at
            || self.expires_at - self.linearized_at > MAX_DEVICE_REVOCATION_RECEIPT_LIFETIME
        {
            return Err(WireError::Protocol(
                "device revocation gate receipt has invalid selector or linearization lifetime"
                    .to_owned(),
            ));
        }
        validate_gate_decision_witness(
            self.decision,
            self.target_device_authorize_event_id.as_ref(),
            self.target_device_generation_ref,
            self.blocking_proposal_digest.as_ref(),
            self.covering_seal_id.as_ref(),
        )
    }

    /// The origin-derived binding an `allow` admits. Every other decision
    /// carries no binding by construction.
    pub fn allowed_binding(&self) -> Option<(&EventId, u64)> {
        match (
            self.decision,
            self.target_device_authorize_event_id.as_ref(),
            self.target_device_generation_ref,
        ) {
            (DeviceRevocationGateDecision::Allow, Some(event_id), Some(generation))
                if generation > 0 =>
            {
                Some((event_id, generation))
            }
            _ => None,
        }
    }

    pub fn validate_for_request(
        &self,
        request: &DeviceRevocationGateCheckRequestBody,
    ) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.account_id != request.account_id
            || self.device_id != request.device_id
            || self.action_class != request.action_class
            || self.intent_digest != request.intent_digest
        {
            return Err(WireError::Protocol(
                "device revocation gate receipt does not bind the request".to_owned(),
            ));
        }
        let expected_possession_proof_digest = request
            .accepted_device_possession_proof
            .as_ref()
            .map(AcceptedDevicePossessionProof::proof_digest)
            .transpose()?;
        if self.accepted_device_possession_proof_digest != expected_possession_proof_digest {
            return Err(WireError::Protocol(
                "device revocation gate receipt does not attest the request's device proof"
                    .to_owned(),
            ));
        }
        // An allow answering an expected binding MUST be that same binding: a
        // difference is generation_mismatch, never a silently upgraded allow.
        if self.decision == DeviceRevocationGateDecision::Allow
            && request.expected_device_authorize_event_id.is_some()
            && (self.target_device_authorize_event_id != request.expected_device_authorize_event_id
                || self.target_device_generation_ref != request.expected_device_generation_ref)
        {
            return Err(WireError::Protocol(
                "device revocation gate allow does not match the expected binding it answered"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_possession_verification_presence(
    action_class: DeviceRevocationGateActionClass,
    proof_digest: Option<&Hash>,
) -> Result<()> {
    let required = matches!(
        action_class,
        DeviceRevocationGateActionClass::ReturningSessionGrantIssue
            | DeviceRevocationGateActionClass::SessionGrantRefresh
    );
    if required != proof_digest.is_some() {
        return Err(WireError::Protocol(
            "gate receipt device-possession verification does not match its action class"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationGateCheckOutcome {
    pub decision_receipt: DeviceRevocationGateDecisionReceipt,
}

impl DeviceRevocationGateCheckOutcome {
    pub fn validate_for_request(
        &self,
        request: &DeviceRevocationGateCheckRequestBody,
    ) -> Result<()> {
        self.decision_receipt.validate_for_request(request)
    }

    /// Validate the receipt against the request it answered and reduce the
    /// origin decision to typed issuer control flow. Only `Authorized` permits
    /// issuance; setup/block outcomes issue nothing, while a stale or malformed
    /// receipt is a protocol error. The caller must never fall back to local
    /// device state.
    pub fn session_grant_admission(
        &self,
        request: &DeviceRevocationGateCheckRequestBody,
        now: DateTime<Utc>,
    ) -> Result<SessionGrantGateAdmission<'_>> {
        self.validate_for_request(request)?;
        if now >= self.decision_receipt.expires_at {
            return Err(WireError::Protocol(
                "device revocation gate receipt is no longer fresh".to_owned(),
            ));
        }
        Ok(match self.decision_receipt.decision {
            DeviceRevocationGateDecision::Allow => self
                .decision_receipt
                .allowed_binding()
                .map(|(authorization_event_id, model_generation_ref)| {
                    SessionGrantGateAdmission::Authorized {
                        authorization_event_id,
                        model_generation_ref,
                    }
                })
                .ok_or_else(|| {
                    WireError::Protocol(
                        "device revocation gate allow carries no derived binding".to_owned(),
                    )
                })?,
            DeviceRevocationGateDecision::AuthorityMismatch => {
                SessionGrantGateAdmission::DeviceSetupRequired
            }
            DeviceRevocationGateDecision::RevocationPending => SessionGrantGateAdmission::Blocked {
                reason: SessionGrantGateBlockReason::RevocationPending,
            },
            DeviceRevocationGateDecision::Revoked => SessionGrantGateAdmission::Blocked {
                reason: SessionGrantGateBlockReason::Revoked,
            },
            DeviceRevocationGateDecision::GenerationMismatch => {
                SessionGrantGateAdmission::Blocked {
                    reason: SessionGrantGateBlockReason::GenerationMismatch,
                }
            }
        })
    }
}

/// What a validated, fresh gate receipt lets a human session-grant issuer do.
///
/// Only `Authorized` permits issuance. Device setup and each current-device
/// block are typed control-flow results, never restricted-grant fallbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionGrantGateAdmission<'a> {
    /// The device has an accepted authorization the origin derived. The issued
    /// grant MUST carry exactly this binding.
    Authorized {
        authorization_event_id: &'a EventId,
        model_generation_ref: u64,
    },
    DeviceSetupRequired,
    Blocked {
        reason: SessionGrantGateBlockReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionGrantGateBlockReason {
    RevocationPending,
    Revoked,
    GenerationMismatch,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::{
        AcceptedDeviceIssuePossessionProof, AcceptedDeviceIssuePossessionPurpose,
        AcceptedDevicePossessionProofContext, Base64UrlString, DidCoreId, DidUrl, RequestId,
    };

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_776_000_000 + seconds, 0).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn authorize_event() -> EventId {
        EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e").unwrap()
    }

    fn request() -> DeviceRevocationGateCheckRequestBody {
        DeviceRevocationGateCheckRequestBody {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            ),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            expected_device_authorize_event_id: None,
            expected_device_generation_ref: None,
            action_class: DeviceRevocationGateActionClass::SessionGrantIssue,
            intent_digest: hash('a'),
            accepted_device_possession_proof: None,
            requested_at: at(0),
        }
    }

    fn receipt() -> DeviceRevocationGateDecisionReceipt {
        let request = request();
        DeviceRevocationGateDecisionReceipt {
            account_id: request.account_id,
            device_id: request.device_id,
            target_device_authorize_event_id: Some(authorize_event()),
            target_device_generation_ref: Some(7),
            action_class: request.action_class,
            intent_digest: request.intent_digest,
            accepted_device_possession_proof_digest: None,
            decision: DeviceRevocationGateDecision::Allow,
            linearization_seq: 9,
            linearized_at: at(1),
            expires_at: at(31),
            blocking_proposal_digest: None,
            covering_seal_id: None,
        }
    }

    fn issue_possession_proof(intent_digest: Hash) -> AcceptedDevicePossessionProof {
        AcceptedDevicePossessionProof::Issue(AcceptedDeviceIssuePossessionProof {
            context: AcceptedDevicePossessionProofContext::V1,
            purpose: AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000021").unwrap(),
            account_subject: hash('b'),
            account_handoff_grant_digest: hash('c'),
            // Must bind the same account as `request()`: the holder's Station
            // is `ps.example`; `service.example` is only the proof audience.
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            ),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            audience_id: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            holder_jkt: "A".repeat(43),
            session_intent_digest: intent_digest,
            issued_at: at(0),
            expires_at: at(300),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            signature: Base64UrlString::new(crate::base64url::base64url_encode([0u8; 64])).unwrap(),
        })
    }

    #[test]
    fn gate_receipt_binds_exact_request() {
        let request = request();
        let receipt = receipt();
        receipt.validate().unwrap();
        receipt.validate_for_request(&request).unwrap();
    }

    /// The deployment-internal authenticated channel supplies authenticity, so
    /// the receipt shape is closed in both directions: either signature member
    /// makes the whole receipt undeserializable rather than merely ignored.
    #[test]
    fn gate_receipt_rejects_any_carried_proof_member() {
        let base = serde_json::to_value(receipt()).unwrap();
        assert!(base.get("proof").is_none());
        assert!(base.get("verification_method").is_none());

        for (member, value) in [
            (
                "verification_method",
                serde_json::json!("did:web:ps.example#assertion-1"),
            ),
            (
                "proof",
                serde_json::json!({
                    "kind": "detached_jws",
                    "verification_method": "did:web:ps.example#assertion-1",
                    "payload_digest": format!("sha256:{}", "a".repeat(64)),
                    "created_at": "2026-04-12T00:00:01.000Z",
                    "jws": "e30..c2ln"
                }),
            ),
        ] {
            let mut carried = base.clone();
            carried[member] = value;
            assert!(
                serde_json::from_value::<DeviceRevocationGateDecisionReceipt>(carried).is_err(),
                "a receipt carrying {member} must be rejected outright"
            );
        }
    }

    #[test]
    fn gate_receipt_rejects_open_branch_or_stale_window() {
        let request = request();
        let mut invalid = receipt();
        invalid.blocking_proposal_digest = Some(hash('b'));
        assert!(invalid.validate().is_err());
        assert!(invalid.validate_for_request(&request).is_err());

        let mut expired = receipt();
        expired.expires_at = expired.linearized_at;
        assert!(expired.validate().is_err());
        assert!(expired.validate_for_request(&request).is_err());

        let mut overlong = receipt();
        overlong.expires_at = overlong.linearized_at + Duration::seconds(31);
        assert!(overlong.validate().is_err());
    }

    #[test]
    fn request_is_closed_and_generation_is_positive() {
        let mut value = serde_json::to_value(request()).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DeviceRevocationGateCheckRequestBody>(value).is_err());
        let mut invalid = request();
        invalid.expected_device_authorize_event_id = Some(authorize_event());
        invalid.expected_device_generation_ref = Some(0);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn first_issue_omits_the_expected_binding_and_every_other_action_class_requires_it() {
        let first_issue = request();
        assert!(first_issue.expected_device_authorize_event_id.is_none());
        first_issue.validate().unwrap();
        // Omission is not serialized, so the request cannot smuggle a null.
        let value = serde_json::to_value(&first_issue).unwrap();
        assert!(value.get("expected_device_authorize_event_id").is_none());

        let mut refresh = request();
        refresh.action_class = DeviceRevocationGateActionClass::EventWrite;
        assert!(refresh.validate().is_err());
        refresh.expected_device_authorize_event_id = Some(authorize_event());
        refresh.expected_device_generation_ref = Some(7);
        refresh.validate().unwrap();

        let mut half = request();
        half.expected_device_generation_ref = Some(7);
        assert!(half.validate().is_err());
    }

    #[test]
    fn returning_issue_requires_a_matching_full_device_possession_proof() {
        let mut returning = request();
        returning.action_class = DeviceRevocationGateActionClass::ReturningSessionGrantIssue;
        returning.accepted_device_possession_proof =
            Some(issue_possession_proof(returning.intent_digest.clone()));
        returning.validate().unwrap();

        let mut missing = returning.clone();
        missing.accepted_device_possession_proof = None;
        assert!(missing.validate().is_err());

        let mut mismatched = returning;
        mismatched.intent_digest = hash('d');
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn only_allow_carries_the_derived_binding() {
        let request = request();
        let allow = receipt();
        assert_eq!(
            allow.allowed_binding(),
            Some((&authorize_event(), 7u64)),
            "allow admits the origin-derived binding"
        );
        allow.validate_for_request(&request).unwrap();

        let mut mismatch = receipt();
        mismatch.decision = DeviceRevocationGateDecision::GenerationMismatch;
        assert!(
            mismatch.validate_for_request(&request).is_err(),
            "a mismatch that still discloses the derived binding is rejected"
        );

        mismatch.target_device_authorize_event_id = None;
        mismatch.target_device_generation_ref = None;
        mismatch.validate_for_request(&request).unwrap();
        assert!(mismatch.allowed_binding().is_none());

        let mut allow_without_binding = receipt();
        allow_without_binding.target_device_authorize_event_id = None;
        allow_without_binding.target_device_generation_ref = None;
        assert!(
            allow_without_binding
                .validate_for_request(&request)
                .is_err()
        );
    }

    #[test]
    fn allow_must_answer_the_expected_binding_it_was_given() {
        let mut refresh = request();
        refresh.action_class = DeviceRevocationGateActionClass::SessionGrantRefresh;
        refresh.expected_device_authorize_event_id = Some(authorize_event());
        refresh.expected_device_generation_ref = Some(6);

        let mut upgraded = receipt();
        upgraded.action_class = DeviceRevocationGateActionClass::EventWrite;
        assert!(
            upgraded.validate_for_request(&refresh).is_err(),
            "an allow may not answer generation 6 with generation 7"
        );
    }

    #[test]
    fn blocked_or_stale_receipts_admit_nothing() {
        let request = request();
        let outcome = DeviceRevocationGateCheckOutcome {
            decision_receipt: receipt(),
        };
        assert_eq!(
            outcome.session_grant_admission(&request, at(2)).unwrap(),
            SessionGrantGateAdmission::Authorized {
                authorization_event_id: &authorize_event(),
                model_generation_ref: 7,
            }
        );
        assert!(
            outcome.session_grant_admission(&request, at(31)).is_err(),
            "a receipt at or past expires_at admits nothing"
        );

        for decision in [
            DeviceRevocationGateDecision::RevocationPending,
            DeviceRevocationGateDecision::Revoked,
            DeviceRevocationGateDecision::GenerationMismatch,
        ] {
            let mut blocked = receipt();
            blocked.decision = decision;
            blocked.target_device_authorize_event_id = None;
            blocked.target_device_generation_ref = None;
            match decision {
                DeviceRevocationGateDecision::RevocationPending => {
                    blocked.blocking_proposal_digest = Some(hash('b'));
                }
                DeviceRevocationGateDecision::Revoked => {
                    blocked.covering_seal_id =
                        Some(SealId::new(format!("ak:seal:sha256:{}", "c".repeat(64))).unwrap());
                }
                _ => {}
            }
            let outcome = DeviceRevocationGateCheckOutcome {
                decision_receipt: blocked,
            };
            let admission = outcome.session_grant_admission(&request, at(2)).unwrap();
            assert!(matches!(
                admission,
                SessionGrantGateAdmission::Blocked { .. }
            ));
        }
    }

    #[test]
    fn authority_mismatch_requires_device_setup_and_never_issues_a_grant() {
        let request = request();
        let mut fresh = receipt();
        fresh.decision = DeviceRevocationGateDecision::AuthorityMismatch;
        fresh.target_device_authorize_event_id = None;
        fresh.target_device_generation_ref = None;
        let outcome = DeviceRevocationGateCheckOutcome {
            decision_receipt: fresh,
        };
        assert_eq!(
            outcome.session_grant_admission(&request, at(2)).unwrap(),
            SessionGrantGateAdmission::DeviceSetupRequired
        );
    }
}
