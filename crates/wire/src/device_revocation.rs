//! Durable device-revocation state and the service-to-service gate contract.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    ControlProposalAck, ControlProposalDecision, DeviceId, DidFullId, DidUrl, Error, EventId, Hash,
    PayloadProof, PrincipalAuthorityKey, ProofContextId, Result, SealId, UnsignedPayloadProof,
    canonical, project_full_id_to_core_id,
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
    PrincipalServerAdmissionProofIssue,
}

pub const DEVICE_REVOCATION_DENIED_ACTIONS: [DeviceRevocationDeniedAction; 5] = [
    DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
    DeviceRevocationDeniedAction::KeypackageClaim,
    DeviceRevocationDeniedAction::ToDeviceWrite,
    DeviceRevocationDeniedAction::EventWrite,
    DeviceRevocationDeniedAction::PrincipalServerAdmissionProofIssue,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevocationPendingStatus {
    #[serde(rename = "revocation_pending")]
    RevocationPending,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevocationRejectedStatus {
    #[serde(rename = "revocation_rejected")]
    RevocationRejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevokedStatus {
    #[serde(rename = "revoked")]
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationPendingState {
    pub schema: DeviceRevocationStateSchema,
    pub principal_authority: PrincipalAuthorityKey,
    pub device_id: DeviceId,
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    pub proposal_event_id: EventId,
    pub proposal_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: ControlProposalAck,
    pub status: DeviceRevocationPendingStatus,
    pub decision_state: DeviceRevocationDecisionState,
    pub denied_actions: [DeviceRevocationDeniedAction; 5],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<Vec<ControlProposalDecision>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_reason: Option<DeviceRevocationFaultReason>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationRejectedState {
    pub schema: DeviceRevocationStateSchema,
    pub principal_authority: PrincipalAuthorityKey,
    pub device_id: DeviceId,
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    pub proposal_event_id: EventId,
    pub proposal_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: ControlProposalAck,
    pub status: DeviceRevocationRejectedStatus,
    pub terminal_decision: ControlProposalDecision,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokedState {
    pub schema: DeviceRevocationStateSchema,
    pub principal_authority: PrincipalAuthorityKey,
    pub device_id: DeviceId,
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    pub proposal_event_id: EventId,
    pub proposal_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: ControlProposalAck,
    pub status: DeviceRevokedStatus,
    pub covering_seal_id: SealId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceRevocationRecord {
    Pending(DeviceRevocationPendingState),
    Rejected(DeviceRevocationRejectedState),
    Revoked(DeviceRevokedState),
}

impl DeviceRevocationRecord {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Pending(state) => state.validate(),
            Self::Rejected(state) => state.validate(),
            Self::Revoked(state) => state.validate(),
        }
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
    principal_authority: &PrincipalAuthorityKey,
    target_device_generation_ref: u64,
    proposal_digest: &Hash,
    acceptance_seq: u64,
    ack: &ControlProposalAck,
) -> Result<()> {
    principal_authority.validate()?;
    if target_device_generation_ref == 0 || acceptance_seq == 0 {
        return Err(Error::Protocol(
            "device revocation generation and acceptance_seq must be positive".to_owned(),
        ));
    }
    ack.validate_protocol_bounds()?;
    if &ack.proposal_digest != proposal_digest {
        return Err(Error::Protocol(
            "device revocation record proposal digest does not match its Ack".to_owned(),
        ));
    }
    Ok(())
}

impl DeviceRevocationPendingState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.principal_authority,
            self.target_device_generation_ref,
            &self.proposal_digest,
            self.acceptance_seq,
            &self.control_proposal_ack,
        )?;
        if self.denied_actions != DEVICE_REVOCATION_DENIED_ACTIONS {
            return Err(Error::Protocol(
                "device revocation denied_actions must equal the canonical five-action list"
                    .to_owned(),
            ));
        }
        let decisions = self.decisions.as_deref().unwrap_or_default();
        if decisions.len() > 2 || decisions.iter().any(ControlProposalDecision::is_reject) {
            return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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

impl DeviceRevocationRejectedState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.principal_authority,
            self.target_device_generation_ref,
            &self.proposal_digest,
            self.acceptance_seq,
            &self.control_proposal_ack,
        )?;
        if !self.terminal_decision.is_reject() {
            return Err(Error::Protocol(
                "device revocation terminal_decision must be signed_reject".to_owned(),
            ));
        }
        self.terminal_decision
            .validate_ack_binding_protocol_bounds(&self.control_proposal_ack)
    }
}

impl DeviceRevokedState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.principal_authority,
            self.target_device_generation_ref,
            &self.proposal_digest,
            self.acceptance_seq,
            &self.control_proposal_ack,
        )?;
        if self.sealed_at < self.accepted_at {
            return Err(Error::Protocol(
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

    pub fn proposal_digest(&self) -> &Hash {
        match self {
            Self::Pending(state) => &state.proposal_digest,
            Self::Revoked(state) => &state.proposal_digest,
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
    SessionGrantRefresh,
    KeypackageClaim,
    ToDeviceWrite,
    EventWrite,
    PrincipalServerAdmissionProofIssue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationGateCheckRequestBody {
    pub principal_authority: PrincipalAuthorityKey,
    pub device_id: DeviceId,
    /// Issuer-held verified binding, never a client-supplied value. Present
    /// together with `expected_device_generation_ref` or not at all, and only
    /// omittable for `SessionGrantIssue`, which is how a first ordinary human
    /// grant acquires its binding from the allow receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_generation_ref: Option<u64>,
    pub action_class: DeviceRevocationGateActionClass,
    pub intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
}

impl DeviceRevocationGateCheckRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.principal_authority.validate()?;
        match (
            &self.expected_device_authorize_event_id,
            self.expected_device_generation_ref,
        ) {
            (Some(_), Some(generation)) => {
                if generation == 0 {
                    return Err(Error::Protocol(
                        "device revocation gate generation must be positive".to_owned(),
                    ));
                }
            }
            (None, None) => {
                if self.action_class != DeviceRevocationGateActionClass::SessionGrantIssue {
                    return Err(Error::Protocol(
                        "device revocation gate expected binding is required for every action class other than session_grant_issue"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(Error::Protocol(
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationGateDecisionReceipt {
    pub principal_authority: PrincipalAuthorityKey,
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
    pub verification_method: DidUrl,
    pub proof: PayloadProof,
}

/// Public authoring state for a gate receipt before its detached JWS exists.
///
/// This prevents signers from manufacturing an invalid placeholder proof just
/// to compute the proof-less receipt digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnsignedDeviceRevocationGateDecisionReceipt {
    pub principal_authority: PrincipalAuthorityKey,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_generation_ref: Option<u64>,
    pub action_class: DeviceRevocationGateActionClass,
    pub intent_digest: Hash,
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
    pub verification_method: DidUrl,
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
            return Err(Error::Protocol(
                "device revocation gate receipt derived binding must carry both the authorization Event and a positive generation"
                    .to_owned(),
            ));
        }
    };
    if derived_binding != matches!(decision, DeviceRevocationGateDecision::Allow) {
        return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "device revocation gate receipt decision witness is inconsistent".to_owned(),
            ));
        }
    }
    Ok(())
}

impl UnsignedDeviceRevocationGateDecisionReceipt {
    pub fn validate(&self) -> Result<()> {
        self.principal_authority.validate()?;
        if self.linearization_seq == 0
            || self.expires_at <= self.linearized_at
            || self.expires_at - self.linearized_at > MAX_DEVICE_REVOCATION_RECEIPT_LIFETIME
        {
            return Err(Error::Protocol(
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

    pub fn payload_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(canonical::canonical_sha256(self)?)?)
    }

    pub fn proof_metadata(&self) -> Result<UnsignedPayloadProof> {
        Ok(UnsignedPayloadProof {
            kind: crate::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: self.verification_method.clone(),
            payload_digest: self.payload_digest()?,
            created_at: self.linearized_at,
            domain: None,
            audience: None,
            proof_purpose: None,
        })
    }

    pub fn proof_signing_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest
            || proof.verification_method != self.verification_method
            || proof.created_at != self.linearized_at
        {
            return Err(Error::Protocol(
                "device revocation gate proof binding fields do not match the receipt".to_owned(),
            ));
        }
        let controller = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| Error::Protocol("verification method has no controller".to_owned()))?;
        let controller = project_full_id_to_core_id(&DidFullId::new(controller)?)?;
        if controller != self.principal_authority.principal_server_id {
            return Err(Error::Protocol(
                "device revocation gate proof controller is not the origin Principal Server"
                    .to_owned(),
            ));
        }
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::DEVICE_REVOCATION_GATE_DECISION_PROOF_V1,
            "payload_digest": payload_digest,
            "verification_method": self.verification_method,
            "created_at": canonical::format_timestamp_canonical(proof.created_at),
        }))
        .map_err(Into::into)
    }

    pub fn attach_proof(self, proof: PayloadProof) -> Result<DeviceRevocationGateDecisionReceipt> {
        self.proof_signing_bytes(&proof.unsigned())?;
        Ok(DeviceRevocationGateDecisionReceipt {
            principal_authority: self.principal_authority,
            device_id: self.device_id,
            target_device_authorize_event_id: self.target_device_authorize_event_id,
            target_device_generation_ref: self.target_device_generation_ref,
            action_class: self.action_class,
            intent_digest: self.intent_digest,
            decision: self.decision,
            linearization_seq: self.linearization_seq,
            linearized_at: self.linearized_at,
            expires_at: self.expires_at,
            blocking_proposal_digest: self.blocking_proposal_digest,
            covering_seal_id: self.covering_seal_id,
            verification_method: self.verification_method,
            proof,
        })
    }
}

impl DeviceRevocationGateDecisionReceipt {
    pub fn unsigned(&self) -> UnsignedDeviceRevocationGateDecisionReceipt {
        UnsignedDeviceRevocationGateDecisionReceipt {
            principal_authority: self.principal_authority.clone(),
            device_id: self.device_id.clone(),
            target_device_authorize_event_id: self.target_device_authorize_event_id.clone(),
            target_device_generation_ref: self.target_device_generation_ref,
            action_class: self.action_class,
            intent_digest: self.intent_digest.clone(),
            decision: self.decision,
            linearization_seq: self.linearization_seq,
            linearized_at: self.linearized_at,
            expires_at: self.expires_at,
            blocking_proposal_digest: self.blocking_proposal_digest.clone(),
            covering_seal_id: self.covering_seal_id.clone(),
            verification_method: self.verification_method.clone(),
        }
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("device revocation receipt serializes as an object")
            .remove("proof");
        Ok(Hash::new(canonical::canonical_sha256(&value)?)?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.proof.validate_production()?;
        let payload_digest = self.payload_digest()?;
        if self.proof.payload_digest != payload_digest
            || self.proof.verification_method != self.verification_method
            || self.proof.created_at != self.linearized_at
        {
            return Err(Error::Protocol(
                "device revocation gate proof binding fields do not match the receipt".to_owned(),
            ));
        }
        let controller = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| Error::Protocol("verification method has no controller".to_owned()))?;
        let controller = project_full_id_to_core_id(&DidFullId::new(controller)?)?;
        if controller != self.principal_authority.principal_server_id {
            return Err(Error::Protocol(
                "device revocation gate proof controller is not the origin Principal Server"
                    .to_owned(),
            ));
        }
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::DEVICE_REVOCATION_GATE_DECISION_PROOF_V1,
            "payload_digest": payload_digest,
            "verification_method": self.verification_method,
            "created_at": canonical::format_timestamp_canonical(self.proof.created_at),
        }))
        .map_err(Into::into)
    }

    /// Verify the family-specific canonical binding with caller-resolved key
    /// material. The callback owns cryptographic algorithm and DID method-state
    /// verification; this type owns every wire and transcript invariant.
    pub fn verify_proof_with<F>(&self, verify: F) -> Result<()>
    where
        F: FnOnce(&PayloadProof, &[u8]) -> Result<()>,
    {
        let binding = self.proof_binding_bytes()?;
        verify(&self.proof, &binding)
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
        if self.principal_authority != request.principal_authority
            || self.device_id != request.device_id
            || self.action_class != request.action_class
            || self.intent_digest != request.intent_digest
        {
            return Err(Error::Protocol(
                "device revocation gate receipt does not bind the request".to_owned(),
            ));
        }
        if self.linearization_seq == 0
            || self.expires_at <= self.linearized_at
            || self.expires_at - self.linearized_at > MAX_DEVICE_REVOCATION_RECEIPT_LIFETIME
        {
            return Err(Error::Protocol(
                "device revocation gate receipt has invalid linearization lifetime".to_owned(),
            ));
        }
        validate_gate_decision_witness(
            self.decision,
            self.target_device_authorize_event_id.as_ref(),
            self.target_device_generation_ref,
            self.blocking_proposal_digest.as_ref(),
            self.covering_seal_id.as_ref(),
        )?;
        // An allow answering an expected binding MUST be that same binding: a
        // difference is generation_mismatch, never a silently upgraded allow.
        if self.decision == DeviceRevocationGateDecision::Allow
            && request.expected_device_authorize_event_id.is_some()
            && (self.target_device_authorize_event_id != request.expected_device_authorize_event_id
                || self.target_device_generation_ref != request.expected_device_generation_ref)
        {
            return Err(Error::Protocol(
                "device revocation gate allow does not match the expected binding it answered"
                    .to_owned(),
            ));
        }
        self.proof_binding_bytes().map(|_| ())
    }
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

    /// Validate the receipt against the request it answered and return the
    /// origin-derived binding an `allow` admits. Every other decision, and any
    /// receipt already past `expires_at`, fails closed: the caller has nothing
    /// to commit and MUST NOT fall back to its own device state.
    pub fn admitted_binding(
        &self,
        request: &DeviceRevocationGateCheckRequestBody,
        now: DateTime<Utc>,
    ) -> Result<(&EventId, u64)> {
        self.validate_for_request(request)?;
        if now >= self.decision_receipt.expires_at {
            return Err(Error::Protocol(
                "device revocation gate receipt is no longer fresh".to_owned(),
            ));
        }
        self.decision_receipt.allowed_binding().ok_or_else(|| {
            Error::Protocol(format!(
                "device revocation gate did not admit the intent: {:?}",
                self.decision_receipt.decision
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::DidCoreId;

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
            principal_authority: PrincipalAuthorityKey::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            ),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            expected_device_authorize_event_id: None,
            expected_device_generation_ref: None,
            action_class: DeviceRevocationGateActionClass::SessionGrantIssue,
            intent_digest: hash('a'),
            requested_at: at(0),
        }
    }

    fn receipt() -> DeviceRevocationGateDecisionReceipt {
        let request = request();
        let unsigned = UnsignedDeviceRevocationGateDecisionReceipt {
            principal_authority: request.principal_authority,
            device_id: request.device_id,
            target_device_authorize_event_id: Some(authorize_event()),
            target_device_generation_ref: Some(7),
            action_class: request.action_class,
            intent_digest: request.intent_digest,
            decision: DeviceRevocationGateDecision::Allow,
            linearization_seq: 9,
            linearized_at: at(1),
            expires_at: at(31),
            blocking_proposal_digest: None,
            covering_seal_id: None,
            verification_method: DidUrl::new("did:web:ps.example#assertion-1").unwrap(),
        };
        let proof = unsigned
            .proof_metadata()
            .unwrap()
            .finalize("e30..c2ln")
            .unwrap();
        unsigned.attach_proof(proof).unwrap()
    }

    #[test]
    fn gate_receipt_binds_exact_request_and_canonical_proof_transcript() {
        let request = request();
        let receipt = receipt();
        receipt.validate_for_request(&request).unwrap();
        assert_eq!(
            receipt.unsigned().payload_digest().unwrap(),
            receipt.payload_digest().unwrap()
        );
        assert_eq!(
            receipt.proof.payload_digest,
            receipt.payload_digest().unwrap()
        );
        let binding: serde_json::Value =
            serde_json::from_slice(&receipt.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(
            binding["context"],
            ProofContextId::DEVICE_REVOCATION_GATE_DECISION_PROOF_V1
        );
    }

    #[test]
    fn gate_receipt_rejects_open_branch_or_proof_shapes() {
        let request = request();
        let mut invalid = receipt();
        invalid.blocking_proposal_digest = Some(hash('b'));
        invalid.proof.payload_digest = invalid.payload_digest().unwrap();
        assert!(invalid.validate_for_request(&request).is_err());

        let mut expired = receipt();
        expired.expires_at = expired.linearized_at;
        expired.proof.payload_digest = expired.payload_digest().unwrap();
        assert!(expired.validate_for_request(&request).is_err());

        let mut wrong_controller = receipt();
        wrong_controller.verification_method = DidUrl::new("did:web:other.example#key").unwrap();
        wrong_controller.proof.verification_method = wrong_controller.verification_method.clone();
        wrong_controller.proof.payload_digest = wrong_controller.payload_digest().unwrap();
        assert!(wrong_controller.validate_for_request(&request).is_err());
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
        refresh.action_class = DeviceRevocationGateActionClass::SessionGrantRefresh;
        assert!(refresh.validate().is_err());
        refresh.expected_device_authorize_event_id = Some(authorize_event());
        refresh.expected_device_generation_ref = Some(7);
        refresh.validate().unwrap();

        let mut half = request();
        half.expected_device_generation_ref = Some(7);
        assert!(half.validate().is_err());
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
        mismatch.proof.payload_digest = mismatch.payload_digest().unwrap();
        assert!(
            mismatch.validate_for_request(&request).is_err(),
            "a mismatch that still discloses the derived binding is rejected"
        );

        mismatch.target_device_authorize_event_id = None;
        mismatch.target_device_generation_ref = None;
        mismatch.proof.payload_digest = mismatch.payload_digest().unwrap();
        mismatch.validate_for_request(&request).unwrap();
        assert!(mismatch.allowed_binding().is_none());

        let mut allow_without_binding = receipt();
        allow_without_binding.target_device_authorize_event_id = None;
        allow_without_binding.target_device_generation_ref = None;
        allow_without_binding.proof.payload_digest =
            allow_without_binding.payload_digest().unwrap();
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
        upgraded.action_class = DeviceRevocationGateActionClass::SessionGrantRefresh;
        upgraded.proof.payload_digest = upgraded.payload_digest().unwrap();
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
        assert!(outcome.admitted_binding(&request, at(2)).is_ok());
        assert!(
            outcome.admitted_binding(&request, at(31)).is_err(),
            "a receipt at or past expires_at admits nothing"
        );

        let mut pending = receipt();
        pending.decision = DeviceRevocationGateDecision::RevocationPending;
        pending.target_device_authorize_event_id = None;
        pending.target_device_generation_ref = None;
        pending.blocking_proposal_digest = Some(hash('b'));
        pending.proof.payload_digest = pending.payload_digest().unwrap();
        let blocked = DeviceRevocationGateCheckOutcome {
            decision_receipt: pending,
        };
        assert!(blocked.admitted_binding(&request, at(2)).is_err());
    }
}
