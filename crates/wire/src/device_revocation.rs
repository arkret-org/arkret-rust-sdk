//! Durable device-revocation state and in-process admission semantics.
//!
//! Counterpart for `spec/v1/artifacts/schemas/device-revocation-state.schema.json`.
//! The durable records fence an exact device generation. Admission inputs and
//! records are domain values used inside one Station trust boundary; they do
//! not define a canonical Arkret service operation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AcceptedDevicePossessionProof, AccountId, DeviceId, ErrorCode, EventId, Hash, RealmCommitId,
    Result, WireError,
};

/// Hard admission-use deadline bound: `expires_at` is no later than 30 seconds
/// after `linearized_at`. It is a freshness bound, not a cache TTL and not a
/// revocation deadline.
pub const MAX_DEVICE_REVOCATION_ADMISSION_LIFETIME: Duration = Duration::seconds(30);

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRevocationStateSchema {
    #[serde(rename = "ak.schema.device_revocation_state.v1")]
    V1,
}

/// Closed canonical action-class list blocked by `revocation_pending` on every
/// deployment.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationDeniedAction {
    SessionGrantIssueOrRefresh,
    DevicePairingCodeClaim,
    KeypackageClaim,
    ToDeviceWrite,
    EventWrite,
}

pub const DEVICE_REVOCATION_DENIED_ACTIONS: [DeviceRevocationDeniedAction; 5] = [
    DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
    DeviceRevocationDeniedAction::DevicePairingCodeClaim,
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
// Field declaration order is byte-for-byte the `properties` order of
// `device-revocation-state.schema.json#/$defs/common_record` followed by
// `device-revocation-state.schema.json#/$defs/device_revocation_pending_state`.
pub struct DeviceRevocationPendingState {
    pub schema: DeviceRevocationStateSchema,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    /// Reducer-derived accepted `ak.device.authorize` Event targeted by this
    /// proposal.
    pub target_device_authorize_event_id: EventId,
    pub target_device_generation_ref: u64,
    /// The complete accepted revoke Event identifier and the sole wire source
    /// of that Event digest. Consumers recover the digest from this identifier
    /// rather than from a sibling field.
    pub proposal_event_id: EventId,
    /// Durable atomic-commit time assigned by the authority transaction, never
    /// producer supplied.
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub status: DeviceRevocationPendingStatus,
    pub denied_actions: [DeviceRevocationDeniedAction; 5],
}

/// A rejected revocation clears only the pending gate for this exact proposal
/// and remains as audit history. The gate never consults it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `device-revocation-state.schema.json#/$defs/common_record` followed by
// `device-revocation-state.schema.json#/$defs/device_revocation_rejected_state`.
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
    pub status: DeviceRevocationRejectedStatus,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `device-revocation-state.schema.json#/$defs/common_record` followed by
// `device-revocation-state.schema.json#/$defs/device_revoked_state`.
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
    pub status: DeviceRevokedStatus,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
}

/// Every durable record shape for one exact device generation, including the
/// rejected audit history the gate excludes.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceRevocationRecord {
    Pending(DeviceRevocationPendingState),
    Rejected(DeviceRevocationRejectedState),
    Revoked(DeviceRevokedState),
}

/// Gate-relevant durable state. Pending and revoked records stay visible
/// together so committing one transaction cannot hide another surviving
/// pending transaction.
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
    acceptance_seq: u64,
) -> Result<()> {
    account_id.validate()?;
    if target_device_generation_ref == 0 || acceptance_seq == 0 {
        return Err(WireError::Protocol(
            "device revocation generation and acceptance_seq must be positive".to_owned(),
        ));
    }
    Ok(())
}

impl DeviceRevocationPendingState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.account_id,
            self.target_device_generation_ref,
            self.acceptance_seq,
        )?;
        if self.denied_actions != DEVICE_REVOCATION_DENIED_ACTIONS {
            return Err(WireError::Protocol(
                "device revocation denied_actions must equal the canonical four-action list"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl DeviceRevocationRejectedState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.account_id,
            self.target_device_generation_ref,
            self.acceptance_seq,
        )
    }
}

impl DeviceRevokedState {
    pub fn validate(&self) -> Result<()> {
        validate_record_common(
            &self.account_id,
            self.target_device_generation_ref,
            self.acceptance_seq,
        )?;
        if self.committed_at < self.accepted_at {
            return Err(WireError::Protocol(
                "device revocation committed_at precedes accepted_at".to_owned(),
            ));
        }
        Ok(())
    }
}

impl DeviceRevocationRecord {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Pending(state) => state.validate(),
            Self::Rejected(state) => state.validate(),
            Self::Revoked(state) => state.validate(),
        }
    }

    pub fn acceptance_seq(&self) -> u64 {
        match self {
            Self::Pending(state) => state.acceptance_seq,
            Self::Rejected(state) => state.acceptance_seq,
            Self::Revoked(state) => state.acceptance_seq,
        }
    }

    pub fn proposal_event_id(&self) -> &EventId {
        match self {
            Self::Pending(state) => &state.proposal_event_id,
            Self::Rejected(state) => &state.proposal_event_id,
            Self::Revoked(state) => &state.proposal_event_id,
        }
    }

    /// The gate projection of this record. A rejected record is audit history
    /// and contributes nothing to the gate.
    pub fn gate_record(&self) -> Option<DeviceRevocationGateRecord> {
        match self {
            Self::Pending(state) => Some(DeviceRevocationGateRecord::Pending(state.clone())),
            Self::Rejected(_) => None,
            Self::Revoked(state) => Some(DeviceRevocationGateRecord::Revoked(state.clone())),
        }
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

/// Action class a current-device admission decision is linearized for.
///
/// Every class is one of the closed [`DEVICE_REVOCATION_DENIED_ACTIONS`].
/// Session-grant issue and refresh are
/// the single `session_grant_issue_or_refresh` class; which of them an input
/// is follows from its accepted-device proof alone: none for
/// registration/recovery issue, an issue proof for returning account-handoff
/// issue, and a refresh proof for human refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationAdmissionAction {
    SessionGrantIssueOrRefresh,
    DevicePairingCodeClaim,
    KeypackageClaim,
    ToDeviceWrite,
    EventWrite,
}

impl DeviceRevocationAdmissionAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionGrantIssueOrRefresh => "session_grant_issue_or_refresh",
            Self::DevicePairingCodeClaim => "device_pairing_code_claim",
            Self::KeypackageClaim => "keypackage_claim",
            Self::ToDeviceWrite => "to_device_write",
            Self::EventWrite => "event_write",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationAdmissionInput {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    /// Issuer-verified binding, never a client-supplied value. Present together
    /// with `expected_device_generation_ref` or not at all, and omittable only
    /// for a session-grant issue (no proof or an issue proof); both issue paths
    /// learn the current binding from the locally linearized allow record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_generation_ref: Option<u64>,
    pub action_class: DeviceRevocationAdmissionAction,
    /// Digest of the complete immutable issue, refresh or revoke intent. Issue
    /// and refresh bind the exact grant id, jti, subject, device, audience,
    /// scope, holder binding, issued_at and expiry. For `DevicePairingCodeClaim`, the digest binds
    /// the operation id, exact account, caller device and canonical claim
    /// request without disclosing the plaintext pairing code to the origin.
    pub intent_digest: Hash,
    /// Accepted-device proof the origin verifies with the accepted device key
    /// from the same locked durable projection used to decide current
    /// authorization. Carried only by `SessionGrantIssueOrRefresh`, and there
    /// only for returning account-handoff issue and human refresh;
    /// registration/recovery issue, device-pairing code claim and Agent
    /// runtime issuers omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_device_possession_proof: Option<AcceptedDevicePossessionProof>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
}

impl DeviceRevocationAdmissionInput {
    /// Whether this input may omit the expected binding: a session-grant issue,
    /// that is `SessionGrantIssueOrRefresh` without a refresh proof.
    #[must_use]
    pub fn is_session_grant_issue(&self) -> bool {
        self.action_class == DeviceRevocationAdmissionAction::SessionGrantIssueOrRefresh
            && !matches!(
                self.accepted_device_possession_proof,
                Some(AcceptedDevicePossessionProof::Refresh(_))
            )
    }

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        if let Some(proof) = &self.accepted_device_possession_proof {
            if self.action_class != DeviceRevocationAdmissionAction::SessionGrantIssueOrRefresh {
                return Err(WireError::Protocol(
                    "accepted-device proof is forbidden outside session-grant issue or refresh"
                        .to_owned(),
                ));
            }
            proof.validate()?;
            if proof.account_id() != &self.account_id
                || proof.device_id() != &self.device_id
                || proof.session_intent_digest() != &self.intent_digest
            {
                return Err(WireError::Protocol(
                    "accepted-device proof does not bind the gate principal, device and intent"
                        .to_owned(),
                ));
            }
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
                if !self.is_session_grant_issue() {
                    return Err(WireError::Protocol(
                        "device revocation gate expected binding is required outside session-grant issue"
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationAdmissionDecision {
    Allow,
    RevocationPending,
    Revoked,
    AuthorityMismatch,
    GenerationMismatch,
}

impl DeviceRevocationAdmissionDecision {
    /// The single mapping from a current-device admission decision to the
    /// protocol error code a rejection surfaces; `None` for `Allow`.
    ///
    /// `AuthorityMismatch` is the "no complete current accepted device
    /// authorization" outcome — unknown, foreign, never authorized, or outside
    /// its authorization window — and surfaces as `device_unauthorized`.
    pub const fn error_code(self) -> Option<ErrorCode> {
        match self {
            Self::Allow => None,
            Self::RevocationPending => Some(ErrorCode::DeviceRevocationPending),
            Self::Revoked => Some(ErrorCode::DeviceRevoked),
            Self::AuthorityMismatch => Some(ErrorCode::DeviceUnauthorized),
            Self::GenerationMismatch => Some(ErrorCode::DeviceGenerationFenced),
        }
    }
}

/// Station-local durable decision made under its device lock.
///
/// This record remains inside the Station trust boundary. It is not a wire
/// receipt and carries no canonical operation identity or detached signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationAdmissionRecord {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    /// Origin-derived current device authorization Event. Present only for
    /// [`DeviceRevocationAdmissionDecision::Allow`], where it is the sole source for
    /// the issued grant's device binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_generation_ref: Option<u64>,
    pub action_class: DeviceRevocationAdmissionAction,
    pub intent_digest: Hash,
    /// SHA-256 of the exact canonical `AcceptedDevicePossessionProof`, present
    /// for a returning session-grant issue or human refresh once the proof was validated
    /// under the locked current accepted-device key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_device_possession_proof_digest: Option<Hash>,
    pub decision: DeviceRevocationAdmissionDecision,
    /// Monotonic sequence from the origin Station's durable
    /// device-revocation log.
    pub linearization_seq: u64,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub linearized_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    /// Present only when `decision` is
    /// [`DeviceRevocationAdmissionDecision::Revoked`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_commit_id: Option<RealmCommitId>,
}

/// Only `allow` discloses the origin-derived binding; withholding it from
/// `generation_mismatch` is what stops a refresh from being re-issued at a
/// replaced generation.
fn validate_gate_decision_witness(
    decision: DeviceRevocationAdmissionDecision,
    target_device_authorize_event_id: Option<&EventId>,
    target_device_generation_ref: Option<u64>,
    accepted_commit_id: Option<&RealmCommitId>,
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
    if derived_binding != matches!(decision, DeviceRevocationAdmissionDecision::Allow) {
        return Err(WireError::Protocol(
            "device revocation gate receipt discloses the derived binding for exactly the allow decision"
                .to_owned(),
        ));
    }
    if accepted_commit_id.is_some()
        != matches!(decision, DeviceRevocationAdmissionDecision::Revoked)
    {
        return Err(WireError::Protocol(
            "device revocation gate receipt carries the accepted commit for exactly the revoked decision"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_possession_verification_presence(
    action_class: DeviceRevocationAdmissionAction,
    proof_digest: Option<&Hash>,
) -> Result<()> {
    if proof_digest.is_some()
        && action_class != DeviceRevocationAdmissionAction::SessionGrantIssueOrRefresh
    {
        return Err(WireError::Protocol(
            "gate receipt device-possession verification does not match its action class"
                .to_owned(),
        ));
    }
    Ok(())
}

impl DeviceRevocationAdmissionRecord {
    /// Every invariant the Station-local admission record owns on its own,
    /// independent of the input it answered.
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        validate_possession_verification_presence(
            self.action_class,
            self.accepted_device_possession_proof_digest.as_ref(),
        )?;
        if self.linearization_seq == 0
            || self.expires_at <= self.linearized_at
            || self.expires_at - self.linearized_at > MAX_DEVICE_REVOCATION_ADMISSION_LIFETIME
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
            self.accepted_commit_id.as_ref(),
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
            (DeviceRevocationAdmissionDecision::Allow, Some(event_id), Some(generation))
                if generation > 0 =>
            {
                Some((event_id, generation))
            }
            _ => None,
        }
    }

    pub fn validate_for_request(&self, request: &DeviceRevocationAdmissionInput) -> Result<()> {
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
        if self.decision == DeviceRevocationAdmissionDecision::Allow
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

/// In-process result of one device-revocation admission decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationAdmissionResult {
    pub admission_record: DeviceRevocationAdmissionRecord,
}

impl DeviceRevocationAdmissionResult {
    pub fn validate_for_request(&self, request: &DeviceRevocationAdmissionInput) -> Result<()> {
        self.admission_record.validate_for_request(request)
    }

    /// Validate the receipt against the request it answered and reduce the
    /// origin decision to typed issuer control flow. Only `Authorized` permits
    /// issuance; setup and block outcomes issue nothing, while a stale or
    /// malformed receipt is a protocol error. The caller must never fall back
    /// to local device state.
    pub fn session_grant_admission(
        &self,
        request: &DeviceRevocationAdmissionInput,
        now: DateTime<Utc>,
    ) -> Result<SessionGrantAdmission<'_>> {
        self.validate_for_request(request)?;
        if now >= self.admission_record.expires_at {
            return Err(WireError::Protocol(
                "device revocation gate receipt is no longer fresh".to_owned(),
            ));
        }
        Ok(match self.admission_record.decision {
            DeviceRevocationAdmissionDecision::Allow => self
                .admission_record
                .allowed_binding()
                .map(|(authorization_event_id, device_generation_ref)| {
                    SessionGrantAdmission::Authorized {
                        authorization_event_id,
                        device_generation_ref,
                    }
                })
                .ok_or_else(|| {
                    WireError::Protocol(
                        "device revocation gate allow carries no derived binding".to_owned(),
                    )
                })?,
            DeviceRevocationAdmissionDecision::AuthorityMismatch => {
                SessionGrantAdmission::DeviceSetupRequired
            }
            DeviceRevocationAdmissionDecision::RevocationPending => {
                SessionGrantAdmission::Blocked {
                    reason: SessionGrantAdmissionBlockReason::RevocationPending,
                }
            }
            DeviceRevocationAdmissionDecision::Revoked => SessionGrantAdmission::Blocked {
                reason: SessionGrantAdmissionBlockReason::Revoked,
            },
            DeviceRevocationAdmissionDecision::GenerationMismatch => {
                SessionGrantAdmission::Blocked {
                    reason: SessionGrantAdmissionBlockReason::GenerationMismatch,
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
pub enum SessionGrantAdmission<'a> {
    /// The device has an accepted authorization the origin derived. The issued
    /// grant MUST carry exactly this binding.
    Authorized {
        authorization_event_id: &'a EventId,
        device_generation_ref: u64,
    },
    DeviceSetupRequired,
    Blocked {
        reason: SessionGrantAdmissionBlockReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionGrantAdmissionBlockReason {
    RevocationPending,
    Revoked,
    GenerationMismatch,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    use super::*;
    use crate::{
        AcceptedDeviceIssuePossessionProof, AcceptedDeviceIssuePossessionPurpose,
        AcceptedDevicePossessionProofContext, AcceptedDeviceRefreshPossessionProof,
        AcceptedDeviceRefreshPossessionPurpose, Base64UrlString, DidCoreId, DidUrl, RequestId,
        SessionGrantId,
    };

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_776_000_000 + seconds, 0).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        )
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap()
    }

    fn authorize_event() -> EventId {
        EventId::from_event_digest(&hash('e')).unwrap()
    }

    fn accepted_commit_id() -> RealmCommitId {
        RealmCommitId::from_digest([9_u8; 32])
    }

    fn request() -> DeviceRevocationAdmissionInput {
        DeviceRevocationAdmissionInput {
            account_id: account_id(),
            device_id: device_id(),
            expected_device_authorize_event_id: None,
            expected_device_generation_ref: None,
            action_class: DeviceRevocationAdmissionAction::SessionGrantIssueOrRefresh,
            intent_digest: hash('a'),
            accepted_device_possession_proof: None,
            requested_at: at(0),
        }
    }

    fn receipt() -> DeviceRevocationAdmissionRecord {
        DeviceRevocationAdmissionRecord {
            account_id: account_id(),
            device_id: device_id(),
            target_device_authorize_event_id: Some(authorize_event()),
            target_device_generation_ref: Some(7),
            action_class: DeviceRevocationAdmissionAction::SessionGrantIssueOrRefresh,
            intent_digest: hash('a'),
            accepted_device_possession_proof_digest: None,
            decision: DeviceRevocationAdmissionDecision::Allow,
            linearization_seq: 9,
            linearized_at: at(1),
            expires_at: at(31),
            accepted_commit_id: None,
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
            account_id: account_id(),
            device_id: device_id(),
            audience_id: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            holder_jkt: "A".repeat(43),
            session_intent_digest: intent_digest,
            issued_at: at(0),
            expires_at: at(300),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            signature: Base64UrlString::new(crate::base64url::base64url_encode([0u8; 64])).unwrap(),
        })
    }

    fn refresh_possession_proof(intent_digest: Hash) -> AcceptedDevicePossessionProof {
        AcceptedDevicePossessionProof::Refresh(AcceptedDeviceRefreshPossessionProof {
            context: AcceptedDevicePossessionProofContext::V1,
            purpose: AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
            predecessor_session_grant_id: SessionGrantId::new(
                "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            )
            .unwrap(),
            account_id: account_id(),
            device_id: device_id(),
            audience_id: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            holder_jkt: "A".repeat(43),
            session_intent_digest: intent_digest,
            issued_at: at(0),
            expires_at: at(300),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            signature: Base64UrlString::new(crate::base64url::base64url_encode([0u8; 64])).unwrap(),
        })
    }

    /// Round-trip the value and hold it to the schema's closed member set and
    /// its `required` list.
    fn assert_schema_shape<T>(value: &T, required: &[&str])
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let encoded = serde_json::to_value(value).unwrap();
        let decoded: T = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(&decoded, value, "the value must survive a serde round trip");

        let mut carried = encoded.clone();
        carried
            .as_object_mut()
            .unwrap()
            .insert("unexpected_member".to_owned(), Value::Bool(true));
        assert!(
            serde_json::from_value::<T>(carried).is_err(),
            "an unknown member must be rejected outright"
        );

        for member in required {
            let mut missing = encoded.clone();
            assert!(
                missing.as_object_mut().unwrap().remove(*member).is_some(),
                "the fixture must carry required member {member}"
            );
            assert!(
                serde_json::from_value::<T>(missing).is_err(),
                "required member {member} must not be omittable"
            );
        }
    }

    #[test]
    fn every_denied_admission_decision_maps_to_its_device_error_code() {
        for (decision, code) in [
            (DeviceRevocationAdmissionDecision::Allow, None),
            (
                DeviceRevocationAdmissionDecision::RevocationPending,
                Some("device_revocation_pending"),
            ),
            (
                DeviceRevocationAdmissionDecision::Revoked,
                Some("device_revoked"),
            ),
            (
                DeviceRevocationAdmissionDecision::AuthorityMismatch,
                Some("device_unauthorized"),
            ),
            (
                DeviceRevocationAdmissionDecision::GenerationMismatch,
                Some("device_generation_fenced"),
            ),
        ] {
            assert_eq!(
                decision.error_code().map(|code| code.as_str()),
                code,
                "{decision:?}"
            );
        }
    }

    #[test]
    fn gate_request_matches_its_schema_shape() {
        assert_schema_shape(
            &request(),
            &[
                "account_id",
                "device_id",
                "action_class",
                "intent_digest",
                "requested_at",
            ],
        );

        let mut full = request();
        full.expected_device_authorize_event_id = Some(authorize_event());
        full.expected_device_generation_ref = Some(7);
        full.accepted_device_possession_proof =
            Some(issue_possession_proof(full.intent_digest.clone()));
        full.validate().unwrap();
        let encoded = serde_json::to_value(&full).unwrap();
        assert_eq!(
            serde_json::from_value::<DeviceRevocationAdmissionInput>(encoded).unwrap(),
            full,
            "every optional member must survive a round trip too"
        );
    }

    #[test]
    fn gate_receipt_matches_its_schema_shape() {
        assert_schema_shape(
            &receipt(),
            &[
                "account_id",
                "device_id",
                "action_class",
                "intent_digest",
                "decision",
                "linearization_seq",
                "linearized_at",
                "expires_at",
            ],
        );

        let mut revoked = receipt();
        revoked.decision = DeviceRevocationAdmissionDecision::Revoked;
        revoked.target_device_authorize_event_id = None;
        revoked.target_device_generation_ref = None;
        revoked.accepted_commit_id = Some(accepted_commit_id());
        let encoded = serde_json::to_value(&revoked).unwrap();
        assert_eq!(
            serde_json::from_value::<DeviceRevocationAdmissionRecord>(encoded).unwrap(),
            revoked,
            "the revoked branch must survive a round trip with its accepted commit"
        );
    }

    #[test]
    fn gate_outcome_matches_its_schema_shape() {
        assert_schema_shape(
            &DeviceRevocationAdmissionResult {
                admission_record: receipt(),
            },
            &["admission_record"],
        );
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
                serde_json::from_value::<DeviceRevocationAdmissionRecord>(carried).is_err(),
                "a receipt carrying {member} must be rejected outright"
            );
        }
    }

    #[test]
    fn gate_receipt_binds_exact_request() {
        let request = request();
        let receipt = receipt();
        receipt.validate().unwrap();
        receipt.validate_for_request(&request).unwrap();
    }

    #[test]
    fn gate_receipt_rejects_open_branch_or_stale_window() {
        let request = request();
        let mut invalid = receipt();
        invalid.accepted_commit_id = Some(accepted_commit_id());
        assert!(invalid.validate().is_err());
        assert!(invalid.validate_for_request(&request).is_err());

        let mut expired = receipt();
        expired.expires_at = expired.linearized_at;
        assert!(expired.validate().is_err());
        assert!(expired.validate_for_request(&request).is_err());

        let mut overlong = receipt();
        overlong.expires_at = overlong.linearized_at + Duration::seconds(31);
        assert!(overlong.validate().is_err());

        let mut stray_proof = receipt();
        stray_proof.action_class = DeviceRevocationAdmissionAction::EventWrite;
        stray_proof.accepted_device_possession_proof_digest = Some(hash('e'));
        assert!(stray_proof.validate().is_err());
    }

    #[test]
    fn request_generation_must_be_positive() {
        let mut invalid = request();
        invalid.expected_device_authorize_event_id = Some(authorize_event());
        invalid.expected_device_generation_ref = Some(0);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn registration_issue_omits_the_expected_binding_and_every_other_action_class_requires_it() {
        let registration_issue = request();
        assert!(
            registration_issue
                .expected_device_authorize_event_id
                .is_none()
        );
        registration_issue.validate().unwrap();
        // Omission is not serialized, so the request cannot smuggle a null.
        let value = serde_json::to_value(&registration_issue).unwrap();
        assert!(value.get("expected_device_authorize_event_id").is_none());

        let mut write = request();
        write.action_class = DeviceRevocationAdmissionAction::EventWrite;
        assert!(write.validate().is_err());
        write.expected_device_authorize_event_id = Some(authorize_event());
        write.expected_device_generation_ref = Some(7);
        write.validate().unwrap();

        let mut code_claim = request();
        code_claim.action_class = DeviceRevocationAdmissionAction::DevicePairingCodeClaim;
        assert!(code_claim.validate().is_err());
        code_claim.expected_device_authorize_event_id = Some(authorize_event());
        code_claim.expected_device_generation_ref = Some(7);
        code_claim.validate().unwrap();
        assert_eq!(
            serde_json::to_value(code_claim.action_class).unwrap(),
            serde_json::json!("device_pairing_code_claim")
        );
        code_claim.accepted_device_possession_proof =
            Some(issue_possession_proof(code_claim.intent_digest.clone()));
        assert!(code_claim.validate().is_err());

        let mut half = request();
        half.expected_device_generation_ref = Some(7);
        assert!(half.validate().is_err());
    }

    #[test]
    fn admission_action_text_is_its_wire_spelling() {
        for action in [
            DeviceRevocationAdmissionAction::SessionGrantIssueOrRefresh,
            DeviceRevocationAdmissionAction::DevicePairingCodeClaim,
            DeviceRevocationAdmissionAction::KeypackageClaim,
            DeviceRevocationAdmissionAction::ToDeviceWrite,
            DeviceRevocationAdmissionAction::EventWrite,
        ] {
            assert_eq!(
                serde_json::to_value(action).unwrap(),
                serde_json::json!(action.as_str())
            );
        }
        for denied in DEVICE_REVOCATION_DENIED_ACTIONS {
            let action: DeviceRevocationAdmissionAction =
                serde_json::from_value(serde_json::to_value(denied).unwrap()).unwrap();
            assert_eq!(
                serde_json::to_value(action).unwrap(),
                serde_json::to_value(denied).unwrap()
            );
        }
    }

    #[test]
    fn issue_and_refresh_share_one_action_class_distinguished_by_their_proof() {
        let registration = request();
        assert!(registration.is_session_grant_issue());
        registration.validate().unwrap();

        let mut returning = request();
        returning.accepted_device_possession_proof =
            Some(issue_possession_proof(returning.intent_digest.clone()));
        assert!(returning.is_session_grant_issue());
        returning.validate().unwrap();

        let mut mismatched = returning;
        mismatched.intent_digest = hash('d');
        assert!(mismatched.validate().is_err());

        let mut refresh = request();
        refresh.accepted_device_possession_proof =
            Some(refresh_possession_proof(refresh.intent_digest.clone()));
        assert!(!refresh.is_session_grant_issue());
        assert!(
            refresh.validate().is_err(),
            "a refresh must name the predecessor grant's exact device binding"
        );
        refresh.expected_device_authorize_event_id = Some(authorize_event());
        refresh.expected_device_generation_ref = Some(7);
        refresh.validate().unwrap();
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
        mismatch.decision = DeviceRevocationAdmissionDecision::GenerationMismatch;
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
        let mut returning = request();
        returning.accepted_device_possession_proof =
            Some(issue_possession_proof(returning.intent_digest.clone()));
        returning.expected_device_authorize_event_id = Some(authorize_event());
        returning.expected_device_generation_ref = Some(6);
        returning.validate().unwrap();

        let mut upgraded = receipt();
        upgraded.accepted_device_possession_proof_digest = Some(
            returning
                .accepted_device_possession_proof
                .as_ref()
                .unwrap()
                .proof_digest()
                .unwrap(),
        );
        upgraded.validate().unwrap();
        assert!(
            upgraded.validate_for_request(&returning).is_err(),
            "an allow may not answer generation 6 with generation 7"
        );
    }

    #[test]
    fn blocked_or_stale_receipts_admit_nothing() {
        let request = request();
        let outcome = DeviceRevocationAdmissionResult {
            admission_record: receipt(),
        };
        assert_eq!(
            outcome.session_grant_admission(&request, at(2)).unwrap(),
            SessionGrantAdmission::Authorized {
                authorization_event_id: &authorize_event(),
                device_generation_ref: 7,
            }
        );
        assert!(
            outcome.session_grant_admission(&request, at(31)).is_err(),
            "a receipt at or past expires_at admits nothing"
        );

        for decision in [
            DeviceRevocationAdmissionDecision::RevocationPending,
            DeviceRevocationAdmissionDecision::Revoked,
            DeviceRevocationAdmissionDecision::GenerationMismatch,
        ] {
            let mut blocked = receipt();
            blocked.decision = decision;
            blocked.target_device_authorize_event_id = None;
            blocked.target_device_generation_ref = None;
            if decision == DeviceRevocationAdmissionDecision::Revoked {
                blocked.accepted_commit_id = Some(accepted_commit_id());
            }
            let outcome = DeviceRevocationAdmissionResult {
                admission_record: blocked,
            };
            let admission = outcome.session_grant_admission(&request, at(2)).unwrap();
            assert!(matches!(admission, SessionGrantAdmission::Blocked { .. }));
        }
    }

    #[test]
    fn authority_mismatch_requires_device_setup_and_never_issues_a_grant() {
        let request = request();
        let mut fresh = receipt();
        fresh.decision = DeviceRevocationAdmissionDecision::AuthorityMismatch;
        fresh.target_device_authorize_event_id = None;
        fresh.target_device_generation_ref = None;
        let outcome = DeviceRevocationAdmissionResult {
            admission_record: fresh,
        };
        assert_eq!(
            outcome.session_grant_admission(&request, at(2)).unwrap(),
            SessionGrantAdmission::DeviceSetupRequired
        );
    }

    fn pending_state() -> DeviceRevocationPendingState {
        DeviceRevocationPendingState {
            schema: DeviceRevocationStateSchema::V1,
            account_id: account_id(),
            device_id: device_id(),
            target_device_authorize_event_id: authorize_event(),
            target_device_generation_ref: 7,
            proposal_event_id: EventId::from_event_digest(&hash('f')).unwrap(),
            accepted_at: at(0),
            acceptance_seq: 1,
            status: DeviceRevocationPendingStatus::RevocationPending,
            denied_actions: DEVICE_REVOCATION_DENIED_ACTIONS,
        }
    }

    fn revoked_state() -> DeviceRevokedState {
        DeviceRevokedState {
            schema: DeviceRevocationStateSchema::V1,
            account_id: account_id(),
            device_id: device_id(),
            target_device_authorize_event_id: authorize_event(),
            target_device_generation_ref: 7,
            proposal_event_id: EventId::from_event_digest(&hash('f')).unwrap(),
            accepted_at: at(0),
            acceptance_seq: 1,
            status: DeviceRevokedStatus::Revoked,
            committed_at: at(5),
        }
    }

    fn rejected_state() -> DeviceRevocationRejectedState {
        DeviceRevocationRejectedState {
            schema: DeviceRevocationStateSchema::V1,
            account_id: account_id(),
            device_id: device_id(),
            target_device_authorize_event_id: authorize_event(),
            target_device_generation_ref: 7,
            proposal_event_id: EventId::from_event_digest(&hash('f')).unwrap(),
            accepted_at: at(0),
            acceptance_seq: 1,
            status: DeviceRevocationRejectedStatus::RevocationRejected,
        }
    }

    #[test]
    fn durable_records_match_their_schema_shape() {
        let common = [
            "schema",
            "account_id",
            "device_id",
            "target_device_authorize_event_id",
            "target_device_generation_ref",
            "proposal_event_id",
            "accepted_at",
            "acceptance_seq",
        ];
        let mut pending_required = common.to_vec();
        pending_required.extend(["status", "denied_actions"]);
        assert_schema_shape(&pending_state(), &pending_required);

        let mut rejected_required = common.to_vec();
        rejected_required.push("status");
        assert_schema_shape(&rejected_state(), &rejected_required);

        let mut revoked_required = common.to_vec();
        revoked_required.extend(["status", "committed_at"]);
        assert_schema_shape(&revoked_state(), &revoked_required);
    }

    #[test]
    fn record_status_selects_the_branch_and_the_gate_excludes_rejections() {
        for (record, is_gate_relevant) in [
            (DeviceRevocationRecord::Pending(pending_state()), true),
            (DeviceRevocationRecord::Rejected(rejected_state()), false),
            (DeviceRevocationRecord::Revoked(revoked_state()), true),
        ] {
            record.validate().unwrap();
            let encoded = serde_json::to_value(&record).unwrap();
            assert_eq!(
                serde_json::from_value::<DeviceRevocationRecord>(encoded).unwrap(),
                record,
                "the status const must select the same branch on the way back"
            );
            assert_eq!(record.gate_record().is_some(), is_gate_relevant);
        }

        let gate = DeviceRevocationGateRecord::Pending(pending_state());
        gate.validate().unwrap();
        assert!(gate.is_pending());
        assert!(!gate.is_revoked());
        assert!(
            serde_json::from_value::<DeviceRevocationGateRecord>(
                serde_json::to_value(rejected_state()).unwrap()
            )
            .is_err(),
            "a rejected record is not a gate record"
        );
    }

    #[test]
    fn durable_records_reject_inconsistent_selectors() {
        let mut zero_generation = pending_state();
        zero_generation.target_device_generation_ref = 0;
        assert!(zero_generation.validate().is_err());

        let mut zero_seq = pending_state();
        zero_seq.acceptance_seq = 0;
        assert!(zero_seq.validate().is_err());

        let mut reordered = pending_state();
        reordered.denied_actions = [
            DeviceRevocationDeniedAction::EventWrite,
            DeviceRevocationDeniedAction::KeypackageClaim,
            DeviceRevocationDeniedAction::ToDeviceWrite,
            DeviceRevocationDeniedAction::DevicePairingCodeClaim,
            DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        ];
        assert!(reordered.validate().is_err());

        let mut early_commit = revoked_state();
        early_commit.committed_at = at(-1);
        assert!(early_commit.validate().is_err());
    }
}
