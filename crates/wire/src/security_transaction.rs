//! Cross-service security transactions (`zh/identity/security-transactions.md`).
//!
//! v1 defines exactly two: recovery and security rotation. They are
//! deliberately NOT a general Saga/Plan DSL — each `kind` selects a closed
//! binding shape and a closed, ordered step set, and `accepted_steps` must
//! be a contiguous prefix of that order. A generic "submit an arbitrary step
//! list" interface would reintroduce exactly the executable-plan surface v1
//! removed.
//!
//! Server-side transaction state MUST NOT contain mnemonics, seeds, device
//! private keys, plaintext keybags or MLS secrets.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::primitives::Proof;
use crate::{DeviceId, Did, EventId, Hash, ReceiptId, TransactionId};

/// Default ceiling on `expires_at - created_at`.
pub const MAX_SECURITY_TRANSACTION_TTL: Duration = Duration::hours(24);

/// Maximum recorded accepted steps (the longer of the two closed step sets).
pub const MAX_ACCEPTED_STEPS: usize = 5;

pub const MAX_OPAQUE_REF_CHARS: usize = 512;

/// Closed recovery step order.
pub const RECOVERY_STEP_ORDER: [SecurityTransactionStep; 5] = [
    SecurityTransactionStep::OpenRecoverySession,
    SecurityTransactionStep::ValidateAuthorityTicket,
    SecurityTransactionStep::PublishDidEntry,
    SecurityTransactionStep::SubmitReanchorUnit,
    SecurityTransactionStep::IssueTerminalReceipt,
];

/// Closed security-rotation step order.
pub const SECURITY_ROTATION_STEP_ORDER: [SecurityTransactionStep; 5] = [
    SecurityTransactionStep::Revoke,
    SecurityTransactionStep::UploadNewMaterial,
    SecurityTransactionStep::SwitchAuthoritativePointer,
    SecurityTransactionStep::EraseOldMaterial,
    SecurityTransactionStep::LocalCommit,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionKind {
    Recovery,
    SecurityRotation,
}

impl SecurityTransactionKind {
    pub fn step_order(self) -> &'static [SecurityTransactionStep] {
        match self {
            Self::Recovery => &RECOVERY_STEP_ORDER,
            Self::SecurityRotation => &SECURITY_ROTATION_STEP_ORDER,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionState {
    Pending,
    Running,
    Completed,
    Aborted,
    Expired,
}

impl SecurityTransactionState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted | Self::Expired)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionResultKind {
    Completed,
    Aborted,
    Expired,
}

/// Union of both closed step sets. Which subset is legal is decided by
/// [`SecurityTransactionKind::step_order`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionStep {
    OpenRecoverySession,
    ValidateAuthorityTicket,
    PublishDidEntry,
    SubmitReanchorUnit,
    IssueTerminalReceipt,
    Revoke,
    UploadNewMaterial,
    SwitchAuthoritativePointer,
    EraseOldMaterial,
    LocalCommit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedStep {
    pub step: SecurityTransactionStep,
    pub output_ref: String,
    pub output_digest: Hash,
}

/// Fixed recovery bindings, all reserved before the first irreversible effect.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBinding {
    pub recovery_session_id: String,
    pub did_entry_ref: String,
    pub replacement_device_id: DeviceId,
    pub authorize_event_id: EventId,
    pub reanchor_event_id: EventId,
    pub authority_ticket_ref: String,
    pub terminal_receipt_id: ReceiptId,
}

/// Fixed security-rotation bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationBinding {
    pub revoke_event_id: EventId,
    pub new_secret_commitment: Hash,
    pub series_id: String,
    pub backup_id: String,
    pub active_series_event_id: EventId,
    pub erase_confirmation_digest: String,
    pub local_commit_digest: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecurityTransactionBinding {
    Recovery(RecoveryBinding),
    SecurityRotation(SecurityRotationBinding),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionTerminalResult {
    pub result: SecurityTransactionResultKind,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<ReceiptId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// Authoritative progress resource for one security transaction.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransaction {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub principal_id: Did,
    pub coordinator_service_id: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub request_digest: Hash,
    pub binding: SecurityTransactionBinding,
    pub state: SecurityTransactionState,
    pub accepted_steps: Vec<AcceptedStep>,
    pub next_required_step: Option<SecurityTransactionStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<SecurityTransactionTerminalResult>,
}

/// Typed recovery intent supplied at create time.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryIntent {
    pub recovery_session_id: String,
    pub replacement_device_id: DeviceId,
    pub authority_ticket_ref: String,
    pub did_entry_digest: Hash,
    pub replacement_device_authorization_digest: Hash,
}

/// Typed security-rotation intent supplied at create time.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationIntent {
    pub revoke_event_digest: Hash,
    pub new_secret_commitment: Hash,
    pub staged_material_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecurityTransactionIntent {
    Recovery(RecoveryIntent),
    SecurityRotation(SecurityRotationIntent),
}

/// `ak.self.security_transaction.command.create` body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub principal_id: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub intent: SecurityTransactionIntent,
}

/// Device attestation over one terminal step.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStepAttestation {
    pub output_ref: String,
    pub output_digest: Hash,
    pub proof: Proof,
}

/// `ak.self.security_transaction.command.continue` body.
///
/// This resumes the one step the resource currently expects; it is not an
/// interface for submitting an arbitrary step list.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionContinueRequest {
    pub request_digest: Hash,
    pub expected_next_step: SecurityTransactionStep,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientStepAttestation>,
}

fn validate_opaque_ref(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().count() > MAX_OPAQUE_REF_CHARS {
        return Err(Error::Protocol(format!(
            "{name} must be 1..={MAX_OPAQUE_REF_CHARS} characters"
        )));
    }
    Ok(())
}

/// A pre-reserved step output reference: a typed `ak:` id, a DID, or a bare
/// digest.
///
/// The shape is closed so a coordinator cannot smuggle an opaque local handle
/// into a slot that the transaction contract requires to name a durable,
/// independently resolvable object.
fn validate_step_output_ref(name: &str, value: &str) -> Result<()> {
    validate_opaque_ref(name, value)?;
    let typed_id = value
        .strip_prefix("ak:")
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(kind, rest)| {
            !kind.is_empty()
                && kind.starts_with(|c: char| c.is_ascii_lowercase())
                && kind
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !rest.is_empty()
        });
    let did = value.starts_with("did:") && value.len() > 4;
    let digest = Hash::new(value).is_ok();
    if !(typed_id || did || digest) {
        return Err(Error::Protocol(format!(
            "{name} must be a typed ak: id, a DID, or a bare digest"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(Error::Protocol(format!(
            "{name} must not contain whitespace"
        )));
    }
    Ok(())
}

impl SecurityTransaction {
    /// Steps that may still be accepted, in order, after the recorded prefix.
    pub fn remaining_steps(&self) -> &'static [SecurityTransactionStep] {
        let order = self.kind.step_order();
        &order[self.accepted_steps.len().min(order.len())..]
    }

    /// Enforce every invariant the resource alone can decide.
    ///
    /// The step list must be a contiguous prefix of this kind's closed order —
    /// no skipping, no reordering, no second digest for the same step — and
    /// `next_required_step` must be exactly the next item, or `null` in a
    /// terminal state.
    pub fn validate_structural(&self) -> Result<()> {
        if self.expires_at <= self.created_at {
            return Err(Error::Protocol(
                "security transaction expires_at must be after created_at".to_owned(),
            ));
        }
        if self.expires_at - self.created_at > MAX_SECURITY_TRANSACTION_TTL {
            return Err(Error::Protocol(format!(
                "security transaction TTL exceeds {} hours",
                MAX_SECURITY_TRANSACTION_TTL.num_hours()
            )));
        }
        match (self.kind, &self.binding) {
            (SecurityTransactionKind::Recovery, SecurityTransactionBinding::Recovery(binding)) => {
                validate_opaque_ref("recovery_session_id", &binding.recovery_session_id)?;
                validate_opaque_ref("did_entry_ref", &binding.did_entry_ref)?;
                validate_opaque_ref("authority_ticket_ref", &binding.authority_ticket_ref)?;
            }
            (
                SecurityTransactionKind::SecurityRotation,
                SecurityTransactionBinding::SecurityRotation(binding),
            ) => {
                validate_opaque_ref("series_id", &binding.series_id)?;
                validate_opaque_ref("backup_id", &binding.backup_id)?;
                validate_opaque_ref(
                    "erase_confirmation_digest",
                    &binding.erase_confirmation_digest,
                )?;
                validate_opaque_ref("local_commit_digest", &binding.local_commit_digest)?;
            }
            _ => {
                return Err(Error::Protocol(
                    "security transaction binding shape does not match its kind".to_owned(),
                ));
            }
        }

        let order = self.kind.step_order();
        if self.accepted_steps.len() > order.len() {
            return Err(Error::Protocol(
                "security transaction recorded more steps than its closed order defines".to_owned(),
            ));
        }
        for (index, accepted) in self.accepted_steps.iter().enumerate() {
            if accepted.step != order[index] {
                return Err(Error::Protocol(format!(
                    "security transaction step {index} is {:?}, expected {:?}",
                    accepted.step, order[index]
                )));
            }
            validate_step_output_ref("accepted_steps[].output_ref", &accepted.output_ref)?;
        }

        if self.state.is_terminal() {
            if self.next_required_step.is_some() {
                return Err(Error::Protocol(
                    "terminal security transaction must not declare a next required action"
                        .to_owned(),
                ));
            }
            let outcome = self.terminal_result.as_ref().ok_or_else(|| {
                Error::Protocol(
                    "terminal security transaction must record a terminal outcome".to_owned(),
                )
            })?;
            let expected = match self.state {
                SecurityTransactionState::Completed => SecurityTransactionResultKind::Completed,
                SecurityTransactionState::Aborted => SecurityTransactionResultKind::Aborted,
                SecurityTransactionState::Expired => SecurityTransactionResultKind::Expired,
                _ => unreachable!("state was checked to be terminal"),
            };
            if outcome.result != expected {
                return Err(Error::Protocol(
                    "security transaction terminal outcome disagrees with its state".to_owned(),
                ));
            }
            return Ok(());
        }

        if self.terminal_result.is_some() {
            return Err(Error::Protocol(
                "non-terminal security transaction must not record a terminal outcome".to_owned(),
            ));
        }
        let next = self.next_required_step.ok_or_else(|| {
            Error::Protocol(
                "non-terminal security transaction must declare a next required action".to_owned(),
            )
        })?;
        let expected = order.get(self.accepted_steps.len()).copied();
        if Some(next) != expected {
            return Err(Error::Protocol(format!(
                "security transaction next_required_step {next:?} is not the next closed step {expected:?}"
            )));
        }
        Ok(())
    }

    /// Whether `step` may carry a [`ClientStepAttestation`].
    ///
    /// Only the two terminal device-attested steps may; the attestation `ref`
    /// must equal the id already reserved in the binding.
    pub fn step_accepts_client_attestation(step: SecurityTransactionStep) -> bool {
        matches!(
            step,
            SecurityTransactionStep::IssueTerminalReceipt | SecurityTransactionStep::LocalCommit
        )
    }

    /// Validate a continue request against this resource.
    pub fn validate_continue(&self, request: &SecurityTransactionContinueRequest) -> Result<()> {
        if request.request_digest != self.request_digest {
            return Err(Error::Protocol(
                crate::error_codes::ReasonCode::DUPLICATE_CONFLICT.to_owned(),
            ));
        }
        if Some(request.expected_next_step) != self.next_required_step {
            return Err(Error::Protocol(
                "continue expected_next_step does not equal the resource's next action".to_owned(),
            ));
        }
        if let Some(attestation) = &request.client_attestation {
            if !Self::step_accepts_client_attestation(request.expected_next_step) {
                return Err(Error::Protocol(
                    "client attestation is only accepted on issue_terminal_receipt or local_commit"
                        .to_owned(),
                ));
            }
            let reserved = match &self.binding {
                SecurityTransactionBinding::Recovery(binding) => {
                    binding.terminal_receipt_id.as_str().to_owned()
                }
                SecurityTransactionBinding::SecurityRotation(binding) => {
                    binding.local_commit_digest.clone()
                }
            };
            if attestation.output_ref != reserved {
                return Err(Error::Protocol(
                    "client attestation ref does not equal the reserved binding id".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn rotation(accepted: usize, state: SecurityTransactionState) -> SecurityTransaction {
        let created_at = Utc.with_ymd_and_hms(2026, 7, 28, 0, 0, 0).unwrap();
        let refs = SECURITY_ROTATION_STEP_ORDER
            .iter()
            .take(accepted)
            .enumerate()
            .map(|(i, step)| AcceptedStep {
                step: *step,
                output_ref: format!("ak:receipt:01904100-0000-7000-8000-00000000000{i:x}"),
                output_digest: hash('a'),
            })
            .collect::<Vec<_>>();
        SecurityTransaction {
            transaction_id: TransactionId::new(
                "ak:transaction:01904100-0000-7000-8000-abcdefabcdef",
            )
            .unwrap(),
            kind: SecurityTransactionKind::SecurityRotation,
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            coordinator_service_id: Did::new("did:webvh:z6mkfixture:coordinator.example").unwrap(),
            expires_at: created_at + Duration::hours(4),
            created_at,
            request_digest: hash('b'),
            binding: SecurityTransactionBinding::SecurityRotation(SecurityRotationBinding {
                revoke_event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575")
                    .unwrap(),
                new_secret_commitment: hash('c'),
                series_id: "series-1".to_owned(),
                backup_id: "backup-1".to_owned(),
                active_series_event_id: EventId::new(
                    "ak:event:01904100-0000-7000-8000-a0086f45c576",
                )
                .unwrap(),
                erase_confirmation_digest: "erase-1".to_owned(),
                local_commit_digest: "local-1".to_owned(),
            }),
            state,
            next_required_step: if state.is_terminal() {
                None
            } else {
                SECURITY_ROTATION_STEP_ORDER.get(accepted).copied()
            },
            accepted_steps: refs,
            terminal_result: state
                .is_terminal()
                .then(|| SecurityTransactionTerminalResult {
                    result: SecurityTransactionResultKind::Completed,
                    completed_at: created_at + Duration::hours(1),
                    receipt_id: None,
                    reason_code: None,
                }),
        }
    }

    #[test]
    fn accepted_steps_must_be_a_contiguous_prefix_of_the_closed_order() {
        rotation(2, SecurityTransactionState::Running)
            .validate_structural()
            .unwrap();

        let mut skipped = rotation(2, SecurityTransactionState::Running);
        skipped.accepted_steps[1].step = SecurityTransactionStep::EraseOldMaterial;
        let err = skipped.validate_structural().unwrap_err();
        assert!(err.to_string().contains("step 1"), "{err}");
    }

    #[test]
    fn next_required_step_must_be_the_next_closed_step() {
        let mut jumped = rotation(1, SecurityTransactionState::Running);
        jumped.next_required_step = Some(SecurityTransactionStep::LocalCommit);
        let err = jumped.validate_structural().unwrap_err();
        assert!(err.to_string().contains("next closed step"), "{err}");
    }

    #[test]
    fn terminal_state_requires_a_matching_outcome_and_no_next_action() {
        rotation(5, SecurityTransactionState::Completed)
            .validate_structural()
            .unwrap();

        let mut still_running = rotation(5, SecurityTransactionState::Completed);
        still_running.next_required_step = Some(SecurityTransactionStep::LocalCommit);
        assert!(still_running.validate_structural().is_err());

        let mut wrong_outcome = rotation(5, SecurityTransactionState::Completed);
        wrong_outcome.state = SecurityTransactionState::Aborted;
        let err = wrong_outcome.validate_structural().unwrap_err();
        assert!(
            err.to_string().contains("disagrees with its state"),
            "{err}"
        );
    }

    #[test]
    fn binding_shape_must_match_the_transaction_kind() {
        let mut mismatched = rotation(0, SecurityTransactionState::Pending);
        mismatched.kind = SecurityTransactionKind::Recovery;
        let err = mismatched.validate_structural().unwrap_err();
        assert!(err.to_string().contains("binding shape"), "{err}");
    }

    #[test]
    fn continue_requires_the_recorded_request_digest_and_expected_action() {
        let resource = rotation(2, SecurityTransactionState::Running);
        resource
            .validate_continue(&SecurityTransactionContinueRequest {
                request_digest: hash('b'),
                expected_next_step: SecurityTransactionStep::SwitchAuthoritativePointer,
                client_attestation: None,
            })
            .unwrap();

        let err = resource
            .validate_continue(&SecurityTransactionContinueRequest {
                request_digest: hash('f'),
                expected_next_step: SecurityTransactionStep::SwitchAuthoritativePointer,
                client_attestation: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("duplicate_conflict"), "{err}");
    }
}
