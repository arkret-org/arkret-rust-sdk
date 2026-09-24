//! Closed durable recovery and security-rotation transaction DTOs.
//!
//! Producer Events remain immutable producer facts. A recovery request freezes
//! the two signed Events and the current Principal Control Realm stream head;
//! only the governance Station may later create their consecutive
//! [`arkret_wire::RealmCommit`] records. No authority-side protocol carrier or
//! producer-side ordering coordinate is carried here.

use std::collections::{BTreeSet, HashSet};

use arkret_wire::{
    AccountId, ActorId, BackupId, BackupSeriesId, Base64UrlString, CanonicalPublicMaterial,
    CommitStreamRef, DeviceId, DidCoreId, DidUrl, Event, EventId, EventKind, Hash, MlsGroupId,
    PolicyId, RealmCommitId, RealmId, ReasonCode, ReceiptId, RecoveryCompletionAttestation,
    RecoverySessionId, Result, SchemaId, ScopeRef, TransactionId, TrustDomainId, WireError,
    XExtensionMap,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

pub const MAX_SECURITY_TRANSACTION_TTL: Duration = Duration::hours(24);
pub const MAX_STEP_OUTPUT_REF_CHARS: usize = 2048;
pub const RECOVERY_UNIT_EVENT_COUNT: usize = 2;

pub const RECOVERY_STEP_ORDER: [SecurityTransactionStep; 1] =
    [SecurityTransactionStep::CommitRecoveryUnit];
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryIdentityModel {
    PcrPolicy,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRotationKind {
    SecretStorage,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionStep {
    CommitRecoveryUnit,
    Revoke,
    UploadNewMaterial,
    SwitchAuthoritativePointer,
    EraseOldMaterial,
    LocalCommit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityTransactionAcceptor {
    Principal { principal_id: DidCoreId },
    Device { device_id: DeviceId },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedSecurityTransactionStep {
    pub prepared_material_digest: Hash,
    pub acceptor: SecurityTransactionAcceptor,
    pub output_ref: String,
    pub output_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// Exact signed producer Events frozen as one transaction-owned submit unit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEventBatchRequest {
    pub events: Vec<Event>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEventUnit {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub request: PreparedEventBatchRequest,
    pub request_digest: Hash,
}

impl PreparedEventUnit {
    pub fn new(
        digest_suite: arkret_canonical::DigestSuite,
        request: PreparedEventBatchRequest,
    ) -> Result<Self> {
        let request_digest = digest_value(digest_suite, &request)?;
        Ok(Self {
            request,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest_of(
            "prepared Event request",
            &self.request,
            &self.request_digest,
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommitIntent {
    pub realm_id: RealmId,
    pub predecessor_ref: RealmCommitId,
    pub unit_event_digests: [Hash; RECOVERY_UNIT_EVENT_COUNT],
}

impl RecoveryCommitIntent {
    pub fn validate(&self) -> Result<()> {
        if self.unit_event_digests[0] == self.unit_event_digests[1]
            || self.unit_event_digests.iter().any(|digest| {
                !matches!(
                    digest.digest_suite(),
                    Ok(arkret_canonical::DigestSuite::Sha256)
                )
            })
        {
            return protocol(
                "recovery commit intent requires distinct SHA-256 [reanchor, authorize] Event digests",
            );
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrPolicyRecoveryIntent {
    pub recovery_session_id: RecoverySessionId,
    pub replacement_device_id: DeviceId,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub terminal_receipt_id: ReceiptId,
    pub reanchor_unit: PreparedEventUnit,
    pub reanchor_commit_intent: RecoveryCommitIntent,
}

impl PcrPolicyRecoveryIntent {
    pub fn validate(&self, account_id: &AccountId) -> Result<()> {
        validate_generation_advance(
            self.previous_model_generation_ref,
            self.result_model_generation_ref,
        )?;
        validate_recovery_event_unit(
            account_id,
            &self.reanchor_unit,
            &self.reanchor_commit_intent,
            None,
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrPolicyRecoveryBinding {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_id: RecoverySessionId,
    pub replacement_device_id: DeviceId,
    pub reanchor_event_id: EventId,
    pub authorize_event_id: EventId,
    pub terminal_receipt_id: ReceiptId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrPolicyRecoveryPlan {
    pub binding: PcrPolicyRecoveryBinding,
    pub recovery_session_snapshot_digest: Hash,
    pub proof_digest: Hash,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub reanchor_unit: PreparedEventUnit,
    pub reanchor_commit_intent: RecoveryCommitIntent,
}

impl PcrPolicyRecoveryPlan {
    pub fn validate(&self, account_id: &AccountId) -> Result<()> {
        if self.binding.identity_model != RecoveryIdentityModel::PcrPolicy {
            return protocol("recovery plan requires the PCR-policy identity model");
        }
        validate_generation_advance(
            self.previous_model_generation_ref,
            self.result_model_generation_ref,
        )?;
        validate_recovery_event_unit(
            account_id,
            &self.reanchor_unit,
            &self.reanchor_commit_intent,
            Some(&self.binding),
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupObjectRef {
    pub backup_id: BackupId,
    pub ciphertext_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRotationBinding {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub new_backups: Vec<BackupObjectRef>,
    pub active_series_event_id: EventId,
    pub old_backups: Vec<BackupObjectRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRotationPlan {
    pub binding: BackupRotationBinding,
    pub encrypted_backup_material: CanonicalPublicMaterial,
    pub active_series_unit: PreparedEventUnit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationPlan {
    pub revoke_unit: PreparedEventUnit,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<BackupRotationPlan>,
    pub erase_confirmation_digest: Hash,
    pub local_commit_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeriesEraseStatus {
    Partial,
    Complete,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeriesEraseRowStatus {
    Pending,
    FailedRetryable,
    Erased,
}

/// Exact transaction-bound request for erasing the old `secret_storage` series.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseRequestBody {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub erase_confirmation_digest: Hash,
    pub series: Vec<BackupRotationBinding>,
    pub authority_commit_id: RealmCommitId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseRow {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub status: BackupSeriesEraseRowStatus,
    pub erased_backups: Vec<BackupObjectRef>,
    pub remaining_backups: Vec<BackupObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseConfirmation {
    pub schema: SchemaId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub series: Vec<BackupRotationBinding>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseOutcome {
    pub transaction_id: TransactionId,
    pub request_digest: Hash,
    pub status: BackupSeriesEraseStatus,
    pub series_records: Vec<BackupSeriesEraseRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<BackupSeriesEraseConfirmation>,
}

fn validate_backup_object_refs(refs: &[BackupObjectRef], label: &str) -> Result<()> {
    if refs.len() > 512 {
        return protocol(format!("{label} exceeds 512 backup object references"));
    }
    let mut backup_ids = BTreeSet::new();
    if refs
        .iter()
        .any(|object| !backup_ids.insert(object.backup_id.clone()))
    {
        return protocol(format!("{label} backup object references must be unique"));
    }
    Ok(())
}

fn validate_canonical_backup_object_refs(refs: &[BackupObjectRef], label: &str) -> Result<()> {
    validate_backup_object_refs(refs, label)?;
    if refs
        .windows(2)
        .any(|pair| pair[0].backup_id.as_str() >= pair[1].backup_id.as_str())
    {
        return protocol(format!("{label} must be canonical backup-id sorted"));
    }
    Ok(())
}

fn validate_erase_rotation_bindings(series: &[BackupRotationBinding]) -> Result<()> {
    let [binding]: &[_; 1] = series.try_into().map_err(|_| {
        WireError::Protocol(
            "backup-series erase requires exactly one secret_storage series".to_owned(),
        )
    })?;
    if binding.backup_kind != BackupRotationKind::SecretStorage
        || binding.previous_series_id == binding.new_series_id
        || binding.new_backups.is_empty()
        || binding.old_backups.is_empty()
    {
        return protocol(
            "backup-series erase binding requires one changed secret_storage series with non-empty backup sets",
        );
    }
    validate_backup_object_refs(&binding.new_backups, "new_backups")?;
    validate_backup_object_refs(&binding.old_backups, "old_backups")
}

impl BackupSeriesEraseRequestBody {
    pub fn validate_structural(&self) -> Result<()> {
        validate_erase_rotation_bindings(&self.series)?;
        if self.erase_confirmation_digest
            != security_rotation_erase_confirmation_digest(&self.transaction_id, &self.series)?
        {
            return protocol(
                "backup-series erase confirmation digest changed its fixed projection",
            );
        }
        Ok(())
    }
}

impl BackupSeriesEraseConfirmation {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != SchemaId::BackupSeriesEraseConfirmationV1 {
            return protocol("backup-series erase confirmation schema is invalid");
        }
        validate_erase_rotation_bindings(&self.series)
    }
}

impl BackupSeriesEraseOutcome {
    pub fn validate_structural(&self) -> Result<()> {
        let [record]: &[_; 1] = self.series_records.as_slice().try_into().map_err(|_| {
            WireError::Protocol(
                "backup-series erase outcome requires exactly one secret_storage record".to_owned(),
            )
        })?;
        if record.backup_kind != BackupRotationKind::SecretStorage
            || record.previous_series_id == record.new_series_id
        {
            return protocol("backup-series erase record has an invalid series binding");
        }
        validate_canonical_backup_object_refs(&record.erased_backups, "erased_backups")?;
        validate_canonical_backup_object_refs(&record.remaining_backups, "remaining_backups")?;
        match record.status {
            BackupSeriesEraseRowStatus::Erased
                if !record.remaining_backups.is_empty() || record.reason_code.is_some() =>
            {
                return protocol(
                    "erased backup series requires no remaining backups or reason code",
                );
            }
            BackupSeriesEraseRowStatus::Pending if record.reason_code.is_some() => {
                return protocol("pending backup series cannot carry a reason code");
            }
            BackupSeriesEraseRowStatus::FailedRetryable if record.reason_code.is_none() => {
                return protocol("failed-retryable backup series requires a reason code");
            }
            _ => {}
        }
        match (self.status, self.confirmation.as_ref()) {
            (BackupSeriesEraseStatus::Complete, Some(confirmation)) => {
                confirmation.validate_structural()
            }
            (BackupSeriesEraseStatus::Partial, None) => Ok(()),
            _ => protocol("only a complete erase outcome carries one confirmation"),
        }
    }

    pub fn validate_for_request(&self, request: &BackupSeriesEraseRequestBody) -> Result<()> {
        self.validate_structural()?;
        request.validate_structural()?;
        let request_digest = arkret_canonical::canonical::canonical_sha256(request)?;
        let record = &self.series_records[0];
        let binding = &request.series[0];
        let mut reported_backups = record.erased_backups.clone();
        reported_backups.extend(record.remaining_backups.clone());
        reported_backups
            .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
        let mut planned_backups = binding.old_backups.clone();
        planned_backups
            .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
        if self.transaction_id != request.transaction_id
            || self.request_digest.as_str() != request_digest
            || record.backup_kind != binding.backup_kind
            || record.previous_series_id != binding.previous_series_id
            || record.new_series_id != binding.new_series_id
            || reported_backups != planned_backups
        {
            return protocol(
                "backup-series erase outcome changed the transaction, request, or target binding",
            );
        }
        if let Some(confirmation) = &self.confirmation
            && (confirmation.transaction_id != request.transaction_id
                || confirmation.transaction_request_digest != request.transaction_request_digest
                || confirmation.prepared_plan_digest != request.prepared_plan_digest
                || confirmation.series != request.series
                || request.erase_confirmation_digest
                    != security_rotation_erase_confirmation_digest(
                        &confirmation.transaction_id,
                        &confirmation.series,
                    )?)
        {
            return protocol(
                "backup-series erase confirmation changed the reserved transaction plan",
            );
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityTransactionPreparedPlan {
    Recovery(PcrPolicyRecoveryPlan),
    SecurityRotation(SecurityRotationPlan),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityTransactionTerminalOutcome {
    Completed {
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        completed_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt_id: Option<ReceiptId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completion_attestation: Option<RecoveryCompletionAttestation>,
    },
    Aborted {
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        completed_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason_code: Option<String>,
    },
    Expired {
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        completed_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason_code: Option<String>,
    },
}

impl SecurityTransactionTerminalOutcome {
    pub fn completed_at(&self) -> DateTime<Utc> {
        match self {
            Self::Completed { completed_at, .. }
            | Self::Aborted { completed_at, .. }
            | Self::Expired { completed_at, .. } => *completed_at,
        }
    }
}

/// The immutable PCR Event and covering Commit accepted for a device revoke.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationRevokeProposal {
    pub proposal_event_id: EventId,
    pub covering_commit_id: RealmCommitId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityRotationRevokeCommandResult {
    Accepted,
    Rejected,
}

/// Station-local terminal decision for the exact accepted proposal.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationRevokeCommandOutcome {
    pub proposal_event_id: EventId,
    pub covering_commit_id: RealmCommitId,
    pub result: SecurityRotationRevokeCommandResult,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub decided_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransaction {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizing_device_id: Option<DeviceId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub request_digest: Hash,
    pub prepared_plan: SecurityTransactionPreparedPlan,
    pub prepared_plan_digest: Hash,
    pub accepted_steps: Vec<AcceptedSecurityTransactionStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_proposal: Option<SecurityRotationRevokeProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_command_outcome: Option<SecurityRotationRevokeCommandOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<SecurityTransactionTerminalOutcome>,
}

impl SecurityTransaction {
    pub fn step_order(&self) -> Result<&'static [SecurityTransactionStep]> {
        match (&self.kind, &self.prepared_plan) {
            (SecurityTransactionKind::Recovery, SecurityTransactionPreparedPlan::Recovery(_)) => {
                Ok(&RECOVERY_STEP_ORDER)
            }
            (
                SecurityTransactionKind::SecurityRotation,
                SecurityTransactionPreparedPlan::SecurityRotation(_),
            ) => Ok(&SECURITY_ROTATION_STEP_ORDER),
            _ => protocol("security transaction kind and prepared plan disagree"),
        }
    }

    pub fn next_required_step(&self) -> Result<Option<SecurityTransactionStep>> {
        if self.terminal_outcome.is_some() {
            return Ok(None);
        }
        Ok(self.step_order()?.get(self.accepted_steps.len()).copied())
    }

    pub fn recovery_plan(&self) -> Option<&PcrPolicyRecoveryPlan> {
        match &self.prepared_plan {
            SecurityTransactionPreparedPlan::Recovery(plan) => Some(plan),
            SecurityTransactionPreparedPlan::SecurityRotation(_) => None,
        }
    }

    pub fn security_rotation_plan(&self) -> Option<&SecurityRotationPlan> {
        match &self.prepared_plan {
            SecurityTransactionPreparedPlan::Recovery(_) => None,
            SecurityTransactionPreparedPlan::SecurityRotation(plan) => Some(plan),
        }
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.account_id.validate()?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_SECURITY_TRANSACTION_TTL
        {
            return protocol("security transaction requires a positive TTL of at most 24 hours");
        }
        require_sha256("prepared_plan_digest", &self.prepared_plan_digest)?;
        validate_digest_of(
            "prepared_plan_digest",
            &self.prepared_plan,
            &self.prepared_plan_digest,
        )?;
        match &self.prepared_plan {
            SecurityTransactionPreparedPlan::Recovery(plan) => {
                if self.authorizing_device_id.is_some()
                    || self.revoke_proposal.is_some()
                    || self.revoke_command_outcome.is_some()
                {
                    return protocol("recovery transaction forbids rotation authority fields");
                }
                plan.validate(&self.account_id)?
            }
            SecurityTransactionPreparedPlan::SecurityRotation(plan) => {
                if self.authorizing_device_id.is_none() {
                    return protocol("security rotation requires authorizing_device_id");
                }
                validate_security_rotation_plan(&self.transaction_id, &self.account_id, plan)?;
                match (&self.revoke_proposal, &self.revoke_command_outcome) {
                    (None, None)
                        if self.accepted_steps.is_empty()
                            && matches!(
                                self.terminal_outcome,
                                None | Some(SecurityTransactionTerminalOutcome::Aborted { .. })
                                    | Some(SecurityTransactionTerminalOutcome::Expired { .. })
                            ) => {}
                    (Some(proposal), None)
                        if self.accepted_steps.is_empty() && self.terminal_outcome.is_none() =>
                    {
                        if plan
                            .revoke_unit
                            .request
                            .events
                            .first()
                            .is_none_or(|event| proposal.proposal_event_id != event.event_id)
                        {
                            return protocol("revoke proposal changed the prepared Event");
                        }
                    }
                    (Some(proposal), Some(outcome)) => {
                        if proposal.proposal_event_id != outcome.proposal_event_id
                            || proposal.covering_commit_id != outcome.covering_commit_id
                            || plan
                                .revoke_unit
                                .request
                                .events
                                .first()
                                .is_none_or(|event| proposal.proposal_event_id != event.event_id)
                        {
                            return protocol(
                                "revoke command outcome changed its covering proposal",
                            );
                        }
                        match outcome.result {
                            SecurityRotationRevokeCommandResult::Accepted
                                if self.accepted_steps.is_empty() =>
                            {
                                return protocol("accepted revoke requires an accepted step");
                            }
                            SecurityRotationRevokeCommandResult::Rejected
                                if !self.accepted_steps.is_empty()
                                    || !matches!(
                                        self.terminal_outcome,
                                        Some(
                                            SecurityTransactionTerminalOutcome::Aborted { .. }
                                                | SecurityTransactionTerminalOutcome::Expired { .. }
                                        )
                                    ) =>
                            {
                                return protocol(
                                    "rejected revoke requires an empty aborted/expired transaction",
                                );
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        return protocol(
                            "rotation revoke proposal/result progress is inconsistent",
                        );
                    }
                }
            }
        }

        let order = self.step_order()?;
        if self.accepted_steps.len() > order.len() {
            return protocol("accepted_steps exceeds the transaction's fixed step order");
        }
        for step in &self.accepted_steps {
            validate_step_output_ref(&step.output_ref)?;
        }

        match &self.terminal_outcome {
            None if self.accepted_steps.len() == order.len() => {
                protocol("non-terminal transaction exhausted its fixed step order")
            }
            None => Ok(()),
            Some(SecurityTransactionTerminalOutcome::Completed {
                completed_at,
                receipt_id,
                completion_attestation,
            }) => {
                if self.accepted_steps.len() != order.len() {
                    return protocol("completed transaction requires its complete accepted prefix");
                }
                match (&self.prepared_plan, receipt_id, completion_attestation) {
                    (
                        SecurityTransactionPreparedPlan::Recovery(plan),
                        Some(receipt_id),
                        Some(attestation),
                    ) => self.validate_recovery_completion(
                        plan,
                        receipt_id,
                        attestation,
                        *completed_at,
                    ),
                    (SecurityTransactionPreparedPlan::Recovery(_), ..) => protocol(
                        "completed recovery requires receipt_id and completion_attestation",
                    ),
                    (SecurityTransactionPreparedPlan::SecurityRotation(_), None, None) => Ok(()),
                    (SecurityTransactionPreparedPlan::SecurityRotation(_), ..) => {
                        protocol("security rotation completion must not carry recovery evidence")
                    }
                }
            }
            Some(SecurityTransactionTerminalOutcome::Aborted { reason_code, .. })
            | Some(SecurityTransactionTerminalOutcome::Expired { reason_code, .. }) => {
                if reason_code
                    .as_deref()
                    .is_some_and(|code| !valid_reason_code(code))
                {
                    return protocol("terminal reason_code is not canonical snake_case");
                }
                Ok(())
            }
        }
    }

    fn validate_recovery_completion(
        &self,
        plan: &PcrPolicyRecoveryPlan,
        receipt_id: &ReceiptId,
        attestation: &RecoveryCompletionAttestation,
        completed_at: DateTime<Utc>,
    ) -> Result<()> {
        attestation.validate_structural()?;
        let binding = &plan.binding;
        let last = self.accepted_steps.last().ok_or_else(|| {
            WireError::Protocol("completed recovery is missing its accepted step".to_owned())
        })?;
        if receipt_id != &binding.terminal_receipt_id
            || attestation.transaction_id != self.transaction_id
            || attestation.transaction_request_digest != self.request_digest
            || attestation.prepared_plan_digest != self.prepared_plan_digest
            || attestation.account_id != self.account_id
            || attestation.recovery_session_id != binding.recovery_session_id
            || attestation.terminal_receipt_id != binding.terminal_receipt_id
            || attestation.replacement_device_id != binding.replacement_device_id
            || attestation.reanchor_event_ref.event_id != binding.reanchor_event_id
            || attestation.device_authorization_event_ref.event_id != binding.authorize_event_id
            || attestation.result_model_generation_ref != plan.result_model_generation_ref
            || attestation.completed_at != completed_at
            || last.output_ref != receipt_id.as_str()
            || last.output_digest != attestation.terminal_receipt_digest
            || attestation.reanchor_event_ref.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: plan.reanchor_commit_intent.realm_id.clone(),
                })
        {
            return protocol(
                "recovery completion attestation disagrees with the durable transaction",
            );
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub recovery_intent: PcrPolicyRecoveryIntent,
}

impl RecoveryTransactionCreateRequest {
    pub fn new(
        transaction_id: TransactionId,
        account_id: AccountId,
        expires_at: DateTime<Utc>,
        recovery_intent: PcrPolicyRecoveryIntent,
    ) -> Result<Self> {
        let request = Self {
            transaction_id,
            kind: SecurityTransactionKind::Recovery,
            account_id,
            expires_at,
            recovery_intent,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != SecurityTransactionKind::Recovery {
            return protocol("recovery create request requires kind=recovery");
        }
        self.account_id.validate()?;
        self.recovery_intent.validate(&self.account_id)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    pub authorizing_device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub prepared_plan: SecurityRotationPlan,
}

impl SecurityRotationTransactionCreateRequest {
    pub fn from_prepared_rotations(
        transaction_id: TransactionId,
        account_id: AccountId,
        authorizing_device_id: DeviceId,
        expires_at: DateTime<Utc>,
        revoke_unit: PreparedEventUnit,
        new_secret_commitment: Hash,
        backup_rotations: Vec<BackupRotationPlan>,
    ) -> Result<Self> {
        let bindings = backup_rotations
            .iter()
            .map(|rotation| rotation.binding.clone())
            .collect::<Vec<_>>();
        let prepared_plan = SecurityRotationPlan {
            revoke_unit,
            erase_confirmation_digest: security_rotation_erase_confirmation_digest(
                &transaction_id,
                &bindings,
            )?,
            local_commit_digest: security_rotation_local_commit_digest(
                &transaction_id,
                &new_secret_commitment,
                &bindings,
            )?,
            new_secret_commitment,
            backup_rotations,
        };
        Self::new(
            transaction_id,
            account_id,
            authorizing_device_id,
            expires_at,
            prepared_plan,
        )
    }

    pub fn new(
        transaction_id: TransactionId,
        account_id: AccountId,
        authorizing_device_id: DeviceId,
        expires_at: DateTime<Utc>,
        prepared_plan: SecurityRotationPlan,
    ) -> Result<Self> {
        validate_security_rotation_plan(&transaction_id, &account_id, &prepared_plan)?;
        Ok(Self {
            transaction_id,
            kind: SecurityTransactionKind::SecurityRotation,
            account_id,
            authorizing_device_id,
            expires_at,
            prepared_plan,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != SecurityTransactionKind::SecurityRotation {
            return protocol("security rotation create request requires kind=security_rotation");
        }
        self.account_id.validate()?;
        validate_security_rotation_plan(&self.transaction_id, &self.account_id, &self.prepared_plan)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum SecurityTransactionCreateRequest {
    Recovery(RecoveryTransactionCreateRequest),
    SecurityRotation(SecurityRotationTransactionCreateRequest),
}

impl SecurityTransactionCreateRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Recovery(request) => request.validate(),
            Self::SecurityRotation(request) => request.validate(),
        }
    }

    pub fn transaction_id(&self) -> &TransactionId {
        match self {
            Self::Recovery(request) => &request.transaction_id,
            Self::SecurityRotation(request) => &request.transaction_id,
        }
    }

    pub fn into_initial_resource(
        self,
        prepared_plan: SecurityTransactionPreparedPlan,
        created_at: DateTime<Utc>,
    ) -> Result<(SecurityTransaction, Vec<u8>)> {
        self.validate()?;
        let canonical_request = arkret_canonical::canonical_json_bytes(&self)?;
        let request_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
            &canonical_request,
        ))?;
        let (transaction_id, kind, account_id, authorizing_device_id, expires_at) =
            match (&self, &prepared_plan) {
                (Self::Recovery(request), SecurityTransactionPreparedPlan::Recovery(plan)) => {
                    validate_prepared_plan_matches_intent(&request.recovery_intent, plan)?;
                    (
                        request.transaction_id.clone(),
                        request.kind,
                        request.account_id.clone(),
                        None,
                        request.expires_at,
                    )
                }
                (
                    Self::SecurityRotation(request),
                    SecurityTransactionPreparedPlan::SecurityRotation(plan),
                ) if canonical_equal(&request.prepared_plan, plan)? => (
                    request.transaction_id.clone(),
                    request.kind,
                    request.account_id.clone(),
                    Some(request.authorizing_device_id.clone()),
                    request.expires_at,
                ),
                _ => return protocol("create request and prepared plan disagree"),
            };
        let prepared_plan_digest =
            digest_value(arkret_canonical::DigestSuite::Sha256, &prepared_plan)?;
        let resource = SecurityTransaction {
            transaction_id,
            kind,
            account_id,
            authorizing_device_id,
            expires_at,
            created_at,
            request_digest,
            prepared_plan,
            prepared_plan_digest,
            accepted_steps: Vec::new(),
            revoke_proposal: None,
            revoke_command_outcome: None,
            terminal_outcome: None,
        };
        resource.validate_structural()?;
        Ok((resource, canonical_request))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationLocalCommit {
    pub schema: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub local_commit_digest: Hash,
    pub device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
}

impl SecurityRotationLocalCommit {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1 {
            return protocol("security rotation local commit schema is invalid");
        }
        require_sha256("prepared_plan_digest", &self.prepared_plan_digest)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTerminalCommit {
    pub recovery_receipt: RecoveryReceipt,
}

impl RecoveryTerminalCommit {
    pub fn validate(&self) -> Result<()> {
        self.recovery_receipt.validate()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ClientStepAttestationArtifact {
    Recovery(RecoveryTerminalCommit),
    SecurityRotation(SecurityRotationLocalCommit),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStepAttestationAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStepAttestation {
    pub step: SecurityTransactionStep,
    pub output_ref: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub artifact: ClientStepAttestationArtifact,
    pub auth_data: ClientStepAttestationAuthData,
}

impl ClientStepAttestation {
    pub fn attestation_digest(&self) -> Result<Hash> {
        digest_value(arkret_canonical::DigestSuite::Sha256, &self.artifact)
    }

    pub fn validate(&self) -> Result<()> {
        validate_step_output_ref(&self.output_ref)?;
        require_sha256("prepared_plan_digest", &self.prepared_plan_digest)?;
        if self.auth_data.signature_algorithm != "Ed25519" {
            return protocol("client step attestation requires Ed25519");
        }
        match (&self.step, &self.artifact) {
            (
                SecurityTransactionStep::CommitRecoveryUnit,
                ClientStepAttestationArtifact::Recovery(artifact),
            ) => artifact.validate()?,
            (
                SecurityTransactionStep::LocalCommit,
                ClientStepAttestationArtifact::SecurityRotation(artifact),
            ) => artifact.validate()?,
            _ => return protocol("client attestation step and artifact disagree"),
        }
        self.attestation_digest()?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "step": self.step,
            "output_ref": self.output_ref,
            "transaction_id": self.transaction_id,
            "transaction_request_digest": self.transaction_request_digest,
            "prepared_plan_digest": self.prepared_plan_digest,
            "attestation_digest": self.attestation_digest()?,
        }))
        .map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionContinueRequest {
    pub request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub expected_accepted_step_count: u64,
    pub client_attestation: ClientStepAttestation,
}

impl SecurityTransactionContinueRequest {
    pub fn validate_for_transaction(&self, transaction: &SecurityTransaction) -> Result<()> {
        transaction.validate_structural()?;
        if self.request_digest != transaction.request_digest
            || self.prepared_plan_digest != transaction.prepared_plan_digest
        {
            return protocol("continue request changed request or prepared-plan digest");
        }
        if usize::try_from(self.expected_accepted_step_count).ok()
            != Some(transaction.accepted_steps.len())
        {
            return protocol("continue request accepted-step CAS does not match current progress");
        }
        let next = transaction.next_required_step()?.ok_or_else(|| {
            WireError::Protocol("terminal transaction cannot continue".to_owned())
        })?;
        if !matches!(
            next,
            SecurityTransactionStep::CommitRecoveryUnit | SecurityTransactionStep::LocalCommit
        ) {
            return protocol("coordinator-owned transaction steps cannot be driven by continue");
        }
        let attestation = &self.client_attestation;
        attestation.validate()?;
        if attestation.step != next
            || attestation.transaction_id != transaction.transaction_id
            || attestation.transaction_request_digest != transaction.request_digest
            || attestation.prepared_plan_digest != transaction.prepared_plan_digest
        {
            return protocol("client attestation does not bind the current transaction step");
        }
        match (&transaction.prepared_plan, &attestation.artifact) {
            (
                SecurityTransactionPreparedPlan::Recovery(plan),
                ClientStepAttestationArtifact::Recovery(artifact),
            ) => {
                let receipt = &artifact.recovery_receipt;
                if attestation.output_ref != plan.binding.terminal_receipt_id.as_str()
                    || receipt.receipt_id != plan.binding.terminal_receipt_id
                    || receipt.transaction_id != transaction.transaction_id
                    || receipt.transaction_request_digest != transaction.request_digest
                    || receipt.prepared_plan_digest != transaction.prepared_plan_digest
                    || receipt.account_id != transaction.account_id
                    || receipt.recovery_session_id != plan.binding.recovery_session_id
                    || receipt.new_device_id != plan.binding.replacement_device_id
                    || receipt.reanchor_event_id != plan.binding.reanchor_event_id
                    || receipt.authorization_event_id != plan.binding.authorize_event_id
                    || receipt.previous_model_generation_ref != plan.previous_model_generation_ref
                    || receipt.result_model_generation_ref != plan.result_model_generation_ref
                {
                    return protocol("recovery receipt disagrees with the prepared transaction");
                }
            }
            (
                SecurityTransactionPreparedPlan::SecurityRotation(plan),
                ClientStepAttestationArtifact::SecurityRotation(artifact),
            ) => {
                if attestation.output_ref != plan.local_commit_digest.as_str()
                    || artifact.transaction_id != transaction.transaction_id
                    || artifact.transaction_request_digest != transaction.request_digest
                    || artifact.prepared_plan_digest != transaction.prepared_plan_digest
                    || artifact.local_commit_digest != plan.local_commit_digest
                {
                    return protocol(
                        "security rotation local commit disagrees with the prepared transaction",
                    );
                }
            }
            _ => return protocol("client attestation artifact does not match transaction kind"),
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAuthorityKind {
    PcrPolicy,
    DidRoot,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProofKind {
    DidRoot,
    RecoveryUnlock,
    DeviceQuorum,
    TrustedRecoveryService,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProofSummary {
    pub kind: RecoveryProofKind,
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_participant_count: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBackupUnlocked {
    pub backup_kind: BackupRotationKind,
    pub backup_id: BackupId,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWelcomeRealmSummary {
    pub realm_id: RealmId,
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReceiptOutcome {
    Completed,
    Partial,
    AbortedByUser,
    PolicyDenied,
    EvidenceInsufficient,
    ServiceDefined,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceiptAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub account_id: AccountId,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TrustDomainId,
    pub new_device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    pub recovery_authority_kind: RecoveryAuthorityKind,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub authorization_event_id: EventId,
    pub reanchor_event_id: EventId,
    pub proof_summary: RecoveryProofSummary,
    pub unlocked_backups: Vec<RecoveryBackupUnlocked>,
    pub welcome_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_realm_summaries: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub outcome: RecoveryReceiptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_reason_code: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub started_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    pub auth_data: RecoveryReceiptAuthData,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl RecoveryReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::RECOVERY_RECEIPT_V1
            || self.identity_model != RecoveryIdentityModel::PcrPolicy
            || self.policy_version == 0
            || self.completed_at < self.started_at
        {
            return protocol("recovery receipt has invalid closed fields");
        }
        validate_generation_advance(
            self.previous_model_generation_ref,
            self.result_model_generation_ref,
        )?;
        if self.auth_data.signature_algorithm != "Ed25519" {
            return protocol("recovery receipt requires Ed25519");
        }
        if (self.proof_summary.kind == RecoveryProofKind::DeviceQuorum)
            != self
                .proof_summary
                .quorum_participant_count
                .is_some_and(|count| count > 0)
        {
            return protocol("device-quorum proof requires a positive exclusive participant count");
        }
        if (self.outcome == RecoveryReceiptOutcome::Completed) == self.outcome_reason_code.is_some()
        {
            return protocol(
                "recovery receipt reason is required exactly for non-completed outcomes",
            );
        }
        validate_unique_recovery_artifacts(self)?;
        Ok(())
    }

    pub fn signature_transcript_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| WireError::Protocol("recovery receipt must be an object".to_owned()))?
            .remove("auth_data");
        let mut bytes = b"ak.identity.recovery_receipt.signature.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }
}

pub fn security_rotation_erase_confirmation_digest(
    transaction_id: &TransactionId,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    digest_value(
        arkret_canonical::DigestSuite::Sha256,
        &serde_json::json!({
            "domain": "ak.backup_series_erase_confirmation_preimage.v1",
            "transaction_id": transaction_id,
            "series": backup_rotations,
        }),
    )
}

pub fn security_rotation_local_commit_digest(
    transaction_id: &TransactionId,
    new_secret_commitment: &Hash,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    digest_value(
        arkret_canonical::DigestSuite::Sha256,
        &serde_json::json!({
            "domain": "ak.security_rotation_local_commit_preimage.v1",
            "transaction_id": transaction_id,
            "new_secret_commitment": new_secret_commitment,
            "backup_rotations": backup_rotations,
        }),
    )
}

fn validate_prepared_plan_matches_intent(
    intent: &PcrPolicyRecoveryIntent,
    plan: &PcrPolicyRecoveryPlan,
) -> Result<()> {
    let same_unit = canonical_equal(&intent.reanchor_unit, &plan.reanchor_unit)?;
    if plan.binding.identity_model != RecoveryIdentityModel::PcrPolicy
        || plan.binding.recovery_session_id != intent.recovery_session_id
        || plan.binding.replacement_device_id != intent.replacement_device_id
        || plan.binding.terminal_receipt_id != intent.terminal_receipt_id
        || plan.previous_model_generation_ref != intent.previous_model_generation_ref
        || plan.result_model_generation_ref != intent.result_model_generation_ref
        || plan.reanchor_commit_intent != intent.reanchor_commit_intent
        || !same_unit
    {
        return protocol("recovery prepared plan changed caller-authored intent");
    }
    Ok(())
}

fn validate_recovery_event_unit(
    account_id: &AccountId,
    unit: &PreparedEventUnit,
    commit_intent: &RecoveryCommitIntent,
    binding: Option<&PcrPolicyRecoveryBinding>,
) -> Result<()> {
    unit.validate()?;
    commit_intent.validate()?;
    let [reanchor, authorize]: &[Event; RECOVERY_UNIT_EVENT_COUNT] =
        unit.request.events.as_slice().try_into().map_err(|_| {
            WireError::Protocol(
                "recovery unit requires exactly reanchor and authorize Events".to_owned(),
            )
        })?;
    let account_actor = ActorId::account(account_id.clone());
    if reanchor.kind != EventKind::DeviceReanchor
        || authorize.kind != EventKind::DeviceAuthorize
        || reanchor.actor_id != account_actor
        || authorize.actor_id != account_actor
        || reanchor.realm_id != commit_intent.realm_id
        || authorize.realm_id != commit_intent.realm_id
        || reanchor.scope_ref
            != (ScopeRef::Realm {
                realm_id: commit_intent.realm_id.clone(),
            })
        || authorize.scope_ref != reanchor.scope_ref
        || reanchor.event_id == authorize.event_id
    {
        return protocol(
            "recovery unit must be the exact account-owned PCR Realm reanchor/authorize pair",
        );
    }
    reanchor.validate_for_submit_structural()?;
    authorize.validate_for_submit_structural()?;
    let expected = [
        Hash::new(reanchor.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?)?,
        Hash::new(
            authorize.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        )?,
    ];
    if expected != commit_intent.unit_event_digests {
        return protocol("recovery commit intent does not name the two producer Event digests");
    }
    let reanchor_signer = unique_producer_signer(reanchor)?;
    let authorize_signer = unique_producer_signer(authorize)?;
    if reanchor_signer != authorize_signer {
        return protocol("recovery Events must use the same session-frozen replacement key");
    }
    if let Some(binding) = binding {
        if binding.reanchor_event_id != reanchor.event_id
            || binding.authorize_event_id != authorize.event_id
        {
            return protocol("recovery binding does not name the prepared Event pair");
        }
    }
    Ok(())
}

fn unique_producer_signer(event: &Event) -> Result<&DidUrl> {
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| WireError::Protocol("recovery Event requires producer_proof".to_owned()))?;
    Ok(&proof.verification_method)
}

fn validate_security_rotation_plan(
    transaction_id: &TransactionId,
    account_id: &AccountId,
    plan: &SecurityRotationPlan,
) -> Result<()> {
    plan.revoke_unit.validate()?;
    let [revoke]: &[_; 1] = plan
        .revoke_unit
        .request
        .events
        .as_slice()
        .try_into()
        .map_err(|_| {
            WireError::Protocol("security rotation revoke unit requires one Event".to_owned())
        })?;
    if revoke.kind != EventKind::DeviceRevoke
        || revoke.actor_id != ActorId::account(account_id.clone())
    {
        return protocol("security rotation revoke unit is not account-owned ak.device.revoke");
    }
    if plan.backup_rotations.len() != 1 {
        return protocol("security rotation requires one secret_storage rotation");
    }
    let expected_kinds = [BackupRotationKind::SecretStorage];
    for (rotation, expected_kind) in plan.backup_rotations.iter().zip(expected_kinds) {
        let binding = &rotation.binding;
        if binding.backup_kind != expected_kind
            || binding.previous_series_id == binding.new_series_id
            || !(1..=512).contains(&binding.new_backups.len())
            || !(1..=512).contains(&binding.old_backups.len())
            || !unique_backup_refs(&binding.new_backups)
            || !unique_backup_refs(&binding.old_backups)
        {
            return protocol("security rotation backup binding has invalid fixed shape");
        }
        rotation.encrypted_backup_material.validate_structural()?;
        rotation.active_series_unit.validate()?;
        let [active_series]: &[_; 1] = rotation
            .active_series_unit
            .request
            .events
            .as_slice()
            .try_into()
            .map_err(|_| {
                WireError::Protocol(
                    "backup active-series unit requires exactly one Event".to_owned(),
                )
            })?;
        if active_series.kind != EventKind::KeyBackupActiveSeries
            || active_series.event_id != binding.active_series_event_id
            || active_series.actor_id != ActorId::account(account_id.clone())
        {
            return protocol("backup rotation active-series Event disagrees with its binding");
        }
    }
    let bindings = plan
        .backup_rotations
        .iter()
        .map(|rotation| rotation.binding.clone())
        .collect::<Vec<_>>();
    if plan.erase_confirmation_digest
        != security_rotation_erase_confirmation_digest(transaction_id, &bindings)?
        || plan.local_commit_digest
            != security_rotation_local_commit_digest(
                transaction_id,
                &plan.new_secret_commitment,
                &bindings,
            )?
    {
        return protocol("security rotation reserved digests do not match their projections");
    }
    Ok(())
}

fn unique_backup_refs(refs: &[BackupObjectRef]) -> bool {
    let mut ids = HashSet::with_capacity(refs.len());
    refs.iter()
        .all(|reference| ids.insert(&reference.backup_id))
}

fn validate_unique_recovery_artifacts(receipt: &RecoveryReceipt) -> Result<()> {
    let mut backups = HashSet::with_capacity(receipt.unlocked_backups.len());
    if !receipt
        .unlocked_backups
        .iter()
        .all(|backup| backups.insert((&backup.backup_kind, &backup.backup_id)))
    {
        return protocol("recovery receipt unlocked_backups must be unique");
    }
    if let Some(summaries) = &receipt.welcome_realm_summaries {
        let mut groups = HashSet::with_capacity(summaries.len());
        if !summaries
            .iter()
            .all(|summary| groups.insert((&summary.realm_id, &summary.mls_group_id, summary.epoch)))
        {
            return protocol("recovery receipt Welcome summaries must be unique");
        }
    }
    Ok(())
}

fn validate_generation_advance(previous: u64, result: u64) -> Result<()> {
    if previous == 0 || result <= previous {
        return protocol("PCR generation refs require a positive monotonic advance");
    }
    Ok(())
}

fn validate_step_output_ref(value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > MAX_STEP_OUTPUT_REF_CHARS
        || value.chars().any(char::is_whitespace)
    {
        return protocol("step output_ref must be 1..=2048 non-whitespace characters");
    }
    Ok(())
}

fn valid_reason_code(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && value.len() <= 64
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn require_sha256(name: &str, digest: &Hash) -> Result<()> {
    if !matches!(
        digest.digest_suite(),
        Ok(arkret_canonical::DigestSuite::Sha256)
    ) {
        return protocol(format!("{name} must use SHA-256"));
    }
    Ok(())
}

fn digest_value<T: Serialize + ?Sized>(
    suite: arkret_canonical::DigestSuite,
    value: &T,
) -> Result<Hash> {
    let bytes = arkret_canonical::canonical_json_bytes(value)?;
    Ok(Hash::new(arkret_canonical::canonical::digest(
        suite, &bytes,
    ))?)
}

fn validate_digest_of<T: Serialize + ?Sized>(name: &str, value: &T, digest: &Hash) -> Result<()> {
    let expected = digest_value(digest.digest_suite()?, value)?;
    if &expected != digest {
        return protocol(format!("{name} digest does not match canonical bytes"));
    }
    Ok(())
}

fn canonical_equal<A: Serialize + ?Sized, B: Serialize + ?Sized>(
    left: &A,
    right: &B,
) -> Result<bool> {
    Ok(arkret_canonical::canonical_json_bytes(left)?
        == arkret_canonical::canonical_json_bytes(right)?)
}

fn protocol<T>(message: impl Into<String>) -> Result<T> {
    Err(WireError::Protocol(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn erase_binding() -> BackupRotationBinding {
        serde_json::from_value(serde_json::json!({
            "backup_kind": "secret_storage",
            "previous_series_id": "ak:backup_series:019a7400-0000-7000-8000-000000000001",
            "new_series_id": "ak:backup_series:019a7400-0000-7000-8000-000000000002",
            "new_backups": [{
                "backup_id": "ak:backup:019a7400-0000-7000-8000-000000000003",
                "ciphertext_digest": format!("sha256:{}", "a".repeat(64))
            }],
            "active_series_event_id": "ak:event:AWKDhmQTc5zyfilaLwPF3xnhoZAjxSha7Z-6grioN9aW",
            "old_backups": [{
                "backup_id": "ak:backup:019a7400-0000-7000-8000-000000000005",
                "ciphertext_digest": format!("sha256:{}", "b".repeat(64))
            }]
        }))
        .unwrap()
    }

    fn erase_request() -> BackupSeriesEraseRequestBody {
        let transaction_id =
            TransactionId::new("ak:transaction:019a7400-0000-7000-8000-000000000006").unwrap();
        let series = vec![erase_binding()];
        BackupSeriesEraseRequestBody {
            erase_confirmation_digest: security_rotation_erase_confirmation_digest(
                &transaction_id,
                &series,
            )
            .unwrap(),
            transaction_id,
            transaction_request_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            prepared_plan_digest: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            series,
            authority_commit_id: RealmCommitId::new(
                "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            )
            .unwrap(),
        }
    }

    #[test]
    fn recovery_commit_intent_is_exactly_two_sha256_event_digests() {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let predecessor_ref = RealmCommitId::from_digest([2; 32]);
        let value = serde_json::json!({
            "realm_id": realm_id,
            "predecessor_ref": predecessor_ref,
            "unit_event_digests": [
                format!("sha256:{}", "a".repeat(64)),
                format!("sha256:{}", "b".repeat(64)),
            ]
        });
        let intent: RecoveryCommitIntent = serde_json::from_value(value.clone()).unwrap();
        intent.validate().unwrap();

        let mut one = value;
        one["unit_event_digests"] = serde_json::json!([format!("sha256:{}", "a".repeat(64))]);
        assert!(serde_json::from_value::<RecoveryCommitIntent>(one).is_err());
    }

    #[test]
    fn continue_request_requires_one_client_attestation() {
        let value = serde_json::json!({
            "request_digest": format!("sha256:{}", "a".repeat(64)),
            "prepared_plan_digest": format!("sha256:{}", "b".repeat(64)),
            "expected_accepted_step_count": 0
        });
        assert!(serde_json::from_value::<SecurityTransactionContinueRequest>(value).is_err());
    }

    #[test]
    fn backup_series_erase_request_requires_one_series_and_no_lease() {
        let request = erase_request();
        request.validate_structural().unwrap();

        let mut empty = request.clone();
        empty.series.clear();
        assert!(empty.validate_structural().is_err());

        let mut duplicate = request.clone();
        duplicate.series.push(erase_binding());
        assert!(duplicate.validate_structural().is_err());

        let mut legacy = serde_json::to_value(request).unwrap();
        legacy.as_object_mut().unwrap().insert(
            "authorization_lease".to_owned(),
            serde_json::json!({"lease_id": "removed"}),
        );
        assert!(serde_json::from_value::<BackupSeriesEraseRequestBody>(legacy).is_err());
    }

    #[test]
    fn backup_series_erase_outcome_requires_one_record_and_confirmation_by_status() {
        let request = erase_request();
        let request_digest =
            Hash::new(arkret_canonical::canonical::canonical_sha256(&request).unwrap()).unwrap();
        let binding = request.series[0].clone();
        let record = BackupSeriesEraseRow {
            backup_kind: binding.backup_kind,
            previous_series_id: binding.previous_series_id,
            new_series_id: binding.new_series_id,
            status: BackupSeriesEraseRowStatus::Pending,
            erased_backups: Vec::new(),
            remaining_backups: binding.old_backups,
            reason_code: None,
        };
        let mut outcome = BackupSeriesEraseOutcome {
            transaction_id: request.transaction_id.clone(),
            request_digest,
            status: BackupSeriesEraseStatus::Partial,
            series_records: vec![record],
            confirmation: None,
        };
        outcome.validate_for_request(&request).unwrap();

        outcome.series_records.clear();
        assert!(outcome.validate_structural().is_err());
        outcome.series_records.push(BackupSeriesEraseRow {
            backup_kind: BackupRotationKind::SecretStorage,
            previous_series_id: request.series[0].previous_series_id.clone(),
            new_series_id: request.series[0].new_series_id.clone(),
            status: BackupSeriesEraseRowStatus::Erased,
            erased_backups: request.series[0].old_backups.clone(),
            remaining_backups: Vec::new(),
            reason_code: None,
        });
        outcome.status = BackupSeriesEraseStatus::Complete;
        assert!(outcome.validate_structural().is_err());

        outcome.confirmation = Some(BackupSeriesEraseConfirmation {
            schema: SchemaId::BackupSeriesEraseConfirmationV1,
            transaction_id: request.transaction_id.clone(),
            transaction_request_digest: request.transaction_request_digest.clone(),
            prepared_plan_digest: request.prepared_plan_digest.clone(),
            series: request.series.clone(),
        });
        outcome.validate_for_request(&request).unwrap();
    }
}
