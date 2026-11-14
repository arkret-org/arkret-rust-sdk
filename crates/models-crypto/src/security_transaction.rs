//! Closed durable recovery and security-rotation transaction DTOs.
//!
//! Producer Events remain immutable producer facts. A recovery request freezes
//! the two signed Events and the current Principal Control Realm stream head;
//! only the governance Station may later create their consecutive
//! [`arkret_wire::RealmCommit`] records. No authority-side protocol carrier or
//! producer-side ordering coordinate is carried here.

use std::collections::{BTreeSet, HashSet};

use arkret_wire::{
    AccountId, ActorId, BackupId, BackupSeriesId, Base64UrlString, CommitStreamRef, DeviceId,
    DidCoreId, DidUrl, Event, EventId, EventKind, Hash, MlsGroupId, PolicyId, RealmCommitId,
    RealmId, ReceiptId, RecoveryCompletionAttestation, RecoverySessionId, Result, SchemaId,
    ScopeRef, SessionGrantRef, TransactionId, TrustDomainId, WireError,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::KeyBackup;

pub const MAX_SECURITY_TRANSACTION_TTL: Duration = Duration::hours(24);
pub const MAX_STEP_OUTPUT_REF_CHARS: usize = 2048;
pub const RECOVERY_UNIT_EVENT_COUNT: usize = 2;

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
    pub acceptor: SecurityTransactionAcceptor,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// Exact signed producer submission batch frozen for the durable transaction.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEventUnit {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub request: arkret_wire::EventsSubmitBatchRequestBody,
    pub request_digest: Hash,
}

impl PreparedEventUnit {
    pub fn new(
        digest_suite: arkret_canonical::DigestSuite,
        request: arkret_wire::EventsSubmitBatchRequestBody,
    ) -> Result<Self> {
        let request_digest = digest_value(digest_suite, &request)?;
        Ok(Self {
            request,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
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
    pub new_backup_envelopes: Vec<KeyBackup>,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseConfirmation {
    pub schema: SchemaId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub series: Vec<BackupRotationBinding>,
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

impl BackupSeriesEraseConfirmation {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != SchemaId::BackupSeriesEraseConfirmationV1 {
            return protocol("backup-series erase confirmation schema is invalid");
        }
        validate_erase_rotation_bindings(&self.series)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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
pub enum SecurityRotationRevokeCommandDecision {
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
    pub outcome: SecurityRotationRevokeCommandDecision,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub decided_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationTransaction {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    pub authorizing_device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub request_digest: Hash,
    pub prepared_plan: SecurityRotationPlan,
    pub prepared_plan_digest: Hash,
    pub accepted_steps: Vec<AcceptedSecurityTransactionStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_proposal: Option<SecurityRotationRevokeProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_command_outcome: Option<SecurityRotationRevokeCommandOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<SecurityTransactionTerminalOutcome>,
}

impl SecurityRotationTransaction {
    pub fn step_order(&self) -> Result<&'static [SecurityTransactionStep]> {
        if self.kind != SecurityTransactionKind::SecurityRotation {
            return protocol("Rotation resource requires kind=security_rotation");
        }
        Ok(&SECURITY_ROTATION_STEP_ORDER)
    }

    pub fn next_required_step(&self) -> Result<Option<SecurityTransactionStep>> {
        if self.terminal_outcome.is_some() {
            return Ok(None);
        }
        Ok(self.step_order()?.get(self.accepted_steps.len()).copied())
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.account_id.validate()?;
        self.step_order()?;
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
        let plan = &self.prepared_plan;
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
                    .is_none_or(|slot| proposal.proposal_event_id != slot.event.event_id)
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
                        .is_none_or(|slot| proposal.proposal_event_id != slot.event.event_id)
                {
                    return protocol("revoke command outcome changed its covering proposal");
                }
                match outcome.outcome {
                    SecurityRotationRevokeCommandDecision::Accepted
                        if self.accepted_steps.is_empty() =>
                    {
                        return protocol("accepted revoke requires an accepted step");
                    }
                    SecurityRotationRevokeCommandDecision::Rejected
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
                return protocol("rotation revoke proposal/outcome progress is inconsistent");
            }
        }
        let order = self.step_order()?;
        if self.accepted_steps.len() > order.len() {
            return protocol("accepted_steps exceeds the transaction's fixed step order");
        }
        match &self.terminal_outcome {
            None if self.accepted_steps.len() == order.len() => {
                protocol("non-terminal transaction exhausted its fixed step order")
            }
            None => Ok(()),
            Some(SecurityTransactionTerminalOutcome::Completed {
                receipt_id,
                completion_attestation,
                ..
            }) => {
                if self.accepted_steps.len() != order.len()
                    || receipt_id.is_some()
                    || completion_attestation.is_some()
                {
                    return protocol(
                        "Rotation completion requires its full prefix and forbids Recovery evidence",
                    );
                }
                Ok(())
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
}

impl SecurityTransaction {
    pub fn transaction_id(&self) -> &TransactionId {
        match self {
            Self::Recovery(value) => &value.transaction_id,
            Self::SecurityRotation(value) => &value.transaction_id,
        }
    }
    pub fn account_id(&self) -> &AccountId {
        match self {
            Self::Recovery(value) => &value.account_id,
            Self::SecurityRotation(value) => &value.account_id,
        }
    }
    pub fn validate_structural(&self) -> Result<()> {
        match self {
            Self::Recovery(value) => value.validate_structural(),
            Self::SecurityRotation(value) => value.validate_structural(),
        }
    }
}

impl RecoveryTransactionCreateRequestBody {
    pub fn new(recovery_receipt: RecoveryReceipt) -> Result<Self> {
        let value = Self {
            kind: SecurityTransactionKind::Recovery,
            recovery_receipt,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.kind != SecurityTransactionKind::Recovery
            || self.recovery_receipt.outcome != RecoveryReceiptOutcome::Completed
        {
            return protocol("Recovery create requires the sole completed signed receipt");
        }
        self.recovery_receipt.validate()
    }
}

impl SecurityTransactionCreateRequestBody {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Recovery(value) => value.validate(),
            Self::SecurityRotation(value) => value.validate(),
        }
    }
    pub fn transaction_id(&self) -> &TransactionId {
        match self {
            Self::Recovery(value) => &value.recovery_receipt.transaction_id,
            Self::SecurityRotation(value) => &value.transaction_id,
        }
    }
    pub fn into_rotation_resource(
        self,
        created_at: DateTime<Utc>,
    ) -> Result<(SecurityTransaction, Vec<u8>)> {
        self.validate()?;
        let canonical_request = arkret_canonical::canonical_json_bytes(&self)?;
        let Self::SecurityRotation(request) = self else {
            return protocol("Recovery cannot create a prepared resource");
        };
        let resource = SecurityRotationTransaction {
            transaction_id: request.transaction_id,
            kind: request.kind,
            account_id: request.account_id,
            authorizing_device_id: request.authorizing_device_id,
            expires_at: request.expires_at,
            created_at,
            request_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
                &canonical_request,
            ))?,
            prepared_plan_digest: digest_value(
                arkret_canonical::DigestSuite::Sha256,
                &request.prepared_plan,
            )?,
            prepared_plan: request.prepared_plan,
            accepted_steps: Vec::new(),
            revoke_proposal: None,
            revoke_command_outcome: None,
            terminal_outcome: None,
        };
        resource.validate_structural()?;
        Ok((
            SecurityTransaction::SecurityRotation(resource),
            canonical_request,
        ))
    }
}

impl RecoveryTransactionCompletion {
    pub fn validate_structural(&self) -> Result<()> {
        let receipt = &self.recovery_receipt;
        let completion = &self.completion_attestation;
        receipt.validate()?;
        completion.validate_structural()?;
        let [reanchor, authorize] = &receipt.recovery_unit.events;
        if self.kind != SecurityTransactionKind::Recovery
            || receipt.outcome != RecoveryReceiptOutcome::Completed
            || self.transaction_id != receipt.transaction_id
            || self.account_id != receipt.account_id
            || completion.transaction_id != receipt.transaction_id
            || completion.account_id != receipt.account_id
            || completion.recovery_session_id != receipt.recovery_session_id
            || completion.terminal_receipt_id != receipt.receipt_id
            || completion.terminal_receipt_digest != receipt.receipt_digest()?
            || completion.replacement_device_id != receipt.new_device_id
            || completion.new_model_generation_ref != receipt.new_model_generation_ref
            || completion.completed_at < receipt.completed_at
            || self.created_at != completion.completed_at
            || completion.reanchor_event_ref.event_id != reanchor.event.event_id
            || completion.device_authorization_event_ref.event_id != authorize.event.event_id
            || completion.reanchor_event_ref.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: reanchor.event.realm_id.clone(),
                })
        {
            return protocol(
                "Recovery completion changed the exact signed receipt or native Event binding",
            );
        }
        Ok(())
    }
    pub fn validate_for_request(
        &self,
        request: &RecoveryTransactionCreateRequestBody,
    ) -> Result<()> {
        self.validate_structural()?;
        request.validate()?;
        if !canonical_equal(&self.recovery_receipt, &request.recovery_receipt)? {
            return protocol("Recovery response changed the full signed receipt bytes");
        }
        Ok(())
    }
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationTransactionCreateRequestBody {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    pub authorizing_device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub prepared_plan: SecurityRotationPlan,
}

impl SecurityRotationTransactionCreateRequestBody {
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStepAttestationSignatureProof {
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
    pub artifact: SecurityRotationLocalCommit,
    pub signature_proof: ClientStepAttestationSignatureProof,
}

impl ClientStepAttestation {
    pub fn attestation_digest(&self) -> Result<Hash> {
        digest_value(arkret_canonical::DigestSuite::Sha256, &self.artifact)
    }
    pub fn validate(&self) -> Result<()> {
        validate_step_output_ref(&self.output_ref)?;
        require_sha256("prepared_plan_digest", &self.prepared_plan_digest)?;
        require_sha256("output_ref", &Hash::new(self.output_ref.clone())?)?;
        if self.signature_proof.signature_algorithm != "Ed25519"
            || self.step != SecurityTransactionStep::LocalCommit
        {
            return protocol("client step attestation is only Rotation local_commit Ed25519");
        }
        self.artifact.validate()?;
        self.attestation_digest()?;
        Ok(())
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "step": self.step, "output_ref": self.output_ref, "transaction_id": self.transaction_id,
            "transaction_request_digest": self.transaction_request_digest, "prepared_plan_digest": self.prepared_plan_digest,
            "attestation_digest": self.attestation_digest()?,
        })).map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionContinueRequestBody {
    pub request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub expected_accepted_step_count: u64,
    pub client_attestation: ClientStepAttestation,
}
impl SecurityTransactionContinueRequestBody {
    pub fn validate_for_transaction(&self, transaction: &SecurityTransaction) -> Result<()> {
        let SecurityTransaction::SecurityRotation(transaction) = transaction else {
            return protocol("Recovery has no continue route");
        };
        transaction.validate_structural()?;
        if self.request_digest != transaction.request_digest
            || self.prepared_plan_digest != transaction.prepared_plan_digest
            || usize::try_from(self.expected_accepted_step_count).ok()
                != Some(transaction.accepted_steps.len())
        {
            return protocol("continue request changed request/plan or accepted-prefix CAS");
        }
        if transaction.next_required_step()? != Some(SecurityTransactionStep::LocalCommit) {
            return protocol("only the ready Rotation local_commit may be driven by continue");
        }
        let attestation = &self.client_attestation;
        attestation.validate()?;
        let artifact = &attestation.artifact;
        if attestation.transaction_id != transaction.transaction_id
            || attestation.transaction_request_digest != transaction.request_digest
            || attestation.prepared_plan_digest != transaction.prepared_plan_digest
            || attestation.output_ref != transaction.prepared_plan.local_commit_digest.as_str()
            || artifact.transaction_id != transaction.transaction_id
            || artifact.transaction_request_digest != transaction.request_digest
            || artifact.prepared_plan_digest != transaction.prepared_plan_digest
            || artifact.local_commit_digest != transaction.prepared_plan.local_commit_digest
            || artifact.device_id != transaction.authorizing_device_id
        {
            return protocol(
                "Rotation local commit does not bind the exact current prepared transaction",
            );
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
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
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
pub struct RecoveryReceiptSignatureProof {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceipt {
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub transaction_id: TransactionId,
    pub account_id: AccountId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub recovery_session_id: RecoverySessionId,
    pub session_grant_ref: SessionGrantRef,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TrustDomainId,
    pub new_device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    pub recovery_authority_kind: RecoveryAuthorityKind,
    pub previous_model_generation_ref: u64,
    pub new_model_generation_ref: u64,
    pub proof_summary: RecoveryProofSummary,
    pub recovery_unit: RecoveryUnit,
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
    pub signature_proof: RecoveryReceiptSignatureProof,
}

impl RecoveryReceipt {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        if self.schema != SchemaId::RECOVERY_RECEIPT_V1
            || self.identity_model != RecoveryIdentityModel::PcrPolicy
            || self.recovery_authority_kind != RecoveryAuthorityKind::PcrPolicy
            || self.policy_version == 0
            || self.completed_at < self.started_at
            || self.expires_at <= self.completed_at
            || self.signature_proof.signature_algorithm != "Ed25519"
            || !self
                .signature_proof
                .verification_method
                .as_str()
                .ends_with(&format!("#{}", self.new_device_id))
        {
            return protocol("recovery receipt has invalid closed binding, time or signer fields");
        }
        validate_generation_advance(
            self.previous_model_generation_ref,
            self.new_model_generation_ref,
        )?;
        if (self.proof_summary.kind == RecoveryProofKind::DeviceQuorum)
            != self
                .proof_summary
                .quorum_participant_count
                .is_some_and(|count| count > 0)
            || (self.outcome == RecoveryReceiptOutcome::Completed)
                == self.outcome_reason_code.is_some()
        {
            return protocol("recovery receipt proof or outcome summary is inconsistent");
        }
        for submission in &self.recovery_unit.events {
            submission.validate()?;
            if submission.approval_signatures.is_some() {
                return protocol("native PCR Recovery has no generic approval carrier");
            }
        }
        let [reanchor, authorize] = &self.recovery_unit.events;
        let (reanchor, authorize) = (&reanchor.event, &authorize.event);
        let actor = ActorId::account(self.account_id.clone());
        if reanchor.kind != EventKind::DeviceReanchor
            || authorize.kind != EventKind::DeviceAuthorize
            || reanchor.actor_id != actor
            || authorize.actor_id != actor
            || reanchor.realm_id != authorize.realm_id
            || reanchor.scope_ref
                != (ScopeRef::Realm {
                    realm_id: reanchor.realm_id.clone(),
                })
            || authorize.scope_ref != reanchor.scope_ref
            || reanchor.event_id == authorize.event_id
        {
            return protocol(
                "Recovery unit is not the exact account-owned PCR reanchor/authorize pair",
            );
        }
        for event in [reanchor, authorize] {
            event.validate_for_submit_structural()?;
            event.verify_producer_proof_self_consistency(arkret_canonical::DigestSuite::Sha256)?;
            if unique_producer_signer(event)? != &self.signature_proof.verification_method {
                return protocol("Recovery producer proofs differ from the receipt candidate");
            }
        }
        let r = serde_json::to_value(&reanchor.payload)?;
        let a = serde_json::to_value(&authorize.payload)?;
        if r["account_id"] != serde_json::to_value(&self.account_id)?
            || r["recovery_authority_kind"] != "pcr_policy"
            || r["recovery_policy_id"] != serde_json::to_value(&self.policy_id)?
            || r["recovery_policy_version"] != self.policy_version
            || r["recovery_session_id"] != serde_json::to_value(&self.recovery_session_id)?
            || r["previous_device_generation"] != self.previous_model_generation_ref
            || r["new_device_generation"] != self.new_model_generation_ref
            || r["replacement_authorize_payload_digest"]
                != serde_json::to_value(digest_value(arkret_canonical::DigestSuite::Sha256, &a)?)?
            || a["device_id"] != serde_json::to_value(&self.new_device_id)?
            || a["authorized_by"] != serde_json::to_value(&self.account_id.principal_id)?
            || a["authorization_binding_kind"] != "pcr_recovery"
            || a["authorized_generation_ref"] != self.new_model_generation_ref
            || a["recovery_session_id"] != serde_json::to_value(&self.recovery_session_id)?
        {
            return protocol("Recovery native payloads do not bind the exact receipt intent");
        }
        validate_unique_recovery_artifacts(self)
    }

    /// Check a first submission against independently verified, frozen Session
    /// source. It does not manufacture current grant/policy authorization.
    pub fn validate_for_session(
        &self,
        session: &crate::RecoverySession,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        session.validate_shape()?;
        if session.state != crate::RecoverySessionState::Verified
            || session.transaction_id.is_some()
            || self.account_id != session.account_id
            || self.recovery_session_id != session.recovery_session_id
            || self.session_grant_ref != session.session_grant_ref
            || self.session_grant_cnf_jkt != session.session_grant_cnf_jkt
            || self.policy_id != session.policy_id
            || self.policy_version != session.policy_version
            || self.trust_domain != session.trust_domain
            || self.new_device_id != session.requesting_device_id
            || self.previous_model_generation_ref != session.current_device_generation_ref
            || self.identity_model != session.identity_model
            || self.expires_at > session.expires_at
            || now >= self.expires_at
            || self.completed_at > now
            || session.proof_summary.as_ref().is_none_or(|proof| {
                proof.kind != self.proof_summary.kind
                    || proof.proof_digest != self.proof_summary.proof_digest
            })
            || self.recovery_unit.predecessor_ref != session.realm_stream_head.commit_id
            || session.realm_stream_head.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: self.recovery_unit.events[0].event.realm_id.clone(),
                })
            || serde_json::to_value(&self.recovery_unit.events[1].event.payload)?["device_public_key_did"]
                != serde_json::to_value(&session.requesting_device_public_key_did)?
        {
            return protocol(
                "Recovery receipt differs from the verified Session source or first-admission window",
            );
        }
        Ok(())
    }

    pub fn signature_transcript_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| WireError::Protocol("receipt must be an object".into()))?
            .remove("signature_proof");
        let mut bytes = b"ak.identity.recovery_receipt.signature.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }
    pub fn receipt_digest(&self) -> Result<Hash> {
        self.validate()?;
        digest_value(arkret_canonical::DigestSuite::Sha256, self)
    }
}

fn unique_producer_signer(event: &Event) -> Result<&DidUrl> {
    Ok(&event
        .producer_proof
        .as_ref()
        .ok_or_else(|| WireError::Protocol("Recovery Event requires producer_proof".into()))?
        .verification_method)
}

include!("generated/security_transaction_contracts.rs");
/// `SHA-256(JCS({schema: "ak.backup_series_erase_confirmation_preimage.v1",
/// transaction_id, series}))` over the plan's backup rotation bindings
/// (security-transactions.md §3). The preimage discriminator member is
/// `schema`; the final request/plan digests are deliberately excluded.
pub fn security_rotation_erase_confirmation_digest(
    transaction_id: &TransactionId,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    digest_value(
        arkret_canonical::DigestSuite::Sha256,
        &serde_json::json!({
            "schema": "ak.backup_series_erase_confirmation_preimage.v1",
            "transaction_id": transaction_id,
            "series": backup_rotations,
        }),
    )
}

/// `SHA-256(JCS({schema: "ak.security_rotation_local_commit_preimage.v1",
/// transaction_id, new_secret_commitment, backup_rotations}))` over the plan's
/// backup rotation bindings (security-transactions.md §3).
pub fn security_rotation_local_commit_digest(
    transaction_id: &TransactionId,
    new_secret_commitment: &Hash,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    digest_value(
        arkret_canonical::DigestSuite::Sha256,
        &serde_json::json!({
            "schema": "ak.security_rotation_local_commit_preimage.v1",
            "transaction_id": transaction_id,
            "new_secret_commitment": new_secret_commitment,
            "backup_rotations": backup_rotations,
        }),
    )
}

fn validate_native_control_unit(unit: &PreparedEventUnit) -> Result<()> {
    unit.validate()?;
    // Native PCR control has no registered capability-action approval carrier.
    // Preserve the shared admission DTO, but never silently discard its evidence.
    if unit
        .request
        .events
        .iter()
        .any(|slot| slot.approval_signatures.is_some())
    {
        return protocol("native PCR control unit does not accept approval_signatures");
    }
    Ok(())
}

fn validate_security_rotation_plan(
    transaction_id: &TransactionId,
    account_id: &AccountId,
    plan: &SecurityRotationPlan,
) -> Result<()> {
    validate_native_control_unit(&plan.revoke_unit)?;
    let [revoke]: &[_; 1] = plan
        .revoke_unit
        .request
        .events
        .as_slice()
        .try_into()
        .map_err(|_| {
            WireError::Protocol("security rotation revoke unit requires one Event".to_owned())
        })?;
    let revoke = &revoke.event;
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
        if rotation.new_backup_envelopes.len() != binding.new_backups.len() {
            return protocol("security rotation backup envelope count differs from binding");
        }
        for (index, (envelope, reference)) in rotation
            .new_backup_envelopes
            .iter()
            .zip(&binding.new_backups)
            .enumerate()
        {
            envelope.validate()?;
            if envelope.backup_id != reference.backup_id
                || envelope.ciphertext_digest != reference.ciphertext_digest
                || envelope.series_id != binding.new_series_id
                || envelope.backup_kind != crate::BackupKind::SecretStorage
                || (index > 0
                    && rotation.new_backup_envelopes[index - 1].backup_id.as_str()
                        >= envelope.backup_id.as_str())
            {
                return protocol(
                    "security rotation backup envelopes differ from canonical binding",
                );
            }
        }
        validate_native_control_unit(&rotation.active_series_unit)?;
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
        let active_series = &active_series.event;
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

fn validate_generation_advance(previous: u64, outcome: u64) -> Result<()> {
    if previous == 0
        || previous >= 9_007_199_254_740_991
        || previous.checked_add(1) != Some(outcome)
    {
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

    /// Known-answer vectors for the two non-circular reserved digests of
    /// security-transactions.md §3. The expected values were computed
    /// independently of this crate (RFC 8785 JCS + SHA-256) from the
    /// normative preimages, whose discriminator member is `schema`.
    #[test]
    fn security_rotation_reserved_digests_match_the_normative_preimage_kat() {
        let transaction_id =
            TransactionId::new("ak:transaction:019a7400-0000-7000-8000-000000000006").unwrap();
        let bindings = vec![erase_binding()];
        let new_secret_commitment = Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap();

        let erase_preimage = serde_json::json!({
            "schema": "ak.backup_series_erase_confirmation_preimage.v1",
            "transaction_id": transaction_id,
            "series": bindings,
        });
        assert_eq!(
            String::from_utf8(arkret_canonical::canonical_json_bytes(&erase_preimage).unwrap())
                .unwrap(),
            concat!(
                r#"{"schema":"ak.backup_series_erase_confirmation_preimage.v1","series":[{"#,
                r#""active_series_event_id":"ak:event:AWKDhmQTc5zyfilaLwPF3xnhoZAjxSha7Z-6grioN9aW","#,
                r#""backup_kind":"secret_storage","new_backups":[{"backup_id":"#,
                r#""ak:backup:019a7400-0000-7000-8000-000000000003","ciphertext_digest":"#,
                r#""sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"#,
                r#""new_series_id":"ak:backup_series:019a7400-0000-7000-8000-000000000002","#,
                r#""old_backups":[{"backup_id":"ak:backup:019a7400-0000-7000-8000-000000000005","#,
                r#""ciphertext_digest":"#,
                r#""sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"#,
                r#""previous_series_id":"ak:backup_series:019a7400-0000-7000-8000-000000000001"}],"#,
                r#""transaction_id":"ak:transaction:019a7400-0000-7000-8000-000000000006"}"#,
            )
        );
        assert_eq!(
            security_rotation_erase_confirmation_digest(&transaction_id, &bindings)
                .unwrap()
                .as_str(),
            "sha256:3e7c058a76c28ad2c456d38b6cd039e30e8c6722c82303e7ccf0b6954e58d1fa"
        );
        assert_eq!(
            security_rotation_local_commit_digest(
                &transaction_id,
                &new_secret_commitment,
                &bindings
            )
            .unwrap()
            .as_str(),
            "sha256:2c88de3197cdfcb188ce59f2fe5afe518509b1f5171dff34f585f291800a73f1"
        );

        // The retired `domain` discriminator produces a different digest and
        // must never be accepted as the reserved value.
        let legacy = serde_json::json!({
            "domain": "ak.backup_series_erase_confirmation_preimage.v1",
            "transaction_id": transaction_id,
            "series": bindings,
        });
        assert_ne!(
            digest_value(arkret_canonical::DigestSuite::Sha256, &legacy).unwrap(),
            security_rotation_erase_confirmation_digest(&transaction_id, &bindings).unwrap()
        );
    }

    #[test]
    fn continue_request_requires_one_client_attestation() {
        let value = serde_json::json!({
            "request_digest": format!("sha256:{}", "a".repeat(64)),
            "prepared_plan_digest": format!("sha256:{}", "b".repeat(64)),
            "expected_accepted_step_count": 0
        });
        assert!(serde_json::from_value::<SecurityTransactionContinueRequestBody>(value).is_err());
    }

    #[test]
    fn accepted_step_carries_only_acceptor_and_time() {
        let value = serde_json::json!({
            "acceptor": {
                "kind": "device",
                "device_id": "ak:device:019a7400-0000-7000-8000-000000000003"
            },
            "accepted_at": "2026-09-24T00:00:00.000Z"
        });
        let step: AcceptedSecurityTransactionStep = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(step).unwrap(), value);
        for field in ["prepared_material_digest", "output_ref", "output_digest"] {
            let mut legacy = value.clone();
            legacy[field] = serde_json::json!("retired");
            assert!(serde_json::from_value::<AcceptedSecurityTransactionStep>(legacy).is_err());
        }
    }
}
