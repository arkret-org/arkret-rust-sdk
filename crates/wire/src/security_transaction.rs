//! Closed durable security transactions (`zh/identity/security-transactions.md`).
//!
//! The wire separates three states that implementations must never conflate:
//! reserved identities in `binding`, canonical public bytes in
//! `prepared_plan`, and externally accepted outputs in `accepted_steps`.
//! Recovery is additionally discriminated by identity model. This is not a
//! general Saga/Plan DSL.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::recovery_authority::{
    CanonicalPublicMaterial, RecoveryCompletionAttestation, RecoveryModelGenerationRef,
};
use crate::{
    BackupId, BackupSeriesId, DeviceId, Did, DidUrl, EventId, EventInitialSubmission,
    EventsSubmitBatchRequestBody, Hash, ReceiptId, RecoverySessionId, TransactionId,
};

pub const MAX_SECURITY_TRANSACTION_TTL: Duration = Duration::hours(24);
pub const MAX_ACCEPTED_STEPS: usize = 5;
pub const MAX_OPAQUE_REF_CHARS: usize = 2048;
pub const CLIENT_STEP_ATTESTATION_SIGNED_FIELDS: [&str; 6] = [
    "step",
    "output_ref",
    "transaction_id",
    "transaction_request_digest",
    "prepared_plan_digest",
    "attestation_digest",
];

pub const ROOT_ANCHORED_RECOVERY_STEP_ORDER: [SecurityTransactionStep; 3] = [
    SecurityTransactionStep::PublishDidEntry,
    SecurityTransactionStep::SubmitReanchorUnit,
    SecurityTransactionStep::IssueTerminalReceipt,
];

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
    RootAnchored,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionState {
    Pending,
    Running,
    AwaitingDeviceAttestation,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRotationKind {
    SecretStorage,
    MlsHistory,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTransactionStep {
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
    pub prepared_material_digest: Hash,
    pub acceptor_id: String,
    pub output_ref: String,
    pub output_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootAnchoredRecoveryBinding {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_id: RecoverySessionId,
    pub replacement_device_id: DeviceId,
    pub did_entry_ref: String,
    pub reanchor_event_id: EventId,
    pub authorize_event_id: EventId,
    pub terminal_receipt_id: ReceiptId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryBinding {
    RootAnchored(RootAnchoredRecoveryBinding),
}

impl RecoveryBinding {
    pub fn identity_model(&self) -> RecoveryIdentityModel {
        RecoveryIdentityModel::RootAnchored
    }

    pub fn terminal_receipt_id(&self) -> &ReceiptId {
        let Self::RootAnchored(binding) = self;
        &binding.terminal_receipt_id
    }

    pub fn recovery_session_id(&self) -> &RecoverySessionId {
        let Self::RootAnchored(binding) = self;
        &binding.recovery_session_id
    }

    fn validate_discriminator(&self) -> Result<()> {
        let Self::RootAnchored(binding) = self;
        let valid = binding.identity_model == RecoveryIdentityModel::RootAnchored;
        if !valid {
            return Err(Error::Protocol(
                "recovery binding identity_model disagrees with its closed shape".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationBinding {
    pub revoke_event_id: EventId,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<BackupRotationBinding>,
    pub erase_confirmation_digest: Hash,
    pub local_commit_digest: Hash,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecurityTransactionBinding {
    Recovery(RecoveryBinding),
    SecurityRotation(SecurityRotationBinding),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEventUnit {
    pub operation_id: String,
    pub destination_service_id: Did,
    pub audience: Did,
    pub request_schema: String,
    pub request: BTreeMap<String, Value>,
    pub canonical_request_base64url: String,
    pub request_digest: Hash,
}

impl PreparedEventUnit {
    pub fn new<T: Serialize>(destination_service_id: Did, request: T) -> Result<Self> {
        let request = serde_json::to_value(request)?;
        let Value::Object(request) = request else {
            return Err(Error::Protocol(
                "prepared Event unit request must be a JSON object".to_owned(),
            ));
        };
        let request = request.into_iter().collect::<BTreeMap<_, _>>();
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&request)?;
        Ok(Self {
            operation_id: "ak.self.events.command.submit".to_owned(),
            audience: destination_service_id.clone(),
            destination_service_id,
            request_schema: "https://arkret.org/v1/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitBatchRequestBody".to_owned(),
            canonical_request_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            request_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes))?,
            request,
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEventSubmissionBatch {
    pub destination_service_id: Did,
    pub audience: Did,
    pub request: EventsSubmitBatchRequestBody,
    pub canonical_request_base64url: String,
    pub request_digest: Hash,
}

impl PreparedEventSubmissionBatch {
    pub fn new(destination_service_id: Did, request: EventsSubmitBatchRequestBody) -> Result<Self> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&request)?;
        Ok(Self {
            audience: destination_service_id.clone(),
            destination_service_id,
            request,
            canonical_request_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            request_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes))?,
        })
    }

    fn validate_structural(&self, coordinator_service_id: &Did) -> Result<()> {
        if &self.destination_service_id != coordinator_service_id
            || self.audience != self.destination_service_id
        {
            return Err(Error::Protocol(
                "prepared Event publication batch destination or audience is invalid".to_owned(),
            ));
        }
        let bytes = arkret_canonical::base64url_decode(&self.canonical_request_base64url)?;
        let canonical = arkret_canonical::canonical::canonical_json_bytes(&self.request)?;
        if bytes != canonical {
            return Err(Error::Protocol(
                "prepared Event publication batch bytes do not equal the typed request".to_owned(),
            ));
        }
        arkret_canonical::canonical::verify_digest(&bytes, self.request_digest.as_str())?;
        for submission in &self.request.events {
            submission.validate_structural()?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDidPublication {
    pub registry_service_id: Did,
    pub registry_endpoint: String,
    pub previous_entry_ref: String,
    pub expected_entry_ref: String,
    pub canonical_entry_base64url: String,
    pub entry_digest: Hash,
}

impl PreparedDidPublication {
    pub fn validate_structural(&self) -> Result<()> {
        let endpoint = url::Url::parse(&self.registry_endpoint).map_err(|error| {
            Error::Protocol(format!(
                "prepared DID registry endpoint is invalid: {error}"
            ))
        })?;
        let loopback_http = endpoint.scheme() == "http"
            && endpoint.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
        if (endpoint.scheme() != "https" && !loopback_http)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/_arkret/root/identity/submit-did-operation"
        {
            return Err(Error::Protocol(
                "prepared DID registry endpoint must be the exact standard HTTPS submit endpoint \
                 (HTTP is allowed only on loopback)"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootAnchoredRecoveryPlan {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_snapshot_digest: Hash,
    pub proof_digest: Hash,
    pub previous_model_generation_ref: String,
    pub result_model_generation_ref: String,
    pub did_publication: PreparedDidPublication,
    pub reanchor_unit: PreparedEventUnit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum RecoveryPreparedPlan {
    RootAnchored(RootAnchoredRecoveryPlan),
}

impl RecoveryPreparedPlan {
    pub fn identity_model(&self) -> RecoveryIdentityModel {
        RecoveryIdentityModel::RootAnchored
    }

    fn validate_discriminator(&self) -> Result<()> {
        let Self::RootAnchored(plan) = self;
        let valid = plan.identity_model == RecoveryIdentityModel::RootAnchored;
        if !valid {
            return Err(Error::Protocol(
                "recovery prepared plan identity_model disagrees with its closed shape".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct BackupRotationPlan {
    pub binding: BackupRotationBinding,
    pub encrypted_backup_material: CanonicalPublicMaterial,
    pub active_series_unit: PreparedEventUnit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum SecurityTransactionPreparedPlan {
    Recovery(RecoveryPreparedPlan),
    SecurityRotation(SecurityRotationPlan),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_attestation: Option<RecoveryCompletionAttestation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    pub prepared_plan: SecurityTransactionPreparedPlan,
    pub prepared_plan_digest: Hash,
    pub state: SecurityTransactionState,
    pub accepted_steps: Vec<AcceptedStep>,
    pub next_required_step: Option<SecurityTransactionStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<SecurityTransactionTerminalResult>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub principal_id: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub binding: RecoveryBinding,
    pub prepared_plan: RecoveryPreparedPlan,
    pub prepared_plan_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub principal_id: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub binding: SecurityRotationBinding,
    pub prepared_plan: SecurityRotationPlan,
    pub prepared_plan_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum SecurityTransactionCreateRequest {
    Recovery(RecoveryTransactionCreateRequest),
    SecurityRotation(SecurityRotationTransactionCreateRequest),
}

impl RecoveryTransactionCreateRequest {
    pub fn new(
        transaction_id: TransactionId,
        principal_id: Did,
        expires_at: DateTime<Utc>,
        binding: RecoveryBinding,
        prepared_plan: RecoveryPreparedPlan,
    ) -> Result<Self> {
        binding.validate_discriminator()?;
        prepared_plan.validate_discriminator()?;
        if binding.identity_model() != prepared_plan.identity_model() {
            return Err(Error::Protocol(
                "recovery binding and prepared plan identity models disagree".to_owned(),
            ));
        }
        let prepared_plan_digest = Hash::new(arkret_canonical::canonical::canonical_sha256(
            &SecurityTransactionPreparedPlan::Recovery(prepared_plan.clone()),
        )?)?;
        Ok(Self {
            transaction_id,
            kind: SecurityTransactionKind::Recovery,
            principal_id,
            expires_at,
            binding,
            prepared_plan,
            prepared_plan_digest,
        })
    }
}

impl SecurityRotationTransactionCreateRequest {
    pub fn from_prepared_rotations(
        transaction_id: TransactionId,
        principal_id: Did,
        expires_at: DateTime<Utc>,
        revoke_event_id: EventId,
        revoke_unit: PreparedEventUnit,
        new_secret_commitment: Hash,
        backup_rotations: Vec<BackupRotationPlan>,
    ) -> Result<Self> {
        let bindings = backup_rotations
            .iter()
            .map(|rotation| rotation.binding.clone())
            .collect::<Vec<_>>();
        let erase_confirmation_digest =
            security_rotation_erase_confirmation_digest(&transaction_id, &bindings)?;
        let local_commit_digest = security_rotation_local_commit_digest(
            &transaction_id,
            &new_secret_commitment,
            &bindings,
        )?;
        Self::new(
            transaction_id,
            principal_id,
            expires_at,
            SecurityRotationBinding {
                revoke_event_id,
                new_secret_commitment: new_secret_commitment.clone(),
                backup_rotations: bindings,
                erase_confirmation_digest: erase_confirmation_digest.clone(),
                local_commit_digest: local_commit_digest.clone(),
            },
            SecurityRotationPlan {
                revoke_unit,
                new_secret_commitment,
                backup_rotations,
                erase_confirmation_digest,
                local_commit_digest,
            },
        )
    }

    pub fn new(
        transaction_id: TransactionId,
        principal_id: Did,
        expires_at: DateTime<Utc>,
        binding: SecurityRotationBinding,
        prepared_plan: SecurityRotationPlan,
    ) -> Result<Self> {
        validate_security_rotation_fixed_shape(&binding, &prepared_plan)?;
        if binding.erase_confirmation_digest
            != security_rotation_erase_confirmation_digest(
                &transaction_id,
                &binding.backup_rotations,
            )?
            || binding.local_commit_digest
                != security_rotation_local_commit_digest(
                    &transaction_id,
                    &binding.new_secret_commitment,
                    &binding.backup_rotations,
                )?
        {
            return Err(Error::Protocol(
                "security-rotation reserved outcome digests do not match their non-circular projections"
                    .to_owned(),
            ));
        }
        let prepared_plan_digest = Hash::new(arkret_canonical::canonical::canonical_sha256(
            &SecurityTransactionPreparedPlan::SecurityRotation(prepared_plan.clone()),
        )?)?;
        Ok(Self {
            transaction_id,
            kind: SecurityTransactionKind::SecurityRotation,
            principal_id,
            expires_at,
            binding,
            prepared_plan,
            prepared_plan_digest,
        })
    }
}

pub fn security_rotation_erase_confirmation_digest(
    transaction_id: &TransactionId,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
        &serde_json::json!({
            "domain": "ak.backup_series_erase_confirmation_preimage.v1",
            "transaction_id": transaction_id,
            "series": backup_rotations,
        }),
    )?)?)
}

pub fn security_rotation_local_commit_digest(
    transaction_id: &TransactionId,
    new_secret_commitment: &Hash,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
        &serde_json::json!({
            "domain": "ak.security_rotation_local_commit_preimage.v1",
            "transaction_id": transaction_id,
            "new_secret_commitment": new_secret_commitment,
            "backup_rotations": backup_rotations,
        }),
    )?)?)
}

fn validate_security_rotation_fixed_shape(
    binding: &SecurityRotationBinding,
    plan: &SecurityRotationPlan,
) -> Result<()> {
    if binding.new_secret_commitment != plan.new_secret_commitment
        || binding.backup_rotations.len() != 2
        || plan.backup_rotations.len() != 2
        || binding.erase_confirmation_digest != plan.erase_confirmation_digest
        || binding.local_commit_digest != plan.local_commit_digest
    {
        return Err(Error::Protocol(
            "security-rotation binding and prepared plan artifacts disagree".to_owned(),
        ));
    }
    for (index, expected_kind) in [
        BackupRotationKind::SecretStorage,
        BackupRotationKind::MlsHistory,
    ]
    .into_iter()
    .enumerate()
    {
        let rotation = &binding.backup_rotations[index];
        if rotation.backup_kind != expected_kind
            || plan.backup_rotations[index].binding != *rotation
            || rotation.previous_series_id == rotation.new_series_id
            || rotation.new_backups.is_empty()
            || rotation.old_backups.is_empty()
        {
            return Err(Error::Protocol(
                "security-rotation requires exact secret_storage and mls_history rotations"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

impl SecurityTransactionCreateRequest {
    /// Converts the exact canonical create request into its durable initial
    /// resource. Coordinators persist both returned values atomically before
    /// executing the first external side effect.
    pub fn into_initial_resource(
        self,
        coordinator_service_id: Did,
        created_at: DateTime<Utc>,
    ) -> Result<(SecurityTransaction, Vec<u8>)> {
        let canonical_request = arkret_canonical::canonical::canonical_json_bytes(&self)?;
        let request_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
            &canonical_request,
        ))?;
        let (
            transaction_id,
            kind,
            principal_id,
            expires_at,
            binding,
            prepared_plan,
            prepared_plan_digest,
            next_required_step,
        ) = match self {
            Self::Recovery(request) => {
                let next = SecurityTransactionStep::PublishDidEntry;
                (
                    request.transaction_id,
                    request.kind,
                    request.principal_id,
                    request.expires_at,
                    SecurityTransactionBinding::Recovery(request.binding),
                    SecurityTransactionPreparedPlan::Recovery(request.prepared_plan),
                    request.prepared_plan_digest,
                    next,
                )
            }
            Self::SecurityRotation(request) => (
                request.transaction_id,
                request.kind,
                request.principal_id,
                request.expires_at,
                SecurityTransactionBinding::SecurityRotation(request.binding),
                SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan),
                request.prepared_plan_digest,
                SecurityTransactionStep::Revoke,
            ),
        };
        let resource = SecurityTransaction {
            transaction_id,
            kind,
            principal_id,
            coordinator_service_id,
            expires_at,
            created_at,
            request_digest,
            binding,
            prepared_plan,
            prepared_plan_digest,
            state: SecurityTransactionState::Pending,
            accepted_steps: Vec::new(),
            next_required_step: Some(next_required_step),
            terminal_result: None,
        };
        resource.validate_structural()?;
        Ok((resource, canonical_request))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStepAttestationAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStepAttestation<A = Value> {
    pub step: SecurityTransactionStep,
    pub output_ref: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub attestation_digest: Hash,
    pub artifact: A,
    pub auth_data: ClientStepAttestationAuthData,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[cfg_attr(
    feature = "openapi",
    salvo(schema(bound = "A: salvo_oapi::ToSchema + salvo_oapi::ComposeSchema + 'static"))
)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(serialize = "A: Serialize", deserialize = "A: Deserialize<'de>")
)]
pub struct SecurityTransactionContinueRequest<A = Value> {
    pub request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub expected_next_step: SecurityTransactionStep,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientStepAttestation<A>>,
}

impl<A: Serialize> ClientStepAttestation<A> {
    pub fn validate_structural(&self) -> Result<()> {
        if self.auth_data.signature_algorithm != "Ed25519"
            || self.auth_data.verification_method.is_empty()
            || self.auth_data.signature.is_empty()
            || self
                .auth_data
                .signed_fields
                .iter()
                .map(String::as_str)
                .ne(CLIENT_STEP_ATTESTATION_SIGNED_FIELDS)
        {
            return Err(Error::Protocol(
                "client step attestation authorization is incomplete or has invalid signed_fields"
                    .to_owned(),
            ));
        }
        validate_step_output_ref("client_attestation.output_ref", &self.output_ref)?;
        let artifact_bytes = arkret_canonical::canonical::canonical_json_bytes(&self.artifact)?;
        arkret_canonical::canonical::verify_digest(
            &artifact_bytes,
            self.attestation_digest.as_str(),
        )?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        client_step_attestation_signing_bytes(
            self.step,
            &self.output_ref,
            &self.transaction_id,
            &self.transaction_request_digest,
            &self.prepared_plan_digest,
            &self.attestation_digest,
        )
    }
}

/// Client-step attestation before the detached JWS exists. This state is not
/// serializable and owns the one canonical transcript used by producers.
#[derive(Clone, Debug)]
pub struct UnsignedClientStepAttestation<A> {
    step: SecurityTransactionStep,
    output_ref: String,
    transaction_id: TransactionId,
    transaction_request_digest: Hash,
    prepared_plan_digest: Hash,
    attestation_digest: Hash,
    artifact: A,
    verification_method: DidUrl,
}

impl<A: Serialize> UnsignedClientStepAttestation<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        step: SecurityTransactionStep,
        output_ref: String,
        transaction_id: TransactionId,
        transaction_request_digest: Hash,
        prepared_plan_digest: Hash,
        attestation_digest: Hash,
        artifact: A,
        verification_method: DidUrl,
    ) -> Result<Self> {
        validate_step_output_ref("client_attestation.output_ref", &output_ref)?;
        let artifact_bytes = arkret_canonical::canonical::canonical_json_bytes(&artifact)?;
        arkret_canonical::canonical::verify_digest(&artifact_bytes, attestation_digest.as_str())?;
        Ok(Self {
            step,
            output_ref,
            transaction_id,
            transaction_request_digest,
            prepared_plan_digest,
            attestation_digest,
            artifact,
            verification_method,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        client_step_attestation_signing_bytes(
            self.step,
            &self.output_ref,
            &self.transaction_id,
            &self.transaction_request_digest,
            &self.prepared_plan_digest,
            &self.attestation_digest,
        )
    }

    pub fn attach_signature(
        self,
        signature: crate::NonEmptyString,
    ) -> Result<ClientStepAttestation<A>> {
        let attestation = ClientStepAttestation {
            step: self.step,
            output_ref: self.output_ref,
            transaction_id: self.transaction_id,
            transaction_request_digest: self.transaction_request_digest,
            prepared_plan_digest: self.prepared_plan_digest,
            attestation_digest: self.attestation_digest,
            artifact: self.artifact,
            auth_data: ClientStepAttestationAuthData {
                verification_method: self.verification_method,
                signature_algorithm: "Ed25519".to_owned(),
                signature: signature.into_string(),
                signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
        };
        attestation.validate_structural()?;
        Ok(attestation)
    }
}

fn client_step_attestation_signing_bytes(
    step: SecurityTransactionStep,
    output_ref: &str,
    transaction_id: &TransactionId,
    transaction_request_digest: &Hash,
    prepared_plan_digest: &Hash,
    attestation_digest: &Hash,
) -> Result<Vec<u8>> {
    let value = serde_json::json!({
        "step": step,
        "output_ref": output_ref,
        "transaction_id": transaction_id,
        "transaction_request_digest": transaction_request_digest,
        "prepared_plan_digest": prepared_plan_digest,
        "attestation_digest": attestation_digest,
    });
    Ok(arkret_canonical::canonical::canonical_json_bytes(&value)?)
}

fn validate_opaque_ref(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > MAX_OPAQUE_REF_CHARS
        || value.chars().any(char::is_whitespace)
    {
        return Err(Error::Protocol(format!(
            "{name} must be 1..={MAX_OPAQUE_REF_CHARS} non-whitespace characters"
        )));
    }
    Ok(())
}

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
    let did_or_url = value.starts_with("did:") && value.len() > 4;
    let digest = Hash::new(value).is_ok();
    if !(typed_id || did_or_url || digest) {
        return Err(Error::Protocol(format!(
            "{name} must be a typed ak: id, DID/DID URL, or registered digest"
        )));
    }
    Ok(())
}

fn validate_canonical_digest<T: Serialize + ?Sized>(
    name: &str,
    value: &T,
    expected: &Hash,
) -> Result<()> {
    let bytes = arkret_canonical::canonical::canonical_json_bytes(value)?;
    arkret_canonical::canonical::verify_digest(&bytes, expected.as_str()).map_err(|_| {
        Error::Protocol(format!(
            "{name} does not equal the digest of the complete canonical value"
        ))
    })
}

impl PreparedEventUnit {
    fn validate_structural(&self, coordinator_service_id: &Did) -> Result<()> {
        if self.operation_id != "ak.self.events.command.submit"
            || self.request_schema
                != "https://arkret.org/v1/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitBatchRequestBody"
            || &self.destination_service_id != coordinator_service_id
            || self.audience != self.destination_service_id
        {
            return Err(Error::Protocol(
                "prepared Event unit operation/schema/destination/audience binding is invalid"
                    .to_owned(),
            ));
        }
        let bytes =
            arkret_canonical::base64url::base64url_decode(&self.canonical_request_base64url)?;
        if bytes != arkret_canonical::canonical::canonical_json_bytes(&self.request)? {
            return Err(Error::Protocol(
                "prepared Event unit bytes do not equal canonical request bytes".to_owned(),
            ));
        }
        arkret_canonical::canonical::verify_digest(&bytes, self.request_digest.as_str())?;
        Ok(())
    }

    fn events_submit_request(
        &self,
        coordinator_service_id: &Did,
    ) -> Result<EventsSubmitBatchRequestBody> {
        self.validate_structural(coordinator_service_id)?;
        serde_json::from_value(serde_json::to_value(&self.request)?).map_err(|error| {
            Error::Protocol(format!(
                "prepared Event unit is not a typed EventsSubmitBatchRequestBody: {error}"
            ))
        })
    }
}

impl SecurityTransaction {
    pub fn step_order(&self) -> Result<&'static [SecurityTransactionStep]> {
        match (&self.kind, &self.binding, &self.prepared_plan) {
            (
                SecurityTransactionKind::Recovery,
                SecurityTransactionBinding::Recovery(binding),
                SecurityTransactionPreparedPlan::Recovery(plan),
            ) if binding.identity_model() == plan.identity_model() => {
                Ok(&ROOT_ANCHORED_RECOVERY_STEP_ORDER)
            }
            (
                SecurityTransactionKind::SecurityRotation,
                SecurityTransactionBinding::SecurityRotation(_),
                SecurityTransactionPreparedPlan::SecurityRotation(_),
            ) => Ok(&SECURITY_ROTATION_STEP_ORDER),
            _ => Err(Error::Protocol(
                "security transaction kind, binding and prepared plan discriminators disagree"
                    .to_owned(),
            )),
        }
    }

    pub fn remaining_steps(&self) -> Result<&'static [SecurityTransactionStep]> {
        let order = self.step_order()?;
        Ok(&order[self.accepted_steps.len().min(order.len())..])
    }

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

        validate_canonical_digest(
            "prepared_plan_digest",
            &self.prepared_plan,
            &self.prepared_plan_digest,
        )?;

        if let (
            SecurityTransactionBinding::Recovery(binding),
            SecurityTransactionPreparedPlan::Recovery(plan),
        ) = (&self.binding, &self.prepared_plan)
        {
            binding.validate_discriminator()?;
            plan.validate_discriminator()?;
            self.validate_recovery_binding_plan(binding, plan)?;
        }

        if let (
            SecurityTransactionBinding::SecurityRotation(binding),
            SecurityTransactionPreparedPlan::SecurityRotation(plan),
        ) = (&self.binding, &self.prepared_plan)
        {
            self.validate_security_rotation_binding_plan(binding, plan)?;
        }

        if let SecurityTransactionBinding::Recovery(RecoveryBinding::RootAnchored(binding)) =
            &self.binding
        {
            validate_opaque_ref("did_entry_ref", &binding.did_entry_ref)?;
        }

        let order = self.step_order()?;
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
            if Did::new(accepted.acceptor_id.clone()).is_err()
                && DeviceId::new(accepted.acceptor_id.clone()).is_err()
            {
                return Err(Error::Protocol(
                    "accepted_steps[].acceptor_id must be a DID or DeviceId".to_owned(),
                ));
            }
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
                SecurityTransactionState::Completed => {
                    if self.accepted_steps.len() != order.len() {
                        return Err(Error::Protocol(
                            "completed security transaction must contain its full closed step order"
                                .to_owned(),
                        ));
                    }
                    if self.kind == SecurityTransactionKind::Recovery
                        && outcome.receipt_id.is_none()
                    {
                        return Err(Error::Protocol(
                            "completed recovery transaction must carry a receipt_id".to_owned(),
                        ));
                    }
                    if self.kind == SecurityTransactionKind::SecurityRotation
                        && outcome.receipt_id.is_some()
                    {
                        return Err(Error::Protocol(
                            "completed security rotation must not invent a receipt_id".to_owned(),
                        ));
                    }
                    SecurityTransactionResultKind::Completed
                }
                SecurityTransactionState::Aborted => SecurityTransactionResultKind::Aborted,
                SecurityTransactionState::Expired => SecurityTransactionResultKind::Expired,
                _ => unreachable!("state was checked to be terminal"),
            };
            if outcome.result != expected {
                return Err(Error::Protocol(
                    "security transaction terminal outcome disagrees with its state".to_owned(),
                ));
            }
            match (self.kind, self.state, &outcome.completion_attestation) {
                (
                    SecurityTransactionKind::Recovery,
                    SecurityTransactionState::Completed,
                    Some(attestation),
                ) => {
                    attestation.validate_structural()?;
                    let (
                        SecurityTransactionBinding::Recovery(binding),
                        SecurityTransactionPreparedPlan::Recovery(plan),
                    ) = (&self.binding, &self.prepared_plan)
                    else {
                        unreachable!("kind/binding/plan closure was validated above")
                    };
                    let (
                        RecoveryBinding::RootAnchored(binding),
                        RecoveryPreparedPlan::RootAnchored(plan),
                    ) = (binding, plan);
                    let replacement_device_id = &binding.replacement_device_id;
                    let authorize_event_id = &binding.authorize_event_id;
                    let result_generation = RecoveryModelGenerationRef::RootAnchored(
                        plan.result_model_generation_ref.clone(),
                    );
                    let receipt_step = self.accepted_steps.last().ok_or_else(|| {
                        Error::Protocol(
                            "completed recovery transaction is missing its receipt step".to_owned(),
                        )
                    })?;
                    if attestation.transaction_id != self.transaction_id
                        || attestation.transaction_request_digest != self.request_digest
                        || attestation.prepared_plan_digest != self.prepared_plan_digest
                        || attestation.principal_id != self.principal_id
                        || attestation.coordinator_service_id != self.coordinator_service_id
                        || attestation.recovery_session_id != binding.recovery_session_id
                        || attestation.terminal_receipt_id != binding.terminal_receipt_id
                        || receipt_step.output_ref != attestation.terminal_receipt_id.as_str()
                        || receipt_step.output_digest != attestation.terminal_receipt_digest
                        || &attestation.replacement_device_id != replacement_device_id
                        || &attestation.device_authorization_event_id != authorize_event_id
                        || attestation.result_model_generation_ref != result_generation
                        || attestation.completed_at != outcome.completed_at
                    {
                        return Err(Error::Protocol(
                            "recovery completion attestation disagrees with the durable transaction"
                                .to_owned(),
                        ));
                    }
                }
                (SecurityTransactionKind::Recovery, SecurityTransactionState::Completed, None) => {
                    return Err(Error::Protocol(
                        "completed recovery transaction requires a completion attestation"
                            .to_owned(),
                    ));
                }
                (_, _, Some(_)) => {
                    return Err(Error::Protocol(
                        "only a completed recovery transaction may carry a completion attestation"
                            .to_owned(),
                    ));
                }
                _ => {}
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
        let awaiting_expected = self.accepted_steps.len() + 1 == order.len()
            && matches!(
                next,
                SecurityTransactionStep::IssueTerminalReceipt
                    | SecurityTransactionStep::LocalCommit
            );
        if (self.state == SecurityTransactionState::AwaitingDeviceAttestation) != awaiting_expected
        {
            return Err(Error::Protocol(
                "awaiting_device_attestation must be used exactly at the terminal client-attestation boundary"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_recovery_binding_plan(
        &self,
        binding: &RecoveryBinding,
        plan: &RecoveryPreparedPlan,
    ) -> Result<()> {
        let (RecoveryBinding::RootAnchored(binding), RecoveryPreparedPlan::RootAnchored(plan)) =
            (binding, plan);
        plan.did_publication.validate_structural()?;
        let reanchor_request = plan
            .reanchor_unit
            .events_submit_request(&self.coordinator_service_id)?;
        let expected = [
            (binding.reanchor_event_id.as_str(), "ak.device.reanchor"),
            (binding.authorize_event_id.as_str(), "ak.device.authorize"),
        ];
        if plan.did_publication.expected_entry_ref != binding.did_entry_ref
            || reanchor_request.events.len() != expected.len()
            || reanchor_request
                .events
                .iter()
                .zip(expected)
                .any(|(submission, (id, kind))| {
                    submission.event.event_id.as_str() != id || submission.event.kind != kind
                })
        {
            return Err(Error::Protocol(
                "root-anchored binding and prepared reanchor unit disagree".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_security_rotation_binding_plan(
        &self,
        binding: &SecurityRotationBinding,
        plan: &SecurityRotationPlan,
    ) -> Result<()> {
        let revoke_request = plan
            .revoke_unit
            .events_submit_request(&self.coordinator_service_id)?;
        if revoke_request.events.len() != 1
            || revoke_request.events[0].event.event_id != binding.revoke_event_id
            || revoke_request.events[0].event.kind != "ak.device.revoke"
        {
            return Err(Error::Protocol(
                "security-rotation revoke unit must contain exactly the reserved ak.device.revoke Event"
                    .to_owned(),
            ));
        }
        if binding.erase_confirmation_digest
            != security_rotation_erase_confirmation_digest(
                &self.transaction_id,
                &binding.backup_rotations,
            )?
            || binding.local_commit_digest
                != security_rotation_local_commit_digest(
                    &self.transaction_id,
                    &binding.new_secret_commitment,
                    &binding.backup_rotations,
                )?
        {
            return Err(Error::Protocol(
                "security-rotation reserved outcome digests do not match their non-circular projections"
                    .to_owned(),
            ));
        }
        if binding.new_secret_commitment != plan.new_secret_commitment
            || binding.backup_rotations.len() != 2
            || plan.backup_rotations.len() != 2
            || binding.erase_confirmation_digest != plan.erase_confirmation_digest
            || binding.local_commit_digest != plan.local_commit_digest
        {
            return Err(Error::Protocol(
                "security-rotation binding and prepared plan artifacts disagree".to_owned(),
            ));
        }
        let expected_kinds = [
            BackupRotationKind::SecretStorage,
            BackupRotationKind::MlsHistory,
        ];
        for (index, expected_kind) in expected_kinds.into_iter().enumerate() {
            let binding_rotation = &binding.backup_rotations[index];
            let plan_rotation = &plan.backup_rotations[index];
            if binding_rotation.backup_kind != expected_kind
                || plan_rotation.binding != *binding_rotation
                || binding_rotation.previous_series_id == binding_rotation.new_series_id
                || binding_rotation.new_backups.is_empty()
                || binding_rotation.new_backups.len() > 512
                || binding_rotation.old_backups.is_empty()
                || binding_rotation.old_backups.len() > 512
            {
                return Err(Error::Protocol(
                    "security-rotation backup entries must be the exact canonical secret_storage and mls_history bindings"
                        .to_owned(),
                ));
            }
            let mut new_backups = binding_rotation.new_backups.clone();
            new_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            let mut old_backups = binding_rotation.old_backups.clone();
            old_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            if new_backups
                .windows(2)
                .any(|pair| pair[0].backup_id == pair[1].backup_id)
                || old_backups
                    .windows(2)
                    .any(|pair| pair[0].backup_id == pair[1].backup_id)
            {
                return Err(Error::Protocol(
                    "security-rotation backup object references must be unique".to_owned(),
                ));
            }
            let active_series_request = plan_rotation
                .active_series_unit
                .events_submit_request(&self.coordinator_service_id)?;
            if active_series_request.events.len() != 1
                || active_series_request.events[0].event.event_id
                    != binding_rotation.active_series_event_id
                || active_series_request.events[0].event.kind != "ak.key_backup.active_series"
            {
                return Err(Error::Protocol(
                    "security-rotation active-series unit must contain exactly its reserved ak.key_backup.active_series Event"
                        .to_owned(),
                ));
            }
            plan_rotation
                .encrypted_backup_material
                .validate_structural()?;
            let prepared_backups = plan_rotation
                .encrypted_backup_material
                .value
                .get("backups")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    Error::Protocol(
                        "security-rotation public material must contain a backups array".to_owned(),
                    )
                })?;
            let expected_kind = match binding_rotation.backup_kind {
                BackupRotationKind::SecretStorage => "secret_storage",
                BackupRotationKind::MlsHistory => "mls_history",
            };
            if prepared_backups.len() != binding_rotation.new_backups.len()
                || binding_rotation.new_backups.iter().any(|expected| {
                    !prepared_backups.iter().any(|prepared| {
                        prepared.get("backup_id").and_then(Value::as_str)
                            == Some(expected.backup_id.as_str())
                            && prepared.get("ciphertext_digest").and_then(Value::as_str)
                                == Some(expected.ciphertext_digest.as_str())
                            && prepared.get("actor_id").and_then(Value::as_str)
                                == Some(self.principal_id.as_str())
                            && prepared.get("series_id").and_then(Value::as_str)
                                == Some(binding_rotation.new_series_id.as_str())
                            && prepared.get("backup_kind").and_then(Value::as_str)
                                == Some(expected_kind)
                    })
                })
            {
                return Err(Error::Protocol(
                    "security-rotation encrypted backup material must exactly cover the reserved new backups"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn step_requires_client_attestation(step: SecurityTransactionStep) -> bool {
        matches!(
            step,
            SecurityTransactionStep::IssueTerminalReceipt | SecurityTransactionStep::LocalCommit
        )
    }

    pub fn validate_continue<A: Serialize>(
        &self,
        request: &SecurityTransactionContinueRequest<A>,
    ) -> Result<()> {
        if request.request_digest != self.request_digest
            || request.prepared_plan_digest != self.prepared_plan_digest
        {
            return Err(Error::Protocol(
                crate::error_codes::ReasonCode::DUPLICATE_CONFLICT.to_owned(),
            ));
        }
        if Some(request.expected_next_step) != self.next_required_step {
            return Err(Error::Protocol(
                "continue expected_next_step does not equal the resource's next action".to_owned(),
            ));
        }
        let requires_attestation =
            Self::step_requires_client_attestation(request.expected_next_step);
        if requires_attestation != request.client_attestation.is_some() {
            return Err(Error::Protocol(
                "terminal client-attested steps require exactly one client_attestation".to_owned(),
            ));
        }
        if let Some(attestation) = &request.client_attestation {
            attestation.validate_structural()?;
            if attestation.step != request.expected_next_step
                || attestation.transaction_id != self.transaction_id
                || attestation.transaction_request_digest != self.request_digest
                || attestation.prepared_plan_digest != self.prepared_plan_digest
            {
                return Err(Error::Protocol(
                    "client attestation does not bind the current transaction/request/plan/step"
                        .to_owned(),
                ));
            }
            let reserved = match &self.binding {
                SecurityTransactionBinding::Recovery(binding) => {
                    binding.terminal_receipt_id().as_str()
                }
                SecurityTransactionBinding::SecurityRotation(binding) => {
                    binding.local_commit_digest.as_str()
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

#[cfg(any())]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::recovery_authority::CanonicalEncoding;
    use crate::{
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, DeviceId, Event, Hlc,
        LeaseBasisRef, RealmId, RiskTier, SchemaId, ScopeRef, SealId,
    };

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn did_publication_endpoint_allows_only_https_or_loopback_http() {
        let mut publication = PreparedDidPublication {
            registry_service_id: Did::new("did:web:registry.example").unwrap(),
            registry_endpoint: "http://127.0.0.1:3000/_arkret/root/identity/submit-did-operation"
                .to_owned(),
            previous_entry_ref: "did:web:alice.example?versionId=1-a".to_owned(),
            expected_entry_ref: "did:web:alice.example?versionId=2-b".to_owned(),
            canonical_entry_base64url: "e30".to_owned(),
            entry_digest: hash('a'),
        };
        publication
            .validate_structural()
            .expect("loopback development transport");

        publication.registry_endpoint =
            "http://registry.example/_arkret/root/identity/submit-did-operation".to_owned();
        assert!(publication.validate_structural().is_err());
    }

    fn material(binding: &BackupRotationBinding) -> CanonicalPublicMaterial {
        let backup_kind = match binding.backup_kind {
            BackupRotationKind::SecretStorage => "secret_storage",
            BackupRotationKind::MlsHistory => "mls_history",
        };
        let value = json!({
            "backups": binding
                .new_backups
                .iter()
                .map(|backup| {
                    json!({
                        "actor_id": "did:webvh:z6mkfixture:alice.example",
                        "backup_id": backup.backup_id,
                        "backup_kind": backup_kind,
                        "ciphertext_digest": backup.ciphertext_digest,
                        "series_id": binding.new_series_id,
                    })
                })
                .collect::<Vec<_>>()
        });
        CanonicalPublicMaterial::canonical_json(value).unwrap()
    }

    fn event_unit(coordinator: &Did, kind: &str) -> PreparedEventUnit {
        let scope_ref = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .unwrap(),
        };
        let actor_id = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let event = Event::new_at(
            kind,
            scope_ref.clone(),
            actor_id.clone(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"fixture": true}),
            Utc.with_ymd_and_hms(2026, 7, 28, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let authority_set_policy = AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.rotation_fixture.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: "ak:event:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD".to_owned(),
                source_digest: hash('a'),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: Vec::new(),
        };
        let request = EventsSubmitBatchRequestBody {
            events: vec![EventInitialSubmission {
                event,
                authorization_lease: Some(AuthorizationLease {
                    authorization_lease_id: AuthorizationLeaseId::new(
                        "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
                    )
                    .unwrap(),
                    basis_ref: LeaseBasisRef::Seal(
                        SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap(),
                    ),
                    actor_id,
                    device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb")
                        .unwrap(),
                    scope_ref,
                    action: "ak.realm.admin".to_owned(),
                    authorization_rule_id: "fixture".to_owned(),
                    risk_tier: RiskTier::High,
                    issued_at: Utc.with_ymd_and_hms(2026, 7, 28, 0, 0, 0).unwrap(),
                    expires_at: Utc.with_ymd_and_hms(2026, 7, 28, 1, 0, 0).unwrap(),
                    authority_set_ref: AuthoritySetRef {
                        authority_set_id: authority_set_policy.authority_set_id.clone(),
                        authority_set_digest: hash('c'),
                    },
                    authority_set_policy,
                    proofs: Vec::new(),
                }),
                cba_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            }],
        };
        PreparedEventUnit::new(coordinator.clone(), serde_json::to_value(request).unwrap()).unwrap()
    }

    fn prepared_event_id(unit: &PreparedEventUnit) -> EventId {
        serde_json::from_value::<EventsSubmitBatchRequestBody>(
            serde_json::to_value(&unit.request).unwrap(),
        )
        .unwrap()
        .events[0]
            .event
            .event_id
            .clone()
    }

    fn rotation(accepted: usize, state: SecurityTransactionState) -> SecurityTransaction {
        let created_at = Utc.with_ymd_and_hms(2026, 7, 28, 0, 0, 0).unwrap();
        let coordinator_service_id = Did::new("did:webvh:z6mkfixture:coordinator.example").unwrap();
        let backup_binding = |kind, offset: u8| BackupRotationBinding {
            backup_kind: kind,
            previous_series_id: BackupSeriesId::new(format!(
                "ak:backup_series:01904100-0000-7000-8000-a0086f45c5{offset:02x}"
            ))
            .unwrap(),
            new_series_id: BackupSeriesId::new(format!(
                "ak:backup_series:01904100-0000-7000-8000-a0086f45c6{offset:02x}"
            ))
            .unwrap(),
            new_backups: vec![BackupObjectRef {
                backup_id: BackupId::new(format!(
                    "ak:backup:01904100-0000-7000-8000-a0086f45c7{offset:02x}"
                ))
                .unwrap(),
                ciphertext_digest: hash('7'),
            }],
            active_series_event_id: EventId::from_event_digest(
                &Hash::new(arkret_canonical::sha256_digest(offset.to_be_bytes())).unwrap(),
            )
            .unwrap(),
            old_backups: vec![BackupObjectRef {
                backup_id: BackupId::new(format!(
                    "ak:backup:01904100-0000-7000-8000-a0086f45c9{offset:02x}"
                ))
                .unwrap(),
                ciphertext_digest: hash('9'),
            }],
        };
        let mut backup_rotations = vec![
            backup_binding(BackupRotationKind::SecretStorage, 1),
            backup_binding(BackupRotationKind::MlsHistory, 2),
        ];
        let backup_rotation_plans = backup_rotations
            .iter_mut()
            .map(|binding| {
                let active_series_unit =
                    event_unit(&coordinator_service_id, "ak.key_backup.active_series");
                binding.active_series_event_id = prepared_event_id(&active_series_unit);
                BackupRotationPlan {
                    active_series_unit,
                    encrypted_backup_material: material(binding),
                    binding: binding.clone(),
                }
            })
            .collect();
        let transaction_id =
            TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdef").unwrap();
        let erase_confirmation_digest =
            security_rotation_erase_confirmation_digest(&transaction_id, &backup_rotations)
                .unwrap();
        let local_commit_digest =
            security_rotation_local_commit_digest(&transaction_id, &hash('e'), &backup_rotations)
                .unwrap();
        let revoke_unit = event_unit(&coordinator_service_id, "ak.device.revoke");
        let revoke_event_id = prepared_event_id(&revoke_unit);
        let plan = SecurityRotationPlan {
            revoke_unit,
            new_secret_commitment: hash('e'),
            backup_rotations: backup_rotation_plans,
            erase_confirmation_digest: erase_confirmation_digest.clone(),
            local_commit_digest: local_commit_digest.clone(),
        };
        let accepted_steps = SECURITY_ROTATION_STEP_ORDER
            .iter()
            .take(accepted)
            .enumerate()
            .map(|(index, step)| AcceptedStep {
                step: *step,
                prepared_material_digest: hash('4'),
                acceptor_id: "did:webvh:z6mkfixture:coordinator.example".to_owned(),
                output_ref: format!("ak:receipt:01904100-0000-7000-8000-00000000000{index:x}"),
                output_digest: hash('5'),
                accepted_at: created_at + Duration::minutes(index as i64 + 1),
            })
            .collect();
        let prepared_plan = SecurityTransactionPreparedPlan::SecurityRotation(plan);
        let prepared_plan_digest =
            Hash::new(arkret_canonical::canonical::canonical_sha256(&prepared_plan).unwrap())
                .unwrap();
        SecurityTransaction {
            transaction_id,
            kind: SecurityTransactionKind::SecurityRotation,
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            coordinator_service_id,
            expires_at: created_at + Duration::hours(4),
            created_at,
            request_digest: hash('b'),
            binding: SecurityTransactionBinding::SecurityRotation(SecurityRotationBinding {
                revoke_event_id,
                new_secret_commitment: hash('e'),
                backup_rotations,
                erase_confirmation_digest,
                local_commit_digest,
            }),
            prepared_plan,
            prepared_plan_digest,
            state,
            next_required_step: if state.is_terminal() {
                None
            } else {
                SECURITY_ROTATION_STEP_ORDER.get(accepted).copied()
            },
            accepted_steps,
            terminal_result: state
                .is_terminal()
                .then(|| SecurityTransactionTerminalResult {
                    result: match state {
                        SecurityTransactionState::Completed => {
                            SecurityTransactionResultKind::Completed
                        }
                        SecurityTransactionState::Aborted => SecurityTransactionResultKind::Aborted,
                        SecurityTransactionState::Expired => SecurityTransactionResultKind::Expired,
                        _ => unreachable!(),
                    },
                    completed_at: created_at + Duration::hours(1),
                    receipt_id: None,
                    reason_code: None,
                    completion_attestation: None,
                }),
        }
    }

    #[test]
    fn accepted_steps_must_be_a_contiguous_prefix() {
        rotation(2, SecurityTransactionState::Running)
            .validate_structural()
            .unwrap();
        let mut skipped = rotation(2, SecurityTransactionState::Running);
        skipped.accepted_steps[1].step = SecurityTransactionStep::EraseOldMaterial;
        assert!(skipped.validate_structural().is_err());
    }

    #[test]
    fn accepted_step_acceptor_is_strongly_typed() {
        let mut invalid = rotation(1, SecurityTransactionState::Running);
        invalid.accepted_steps[0].acceptor_id = "opaque-service-name".to_owned();
        assert!(invalid.validate_structural().is_err());

        let mut device = rotation(1, SecurityTransactionState::Running);
        device.accepted_steps[0].acceptor_id =
            "ak:device:01904100-0000-7000-8000-000000000001".to_owned();
        device.validate_structural().unwrap();
    }

    #[test]
    fn terminal_client_boundary_is_explicit() {
        rotation(4, SecurityTransactionState::AwaitingDeviceAttestation)
            .validate_structural()
            .unwrap();
        assert!(
            rotation(4, SecurityTransactionState::Running)
                .validate_structural()
                .is_err()
        );
    }

    #[test]
    fn completed_transaction_requires_the_full_order() {
        rotation(5, SecurityTransactionState::Completed)
            .validate_structural()
            .unwrap();
        assert!(
            rotation(4, SecurityTransactionState::Completed)
                .validate_structural()
                .is_err()
        );
    }

    #[test]
    fn rotation_create_constructor_fixes_kind_and_plan_digest() {
        let resource = rotation(0, SecurityTransactionState::Pending);
        let SecurityTransactionBinding::SecurityRotation(binding) = resource.binding.clone() else {
            panic!("rotation fixture binding");
        };
        let SecurityTransactionPreparedPlan::SecurityRotation(plan) =
            resource.prepared_plan.clone()
        else {
            panic!("rotation fixture plan");
        };
        let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            resource.transaction_id,
            resource.principal_id,
            resource.expires_at,
            binding.revoke_event_id,
            plan.revoke_unit,
            binding.new_secret_commitment,
            plan.backup_rotations,
        )
        .unwrap();
        assert_eq!(request.kind, SecurityTransactionKind::SecurityRotation);
        assert_eq!(
            request.prepared_plan_digest,
            Hash::new(
                arkret_canonical::canonical::canonical_sha256(
                    &SecurityTransactionPreparedPlan::SecurityRotation(
                        request.prepared_plan.clone()
                    )
                )
                .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn rotation_plan_binds_reserved_event_ids_and_kinds_before_execution() {
        let resource = rotation(0, SecurityTransactionState::Pending);
        let SecurityTransactionBinding::SecurityRotation(binding) = &resource.binding else {
            panic!("rotation fixture binding");
        };
        let SecurityTransactionPreparedPlan::SecurityRotation(plan) = &resource.prepared_plan
        else {
            panic!("rotation fixture plan");
        };

        let mut wrong_revoke = plan.clone();
        wrong_revoke.revoke_unit =
            event_unit(&resource.coordinator_service_id, "ak.device.authorize");
        let error = resource
            .validate_security_rotation_binding_plan(binding, &wrong_revoke)
            .unwrap_err();
        assert!(error.to_string().contains("reserved ak.device.revoke"));

        let mut wrong_pointer = plan.clone();
        wrong_pointer.backup_rotations[0].active_series_unit =
            event_unit(&resource.coordinator_service_id, "ak.message.create");
        let error = resource
            .validate_security_rotation_binding_plan(binding, &wrong_pointer)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reserved ak.key_backup.active_series")
        );

        let mut wrong_backup = plan.clone();
        let mut value = wrong_backup.backup_rotations[0]
            .encrypted_backup_material
            .value
            .clone();
        value.get_mut("backups").unwrap()[0]["actor_id"] =
            json!("did:webvh:z6mkfixture:mallory.example");
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&value).unwrap();
        wrong_backup.backup_rotations[0].encrypted_backup_material = CanonicalPublicMaterial {
            canonical_encoding: CanonicalEncoding::CanonicalJson,
            value,
            canonical_bytes_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes)).unwrap(),
        };
        let error = resource
            .validate_security_rotation_binding_plan(binding, &wrong_backup)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exactly cover the reserved new backups")
        );
    }

    #[test]
    fn rotation_create_constructor_rejects_single_backup_compatibility_shape() {
        let resource = rotation(0, SecurityTransactionState::Pending);
        let SecurityTransactionBinding::SecurityRotation(mut binding) = resource.binding else {
            panic!("rotation fixture binding");
        };
        let SecurityTransactionPreparedPlan::SecurityRotation(mut plan) = resource.prepared_plan
        else {
            panic!("rotation fixture plan");
        };
        binding.backup_rotations.pop();
        plan.backup_rotations.pop();
        assert!(
            SecurityRotationTransactionCreateRequest::new(
                resource.transaction_id,
                resource.principal_id,
                resource.expires_at,
                binding,
                plan,
            )
            .is_err()
        );
    }

    #[test]
    fn continue_binds_request_plan_and_requires_terminal_attestation() {
        let resource = rotation(4, SecurityTransactionState::AwaitingDeviceAttestation);
        let missing: SecurityTransactionContinueRequest<Value> =
            SecurityTransactionContinueRequest {
                request_digest: hash('b'),
                prepared_plan_digest: resource.prepared_plan_digest.clone(),
                expected_next_step: SecurityTransactionStep::LocalCommit,
                client_attestation: None,
            };
        assert!(resource.validate_continue(&missing).is_err());

        let artifact = json!({"fixture": true});
        let attestation_digest =
            Hash::new(arkret_canonical::canonical::canonical_sha256(&artifact).unwrap()).unwrap();
        let valid = SecurityTransactionContinueRequest {
            request_digest: hash('b'),
            prepared_plan_digest: resource.prepared_plan_digest.clone(),
            expected_next_step: SecurityTransactionStep::LocalCommit,
            client_attestation: Some(ClientStepAttestation {
                step: SecurityTransactionStep::LocalCommit,
                output_ref: match &resource.binding {
                    SecurityTransactionBinding::SecurityRotation(binding) => {
                        binding.local_commit_digest.as_str().to_owned()
                    }
                    _ => unreachable!(),
                },
                transaction_id: resource.transaction_id.clone(),
                transaction_request_digest: hash('b'),
                prepared_plan_digest: resource.prepared_plan_digest.clone(),
                attestation_digest,
                artifact,
                auth_data: ClientStepAttestationAuthData {
                    verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#device")
                        .unwrap(),
                    signature_algorithm: "Ed25519".to_owned(),
                    signature: "c2ln".to_owned(),
                    signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect(),
                },
            }),
        };
        resource.validate_continue(&valid).unwrap();
    }
}
