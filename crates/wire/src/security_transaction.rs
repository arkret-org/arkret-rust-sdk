//! Closed durable security transactions (`zh/identity/security-transactions.md`).
//!
//! The wire separates canonical public intent in `prepared_plan` from
//! externally accepted outputs in `accepted_steps`. Reserved identities are
//! owned by the plan and progress is the accepted-prefix length.
//! Recovery is additionally discriminated by identity model. This is not a
//! general Saga/Plan DSL.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::recovery_authority::{CanonicalPublicMaterial, RecoveryCompletionAttestation};
use crate::{
    AccountId, ActorId, BackupId, BackupSeriesId, DeviceId, DidCoreId, DidUrl, EventId,
    EventsSubmitBatchRequestBody, Hash, ReceiptId, RecoverySessionId, TransactionId,
};

pub const MAX_SECURITY_TRANSACTION_TTL: Duration = Duration::hours(24);
pub const MAX_OPAQUE_REF_CHARS: usize = 2048;
pub const PCR_POLICY_RECOVERY_STEP_ORDER: [SecurityTransactionStep; 2] = [
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
    PcrPolicy,
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityTransactionAcceptor {
    Principal { principal_id: DidCoreId },
    Device { device_id: DeviceId },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedStep {
    pub prepared_material_digest: Hash,
    pub acceptor: SecurityTransactionAcceptor,
    pub output_ref: String,
    pub output_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
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
pub struct PreparedEventUnit {
    pub request: EventsSubmitBatchRequestBody,
    pub request_digest: Hash,
}

impl PreparedEventUnit {
    pub fn new(
        digest_suite: arkret_canonical::DigestSuite,
        request: EventsSubmitBatchRequestBody,
    ) -> Result<Self> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&request)?;
        Ok(Self {
            request_digest: Hash::new(arkret_canonical::canonical::digest(digest_suite, &bytes))?,
            request,
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDidPublication {
    pub registry_id: DidCoreId,
    pub registry_endpoint: String,
    pub previous_entry_ref: String,
    pub expected_entry_ref: String,
    pub canonical_entry_base64url: String,
    pub entry_digest: Hash,
}

impl PreparedDidPublication {
    pub fn validate_structural(&self) -> Result<()> {
        let endpoint = url::Url::parse(&self.registry_endpoint).map_err(|error| {
            WireError::Protocol(format!(
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
            return Err(WireError::Protocol(
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
pub struct PcrPolicyRecoveryPlan {
    pub binding: PcrPolicyRecoveryBinding,
    pub recovery_session_snapshot_digest: Hash,
    pub proof_digest: Hash,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub reanchor_unit: PreparedEventUnit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum RecoveryPreparedPlan {
    PcrPolicy(PcrPolicyRecoveryPlan),
}

impl RecoveryPreparedPlan {
    pub fn identity_model(&self) -> RecoveryIdentityModel {
        let Self::PcrPolicy(plan) = self;
        plan.binding.identity_model
    }

    pub fn binding(&self) -> &PcrPolicyRecoveryBinding {
        let Self::PcrPolicy(plan) = self;
        &plan.binding
    }

    fn validate_discriminator(&self) -> Result<()> {
        let Self::PcrPolicy(plan) = self;
        let valid = plan.binding.identity_model == RecoveryIdentityModel::PcrPolicy
            && plan.previous_model_generation_ref > 0
            && plan.result_model_generation_ref > plan.previous_model_generation_ref;
        if !valid {
            return Err(WireError::Protocol(
                "recovery prepared plan requires its closed PCR model and advancing generations"
                    .to_owned(),
            ));
        }
        Ok(())
    }
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub struct SecurityTransactionTerminalOutcome {
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
    pub account_id: AccountId,
    pub coordinator_id: DidCoreId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub request_digest: Hash,
    pub prepared_plan: SecurityTransactionPreparedPlan,
    pub prepared_plan_digest: Hash,
    pub accepted_steps: Vec<AcceptedStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<SecurityTransactionTerminalOutcome>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub prepared_plan: RecoveryPreparedPlan,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationTransactionCreateRequest {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub prepared_plan: SecurityRotationPlan,
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
        account_id: AccountId,
        expires_at: DateTime<Utc>,
        prepared_plan: RecoveryPreparedPlan,
    ) -> Result<Self> {
        prepared_plan.validate_discriminator()?;
        Ok(Self {
            transaction_id,
            kind: SecurityTransactionKind::Recovery,
            account_id,
            expires_at,
            prepared_plan,
        })
    }
}

impl SecurityRotationTransactionCreateRequest {
    pub fn from_prepared_rotations(
        transaction_id: TransactionId,
        account_id: AccountId,
        expires_at: DateTime<Utc>,
        revoke_unit: PreparedEventUnit,
        new_secret_commitment: Hash,
        backup_rotations: Vec<BackupRotationPlan>,
    ) -> Result<Self> {
        let bindings = backup_rotation_binding_refs(&backup_rotations);
        let erase_confirmation_digest =
            security_rotation_erase_confirmation_digest_from(&transaction_id, &bindings)?;
        let local_commit_digest = security_rotation_local_commit_digest_from(
            &transaction_id,
            &new_secret_commitment,
            &bindings,
        )?;
        Self::new(
            transaction_id,
            account_id,
            expires_at,
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
        account_id: AccountId,
        expires_at: DateTime<Utc>,
        prepared_plan: SecurityRotationPlan,
    ) -> Result<Self> {
        validate_security_rotation_fixed_shape(&prepared_plan)?;
        let bindings = backup_rotation_binding_refs(&prepared_plan.backup_rotations);
        if prepared_plan.erase_confirmation_digest
            != security_rotation_erase_confirmation_digest_from(&transaction_id, &bindings)?
            || prepared_plan.local_commit_digest
                != security_rotation_local_commit_digest_from(
                    &transaction_id,
                    &prepared_plan.new_secret_commitment,
                    &bindings,
                )?
        {
            return Err(WireError::Protocol(
                "security-rotation reserved outcome digests do not match their non-circular projections"
                    .to_owned(),
            ));
        }
        Ok(Self {
            transaction_id,
            kind: SecurityTransactionKind::SecurityRotation,
            account_id,
            expires_at,
            prepared_plan,
        })
    }
}

pub fn security_rotation_erase_confirmation_digest(
    transaction_id: &TransactionId,
    backup_rotations: &[BackupRotationBinding],
) -> Result<Hash> {
    security_rotation_erase_confirmation_digest_from(transaction_id, backup_rotations)
}

fn security_rotation_erase_confirmation_digest_from<T: Serialize + ?Sized>(
    transaction_id: &TransactionId,
    backup_rotations: &T,
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
    security_rotation_local_commit_digest_from(
        transaction_id,
        new_secret_commitment,
        backup_rotations,
    )
}

fn security_rotation_local_commit_digest_from<T: Serialize + ?Sized>(
    transaction_id: &TransactionId,
    new_secret_commitment: &Hash,
    backup_rotations: &T,
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

fn backup_rotation_binding_refs(rotations: &[BackupRotationPlan]) -> Vec<&BackupRotationBinding> {
    rotations.iter().map(|rotation| &rotation.binding).collect()
}

fn validate_security_rotation_fixed_shape(plan: &SecurityRotationPlan) -> Result<()> {
    if plan.backup_rotations.len() != 2 {
        return Err(WireError::Protocol(
            "security-rotation requires exact secret_storage and mls_history rotations".to_owned(),
        ));
    }
    for (index, expected_kind) in [
        BackupRotationKind::SecretStorage,
        BackupRotationKind::MlsHistory,
    ]
    .into_iter()
    .enumerate()
    {
        let rotation = &plan.backup_rotations[index].binding;
        if rotation.backup_kind != expected_kind
            || rotation.previous_series_id == rotation.new_series_id
            || rotation.new_backups.is_empty()
            || rotation.old_backups.is_empty()
        {
            return Err(WireError::Protocol(
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
        coordinator_id: DidCoreId,
        created_at: DateTime<Utc>,
    ) -> Result<(SecurityTransaction, Vec<u8>)> {
        let canonical_request = arkret_canonical::canonical::canonical_json_bytes(&self)?;
        let request_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
            &canonical_request,
        ))?;
        let (transaction_id, kind, account_id, expires_at, prepared_plan) = match self {
            Self::Recovery(request) => (
                request.transaction_id,
                request.kind,
                request.account_id,
                request.expires_at,
                SecurityTransactionPreparedPlan::Recovery(request.prepared_plan),
            ),
            Self::SecurityRotation(request) => (
                request.transaction_id,
                request.kind,
                request.account_id,
                request.expires_at,
                SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan),
            ),
        };
        let prepared_plan_digest = Hash::new(arkret_canonical::canonical::canonical_sha256(
            &prepared_plan,
        )?)?;
        let resource = SecurityTransaction {
            transaction_id,
            kind,
            account_id,
            coordinator_id,
            expires_at,
            created_at,
            request_digest,
            prepared_plan,
            prepared_plan_digest,
            accepted_steps: Vec::new(),
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

impl<A: Serialize> ClientStepAttestation<A> {
    pub fn validate_structural(&self) -> Result<()> {
        if self.auth_data.signature_algorithm != "Ed25519"
            || self.auth_data.verification_method.is_empty()
            || self.auth_data.signature.is_empty()
        {
            return Err(WireError::Protocol(
                "client step attestation authorization is incomplete".to_owned(),
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
        return Err(WireError::Protocol(format!(
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
        return Err(WireError::Protocol(format!(
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
        WireError::Protocol(format!(
            "{name} does not equal the digest of the complete canonical value"
        ))
    })
}

impl PreparedEventUnit {
    fn validate_structural(&self) -> Result<()> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&self.request)?;
        arkret_canonical::canonical::verify_digest(&bytes, self.request_digest.as_str())?;
        Ok(())
    }

    fn events_submit_request(&self) -> Result<&EventsSubmitBatchRequestBody> {
        self.validate_structural()?;
        Ok(&self.request)
    }
}

impl SecurityTransaction {
    pub fn step_order(&self) -> Result<&'static [SecurityTransactionStep]> {
        match (&self.kind, &self.prepared_plan) {
            (
                SecurityTransactionKind::Recovery,
                SecurityTransactionPreparedPlan::Recovery(plan),
            ) if plan.identity_model() == RecoveryIdentityModel::PcrPolicy => {
                Ok(&PCR_POLICY_RECOVERY_STEP_ORDER)
            }
            (
                SecurityTransactionKind::SecurityRotation,
                SecurityTransactionPreparedPlan::SecurityRotation(_),
            ) => Ok(&SECURITY_ROTATION_STEP_ORDER),
            _ => Err(WireError::Protocol(
                "security transaction kind and prepared plan discriminators disagree".to_owned(),
            )),
        }
    }

    pub fn next_required_step(&self) -> Result<Option<SecurityTransactionStep>> {
        if self.is_terminal() {
            return Ok(None);
        }
        Ok(self.step_order()?.get(self.accepted_steps.len()).copied())
    }

    pub fn terminal_kind(&self) -> Option<SecurityTransactionResultKind> {
        self.terminal_result.as_ref().map(|result| result.result)
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal_result.is_some()
    }

    pub fn is_completed(&self) -> bool {
        self.terminal_kind() == Some(SecurityTransactionResultKind::Completed)
    }

    pub fn requires_device_attestation(&self) -> Result<bool> {
        Ok(self
            .next_required_step()?
            .is_some_and(Self::step_requires_client_attestation))
    }

    pub fn accepted_step_kind(&self, index: usize) -> Result<SecurityTransactionStep> {
        self.step_order()?.get(index).copied().ok_or_else(|| {
            WireError::Protocol(
                "accepted step index exceeds the fixed transaction order".to_owned(),
            )
        })
    }

    pub fn recovery_binding(&self) -> Option<&PcrPolicyRecoveryBinding> {
        match &self.prepared_plan {
            SecurityTransactionPreparedPlan::Recovery(plan) => Some(plan.binding()),
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
        if self.account_id.station_id != self.coordinator_id {
            return Err(WireError::Protocol(
                "security transaction coordinator must be the exact account Station service"
                    .to_owned(),
            ));
        }
        if self.expires_at <= self.created_at {
            return Err(WireError::Protocol(
                "security transaction expires_at must be after created_at".to_owned(),
            ));
        }
        if self.expires_at - self.created_at > MAX_SECURITY_TRANSACTION_TTL {
            return Err(WireError::Protocol(format!(
                "security transaction TTL exceeds {} hours",
                MAX_SECURITY_TRANSACTION_TTL.num_hours()
            )));
        }

        validate_canonical_digest(
            "prepared_plan_digest",
            &self.prepared_plan,
            &self.prepared_plan_digest,
        )?;

        if let SecurityTransactionPreparedPlan::Recovery(plan) = &self.prepared_plan {
            plan.validate_discriminator()?;
            self.validate_recovery_plan(plan)?;
        }

        if let SecurityTransactionPreparedPlan::SecurityRotation(plan) = &self.prepared_plan {
            self.validate_security_rotation_plan(plan)?;
        }

        let order = self.step_order()?;
        if self.accepted_steps.len() > order.len() {
            return Err(WireError::Protocol(
                "security transaction recorded more steps than its closed order defines".to_owned(),
            ));
        }
        for accepted in &self.accepted_steps {
            validate_step_output_ref("accepted_steps[].output_ref", &accepted.output_ref)?;
        }

        if let Some(outcome) = self.terminal_result.as_ref() {
            match outcome.result {
                SecurityTransactionResultKind::Completed => {
                    if self.accepted_steps.len() != order.len() {
                        return Err(WireError::Protocol(
                            "completed security transaction must contain its full closed step order"
                                .to_owned(),
                        ));
                    }
                    if self.kind == SecurityTransactionKind::Recovery
                        && outcome.receipt_id.is_none()
                    {
                        return Err(WireError::Protocol(
                            "completed recovery transaction must carry a receipt_id".to_owned(),
                        ));
                    }
                    if self.kind == SecurityTransactionKind::SecurityRotation
                        && outcome.receipt_id.is_some()
                    {
                        return Err(WireError::Protocol(
                            "completed security rotation must not invent a receipt_id".to_owned(),
                        ));
                    }
                    if outcome.reason_code.is_some() {
                        return Err(WireError::Protocol(
                            "completed security transaction must not carry a reason_code"
                                .to_owned(),
                        ));
                    }
                }
                SecurityTransactionResultKind::Aborted | SecurityTransactionResultKind::Expired => {
                    if outcome.receipt_id.is_some() || outcome.completion_attestation.is_some() {
                        return Err(WireError::Protocol(
                            "aborted or expired security transaction must not carry completion evidence"
                                .to_owned(),
                        ));
                    }
                }
            }
            match (self.kind, outcome.result, &outcome.completion_attestation) {
                (
                    SecurityTransactionKind::Recovery,
                    SecurityTransactionResultKind::Completed,
                    Some(attestation),
                ) => {
                    attestation.validate_structural()?;
                    let SecurityTransactionPreparedPlan::Recovery(plan) = &self.prepared_plan
                    else {
                        unreachable!("kind/plan closure was validated above")
                    };
                    let RecoveryPreparedPlan::PcrPolicy(plan) = plan;
                    let binding = &plan.binding;
                    let replacement_device_id = &binding.replacement_device_id;
                    let authorize_event_id = &binding.authorize_event_id;
                    let result_generation = plan.result_model_generation_ref;
                    let receipt_step = self.accepted_steps.last().ok_or_else(|| {
                        WireError::Protocol(
                            "completed recovery transaction is missing its receipt step".to_owned(),
                        )
                    })?;
                    if attestation.transaction_id != self.transaction_id
                        || attestation.transaction_request_digest != self.request_digest
                        || attestation.prepared_plan_digest != self.prepared_plan_digest
                        || attestation.account_id != self.account_id
                        || attestation.coordinator_id != self.coordinator_id
                        || attestation.recovery_session_id != binding.recovery_session_id
                        || attestation.terminal_receipt_id != binding.terminal_receipt_id
                        || receipt_step.output_ref != attestation.terminal_receipt_id.as_str()
                        || receipt_step.output_digest != attestation.terminal_receipt_digest
                        || &attestation.replacement_device_id != replacement_device_id
                        || &attestation.device_authorization_event_id != authorize_event_id
                        || attestation.result_model_generation_ref != result_generation
                        || attestation.completed_at != outcome.completed_at
                    {
                        return Err(WireError::Protocol(
                            "recovery completion attestation disagrees with the durable transaction"
                                .to_owned(),
                        ));
                    }
                }
                (
                    SecurityTransactionKind::Recovery,
                    SecurityTransactionResultKind::Completed,
                    None,
                ) => {
                    return Err(WireError::Protocol(
                        "completed recovery transaction requires a completion attestation"
                            .to_owned(),
                    ));
                }
                (_, _, Some(_)) => {
                    return Err(WireError::Protocol(
                        "only a completed recovery transaction may carry a completion attestation"
                            .to_owned(),
                    ));
                }
                _ => {}
            }
            return Ok(());
        }

        self.next_required_step()?.ok_or_else(|| {
            WireError::Protocol(
                "non-terminal security transaction has exhausted its fixed step order".to_owned(),
            )
        })?;
        Ok(())
    }

    fn validate_recovery_plan(&self, plan: &RecoveryPreparedPlan) -> Result<()> {
        let RecoveryPreparedPlan::PcrPolicy(plan) = plan;
        let binding = &plan.binding;
        let reanchor_request = plan.reanchor_unit.events_submit_request()?;
        let expected = [
            (
                binding.reanchor_event_id.as_str(),
                crate::event_kind_str::DEVICE_REANCHOR,
            ),
            (
                binding.authorize_event_id.as_str(),
                crate::event_kind_str::DEVICE_AUTHORIZE,
            ),
        ];
        if reanchor_request.events.len() != expected.len()
            || reanchor_request
                .events
                .iter()
                .zip(expected)
                .any(|(submission, (id, kind))| {
                    submission.event.event_id.as_str() != id || submission.event.kind != kind
                })
        {
            return Err(WireError::Protocol(
                "PCR-policy prepared plan binding and reanchor unit disagree".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_security_rotation_plan(&self, plan: &SecurityRotationPlan) -> Result<()> {
        validate_security_rotation_fixed_shape(plan)?;
        let revoke_request = plan.revoke_unit.events_submit_request()?;
        let rotation_actor = ActorId::account(self.account_id.clone());
        if revoke_request.events.len() != 1
            || revoke_request.events[0].event.kind != crate::event_kind_str::DEVICE_REVOKE
            || revoke_request.events[0].event.actor_id != rotation_actor
        {
            return Err(WireError::Protocol(
                "security-rotation revoke unit must contain exactly the reserved ak.device.revoke Event"
                    .to_owned(),
            ));
        }
        let binding_refs = backup_rotation_binding_refs(&plan.backup_rotations);
        if plan.erase_confirmation_digest
            != security_rotation_erase_confirmation_digest_from(
                &self.transaction_id,
                &binding_refs,
            )?
            || plan.local_commit_digest
                != security_rotation_local_commit_digest_from(
                    &self.transaction_id,
                    &plan.new_secret_commitment,
                    &binding_refs,
                )?
        {
            return Err(WireError::Protocol(
                "security-rotation reserved outcome digests do not match their non-circular projections"
                    .to_owned(),
            ));
        }
        let expected_kinds = [
            BackupRotationKind::SecretStorage,
            BackupRotationKind::MlsHistory,
        ];
        for (index, expected_kind) in expected_kinds.into_iter().enumerate() {
            let plan_rotation = &plan.backup_rotations[index];
            let binding_rotation = &plan_rotation.binding;
            if binding_rotation.backup_kind != expected_kind
                || binding_rotation.previous_series_id == binding_rotation.new_series_id
                || binding_rotation.new_backups.is_empty()
                || binding_rotation.new_backups.len() > 512
                || binding_rotation.old_backups.is_empty()
                || binding_rotation.old_backups.len() > 512
            {
                return Err(WireError::Protocol(
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
                return Err(WireError::Protocol(
                    "security-rotation backup object references must be unique".to_owned(),
                ));
            }
            let active_series_request = plan_rotation.active_series_unit.events_submit_request()?;
            if active_series_request.events.len() != 1
                || active_series_request.events[0].event.event_id
                    != binding_rotation.active_series_event_id
                || active_series_request.events[0].event.kind
                    != crate::event_kind_str::KEY_BACKUP_ACTIVE_SERIES
                || active_series_request.events[0].event.actor_id != rotation_actor
            {
                return Err(WireError::Protocol(
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
                    WireError::Protocol(
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
                            && prepared.get("actor_id").is_some_and(|actor| {
                                serde_json::from_value::<ActorId>(actor.clone())
                                    .is_ok_and(|actor| actor == rotation_actor)
                            })
                            && prepared.get("series_id").and_then(Value::as_str)
                                == Some(binding_rotation.new_series_id.as_str())
                            && prepared.get("backup_kind").and_then(Value::as_str)
                                == Some(expected_kind)
                    })
                })
            {
                return Err(WireError::Protocol(
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
        request_digest: &Hash,
        prepared_plan_digest: &Hash,
        expected_accepted_step_count: u8,
        client_attestation: Option<&ClientStepAttestation<A>>,
    ) -> Result<()> {
        if request_digest != &self.request_digest
            || prepared_plan_digest != &self.prepared_plan_digest
        {
            return Err(WireError::Protocol(
                crate::error_codes::ReasonCode::DUPLICATE_CONFLICT.to_owned(),
            ));
        }
        if usize::from(expected_accepted_step_count) != self.accepted_steps.len() {
            return Err(WireError::Protocol(
                "continue expected_accepted_step_count does not equal current progress".to_owned(),
            ));
        }
        let next_step = self.next_required_step()?.ok_or_else(|| {
            WireError::Protocol("terminal transaction cannot continue".to_owned())
        })?;
        let requires_attestation = Self::step_requires_client_attestation(next_step);
        if requires_attestation != client_attestation.is_some() {
            return Err(WireError::Protocol(
                "terminal client-attested steps require exactly one client_attestation".to_owned(),
            ));
        }
        if let Some(attestation) = client_attestation {
            attestation.validate_structural()?;
            if attestation.step != next_step
                || attestation.transaction_id != self.transaction_id
                || attestation.transaction_request_digest != self.request_digest
                || attestation.prepared_plan_digest != self.prepared_plan_digest
            {
                return Err(WireError::Protocol(
                    "client attestation does not bind the current transaction/request/plan/step"
                        .to_owned(),
                ));
            }
            let reserved = match &self.prepared_plan {
                SecurityTransactionPreparedPlan::Recovery(plan) => {
                    plan.binding().terminal_receipt_id.as_str()
                }
                SecurityTransactionPreparedPlan::SecurityRotation(plan) => {
                    plan.local_commit_digest.as_str()
                }
            };
            if attestation.output_ref != reserved {
                return Err(WireError::Protocol(
                    "client attestation ref does not equal the prepared plan reservation"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod untagged_contract_tests {
    use super::*;

    #[test]
    fn acceptor_is_a_closed_stable_identity_union() {
        let principal = serde_json::from_value::<SecurityTransactionAcceptor>(serde_json::json!({
            "kind": "principal",
            "principal_id": "ak:did_core:web:principal.example"
        }))
        .unwrap();
        assert!(matches!(
            principal,
            SecurityTransactionAcceptor::Principal { .. }
        ));

        let device = serde_json::from_value::<SecurityTransactionAcceptor>(serde_json::json!({
            "kind": "device",
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001"
        }))
        .unwrap();
        assert!(matches!(device, SecurityTransactionAcceptor::Device { .. }));

        assert!(
            serde_json::from_value::<SecurityTransactionAcceptor>(serde_json::json!(
                "did:web:principal.example"
            ))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SecurityTransactionAcceptor>(serde_json::json!("opaque"))
                .is_err()
        );
    }

    #[test]
    fn recovery_step_order_is_the_closed_pcr_policy_pair() {
        let steps = serde_json::to_value(PCR_POLICY_RECOVERY_STEP_ORDER).unwrap();
        assert_eq!(
            steps,
            serde_json::json!(["submit_reanchor_unit", "issue_terminal_receipt"])
        );
    }

    #[test]
    fn prepared_event_unit_is_minimal_and_suite_aware() {
        let request = EventsSubmitBatchRequestBody { events: Vec::new() };
        for suite in [
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::DigestSuite::Blake3,
        ] {
            let unit = PreparedEventUnit::new(suite, request.clone()).unwrap();
            unit.validate_structural().unwrap();
            assert_eq!(unit.request_digest.digest_suite().unwrap(), suite);
            let encoded = serde_json::to_value(&unit).unwrap();
            assert_eq!(
                encoded
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                ["request", "request_digest"]
            );
        }
    }
}
