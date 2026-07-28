//! Closed durable security transactions (`zh/identity/security-transactions.md`).
//!
//! The wire separates three states that implementations must never conflate:
//! reserved identities in `binding`, canonical public bytes in
//! `prepared_plan`, and externally accepted outputs in `accepted_steps`.
//! Recovery is additionally discriminated by identity model. This is not a
//! general Saga/Plan DSL.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::recovery_authority::{
    AuthorizeEventPublicationIntent, AuthorizeRecoveryDeviceRequest, CanonicalPublicMaterial,
    IssueAuthorityTicketStep, RecoveryAuthorityTicketIssueRequest, RecoveryAuthorizationPreimage,
    RecoveryCompletionAttestation, RecoveryModelGenerationRef,
};
use crate::{
    BackupId, BackupSeriesId, DeviceId, Did, EventId, EventInitialSubmission,
    EventsSubmitBatchRequestBody, Hash, ReceiptId, RecoveryAuthorityTicketId, RecoverySessionId,
    TransactionId,
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

pub const CROSS_SIGNING_RECOVERY_STEP_ORDER: [SecurityTransactionStep; 2] = [
    SecurityTransactionStep::SubmitAuthorizeUnit,
    SecurityTransactionStep::IssueTerminalReceipt,
];

pub const ENROLLMENT_AUTHORITY_RECOVERY_STEP_ORDER: [SecurityTransactionStep; 5] = [
    SecurityTransactionStep::IssueAuthorityTicket,
    SecurityTransactionStep::AuthorizeRecoveryDevice,
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
    CrossSigning,
    EnrollmentAuthority,
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
pub enum SecurityTransactionStep {
    SubmitAuthorizeUnit,
    IssueAuthorityTicket,
    AuthorizeRecoveryDevice,
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
pub struct CrossSigningRecoveryBinding {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_id: RecoverySessionId,
    pub replacement_device_id: DeviceId,
    pub authorize_event_id: EventId,
    pub device_list_update_event_id: EventId,
    pub terminal_receipt_id: ReceiptId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentAuthorityRecoveryBinding {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_id: RecoverySessionId,
    pub replacement_device_id: DeviceId,
    pub authority_ticket_id: RecoveryAuthorityTicketId,
    pub did_entry_ref: String,
    pub reanchor_event_id: EventId,
    pub authorize_event_id: EventId,
    pub terminal_receipt_id: ReceiptId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryBinding {
    CrossSigning(CrossSigningRecoveryBinding),
    EnrollmentAuthority(EnrollmentAuthorityRecoveryBinding),
}

impl RecoveryBinding {
    pub fn identity_model(&self) -> RecoveryIdentityModel {
        match self {
            Self::CrossSigning(_) => RecoveryIdentityModel::CrossSigning,
            Self::EnrollmentAuthority(_) => RecoveryIdentityModel::EnrollmentAuthority,
        }
    }

    pub fn terminal_receipt_id(&self) -> &ReceiptId {
        match self {
            Self::CrossSigning(binding) => &binding.terminal_receipt_id,
            Self::EnrollmentAuthority(binding) => &binding.terminal_receipt_id,
        }
    }

    pub fn recovery_session_id(&self) -> &RecoverySessionId {
        match self {
            Self::CrossSigning(binding) => &binding.recovery_session_id,
            Self::EnrollmentAuthority(binding) => &binding.recovery_session_id,
        }
    }

    fn validate_discriminator(&self) -> Result<()> {
        let valid = match self {
            Self::CrossSigning(binding) => {
                binding.identity_model == RecoveryIdentityModel::CrossSigning
            }
            Self::EnrollmentAuthority(binding) => {
                binding.identity_model == RecoveryIdentityModel::EnrollmentAuthority
            }
        };
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
    pub series_id: BackupSeriesId,
    pub backup_id: BackupId,
    pub active_series_event_id: EventId,
    pub erase_confirmation_digest: Hash,
    pub local_commit_digest: Hash,
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
    pub request: Value,
    pub canonical_request_base64url: String,
    pub request_digest: Hash,
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
        if endpoint.scheme() != "https"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/_arkret/root/identity/submit-did-operation"
        {
            return Err(Error::Protocol(
                "prepared DID registry endpoint must be the exact standard HTTPS submit endpoint"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSigningRecoveryPlan {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_snapshot_digest: Hash,
    pub proof_digest: Hash,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub authorize_unit: PreparedEventSubmissionBatch,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentAuthorityRecoveryPlan {
    pub identity_model: RecoveryIdentityModel,
    pub recovery_session_snapshot_digest: Hash,
    pub proof_digest: Hash,
    pub previous_model_generation_ref: String,
    pub result_model_generation_ref: String,
    pub authorization_preimage: RecoveryAuthorizationPreimage,
    pub authorization_request_digest: Hash,
    pub did_publication: PreparedDidPublication,
    pub reanchor_event_submission: EventInitialSubmission,
    pub reanchor_event_submission_digest: Hash,
    pub authorize_event_publication_intent: AuthorizeEventPublicationIntent,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryPreparedPlan {
    CrossSigning(CrossSigningRecoveryPlan),
    EnrollmentAuthority(EnrollmentAuthorityRecoveryPlan),
}

impl RecoveryPreparedPlan {
    pub fn identity_model(&self) -> RecoveryIdentityModel {
        match self {
            Self::CrossSigning(_) => RecoveryIdentityModel::CrossSigning,
            Self::EnrollmentAuthority(_) => RecoveryIdentityModel::EnrollmentAuthority,
        }
    }

    fn validate_discriminator(&self) -> Result<()> {
        let valid = match self {
            Self::CrossSigning(plan) => plan.identity_model == RecoveryIdentityModel::CrossSigning,
            Self::EnrollmentAuthority(plan) => {
                plan.identity_model == RecoveryIdentityModel::EnrollmentAuthority
            }
        };
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
    pub encrypted_backup_material: CanonicalPublicMaterial,
    pub active_series_unit: PreparedEventUnit,
    pub erase_confirmation_digest: Hash,
    pub local_commit_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
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
pub enum SecurityTransactionCreateRequest {
    Recovery(RecoveryTransactionCreateRequest),
    SecurityRotation(SecurityRotationTransactionCreateRequest),
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
                let next = match request.binding.identity_model() {
                    RecoveryIdentityModel::CrossSigning => {
                        SecurityTransactionStep::SubmitAuthorizeUnit
                    }
                    RecoveryIdentityModel::EnrollmentAuthority => {
                        SecurityTransactionStep::IssueAuthorityTicket
                    }
                };
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
    pub verification_method: String,
    pub alg: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_request: Option<AuthorizeRecoveryDeviceRequest>,
}

impl<A: Serialize> ClientStepAttestation<A> {
    pub fn validate_structural(&self) -> Result<()> {
        if self.auth_data.alg != "EdDSA"
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
        let value = serde_json::to_value(self)?;
        let object = value.as_object().ok_or_else(|| {
            Error::Protocol("client step attestation must serialize as an object".to_owned())
        })?;
        let projection = CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
            .iter()
            .map(|field| {
                object
                    .get(*field)
                    .cloned()
                    .map(|value| ((*field).to_owned(), value))
                    .ok_or_else(|| {
                        Error::Protocol(format!(
                            "client step attestation is missing signed field {field}"
                        ))
                    })
            })
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        Ok(arkret_canonical::canonical::canonical_json_bytes(
            &Value::Object(projection),
        )?)
    }
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
}

impl SecurityTransaction {
    pub fn step_order(&self) -> Result<&'static [SecurityTransactionStep]> {
        match (&self.kind, &self.binding, &self.prepared_plan) {
            (
                SecurityTransactionKind::Recovery,
                SecurityTransactionBinding::Recovery(binding),
                SecurityTransactionPreparedPlan::Recovery(plan),
            ) if binding.identity_model() == plan.identity_model() => {
                match binding.identity_model() {
                    RecoveryIdentityModel::CrossSigning => Ok(&CROSS_SIGNING_RECOVERY_STEP_ORDER),
                    RecoveryIdentityModel::EnrollmentAuthority => {
                        Ok(&ENROLLMENT_AUTHORITY_RECOVERY_STEP_ORDER)
                    }
                }
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

        if let SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(binding)) =
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
                    if outcome.receipt_id.is_none() {
                        return Err(Error::Protocol(
                            "completed security transaction must carry a receipt_id".to_owned(),
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
                    let (binding, plan) = match (&self.binding, &self.prepared_plan) {
                        (
                            SecurityTransactionBinding::Recovery(binding),
                            SecurityTransactionPreparedPlan::Recovery(plan),
                        ) => (binding, plan),
                        _ => unreachable!("kind/binding/plan closure was validated above"),
                    };
                    let (replacement_device_id, authorize_event_id, result_generation) =
                        match (binding, plan) {
                            (
                                RecoveryBinding::CrossSigning(binding),
                                RecoveryPreparedPlan::CrossSigning(plan),
                            ) => (
                                &binding.replacement_device_id,
                                &binding.authorize_event_id,
                                RecoveryModelGenerationRef::CrossSigning(
                                    plan.result_model_generation_ref,
                                ),
                            ),
                            (
                                RecoveryBinding::EnrollmentAuthority(binding),
                                RecoveryPreparedPlan::EnrollmentAuthority(plan),
                            ) => (
                                &binding.replacement_device_id,
                                &binding.authorize_event_id,
                                RecoveryModelGenerationRef::EnrollmentAuthority(
                                    plan.result_model_generation_ref.clone(),
                                ),
                            ),
                            _ => unreachable!("recovery model closure was validated above"),
                        };
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
                        || &attestation.recovery_session_id != binding.recovery_session_id()
                        || &attestation.terminal_receipt_id != binding.terminal_receipt_id()
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
        match (binding, plan) {
            (RecoveryBinding::CrossSigning(binding), RecoveryPreparedPlan::CrossSigning(plan)) => {
                plan.authorize_unit
                    .validate_structural(&self.coordinator_service_id)?;
                let events = &plan.authorize_unit.request.events;
                let expected = [
                    (binding.authorize_event_id.as_str(), "ak.device.authorize"),
                    (
                        binding.device_list_update_event_id.as_str(),
                        "ak.device.list_update",
                    ),
                ];
                if events.len() != expected.len()
                    || events.iter().zip(expected).any(|(submission, (id, kind))| {
                        submission.event.event_id.as_str() != id || submission.event.kind != kind
                    })
                {
                    return Err(Error::Protocol(
                        "cross-signing authorize unit must contain the two reserved Events in order"
                            .to_owned(),
                    ));
                }
            }
            (
                RecoveryBinding::EnrollmentAuthority(binding),
                RecoveryPreparedPlan::EnrollmentAuthority(plan),
            ) => {
                plan.authorization_preimage.validate_structural()?;
                plan.did_publication.validate_structural()?;
                validate_canonical_digest(
                    "authorization_request_digest",
                    &plan.authorization_preimage,
                    &plan.authorization_request_digest,
                )?;
                plan.reanchor_event_submission.validate_structural()?;
                plan.authorize_event_publication_intent
                    .validate_structural()?;
                validate_canonical_digest(
                    "reanchor_event_submission_digest",
                    &plan.reanchor_event_submission,
                    &plan.reanchor_event_submission_digest,
                )?;
                let preimage = &plan.authorization_preimage;
                if preimage.principal_id != self.principal_id
                    || preimage.recovery_session_id != binding.recovery_session_id
                    || preimage.replacement_device_id != binding.replacement_device_id
                    || preimage.did_entry_ref != binding.did_entry_ref
                    || preimage.reanchor_event_id != binding.reanchor_event_id
                    || preimage.authorize_event_id != binding.authorize_event_id
                    || preimage.previous_model_generation_ref != plan.previous_model_generation_ref
                    || preimage.result_model_generation_ref != plan.result_model_generation_ref
                    || plan.did_publication.previous_entry_ref != preimage.registry_previous_head
                    || plan.did_publication.expected_entry_ref != preimage.did_entry_ref
                    || plan.did_publication.entry_digest != preimage.did_entry_digest
                    || plan.did_publication.canonical_entry_base64url
                        != preimage.did_entry_preimage.canonical_bytes_base64url
                    || plan.did_publication.entry_digest != preimage.did_entry_preimage.digest
                    || plan.reanchor_event_submission.event.event_id != binding.reanchor_event_id
                    || plan.authorize_event_publication_intent.event_id
                        != binding.authorize_event_id
                    || plan
                        .authorization_preimage
                        .authorize_event_publication_intent
                        != plan.authorize_event_publication_intent
                {
                    return Err(Error::Protocol(
                        "enrollment-authority binding and prepared plan artifacts disagree"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(Error::Protocol(
                    "recovery binding and prepared plan models disagree".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_security_rotation_binding_plan(
        &self,
        binding: &SecurityRotationBinding,
        plan: &SecurityRotationPlan,
    ) -> Result<()> {
        plan.revoke_unit
            .validate_structural(&self.coordinator_service_id)?;
        plan.active_series_unit
            .validate_structural(&self.coordinator_service_id)?;
        plan.encrypted_backup_material.validate_structural()?;
        if binding.new_secret_commitment != plan.new_secret_commitment
            || binding.erase_confirmation_digest != plan.erase_confirmation_digest
            || binding.local_commit_digest != plan.local_commit_digest
        {
            return Err(Error::Protocol(
                "security-rotation binding and prepared plan artifacts disagree".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn recovery_authority_ticket_issue_request(
        &self,
    ) -> Result<RecoveryAuthorityTicketIssueRequest> {
        let binding = match (&self.kind, &self.binding, &self.prepared_plan) {
            (
                SecurityTransactionKind::Recovery,
                SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(binding)),
                SecurityTransactionPreparedPlan::Recovery(
                    RecoveryPreparedPlan::EnrollmentAuthority(_),
                ),
            ) => binding,
            _ => {
                return Err(Error::Protocol(
                    "authority ticket issue request requires an enrollment-authority recovery transaction"
                        .to_owned(),
                ));
            }
        };
        if self.next_required_step != Some(SecurityTransactionStep::IssueAuthorityTicket) {
            return Err(Error::Protocol(
                "authority ticket can only be issued at the closed issue_authority_ticket step"
                    .to_owned(),
            ));
        }
        Ok(RecoveryAuthorityTicketIssueRequest {
            transaction_id: self.transaction_id.clone(),
            transaction_request_digest: self.request_digest.clone(),
            prepared_plan_digest: self.prepared_plan_digest.clone(),
            authority_ticket_id: binding.authority_ticket_id.clone(),
            expected_next_step: IssueAuthorityTicketStep::IssueAuthorityTicket,
        })
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
        let requires_participant_request =
            request.expected_next_step == SecurityTransactionStep::AuthorizeRecoveryDevice;
        if requires_participant_request != request.participant_request.is_some() {
            return Err(Error::Protocol(
                "authorize_recovery_device requires exactly one participant_request".to_owned(),
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::recovery_authority::CanonicalEncoding;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn material() -> CanonicalPublicMaterial {
        let value = json!({"fixture": true});
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&value).unwrap();
        CanonicalPublicMaterial {
            canonical_encoding: CanonicalEncoding::CanonicalJson,
            value,
            canonical_bytes_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes)).unwrap(),
        }
    }

    fn event_unit(coordinator: &Did) -> PreparedEventUnit {
        let request = json!({"events": []});
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&request).unwrap();
        PreparedEventUnit {
            operation_id: "ak.self.events.command.submit".to_owned(),
            destination_service_id: coordinator.clone(),
            audience: coordinator.clone(),
            request_schema: "https://arkret.org/v1/schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitBatchRequestBody".to_owned(),
            request,
            canonical_request_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            request_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes)).unwrap(),
        }
    }

    fn rotation(accepted: usize, state: SecurityTransactionState) -> SecurityTransaction {
        let created_at = Utc.with_ymd_and_hms(2026, 7, 28, 0, 0, 0).unwrap();
        let coordinator_service_id = Did::new("did:webvh:z6mkfixture:coordinator.example").unwrap();
        let plan = SecurityRotationPlan {
            revoke_unit: event_unit(&coordinator_service_id),
            new_secret_commitment: hash('e'),
            encrypted_backup_material: material(),
            active_series_unit: event_unit(&coordinator_service_id),
            erase_confirmation_digest: hash('2'),
            local_commit_digest: hash('3'),
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
            transaction_id: TransactionId::new(
                "ak:transaction:01904100-0000-7000-8000-abcdefabcdef",
            )
            .unwrap(),
            kind: SecurityTransactionKind::SecurityRotation,
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            coordinator_service_id,
            expires_at: created_at + Duration::hours(4),
            created_at,
            request_digest: hash('b'),
            binding: SecurityTransactionBinding::SecurityRotation(SecurityRotationBinding {
                revoke_event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575")
                    .unwrap(),
                new_secret_commitment: hash('e'),
                series_id: BackupSeriesId::new(
                    "ak:backup_series:01904100-0000-7000-8000-a0086f45c576",
                )
                .unwrap(),
                backup_id: BackupId::new("ak:backup:01904100-0000-7000-8000-a0086f45c577").unwrap(),
                active_series_event_id: EventId::new(
                    "ak:event:01904100-0000-7000-8000-a0086f45c578",
                )
                .unwrap(),
                erase_confirmation_digest: hash('2'),
                local_commit_digest: hash('3'),
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
                    receipt_id: Some(
                        ReceiptId::new("ak:receipt:01904100-0000-7000-8000-a0086f45c579").unwrap(),
                    ),
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
    fn continue_binds_request_plan_and_requires_terminal_attestation() {
        let resource = rotation(4, SecurityTransactionState::AwaitingDeviceAttestation);
        let missing: SecurityTransactionContinueRequest<Value> =
            SecurityTransactionContinueRequest {
                request_digest: hash('b'),
                prepared_plan_digest: resource.prepared_plan_digest.clone(),
                expected_next_step: SecurityTransactionStep::LocalCommit,
                client_attestation: None,
                participant_request: None,
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
                output_ref: hash('3').as_str().to_owned(),
                transaction_id: resource.transaction_id.clone(),
                transaction_request_digest: hash('b'),
                prepared_plan_digest: resource.prepared_plan_digest.clone(),
                attestation_digest,
                artifact,
                auth_data: ClientStepAttestationAuthData {
                    verification_method: "did:webvh:z6mkfixture:alice.example#device".to_owned(),
                    alg: "EdDSA".to_owned(),
                    signature: "c2ln".to_owned(),
                    signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect(),
                },
            }),
            participant_request: None,
        };
        resource.validate_continue(&valid).unwrap();

        let mut authority_resource = resource.clone();
        authority_resource.next_required_step =
            Some(SecurityTransactionStep::AuthorizeRecoveryDevice);
        let missing_participant = SecurityTransactionContinueRequest {
            request_digest: hash('b'),
            prepared_plan_digest: authority_resource.prepared_plan_digest.clone(),
            expected_next_step: SecurityTransactionStep::AuthorizeRecoveryDevice,
            client_attestation: None::<ClientStepAttestation<Value>>,
            participant_request: None,
        };
        assert!(
            authority_resource
                .validate_continue(&missing_participant)
                .is_err()
        );
    }
}
