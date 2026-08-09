//! Root-anchored recovery completion and direct Standard-grant DTOs.
//!
//! Recovery publishes the next DID entry and submits one atomic re-anchor
//! unit. No external enrollment authority, approval ticket, or service-signed
//! device authorization exists on this boundary.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::{DeviceId, Did, DidUrl, EventId, Hash, ReceiptId, RecoverySessionId, TransactionId};

pub const RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS: [&str; 14] = [
    "schema",
    "transaction_id",
    "transaction_request_digest",
    "prepared_plan_digest",
    "principal_id",
    "coordinator_service_id",
    "recovery_session_id",
    "terminal_receipt_id",
    "terminal_receipt_digest",
    "replacement_device_id",
    "device_authorization_event_id",
    "device_authorization_event_digest",
    "result_model_generation_ref",
    "completed_at",
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEncoding {
    CanonicalJson,
    DeterministicCbor,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPublicMaterial {
    pub canonical_encoding: CanonicalEncoding,
    pub value: BTreeMap<String, Value>,
    pub canonical_bytes_base64url: String,
    pub digest: Hash,
}

impl CanonicalPublicMaterial {
    pub fn canonical_json<T: Serialize>(value: T) -> Result<Self> {
        let value = serde_json::to_value(value)?;
        let Value::Object(value) = value else {
            return Err(Error::Protocol(
                "canonical public material value must be a JSON object".to_owned(),
            ));
        };
        let value = value.into_iter().collect::<BTreeMap<_, _>>();
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&value)?;
        Ok(Self {
            canonical_encoding: CanonicalEncoding::CanonicalJson,
            canonical_bytes_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes))?,
            value,
        })
    }

    pub fn validate_structural(&self) -> Result<()> {
        let bytes = arkret_canonical::base64url::base64url_decode(&self.canonical_bytes_base64url)?;
        arkret_canonical::canonical::verify_digest(&bytes, self.digest.as_str())?;
        if self.canonical_encoding == CanonicalEncoding::CanonicalJson
            && bytes != arkret_canonical::canonical::canonical_json_bytes(&self.value)?
        {
            return Err(Error::Protocol(
                "canonical public material bytes do not equal canonical JSON of value".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryModelGenerationRef {
    RootAnchored(String),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCompletionAttestationAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCompletionAttestation {
    pub schema: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub principal_id: Did,
    pub coordinator_service_id: Did,
    pub recovery_session_id: RecoverySessionId,
    pub terminal_receipt_id: ReceiptId,
    pub terminal_receipt_digest: Hash,
    pub replacement_device_id: DeviceId,
    pub device_authorization_event_id: EventId,
    pub device_authorization_event_digest: Hash,
    pub result_model_generation_ref: RecoveryModelGenerationRef,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    pub auth_data: RecoveryCompletionAttestationAuthData,
}

impl RecoveryCompletionAttestation {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != "ak.schema.recovery_completion_attestation.v1" {
            return Err(Error::Protocol(
                "recovery completion attestation schema is invalid".to_owned(),
            ));
        }
        if self.auth_data.signature_algorithm != "Ed25519"
            || self.auth_data.verification_method.is_empty()
            || self.auth_data.signature.is_empty()
        {
            return Err(Error::Protocol(
                "recovery completion attestation requires a complete Ed25519 authorization"
                    .to_owned(),
            ));
        }
        if self
            .auth_data
            .signed_fields
            .iter()
            .map(String::as_str)
            .ne(RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS)
        {
            return Err(Error::Protocol(
                "recovery completion attestation signed_fields must equal the registered ordered set"
                    .to_owned(),
            ));
        }
        if matches!(
            &self.result_model_generation_ref,
            RecoveryModelGenerationRef::RootAnchored(value) if value.is_empty()
        ) {
            return Err(Error::Protocol(
                "recovery completion generation must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical coordinator signature transcript. `auth_data` is excluded so
    /// the Ed25519 signature cannot recursively contain itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        recovery_completion_attestation_signing_bytes(&UnsignedRecoveryCompletionAttestationBody {
            transaction_id: self.transaction_id.clone(),
            transaction_request_digest: self.transaction_request_digest.clone(),
            prepared_plan_digest: self.prepared_plan_digest.clone(),
            principal_id: self.principal_id.clone(),
            coordinator_service_id: self.coordinator_service_id.clone(),
            recovery_session_id: self.recovery_session_id.clone(),
            terminal_receipt_id: self.terminal_receipt_id.clone(),
            terminal_receipt_digest: self.terminal_receipt_digest.clone(),
            replacement_device_id: self.replacement_device_id.clone(),
            device_authorization_event_id: self.device_authorization_event_id.clone(),
            device_authorization_event_digest: self.device_authorization_event_digest.clone(),
            result_model_generation_ref: self.result_model_generation_ref.clone(),
            completed_at: self.completed_at,
        })
    }
}

/// Recovery-completion members before coordinator signature metadata exists.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryCompletionAttestationBody {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub principal_id: Did,
    pub coordinator_service_id: Did,
    pub recovery_session_id: RecoverySessionId,
    pub terminal_receipt_id: ReceiptId,
    pub terminal_receipt_digest: Hash,
    pub replacement_device_id: DeviceId,
    pub device_authorization_event_id: EventId,
    pub device_authorization_event_digest: Hash,
    pub result_model_generation_ref: RecoveryModelGenerationRef,
    pub completed_at: DateTime<Utc>,
}

/// Non-serializable coordinator authoring state for a completion attestation.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryCompletionAttestation {
    body: UnsignedRecoveryCompletionAttestationBody,
    verification_method: DidUrl,
}

impl UnsignedRecoveryCompletionAttestation {
    pub fn new(
        body: UnsignedRecoveryCompletionAttestationBody,
        verification_method: DidUrl,
    ) -> Result<Self> {
        validate_recovery_completion_attestation_body(&body)?;
        Ok(Self {
            body,
            verification_method,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        recovery_completion_attestation_signing_bytes(&self.body)
    }

    pub fn attach_signature(
        self,
        signature: crate::Base64UrlString,
    ) -> Result<RecoveryCompletionAttestation> {
        let body = self.body;
        let attestation = RecoveryCompletionAttestation {
            schema: "ak.schema.recovery_completion_attestation.v1".to_owned(),
            transaction_id: body.transaction_id,
            transaction_request_digest: body.transaction_request_digest,
            prepared_plan_digest: body.prepared_plan_digest,
            principal_id: body.principal_id,
            coordinator_service_id: body.coordinator_service_id,
            recovery_session_id: body.recovery_session_id,
            terminal_receipt_id: body.terminal_receipt_id,
            terminal_receipt_digest: body.terminal_receipt_digest,
            replacement_device_id: body.replacement_device_id,
            device_authorization_event_id: body.device_authorization_event_id,
            device_authorization_event_digest: body.device_authorization_event_digest,
            result_model_generation_ref: body.result_model_generation_ref,
            completed_at: body.completed_at,
            auth_data: RecoveryCompletionAttestationAuthData {
                verification_method: self.verification_method,
                signature_algorithm: "Ed25519".to_owned(),
                signature: signature.into_string(),
                signed_fields: RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
        };
        attestation.validate_structural()?;
        Ok(attestation)
    }
}

fn validate_recovery_completion_attestation_body(
    body: &UnsignedRecoveryCompletionAttestationBody,
) -> Result<()> {
    if matches!(
        &body.result_model_generation_ref,
        RecoveryModelGenerationRef::RootAnchored(value) if value.is_empty()
    ) {
        return Err(Error::Protocol(
            "recovery completion generation must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn recovery_completion_attestation_signing_bytes(
    body: &UnsignedRecoveryCompletionAttestationBody,
) -> Result<Vec<u8>> {
    validate_recovery_completion_attestation_body(body)?;
    let value = serde_json::json!({
        "schema": "ak.schema.recovery_completion_attestation.v1",
        "transaction_id": &body.transaction_id,
        "transaction_request_digest": &body.transaction_request_digest,
        "prepared_plan_digest": &body.prepared_plan_digest,
        "principal_id": &body.principal_id,
        "coordinator_service_id": &body.coordinator_service_id,
        "recovery_session_id": &body.recovery_session_id,
        "terminal_receipt_id": &body.terminal_receipt_id,
        "terminal_receipt_digest": &body.terminal_receipt_digest,
        "replacement_device_id": &body.replacement_device_id,
        "device_authorization_event_id": &body.device_authorization_event_id,
        "device_authorization_event_digest": &body.device_authorization_event_digest,
        "result_model_generation_ref": &body.result_model_generation_ref,
        "completed_at": crate::canonical::format_timestamp_canonical(body.completed_at),
    });
    Ok(arkret_canonical::canonical::canonical_json_bytes(&value)?)
}

fn request_digest_without_digest<T: Serialize>(request: &T) -> Result<Hash> {
    let mut value = serde_json::to_value(request)?;
    let object = value.as_object_mut().ok_or_else(|| {
        Error::Protocol("recovery completion grant request must serialize as an object".to_owned())
    })?;
    object.remove("canonical_request_digest");
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&value)?;
    Ok(Hash::new(arkret_canonical::canonical::sha256_digest(
        &bytes,
    ))?)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRecoveryCompletionGrantRequest {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub terminal_receipt: Value,
    pub completion_attestation: RecoveryCompletionAttestation,
    pub device_authorization_event_id: EventId,
    pub result_model_generation_ref: RecoveryModelGenerationRef,
    pub initial_session: Value,
    pub canonical_request_digest: Hash,
}

impl IssueRecoveryCompletionGrantRequest {
    pub fn expected_canonical_request_digest(&self) -> Result<Hash> {
        request_digest_without_digest(self)
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.completion_attestation.validate_structural()?;
        if self.transaction_id != self.completion_attestation.transaction_id
            || self.transaction_request_digest
                != self.completion_attestation.transaction_request_digest
            || self.device_authorization_event_id
                != self.completion_attestation.device_authorization_event_id
            || self.result_model_generation_ref
                != self.completion_attestation.result_model_generation_ref
        {
            return Err(Error::Protocol(
                "recovery completion grant request and attestation binding disagree".to_owned(),
            ));
        }
        if self.expected_canonical_request_digest()? != self.canonical_request_digest {
            return Err(Error::Protocol(
                "canonical_request_digest does not equal the canonical request projection"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRecoveryCompletionGrantOutcome {
    pub transaction_id: TransactionId,
    pub session_grant_outcome: Value,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
}
