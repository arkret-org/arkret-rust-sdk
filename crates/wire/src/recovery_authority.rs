//! PCR-policy recovery completion and direct Standard-grant DTOs.
//!
//! Recovery publishes the next DID entry and submits one atomic re-anchor
//! unit. No external enrollment authority, approval ticket, or service-signed
//! device authorization exists on this boundary.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::{
    AccountId, CommitStreamRef, CommittedEventRef, DeviceId, DidUrl, EventId, Hash, ReceiptId,
    RecoverySessionId, TransactionId,
};

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
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "canonical public material bytes do not equal canonical JSON of value".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCompletionAttestationAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the properties order of
// recovery-authority.schema.json#/$defs/recovery_completion_attestation.
pub struct RecoveryCompletionAttestation {
    pub schema: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    /// The exact recovered account. Its `station_id` is the coordinator; no
    /// separate coordinator field exists on wire or in the signed projection.
    pub account_id: AccountId,
    pub recovery_session_id: RecoverySessionId,
    pub terminal_receipt_id: ReceiptId,
    pub terminal_receipt_digest: Hash,
    pub replacement_device_id: DeviceId,
    pub result_model_generation_ref: u64,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    pub auth_data: RecoveryCompletionAttestationAuthData,
    /// Exact authority commitment of the accepted recovery re-anchor Event.
    pub reanchor_event_ref: CommittedEventRef,
    /// Exact immediately following authority commitment of the replacement
    /// device authorization Event.
    pub device_authorization_event_ref: CommittedEventRef,
}

impl RecoveryCompletionAttestation {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != crate::SchemaId::RECOVERY_COMPLETION_ATTESTATION_V1 {
            return Err(WireError::Protocol(
                "recovery completion attestation schema is invalid".to_owned(),
            ));
        }
        if self.auth_data.signature_algorithm != "Ed25519"
            || self.auth_data.verification_method.is_empty()
            || self.auth_data.signature.is_empty()
        {
            return Err(WireError::Protocol(
                "recovery completion attestation requires a complete Ed25519 authorization"
                    .to_owned(),
            ));
        }
        if self.result_model_generation_ref == 0 {
            return Err(WireError::Protocol(
                "recovery completion generation must be positive".to_owned(),
            ));
        }
        validate_recovery_commit_pair(
            &self.reanchor_event_ref,
            &self.device_authorization_event_ref,
        )?;
        Ok(())
    }

    /// Canonical coordinator signature transcript. `auth_data` is excluded so
    /// the Ed25519 signature cannot recursively contain itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        recovery_completion_attestation_signing_bytes(&UnsignedRecoveryCompletionAttestationBody {
            transaction_id: self.transaction_id.clone(),
            transaction_request_digest: self.transaction_request_digest.clone(),
            prepared_plan_digest: self.prepared_plan_digest.clone(),
            account_id: self.account_id.clone(),
            recovery_session_id: self.recovery_session_id.clone(),
            terminal_receipt_id: self.terminal_receipt_id.clone(),
            terminal_receipt_digest: self.terminal_receipt_digest.clone(),
            replacement_device_id: self.replacement_device_id.clone(),
            reanchor_event_ref: self.reanchor_event_ref.clone(),
            device_authorization_event_ref: self.device_authorization_event_ref.clone(),
            result_model_generation_ref: self.result_model_generation_ref,
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
    pub account_id: AccountId,
    pub recovery_session_id: RecoverySessionId,
    pub terminal_receipt_id: ReceiptId,
    pub terminal_receipt_digest: Hash,
    pub replacement_device_id: DeviceId,
    pub result_model_generation_ref: u64,
    pub completed_at: DateTime<Utc>,
    pub reanchor_event_ref: CommittedEventRef,
    pub device_authorization_event_ref: CommittedEventRef,
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
            schema: crate::SchemaId::RECOVERY_COMPLETION_ATTESTATION_V1.to_owned(),
            transaction_id: body.transaction_id,
            transaction_request_digest: body.transaction_request_digest,
            prepared_plan_digest: body.prepared_plan_digest,
            account_id: body.account_id,
            recovery_session_id: body.recovery_session_id,
            terminal_receipt_id: body.terminal_receipt_id,
            terminal_receipt_digest: body.terminal_receipt_digest,
            replacement_device_id: body.replacement_device_id,
            result_model_generation_ref: body.result_model_generation_ref,
            completed_at: body.completed_at,
            auth_data: RecoveryCompletionAttestationAuthData {
                verification_method: self.verification_method,
                signature_algorithm: "Ed25519".to_owned(),
                signature: signature.into_string(),
            },
            reanchor_event_ref: body.reanchor_event_ref,
            device_authorization_event_ref: body.device_authorization_event_ref,
        };
        attestation.validate_structural()?;
        Ok(attestation)
    }
}

fn validate_recovery_completion_attestation_body(
    body: &UnsignedRecoveryCompletionAttestationBody,
) -> Result<()> {
    if body.result_model_generation_ref == 0 {
        return Err(WireError::Protocol(
            "recovery completion generation must be positive".to_owned(),
        ));
    }
    validate_recovery_commit_pair(
        &body.reanchor_event_ref,
        &body.device_authorization_event_ref,
    )?;
    Ok(())
}

/// A completed RecoveryTransaction binds the re-anchor Event and the
/// replacement-device authorize Event to two consecutive `CommittedEventRef`
/// values in the same PCR Realm stream
/// (`zh/crypto-media/device-lifecycle.md`, RecoveryTransaction termination).
/// One RealmCommit carries exactly one `event_ref`
/// (`realm-commit.schema.json`), so the pair names two distinct commits and
/// two distinct Events at consecutive stream positions; a shared `commit_id`
/// or a shared `event_id` is therefore a structural violation, not a match.
fn validate_recovery_commit_pair(
    reanchor_event_ref: &CommittedEventRef,
    device_authorization_event_ref: &CommittedEventRef,
) -> Result<()> {
    if reanchor_event_ref.stream_ref != device_authorization_event_ref.stream_ref
        || !matches!(reanchor_event_ref.stream_ref, CommitStreamRef::Realm { .. })
        || Some(device_authorization_event_ref.stream_position)
            != reanchor_event_ref.stream_position.checked_add(1)
    {
        return Err(WireError::Protocol(
            "recovery reanchor and device authorization must be consecutive commits in the same PCR Realm stream"
                .to_owned(),
        ));
    }
    if reanchor_event_ref.commit_id == device_authorization_event_ref.commit_id
        || reanchor_event_ref.event_id == device_authorization_event_ref.event_id
    {
        return Err(WireError::Protocol(
            "recovery reanchor and device authorization must name two distinct commits and two distinct Events"
                .to_owned(),
        ));
    }
    Ok(())
}

fn recovery_completion_attestation_signing_bytes(
    body: &UnsignedRecoveryCompletionAttestationBody,
) -> Result<Vec<u8>> {
    validate_recovery_completion_attestation_body(body)?;
    let value = serde_json::json!({
        "schema": crate::SchemaId::RECOVERY_COMPLETION_ATTESTATION_V1,
        "transaction_id": &body.transaction_id,
        "transaction_request_digest": &body.transaction_request_digest,
        "prepared_plan_digest": &body.prepared_plan_digest,
        "account_id": &body.account_id,
        "recovery_session_id": &body.recovery_session_id,
        "terminal_receipt_id": &body.terminal_receipt_id,
        "terminal_receipt_digest": &body.terminal_receipt_digest,
        "replacement_device_id": &body.replacement_device_id,
        "reanchor_event_ref": &body.reanchor_event_ref,
        "device_authorization_event_ref": &body.device_authorization_event_ref,
        "result_model_generation_ref": &body.result_model_generation_ref,
        "completed_at": crate::canonical::format_timestamp_canonical(body.completed_at),
    });
    Ok(arkret_canonical::canonical::canonical_json_bytes(&value)?)
}

fn request_digest_without_digest<T: Serialize>(request: &T) -> Result<Hash> {
    let mut value = serde_json::to_value(request)?;
    let object = value.as_object_mut().ok_or_else(|| {
        WireError::Protocol(
            "recovery completion grant request must serialize as an object".to_owned(),
        )
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
// Field declaration order is byte-for-byte the properties order of
// recovery-authority.schema.json#/$defs/issue_recovery_completion_grant_request.
pub struct IssueRecoveryCompletionGrantRequest {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub terminal_receipt: Value,
    pub completion_attestation: RecoveryCompletionAttestation,
    pub device_authorization_event_id: EventId,
    pub result_model_generation_ref: u64,
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
                != self
                    .completion_attestation
                    .device_authorization_event_ref
                    .event_id
            || self.result_model_generation_ref
                != self.completion_attestation.result_model_generation_ref
        {
            return Err(WireError::Protocol(
                "recovery completion grant request and attestation binding disagree".to_owned(),
            ));
        }
        // The client-signed recovery receipt and Station completion
        // attestation must name the exact same committed re-anchor. The client
        // never signs or embeds the RealmCommit itself.
        if self.terminal_receipt.get("reanchor_event_id")
            != Some(&serde_json::to_value(
                &self.completion_attestation.reanchor_event_ref.event_id,
            )?)
        {
            return Err(WireError::Protocol(
                "terminal receipt and completion attestation name different reanchor commits"
                    .to_owned(),
            ));
        }
        if self.expected_canonical_request_digest()? != self.canonical_request_digest {
            return Err(WireError::Protocol(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventId, RealmCommitId, RealmId};

    fn committed_ref(event_seed: u8, commit_seed: u8, position: u64) -> CommittedEventRef {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        CommittedEventRef {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [event_seed; 32]),
            commit_id: RealmCommitId::from_digest([commit_seed; 32]),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: position,
        }
    }

    #[test]
    fn recovery_commit_pair_requires_consecutive_same_stream_commits() {
        let reanchor = committed_ref(2, 3, 8);
        let authorization = committed_ref(4, 5, 9);
        validate_recovery_commit_pair(&reanchor, &authorization).unwrap();

        let mut gap = authorization.clone();
        gap.stream_position = 10;
        assert!(validate_recovery_commit_pair(&reanchor, &gap).is_err());

        let other_realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [9; 32],
        ));
        let mut cross_stream = authorization;
        cross_stream.stream_ref = CommitStreamRef::Realm {
            realm_id: other_realm,
        };
        assert!(validate_recovery_commit_pair(&reanchor, &cross_stream).is_err());
    }

    #[test]
    fn recovery_commit_pair_rejects_a_shared_commit_or_event() {
        let reanchor = committed_ref(2, 3, 8);

        let mut shared_commit = committed_ref(4, 3, 9);
        shared_commit.commit_id = reanchor.commit_id.clone();
        assert!(validate_recovery_commit_pair(&reanchor, &shared_commit).is_err());

        let mut shared_event = committed_ref(2, 5, 9);
        shared_event.event_id = reanchor.event_id.clone();
        assert!(validate_recovery_commit_pair(&reanchor, &shared_event).is_err());
    }

    #[test]
    fn recovery_commit_pair_rejects_a_saturating_position() {
        let reanchor = committed_ref(2, 3, u64::MAX);
        let authorization = committed_ref(4, 5, u64::MAX);
        assert!(validate_recovery_commit_pair(&reanchor, &authorization).is_err());
    }
}
