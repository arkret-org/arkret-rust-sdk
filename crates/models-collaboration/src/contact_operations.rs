use arkret_wire::{
    Audience, Base64UrlString, DeviceId, Did, Event, EventId, Hash, IdempotencyKey, PayloadProof,
    PayloadProofPurpose, ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature,
    ReservationHandle, SessionGrantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::peer_contact::{ContactIntroductionEvidence, PeerContactAddress};
use crate::string_marker;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum BootstrapMode {
    Founding,
    SiblingPairing,
}

string_marker!(
    DeviceBootstrapCredentialKind,
    DeviceBootstrap,
    "device_bootstrap"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum FoundingAllowedOperation {
    #[serde(rename = "ak.gate.account.command.enroll_device")]
    EnrollDevice,
    #[serde(rename = "ak.gate.account.command.cancel_device_bootstrap")]
    CancelDeviceBootstrap,
    #[serde(rename = "ak.self.events.command.submit")]
    EventsSubmit,
    #[serde(rename = "ak.self.events.read.resolve")]
    EventsResolve,
}

/// The schema defines this as a positional tuple, not as an arbitrary set of
/// four operation identifiers.  A zero-sized value keeps callers from ever
/// constructing a reordered credential while its custom wire form preserves
/// the required JSON array.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FoundingAllowedOperations;

impl Serialize for FoundingAllowedOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [
            FoundingAllowedOperation::EnrollDevice,
            FoundingAllowedOperation::CancelDeviceBootstrap,
            FoundingAllowedOperation::EventsSubmit,
            FoundingAllowedOperation::EventsResolve,
        ]
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FoundingAllowedOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let operations = <[FoundingAllowedOperation; 4]>::deserialize(deserializer)?;
        let expected = [
            FoundingAllowedOperation::EnrollDevice,
            FoundingAllowedOperation::CancelDeviceBootstrap,
            FoundingAllowedOperation::EventsSubmit,
            FoundingAllowedOperation::EventsResolve,
        ];
        if operations != expected {
            return Err(serde::de::Error::custom(
                "founding allowed_operation_ids must match the fixed operation tuple",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SiblingAllowedOperation {
    #[serde(rename = "ak.gate.account.command.cancel_device_bootstrap")]
    CancelDeviceBootstrap,
    #[serde(rename = "ak.self.device_messages.command.send")]
    DeviceMessagesSend,
    #[serde(rename = "ak.self.device_messages.read.list")]
    DeviceMessagesList,
    #[serde(rename = "ak.self.device_messages.command.ack")]
    DeviceMessagesAck,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SiblingAllowedOperations;

impl Serialize for SiblingAllowedOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [
            SiblingAllowedOperation::CancelDeviceBootstrap,
            SiblingAllowedOperation::DeviceMessagesSend,
            SiblingAllowedOperation::DeviceMessagesList,
            SiblingAllowedOperation::DeviceMessagesAck,
        ]
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SiblingAllowedOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let operations = <[SiblingAllowedOperation; 4]>::deserialize(deserializer)?;
        let expected = [
            SiblingAllowedOperation::CancelDeviceBootstrap,
            SiblingAllowedOperation::DeviceMessagesSend,
            SiblingAllowedOperation::DeviceMessagesList,
            SiblingAllowedOperation::DeviceMessagesAck,
        ];
        if operations != expected {
            return Err(serde::de::Error::custom(
                "sibling allowed_operation_ids must match the fixed operation tuple",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceBootstrapCredential {
    Founding {
        credential_kind: DeviceBootstrapCredentialKind,
        principal_id: Did,
        device_id: DeviceId,
        device_key_digest: Hash,
        transaction_id: ProtocolOpaqueId,
        holder_jkt: String,
        canonical_request_digest: Hash,
        founding_batch_digest: Hash,
        founding_event_ids: Vec<EventId>,
        allowed_operation_ids: FoundingAllowedOperations,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        credential_expires_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        bootstrap_transaction_expires_at: DateTime<Utc>,
    },
    SiblingPairing {
        credential_kind: DeviceBootstrapCredentialKind,
        principal_id: Did,
        device_id: DeviceId,
        device_key_digest: Hash,
        transaction_id: ProtocolOpaqueId,
        holder_jkt: String,
        canonical_request_digest: Hash,
        source_device_id: DeviceId,
        target_device_id: DeviceId,
        verification_content_kinds: Vec<String>,
        allowed_operation_ids: SiblingAllowedOperations,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        credential_expires_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        bootstrap_transaction_expires_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CancelDeviceBootstrapRequestBody {
    pub transaction_id: ProtocolOpaqueId,
    pub mode: BootstrapMode,
    pub canonical_request_digest: Hash,
    pub idempotency_key: IdempotencyKey,
}

impl CancelDeviceBootstrapRequestBody {
    /// Compute the exact-replay identity of this closed request body.
    pub fn canonical_request_digest(&self) -> arkret_wire::Result<Hash> {
        Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(self)?,
        ))
        .map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum BootstrapRetryableError {
    TemporarilyUnavailable,
    ProofRefreshRequired,
    DependencyPending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CancelDeviceBootstrapOutcome {
    Cancelled {
        transaction_id: ProtocolOpaqueId,
        outcome_digest: Hash,
    },
    Expired {
        transaction_id: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expired_at: DateTime<Utc>,
        outcome_digest: Hash,
    },
    Pending {
        transaction_id: ProtocolOpaqueId,
        retryable_error: BootstrapRetryableError,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
        outcome_digest: Hash,
    },
}

impl CancelDeviceBootstrapOutcome {
    /// Recompute the exact response identity after removing the self-referential
    /// `outcome_digest` member from the closed outcome object.
    pub fn recompute_outcome_digest(&self) -> arkret_wire::Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                arkret_wire::Error::Protocol(
                    "cancel outcome must serialize as an object".to_owned(),
                )
            })?
            .remove("outcome_digest");
        Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&value)?,
        ))
        .map_err(Into::into)
    }

    /// Validate the response transaction binding and its canonical outcome digest.
    pub fn validate_against(
        &self,
        request: &CancelDeviceBootstrapRequestBody,
    ) -> arkret_wire::Result<()> {
        let (transaction_id, outcome_digest) = match self {
            Self::Cancelled {
                transaction_id,
                outcome_digest,
            }
            | Self::Expired {
                transaction_id,
                outcome_digest,
                ..
            }
            | Self::Pending {
                transaction_id,
                outcome_digest,
                ..
            } => (transaction_id, outcome_digest),
        };
        if transaction_id != &request.transaction_id
            || outcome_digest != &self.recompute_outcome_digest()?
        {
            return Err(arkret_wire::Error::Protocol(
                "cancel device bootstrap outcome does not match request identity".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Domain tag prepended to the canonical decision-receipt preimage.
pub const DEVICE_BOOTSTRAP_DECISION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"ak.device-bootstrap.decision-receipt.v1\n";
/// Fixed signing context included in the non-Event receipt proof binding.
pub const DEVICE_BOOTSTRAP_DECISION_RECEIPT_PROOF_CONTEXT: &str =
    "ak.device-bootstrap-decision-receipt-proof-v1";

string_marker!(
    DeviceBootstrapDecisionReceiptSchema,
    V1,
    "ak.device_bootstrap.decision_receipt.v1"
);

/// Closed terminal decision stored by the Principal Server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceBootstrapDecision {
    Accepted,
    Cancelled,
    Expired,
}

/// Terminal decision that the Account Authority may request from the
/// Principal Server. `accepted` can only be produced by founding-batch
/// admission and therefore is deliberately not constructible here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum RequestedDeviceBootstrapDecision {
    Cancelled,
    Expired,
}

impl From<RequestedDeviceBootstrapDecision> for DeviceBootstrapDecision {
    fn from(value: RequestedDeviceBootstrapDecision) -> Self {
        match value {
            RequestedDeviceBootstrapDecision::Cancelled => Self::Cancelled,
            RequestedDeviceBootstrapDecision::Expired => Self::Expired,
        }
    }
}

/// Closed Account Authority request for the Principal Server's durable
/// founding-bootstrap decision fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBootstrapDecisionRequestPreimage {
    pub account_authority_id: Did,
    pub transaction_id: ProtocolOpaqueId,
    pub idempotency_key: IdempotencyKey,
    pub requested_decision: RequestedDeviceBootstrapDecision,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub grant_id: SessionGrantId,
    pub canonical_request_digest: Hash,
    pub founding_event_ids: [EventId; 2],
    pub founding_batch_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub bootstrap_transaction_expires_at: DateTime<Utc>,
}

impl DeviceBootstrapDecisionRequestPreimage {
    /// Compute the request self-digest from the complete closed preimage.
    pub fn decision_request_digest(&self) -> arkret_wire::Result<Hash> {
        canonical_sha256_hash(self)
    }

    /// Finalize a request without requiring callers to invent a placeholder
    /// digest or duplicate the canonical hashing algorithm.
    pub fn finalize(self) -> arkret_wire::Result<DeviceBootstrapDecisionRequestBody> {
        let decision_request_digest = self.decision_request_digest()?;
        let request = DeviceBootstrapDecisionRequestBody {
            account_authority_id: self.account_authority_id,
            transaction_id: self.transaction_id,
            idempotency_key: self.idempotency_key,
            requested_decision: self.requested_decision,
            principal_id: self.principal_id,
            device_id: self.device_id,
            grant_id: self.grant_id,
            canonical_request_digest: self.canonical_request_digest,
            founding_event_ids: self.founding_event_ids,
            founding_batch_digest: self.founding_batch_digest,
            bootstrap_transaction_expires_at: self.bootstrap_transaction_expires_at,
            decision_request_digest,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Closed Account Authority request for the Principal Server's durable
/// founding-bootstrap decision fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceBootstrapDecisionRequestBody {
    pub account_authority_id: Did,
    pub transaction_id: ProtocolOpaqueId,
    pub idempotency_key: IdempotencyKey,
    pub requested_decision: RequestedDeviceBootstrapDecision,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub grant_id: SessionGrantId,
    pub canonical_request_digest: Hash,
    pub founding_event_ids: [EventId; 2],
    pub founding_batch_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub bootstrap_transaction_expires_at: DateTime<Utc>,
    pub decision_request_digest: Hash,
}

impl DeviceBootstrapDecisionRequestBody {
    fn preimage(&self) -> DeviceBootstrapDecisionRequestPreimage {
        DeviceBootstrapDecisionRequestPreimage {
            account_authority_id: self.account_authority_id.clone(),
            transaction_id: self.transaction_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            requested_decision: self.requested_decision,
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            grant_id: self.grant_id.clone(),
            canonical_request_digest: self.canonical_request_digest.clone(),
            founding_event_ids: self.founding_event_ids.clone(),
            founding_batch_digest: self.founding_batch_digest.clone(),
            bootstrap_transaction_expires_at: self.bootstrap_transaction_expires_at,
        }
    }

    /// Recompute `decision_request_digest` as SHA-256 over RFC 8785/JCS of
    /// this closed request with the self-referential member omitted.
    pub fn recompute_decision_request_digest(&self) -> arkret_wire::Result<Hash> {
        self.preimage().decision_request_digest()
    }

    /// Validate the request self-digest and the immutable founding-batch
    /// binding. Expiry eligibility remains a Principal Server database-time
    /// decision.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.founding_event_ids[0] == self.founding_event_ids[1]
            || arkret_models_identity::founding_batch_digest(&self.founding_event_ids)?
                != self.founding_batch_digest
            || self.recompute_decision_request_digest()? != self.decision_request_digest
        {
            return Err(protocol_error(
                "device bootstrap decision request digest or founding binding is invalid",
            ));
        }
        Ok(())
    }
}

/// Principal Server notary-signed immutable terminal decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBootstrapDecisionReceiptPreimage {
    pub schema: DeviceBootstrapDecisionReceiptSchema,
    pub receipt_id: ProtocolOpaqueId,
    pub principal_server_id: Did,
    pub account_authority_id: Did,
    pub transaction_id: ProtocolOpaqueId,
    pub decision: DeviceBootstrapDecision,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub grant_id: SessionGrantId,
    pub canonical_request_digest: Hash,
    pub founding_event_ids: [EventId; 2],
    pub founding_batch_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub bootstrap_transaction_expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub decided_at: DateTime<Utc>,
}

impl DeviceBootstrapDecisionReceiptPreimage {
    /// Compute the domain-separated receipt digest.
    pub fn receipt_digest(&self) -> arkret_wire::Result<Hash> {
        domain_separated_sha256(DEVICE_BOOTSTRAP_DECISION_RECEIPT_DIGEST_DOMAIN, self)
    }

    /// Canonical non-Event payload binding that the Principal Server notary
    /// signs for this receipt.
    pub fn proof_binding_bytes(
        &self,
        verification_method: &arkret_wire::DidUrl,
    ) -> arkret_wire::Result<Vec<u8>> {
        receipt_proof_binding_bytes(
            &self.receipt_digest()?,
            &self.principal_server_id,
            &self.account_authority_id,
            &self.transaction_id,
            verification_method,
            &self.decided_at,
        )
    }

    /// Attach a caller-generated proof after checking it was built over this
    /// exact preimage and signing context.
    pub fn finalize(
        self,
        proof: PayloadProof,
    ) -> arkret_wire::Result<DeviceBootstrapDecisionReceipt> {
        let receipt_digest = self.receipt_digest()?;
        let receipt = DeviceBootstrapDecisionReceipt {
            schema: self.schema,
            receipt_id: self.receipt_id,
            principal_server_id: self.principal_server_id,
            account_authority_id: self.account_authority_id,
            transaction_id: self.transaction_id,
            decision: self.decision,
            principal_id: self.principal_id,
            device_id: self.device_id,
            grant_id: self.grant_id,
            canonical_request_digest: self.canonical_request_digest,
            founding_event_ids: self.founding_event_ids,
            founding_batch_digest: self.founding_batch_digest,
            bootstrap_transaction_expires_at: self.bootstrap_transaction_expires_at,
            decided_at: self.decided_at,
            receipt_digest,
            proof,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// Principal Server notary-signed immutable terminal decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceBootstrapDecisionReceipt {
    pub schema: DeviceBootstrapDecisionReceiptSchema,
    pub receipt_id: ProtocolOpaqueId,
    pub principal_server_id: Did,
    pub account_authority_id: Did,
    pub transaction_id: ProtocolOpaqueId,
    pub decision: DeviceBootstrapDecision,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub grant_id: SessionGrantId,
    pub canonical_request_digest: Hash,
    pub founding_event_ids: [EventId; 2],
    pub founding_batch_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub bootstrap_transaction_expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub decided_at: DateTime<Utc>,
    pub receipt_digest: Hash,
    pub proof: PayloadProof,
}

impl DeviceBootstrapDecisionReceipt {
    fn preimage(&self) -> DeviceBootstrapDecisionReceiptPreimage {
        DeviceBootstrapDecisionReceiptPreimage {
            schema: self.schema,
            receipt_id: self.receipt_id.clone(),
            principal_server_id: self.principal_server_id.clone(),
            account_authority_id: self.account_authority_id.clone(),
            transaction_id: self.transaction_id.clone(),
            decision: self.decision,
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            grant_id: self.grant_id.clone(),
            canonical_request_digest: self.canonical_request_digest.clone(),
            founding_event_ids: self.founding_event_ids.clone(),
            founding_batch_digest: self.founding_batch_digest.clone(),
            bootstrap_transaction_expires_at: self.bootstrap_transaction_expires_at,
            decided_at: self.decided_at,
        }
    }

    /// Recompute the domain-separated receipt digest after omitting the
    /// self-reference and notary proof.
    pub fn recompute_receipt_digest(&self) -> arkret_wire::Result<Hash> {
        self.preimage().receipt_digest()
    }

    /// Validate all structural bindings and the proof's payload digest.
    /// Cryptographic JWS verification remains the caller's responsibility and
    /// must use the resolved `proof.verification_method`.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.founding_event_ids[0] == self.founding_event_ids[1]
            || arkret_models_identity::founding_batch_digest(&self.founding_event_ids)?
                != self.founding_batch_digest
            || self.recompute_receipt_digest()? != self.receipt_digest
            || self.proof.payload_digest != self.receipt_digest
            || self.proof.created_at != self.decided_at
        {
            return Err(protocol_error(
                "device bootstrap decision receipt digest or proof binding is invalid",
            ));
        }
        self.proof.validate_production()?;
        let expected_prefix = format!("{}#", self.principal_server_id.as_str());
        if !self
            .proof
            .verification_method
            .as_str()
            .starts_with(&expected_prefix)
        {
            return Err(protocol_error(
                "device bootstrap decision receipt proof is not controlled by principal_server_id",
            ));
        }
        if self.proof.audience
            != Some(Audience::Single(
                self.account_authority_id.as_str().to_owned(),
            ))
            || self.proof.proof_purpose != Some(PayloadProofPurpose::IssuerAttestation)
        {
            return Err(protocol_error(
                "device bootstrap decision receipt proof audience or purpose is invalid",
            ));
        }
        Ok(())
    }

    /// Canonical bytes signed by the receipt notary. The context constant is
    /// part of this binding object, not a wire member of the generic proof.
    pub fn proof_binding_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        receipt_proof_binding_bytes(
            &self.receipt_digest,
            &self.principal_server_id,
            &self.account_authority_id,
            &self.transaction_id,
            &self.proof.verification_method,
            &self.decided_at,
        )
    }

    /// Validate the structural receipt/proof binding and delegate the actual
    /// detached-JWS verification to the caller's DID-key resolver.
    pub fn validate_proof_with(
        &self,
        verify: impl FnOnce(&arkret_wire::DidUrl, &[u8], &str) -> arkret_wire::Result<()>,
    ) -> arkret_wire::Result<()> {
        self.validate()?;
        let binding = self.proof_binding_bytes()?;
        verify(&self.proof.verification_method, &binding, &self.proof.jws)
    }

    /// Validate the receipt against the exact Account Authority request. An
    /// `accepted` receipt may win the race regardless of the requested
    /// negative decision; a negative receipt must equal it exactly.
    pub fn validate_against(
        &self,
        request: &DeviceBootstrapDecisionRequestBody,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        self.validate()?;
        let requested = DeviceBootstrapDecision::from(request.requested_decision);
        if self.account_authority_id != request.account_authority_id
            || self.transaction_id != request.transaction_id
            || self.principal_id != request.principal_id
            || self.device_id != request.device_id
            || self.grant_id != request.grant_id
            || self.canonical_request_digest != request.canonical_request_digest
            || self.founding_event_ids != request.founding_event_ids
            || self.founding_batch_digest != request.founding_batch_digest
            || self.bootstrap_transaction_expires_at != request.bootstrap_transaction_expires_at
            || (self.decision != DeviceBootstrapDecision::Accepted && self.decision != requested)
        {
            return Err(protocol_error(
                "device bootstrap decision receipt does not match request",
            ));
        }
        Ok(())
    }
}

fn receipt_proof_binding_bytes(
    receipt_digest: &Hash,
    principal_server_id: &Did,
    account_authority_id: &Did,
    transaction_id: &ProtocolOpaqueId,
    verification_method: &arkret_wire::DidUrl,
    decided_at: &DateTime<Utc>,
) -> arkret_wire::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Binding<'a> {
        context: &'static str,
        payload_digest: &'a Hash,
        principal_server_id: &'a Did,
        account_authority_id: &'a Did,
        transaction_id: &'a ProtocolOpaqueId,
        verification_method: &'a arkret_wire::DidUrl,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: &'a DateTime<Utc>,
        audience: &'a str,
    }

    arkret_canonical::canonical_json_bytes(&Binding {
        context: DEVICE_BOOTSTRAP_DECISION_RECEIPT_PROOF_CONTEXT,
        payload_digest: receipt_digest,
        principal_server_id,
        account_authority_id,
        transaction_id,
        verification_method,
        created_at: decided_at,
        audience: account_authority_id.as_str(),
    })
    .map_err(protocol_error)
}

/// Closed byte-stable Principal Server response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceBootstrapDecisionOutcome {
    pub transaction_id: ProtocolOpaqueId,
    pub decision: DeviceBootstrapDecision,
    pub receipt: DeviceBootstrapDecisionReceipt,
}

impl DeviceBootstrapDecisionOutcome {
    /// Validate the complete response and its exact request binding.
    pub fn validate_against(
        &self,
        request: &DeviceBootstrapDecisionRequestBody,
    ) -> arkret_wire::Result<()> {
        if self.transaction_id != request.transaction_id || self.decision != self.receipt.decision {
            return Err(protocol_error(
                "device bootstrap decision outcome is internally inconsistent",
            ));
        }
        self.receipt.validate_against(request)
    }
}

/// Durable Principal Server authority row for one terminal bootstrap decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceBootstrapDecisionRecord {
    pub account_authority_id: Did,
    pub transaction_id: ProtocolOpaqueId,
    pub decision: DeviceBootstrapDecision,
    pub binding_digest: Hash,
    pub canonical_outcome_bytes: Base64UrlString,
    pub receipt: DeviceBootstrapDecisionReceipt,
}

impl DeviceBootstrapDecisionRecord {
    /// Decode and validate the retained byte-exact outcome against the typed
    /// row. The caller separately compares `binding_digest` to its durable
    /// transaction binding, whose preimage is storage-contract-specific.
    pub fn decode_and_validate_outcome(
        &self,
    ) -> arkret_wire::Result<DeviceBootstrapDecisionOutcome> {
        self.receipt.validate()?;
        let bytes = arkret_canonical::base64url_decode(self.canonical_outcome_bytes.as_str())
            .map_err(protocol_error)?;
        let outcome: DeviceBootstrapDecisionOutcome =
            serde_json::from_slice(&bytes).map_err(protocol_error)?;
        let canonical = arkret_canonical::canonical_json_bytes(&outcome).map_err(protocol_error)?;
        if canonical != bytes
            || outcome.transaction_id != self.transaction_id
            || outcome.decision != self.decision
            || outcome.receipt != self.receipt
            || self.account_authority_id != self.receipt.account_authority_id
        {
            return Err(protocol_error(
                "device bootstrap decision record does not match canonical outcome bytes",
            ));
        }
        Ok(outcome)
    }
}

fn canonical_sha256_hash(value: &impl Serialize) -> arkret_wire::Result<Hash> {
    Hash::new(arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(value).map_err(protocol_error)?,
    ))
    .map_err(protocol_error)
}

fn domain_separated_sha256(domain: &[u8], value: &impl Serialize) -> arkret_wire::Result<Hash> {
    let canonical = arkret_canonical::canonical_json_bytes(value).map_err(protocol_error)?;
    let mut transcript = Vec::with_capacity(domain.len() + canonical.len());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(transcript)).map_err(protocol_error)
}

fn protocol_error(error: impl std::fmt::Display) -> arkret_wire::Error {
    arkret_wire::Error::Protocol(error.to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum StandardHolderBinding {
    HumanDevice {
        device_binding: ProtocolOpaqueId,
    },
    AgentRuntime {
        agent_id: Did,
        device_id: DeviceId,
        agent_key_authorization_ref: EventId,
        verification_method: arkret_wire::DidUrl,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactPeer {
    Human { principal_id: Did },
    Agent { agent_id: Did, controller_id: Did },
}

impl ContactPeer {
    pub fn subject_id(&self) -> &Did {
        match self {
            Self::Human { principal_id } => principal_id,
            Self::Agent { agent_id, .. } => agent_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactScope {
    Invite,
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
}

pub type ContactScopes = Vec<ContactScope>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RequestAcceptanceReceiptCore {
    pub holder: ContactPeer,
    pub peer: ContactPeer,
    pub slot_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_predecessor: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
    pub request_event_ref: EventId,
    pub request_digest: Hash,
    pub source_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: Did,
}

impl RequestAcceptanceReceiptCore {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.slot_version == 0
            || (self.slot_version == 1) == self.slot_predecessor.is_some()
            || self.holder.subject_id() == self.peer.subject_id()
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid Contact request acceptance receipt core".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RequestAcceptanceReceipt {
    pub core: RequestAcceptanceReceiptCore,
    pub receipt_digest: Hash,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactCurrentProof {
    pub basis_id: Hash,
    pub issuer: Did,
    pub terminal: bool,
    pub head_event_ref: EventId,
    pub head_digest: Hash,
    pub accepted_frontier: Vec<EventId>,
    pub complete_through: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fresh_until: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactBasisRequestRef {
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactBasis {
    Normal {
        sorted_pair_members: [Did; 2],
        request_event_ref: EventId,
        request_acceptance_receipt_digest: Hash,
    },
    Glare {
        sorted_pair_members: [Did; 2],
        requests: [ContactBasisRequestRef; 2],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NormalResponseAcceptanceReceipt {
    pub basis_id: Hash,
    pub request_receipt: RequestAcceptanceReceipt,
    pub response_event_ref: EventId,
    pub response_digest: Hash,
    pub no_outgoing_slot_proof: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RejectAcceptanceReceipt {
    pub request_receipt: RequestAcceptanceReceipt,
    pub reject_event_ref: EventId,
    pub reject_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactLineage {
    pub basis_id: Hash,
    pub issuer: ContactPeer,
    pub peer: ContactPeer,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_event_ref: Option<EventId>,
    pub event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactCommitRequestBody {
    pub phase: ContactCommitPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub reservation_handle: ReservationHandle,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub signed_event: Event,
}

string_marker!(ContactCommitPhase, Commit, "commit");
string_marker!(ContactPreparePhase, Prepare, "prepare");
string_marker!(ContactAcceptAction, Accept, "accept");
string_marker!(ContactRejectAction, Reject, "reject");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub granted_to_peer_scopes: ContactScopes,
    pub introduction_evidence: ContactIntroductionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactOperationRequestBody {
    Prepare(ContactPrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactScopeUpdatePrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactScopeUpdateRequestBody {
    Prepare(ContactScopeUpdatePrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactBasisEvidenceBundle {
    pub basis_id: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
    pub basis: ContactBasis,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_response_receipt: Option<NormalResponseAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glare_concurrency_attestations: Option<[GlareConcurrencyAttestation; 2]>,
    pub current_proofs: Vec<ContactCurrentProof>,
}

pub fn validate_recontact_continuity(
    current: &ContactBasisEvidenceBundle,
    predecessors: &[ContactBasisEvidenceBundle],
) -> arkret_wire::Result<()> {
    if predecessors.len() > 64 {
        return Err(arkret_wire::Error::Protocol(
            "Contact basis continuity exceeds 64 predecessors".to_owned(),
        ));
    }
    let mut expected = current.previous_terminal_basis_id.as_ref();
    if current
        .request_receipts
        .iter()
        .any(|receipt| receipt.core.previous_terminal_basis_id.as_ref() != expected)
    {
        return Err(arkret_wire::Error::Protocol(
            "current Contact request receipt continuity pointer mismatch".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(current.basis_id.clone());
    for predecessor in predecessors {
        if expected != Some(&predecessor.basis_id)
            || predecessor.current_proofs.len() != 2
            || predecessor
                .current_proofs
                .iter()
                .any(|proof| !proof.terminal || proof.basis_id != predecessor.basis_id)
            || !seen.insert(predecessor.basis_id.clone())
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid Contact terminal basis continuity edge".to_owned(),
            ));
        }
        if predecessor.request_receipts.iter().any(|receipt| {
            receipt.core.previous_terminal_basis_id != predecessor.previous_terminal_basis_id
        }) {
            return Err(arkret_wire::Error::Protocol(
                "predecessor Contact request receipt continuity pointer mismatch".to_owned(),
            ));
        }
        expected = predecessor.previous_terminal_basis_id.as_ref();
    }
    if expected.is_some()
        || (current.previous_terminal_basis_id.is_some() && predecessors.is_empty())
    {
        return Err(arkret_wire::Error::Protocol(
            "Contact basis continuity does not terminate at one root".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAcceptPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub request_receipt: RequestAcceptanceReceipt,
    pub action: ContactAcceptAction,
    pub granted_to_peer_scopes: ContactScopes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactAcceptRequestBody {
    Prepare(ContactAcceptPrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRejectPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub request_receipt: RequestAcceptanceReceipt,
    pub action: ContactRejectAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactRejectRequestBody {
    Prepare(ContactRejectPrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactTombstonePrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactTombstoneRequestBody {
    Prepare(ContactTombstonePrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

string_marker!(
    ContactScopeUpdateSchema,
    V1,
    "ak.schema.contact_scope_update.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactScopeUpdatePayload {
    pub schema: ContactScopeUpdateSchema,
    pub peer: ContactPeer,
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactOperationRejectReason {
    ContactIdempotencyConflict,
    ContactBasisConflict,
    ContactLineageConflict,
    ContactTerminal,
    ContactScopeStale,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactPreparedEventDraft {
    pub event_id: EventId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: arkret_wire::EventKind,
    pub unsigned_event_bytes: Base64UrlString,
    pub event_digest: Hash,
}

impl ContactPreparedEventDraft {
    pub fn unsigned_event(&self) -> arkret_wire::Result<Event> {
        let bytes =
            arkret_canonical::base64url_decode(self.unsigned_event_bytes.as_str().as_bytes())?;
        let event = Event::from_digest_payload_bytes(&bytes)?;
        if event.event_id != self.event_id
            || event.kind != self.kind
            || Hash::new(event.event_digest()?)? != self.event_digest
        {
            return Err(arkret_wire::Error::Protocol(
                "prepared Contact Event metadata does not match unsigned_event_bytes".to_owned(),
            ));
        }
        event.validate_for_authoring_structural()?;
        Ok(event)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactResultKind {
    Request,
    Response,
    Reject,
    ScopeUpdate,
    Tombstone,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactPreparedOutcome {
    Request {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Response {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Reject {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    ScopeUpdate {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Tombstone {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactAcceptedOutcome {
    Request {
        operation_id: ProtocolOperationId,
        request_acceptance_receipt: RequestAcceptanceReceipt,
    },
    Response {
        operation_id: ProtocolOperationId,
        normal_response_acceptance_receipt: NormalResponseAcceptanceReceipt,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
    },
    Reject {
        operation_id: ProtocolOperationId,
        reject_acceptance_receipt: RejectAcceptanceReceipt,
    },
    ScopeUpdate {
        operation_id: ProtocolOperationId,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
    },
    Tombstone {
        operation_id: ProtocolOperationId,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactFailedOutcome {
    pub result_kind: ContactResultKind,
    pub operation_id: ProtocolOperationId,
    pub reason: ContactOperationRejectReason,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactOperationOutcome {
    Prepared {
        #[serde(flatten)]
        outcome: ContactPreparedOutcome,
    },
    Accepted {
        #[serde(flatten)]
        outcome: ContactAcceptedOutcome,
    },
    Failed {
        #[serde(flatten)]
        outcome: ContactFailedOutcome,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactSubmitRequestBody {
    Request {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        request_receipt: RequestAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
        introduction_evidence: ContactIntroductionEvidence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
    Response {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        response_receipt: NormalResponseAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
    Reject {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        reject_receipt: RejectAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ScopeUpdate {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    Tombstone {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ProofRefresh {
        idempotency_key: IdempotencyKey,
        prior_mirror_receipt: PeerContactMirrorReceipt,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    GlareFinalize {
        idempotency_key: IdempotencyKey,
        basis_id: Hash,
        basis: ContactBasis,
        request_receipts: [RequestAcceptanceReceipt; 2],
        remote_mirror_receipt: PeerContactMirrorReceipt,
        glare_concurrency_attestation: GlareConcurrencyAttestation,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct GlareConcurrencyAttestation {
    pub issuer: Did,
    pub peer: Did,
    pub request_receipt_digests: [Hash; 2],
    pub observed_frontier: Vec<EventId>,
    pub complete_through: u64,
    pub unconsumed_slot_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

string_marker!(
    PeerContactMirrorReceiptDomain,
    V1,
    "ak.peer-contact.mirror-receipt.v1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactDisposition {
    Accepted,
    Duplicate,
    Deferred,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactMirrorReceipt {
    pub domain: PeerContactMirrorReceiptDomain,
    pub request_digest: Hash,
    pub signed_event_ref: EventId,
    pub signed_event_digest: Hash,
    pub disposition: PeerContactDisposition,
    pub recipient_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

string_marker!(
    PeerContactControlReceiptDomain,
    V1,
    "ak.peer-contact.control-receipt.v1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactControlKind {
    ProofRefresh,
    GlareFinalize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactControlReceipt {
    pub domain: PeerContactControlReceiptDomain,
    pub request_kind: PeerContactControlKind,
    pub request_digest: Hash,
    pub disposition: PeerContactDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<Hash>,
    pub recipient_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactEventSubmitOutcome {
    pub result_kind: ContactResultKind,
    pub status: PeerContactDisposition,
    pub mirror_receipt: PeerContactMirrorReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_proof: Option<ContactCurrentProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum PeerContactControlSubmitOutcome {
    ProofRefresh {
        status: PeerContactDisposition,
        control_receipt: PeerContactControlReceipt,
        current_proof: ContactCurrentProof,
    },
    GlareFinalize {
        status: PeerContactDisposition,
        control_receipt: PeerContactControlReceipt,
        glare_concurrency_attestation: GlareConcurrencyAttestation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactControlDeferredOutcome {
    pub status: PeerContactDisposition,
    pub request_kind: PeerContactControlKind,
    pub control_receipt: PeerContactControlReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactSubmitOutcome {
    Event(PeerContactEventSubmitOutcome),
    Control(PeerContactControlSubmitOutcome),
    ControlDeferred(PeerContactControlDeferredOutcome),
}

impl PeerContactSubmitOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let valid = match self {
            Self::Event(outcome) => outcome.status == outcome.mirror_receipt.disposition,
            Self::Control(_) => true,
            Self::ControlDeferred(outcome) => {
                outcome.status == PeerContactDisposition::Deferred
                    && outcome.control_receipt.disposition == PeerContactDisposition::Deferred
            }
        };
        if valid {
            Ok(())
        } else {
            Err(arkret_wire::Error::Protocol(
                "peer Contact status does not match mirror receipt disposition".to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn bootstrap_operation_tuples_reject_reordering() {
        let founding = json!([
            "ak.gate.account.command.enroll_device",
            "ak.gate.account.command.cancel_device_bootstrap",
            "ak.self.events.command.submit",
            "ak.self.events.read.resolve"
        ]);
        serde_json::from_value::<FoundingAllowedOperations>(founding.clone()).unwrap();
        let mut reordered = founding.as_array().unwrap().clone();
        reordered.swap(0, 1);
        assert!(serde_json::from_value::<FoundingAllowedOperations>(json!(reordered)).is_err());

        let sibling = json!([
            "ak.gate.account.command.cancel_device_bootstrap",
            "ak.self.device_messages.command.send",
            "ak.self.device_messages.read.list",
            "ak.self.device_messages.command.ack"
        ]);
        serde_json::from_value::<SiblingAllowedOperations>(sibling.clone()).unwrap();
        let mut reordered = sibling.as_array().unwrap().clone();
        reordered.swap(2, 3);
        assert!(serde_json::from_value::<SiblingAllowedOperations>(json!(reordered)).is_err());
    }

    fn cancel_request() -> CancelDeviceBootstrapRequestBody {
        CancelDeviceBootstrapRequestBody {
            transaction_id: ProtocolOpaqueId::new("txn-fixture").unwrap(),
            mode: BootstrapMode::Founding,
            canonical_request_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            idempotency_key: IdempotencyKey::new("idem-fixture").unwrap(),
        }
    }

    #[test]
    fn cancel_request_and_outcome_digest_kat() {
        let request = cancel_request();
        assert_eq!(
            request.canonical_request_digest().unwrap().as_str(),
            "sha256:80cc83d8c2559a140eba5e2d9fac29c61b2bb9d2302e6264d160f7580c166e2f"
        );

        let mut outcome = CancelDeviceBootstrapOutcome::Cancelled {
            transaction_id: request.transaction_id.clone(),
            outcome_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };
        let digest = outcome.recompute_outcome_digest().unwrap();
        assert_eq!(
            digest.as_str(),
            "sha256:ebbe9c35f475eebe51d100722e07fab1d6b3884d5e718daece23d6b1f1340d05"
        );
        let CancelDeviceBootstrapOutcome::Cancelled { outcome_digest, .. } = &mut outcome else {
            unreachable!()
        };
        *outcome_digest = digest;
        outcome.validate_against(&request).unwrap();

        let other_request = CancelDeviceBootstrapRequestBody {
            transaction_id: ProtocolOpaqueId::new("different-transaction").unwrap(),
            ..request
        };
        assert!(outcome.validate_against(&other_request).is_err());
    }

    fn decision_fixture() -> serde_json::Value {
        arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json").unwrap()
    }

    fn decision_request_and_receipt() -> (
        DeviceBootstrapDecisionRequestBody,
        DeviceBootstrapDecisionReceipt,
        serde_json::Value,
    ) {
        let fixture = decision_fixture();
        let fence = &fixture["decision_fence"];
        let request = serde_json::from_value(fence["request"].clone()).unwrap();
        let mut receipt = fence["receipt_core"].clone();
        let object = receipt.as_object_mut().unwrap();
        object.insert(
            "receipt_digest".to_owned(),
            serde_json::Value::String(
                fence["expected_receipt_digest"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
        );
        object.insert("proof".to_owned(), fence["proof"].clone());
        let receipt = serde_json::from_value(receipt).unwrap();
        (request, receipt, fixture)
    }

    #[test]
    fn device_bootstrap_decision_fixture_kat_and_proof_binding() {
        let (request, receipt, fixture) = decision_request_and_receipt();
        let fence = &fixture["decision_fence"];

        assert_eq!(
            request
                .recompute_decision_request_digest()
                .unwrap()
                .as_str(),
            fence["expected_request_digest"].as_str().unwrap()
        );
        assert_eq!(request.preimage().finalize().unwrap(), request);
        request.validate().unwrap();
        assert_eq!(
            receipt.recompute_receipt_digest().unwrap().as_str(),
            fence["expected_receipt_digest"].as_str().unwrap()
        );
        assert_eq!(
            std::str::from_utf8(&receipt.proof_binding_bytes().unwrap()).unwrap(),
            fence["proof_binding_canonical_utf8"].as_str().unwrap()
        );
        assert_eq!(
            receipt.preimage().finalize(receipt.proof.clone()).unwrap(),
            receipt
        );
        let mut verifier_called = false;
        receipt
            .validate_proof_with(|method, binding, jws| {
                verifier_called = true;
                assert_eq!(method, &receipt.proof.verification_method);
                assert_eq!(
                    std::str::from_utf8(binding).unwrap(),
                    fence["proof_binding_canonical_utf8"].as_str().unwrap()
                );
                assert_eq!(jws, receipt.proof.jws);
                Ok(())
            })
            .unwrap();
        assert!(verifier_called);
        receipt.validate_against(&request).unwrap();

        let outcome = DeviceBootstrapDecisionOutcome {
            transaction_id: request.transaction_id.clone(),
            decision: receipt.decision,
            receipt: receipt.clone(),
        };
        outcome.validate_against(&request).unwrap();
        let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
        let record = DeviceBootstrapDecisionRecord {
            account_authority_id: request.account_authority_id.clone(),
            transaction_id: request.transaction_id.clone(),
            decision: outcome.decision,
            binding_digest: request.decision_request_digest,
            canonical_outcome_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
                canonical_outcome,
            ))
            .unwrap(),
            receipt,
        };
        assert_eq!(record.decode_and_validate_outcome().unwrap(), outcome);
    }

    #[test]
    fn device_bootstrap_decision_rejects_digest_and_binding_tamper() {
        let (request, receipt, _) = decision_request_and_receipt();

        let mut bad_request = request.clone();
        bad_request.founding_event_ids.swap(0, 1);
        assert!(bad_request.validate().is_err());

        let mut bad_receipt = receipt.clone();
        bad_receipt.principal_id = Did::new("did:webvh:z6mktampered:example.test").unwrap();
        assert!(bad_receipt.validate().is_err());

        let mut bad_proof = receipt.clone();
        bad_proof.proof.audience = Some(Audience::Single(
            "did:webvh:z6mkstranger:example.test".to_owned(),
        ));
        assert!(bad_proof.validate().is_err());

        let accepted = DeviceBootstrapDecisionReceipt {
            decision: DeviceBootstrapDecision::Accepted,
            ..receipt
        };
        // Changing the decision without recomputing and re-signing the receipt
        // is rejected before the accepted race result can be trusted.
        assert!(accepted.validate_against(&request).is_err());
    }
}
