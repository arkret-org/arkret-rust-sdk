//! Erasure receipt wire shapes (`erasure-receipt.schema.json`,
//! `ak.audit.erasure_receipt`): subject/scope/outcome enums, per-peer
//! fanout acknowledgement records, and the canonical proof-input
//! digest rules shared by receipt issuers and verifiers.

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_wire::{
    DidCoreId, DidUrl, Error, Hash, PolicyId, ProtocolSignature, RealmId, Result, SchemaId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::event_wire::VerificationStub;

pub const ERASURE_RECEIPT_DIGEST_DOMAIN: &[u8] = b"ak.erasure-receipt.v1\n";
pub const ERASURE_RECEIPT_ACCEPTANCE_DOMAIN: &[u8] = b"ak.erasure-receipt-acceptance.v1\n";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptPackage {
    pub receipt: ErasureReceipt,
    pub receipt_digest: Hash,
    pub retained_stub: VerificationStub,
}

impl ErasureReceiptPackage {
    pub fn computed_receipt_digest(&self) -> Result<Hash> {
        let bytes = canonical::canonical_json_bytes(&self.receipt)?;
        let mut preimage = Vec::with_capacity(ERASURE_RECEIPT_DIGEST_DOMAIN.len() + bytes.len());
        preimage.extend_from_slice(ERASURE_RECEIPT_DIGEST_DOMAIN);
        preimage.extend_from_slice(&bytes);
        Ok(Hash::new(canonical::sha256_digest(&preimage))?)
    }

    pub fn validate_bindings(&self) -> Result<()> {
        self.receipt.validate_minimal()?;
        if self.computed_receipt_digest()? != self.receipt_digest {
            return Err(Error::Protocol(
                "erasure receipt digest mismatch".to_owned(),
            ));
        }
        self.receipt
            .validate_with_retained_stub(&self.retained_stub)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptSubmitRequestBody {
    pub package: ErasureReceiptPackage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureReceiptAcceptanceStatus {
    Accepted,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptAcceptance {
    pub status: ErasureReceiptAcceptanceStatus,
    pub receipt_id: String,
    pub receipt_digest: Hash,
    pub issuer_service_id: DidCoreId,
    pub receiver_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: ProtocolSignature,
}

impl ErasureReceiptAcceptance {
    pub fn signing_input_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                Error::Protocol("erasure receipt acceptance must be an object".to_owned())
            })?
            .remove("proof");
        let bytes = canonical::canonical_json_bytes(&value)?;
        let mut preimage =
            Vec::with_capacity(ERASURE_RECEIPT_ACCEPTANCE_DOMAIN.len() + bytes.len());
        preimage.extend_from_slice(ERASURE_RECEIPT_ACCEPTANCE_DOMAIN);
        preimage.extend_from_slice(&bytes);
        Ok(preimage)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureReceiptRejectionReason {
    ErasureReceiptAuthorityInvalid,
    ErasureReceiptProofInvalid,
    ErasureReceiptStubBindingMismatch,
    ErasureReceiptStubDigestMismatch,
    DuplicateConflict,
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptRejection {
    pub status: ErasureReceiptRejectionStatus,
    pub receipt_id: String,
    pub reason_code: ErasureReceiptRejectionReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureReceiptRejectionStatus {
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(untagged)]
pub enum ErasureReceiptSubmitOutcome {
    Accepted(ErasureReceiptAcceptance),
    Rejected(ErasureReceiptRejection),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptResource {
    pub package: ErasureReceiptPackage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureSubjectKind {
    Principal,
    Space,
    Event,
    Blob,
    Device,
    AccountPrivateState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureStorageBoundary {
    CanonicalLogMinimization,
    BlobStore,
    ProjectionStore,
    AccountPrivateStore,
    SearchIndex,
    PushRoutes,
    DeviceSecretStore,
    MediaDerivatives,
    ServiceDefined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureOutcome {
    Completed,
    PartiallyCompleted,
    BlockedByLegalHold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasedClass {
    CanonicalPayloadBytes,
    BlobBytes,
    ProjectionRows,
    AccountPrivateState,
    PushRoutes,
    DeviceSecrets,
    SearchIndexEntries,
    DerivedPlaintext,
    MediaDerivatives,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErasureSubject {
    pub kind: ErasureSubjectKind,
    pub subject_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErasureScope {
    pub storage_boundary: ErasureStorageBoundary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErasureReceiptProof {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    pub signature: String,
    #[serde(flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Object)))]
    pub extra: BTreeMap<String, Value>,
}

/// Cross-Principal-Server erasure-receipt fanout aggregate status tracked by
/// the issuing server (mirrors `erasure-receipt.schema.json` `fanout_status`;
/// models/realm-and-space.md §2.6.2). Replaces the dropped point-dotted pseudo
/// kind `ak.audit.erasure_receipt.fanout_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureFanoutStatus {
    /// Peers still within `erasure_propagation_window_ms` and not all
    /// acknowledged.
    Pending,
    /// Every peer that ever held this Realm's content returned a receipt.
    Complete,
    /// At least one peer failed to acknowledge within
    /// `erasure_propagation_window_ms`. The issuing server MUST surface this
    /// to audit/UI and MUST NOT silently swallow it.
    Incomplete,
}

/// Per-peer fanout acknowledgement status (mirrors `erasure-receipt.schema.json`
/// `peer_receipts[].status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasurePeerStatus {
    /// Awaiting this peer's feedback receipt.
    Pending,
    /// Peer returned a receipt (regardless of its outcome).
    Acknowledged,
    /// Peer reported a non-completed feedback outcome
    /// (`partially_completed` / `blocked_by_legal_hold`).
    Failed,
    /// No feedback within `erasure_propagation_window_ms`.
    TimedOut,
}

/// One per-peer fanout acknowledgement record maintained by the issuing server
/// (mirrors `erasure-receipt.schema.json` `peer_receipts[]`). One entry per peer
/// Principal Server that ever held this Realm's content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErasurePeerReceipt {
    /// Peer Principal Server DID.
    pub peer: DidCoreId,
    pub status: ErasurePeerStatus,
    /// The peer's own feedback receipt id, when received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub acknowledged_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErasureReceipt {
    pub receipt_id: String,
    pub schema: String,
    pub issuer: DidCoreId,
    pub subject: ErasureSubject,
    pub scope: ErasureScope,
    pub outcome: ErasureOutcome,
    pub erased_classes: Vec<ErasedClass>,
    pub retained_stub_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_stub: Option<VerificationStub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub issued_at: Option<DateTime<Utc>>,
    pub proofs: Vec<ErasureReceiptProof>,
    /// Cross-Principal-Server erasure fanout aggregate status. Absent on
    /// receipts that do not drive fanout tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_status: Option<ErasureFanoutStatus>,
    /// Per-peer fanout acknowledgement records backing `fanout_status`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_receipts: Vec<ErasurePeerReceipt>,
}

impl ErasureReceipt {
    /// Reducer-input event kind that carries this receipt.
    pub const EVENT_KIND: &'static str = arkret_wire::event_kind_str::AUDIT_ERASURE_RECEIPT;
    pub const SCHEMA: &'static str = SchemaId::ERASURE_RECEIPT_V1;

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != SchemaId::ERASURE_RECEIPT_V1 {
            return Err(Error::Protocol(
                "erasure receipt schema mismatch".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "erasure receipt proofs must not be empty".to_owned(),
            ));
        }
        if matches!(self.outcome, ErasureOutcome::BlockedByLegalHold)
            && self.legal_hold_ref.is_none()
        {
            return Err(Error::Protocol(
                "blocked erasure receipt requires legal_hold_ref".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical bytes signed by every receipt proof. The `proofs` array is
    /// excluded so proof payload digests cannot recursively depend on their
    /// own signatures.
    pub fn canonical_proof_input(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            Error::Protocol("erasure receipt must serialize as an object".to_owned())
        })?;
        object.remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        let input = self.canonical_proof_input()?;
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn validate_proof_payload_digests(&self) -> Result<()> {
        self.validate_minimal()?;
        let expected = self.canonical_payload_digest()?;
        for proof in &self.proofs {
            if proof.payload_digest != expected {
                return Err(Error::Protocol(
                    "erasure receipt proof payload_digest mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Validate a received receipt against the retained verification stub.
    pub fn validate_with_retained_stub(&self, retained_stub: &VerificationStub) -> Result<()> {
        self.validate_minimal()?;
        let retained_stub_digest = Hash::new(canonical::canonical_sha256(retained_stub)?)?;
        if retained_stub_digest != self.retained_stub_digest {
            return Err(Error::Protocol(
                "erasure_receipt_stub_digest_mismatch".to_owned(),
            ));
        }
        if retained_stub.stub_schema != SchemaId::ERASURE_VERIFICATION_STUB_V1
            || retained_stub.receipt_id != self.receipt_id
            || retained_stub.completed_at != self.completed_at
            || retained_stub.subject.kind
                != serde_json::to_value(self.subject.kind)?
                    .as_str()
                    .unwrap_or_default()
            || retained_stub.subject.subject_ref != self.subject.subject_ref
            || retained_stub.scope.storage_boundary
                != serde_json::to_value(self.scope.storage_boundary)?
                    .as_str()
                    .unwrap_or_default()
            || retained_stub.scope.realm_id != self.scope.realm_id
            || retained_stub
                .scope
                .target_refs
                .as_deref()
                .unwrap_or_default()
                != self.scope.target_refs.as_slice()
            || retained_stub.scope.retention_policy_id != self.scope.retention_policy_id
            || retained_stub.scope.service_scope != self.scope.service_scope
            || retained_stub
                .legal_hold_ref
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .as_ref()
                .and_then(Value::as_str)
                != self.legal_hold_ref.as_deref()
        {
            return Err(Error::Protocol(
                "erasure_receipt_stub_binding_mismatch".to_owned(),
            ));
        }
        self.validate_proof_payload_digests()?;
        Ok(())
    }

    /// Validate a receipt that carries its verification stub inline.
    pub fn validate_with_inline_retained_stub(&self) -> Result<()> {
        let retained_stub = self.retained_stub.as_ref().ok_or_else(|| {
            Error::Protocol("erasure receipt retained_stub is required".to_owned())
        })?;
        self.validate_with_retained_stub(retained_stub)?;
        Ok(())
    }
}

#[cfg(test)]
mod erasure_receipt_tests {
    use super::*;
    use crate::events_payloads::event_wire::{VerificationStubScope, VerificationStubSubject};

    fn receipt(stub: &VerificationStub) -> ErasureReceipt {
        let mut receipt = ErasureReceipt {
            receipt_id: "ak:receipt:01970e58-0004-7000-8000-000000000010".to_owned(),
            schema: SchemaId::ERASURE_RECEIPT_V1.to_owned(),
            issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap(),
            subject: ErasureSubject {
                kind: ErasureSubjectKind::Event,
                subject_ref: "ak:event:Aao2sOuPY3tS2nZ7qnksKNP5Rf0xHN8c_r_NEIjv9hg3".to_owned(),
            },
            scope: ErasureScope {
                storage_boundary: ErasureStorageBoundary::CanonicalLogMinimization,
                realm_id: None,
                target_refs: Vec::new(),
                retention_policy_id: None,
                service_scope: None,
            },
            outcome: ErasureOutcome::Completed,
            erased_classes: vec![ErasedClass::CanonicalPayloadBytes],
            retained_stub_digest: Hash::new(canonical::canonical_sha256(stub).unwrap()).unwrap(),
            retained_stub: Some(stub.clone()),
            legal_hold_ref: None,
            completed_at: stub.completed_at,
            issued_at: None,
            proofs: vec![ErasureReceiptProof {
                verification_method: DidUrl::new("did:webvh:z6mkfixture:erasure.example#key-1")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                signature: "zplaceholder".to_owned(),
                extra: BTreeMap::new(),
            }],
            fanout_status: None,
            peer_receipts: Vec::new(),
        };
        receipt.proofs[0].payload_digest = receipt.canonical_payload_digest().unwrap();
        receipt
    }

    #[test]
    fn retained_stub_digest_mismatch_fails_closed() {
        let stub = VerificationStub {
            stub_schema: "ak.schema.erasure_verification_stub.v1".to_owned(),
            subject: VerificationStubSubject {
                kind: "event".to_owned(),
                subject_ref: "ak:event:Aao2sOuPY3tS2nZ7qnksKNP5Rf0xHN8c_r_NEIjv9hg3".to_owned(),
            },
            scope: VerificationStubScope {
                storage_boundary: "canonical_log_minimization".to_owned(),
                realm_id: None,
                target_refs: None,
                retention_policy_id: None,
                service_scope: None,
            },
            event_digest: None,
            retained_digests: None,
            seal_inclusion: None,
            redaction_authorization_ref: None,
            legal_hold_ref: None,
            receipt_id: "ak:receipt:01970e58-0004-7000-8000-000000000010".to_owned(),
            completed_at: Utc::now(),
        };
        let receipt = receipt(&stub);
        assert!(receipt.validate_with_retained_stub(&stub).is_ok());

        let mut tampered = stub;
        tampered.subject.subject_ref =
            "ak:event:AQ2tx4VdnpdE6WOuPQftPsY5gYkzM7Y7qadp81nkk9K4".to_owned();
        assert!(receipt.validate_with_retained_stub(&tampered).is_err());
    }

    #[test]
    fn self_consistent_stub_for_another_receipt_fails_closed() {
        let stub = VerificationStub {
            stub_schema: "ak.schema.erasure_verification_stub.v1".to_owned(),
            subject: VerificationStubSubject {
                kind: "event".to_owned(),
                subject_ref: "ak:event:Aao2sOuPY3tS2nZ7qnksKNP5Rf0xHN8c_r_NEIjv9hg3".to_owned(),
            },
            scope: VerificationStubScope {
                storage_boundary: "canonical_log_minimization".to_owned(),
                realm_id: None,
                target_refs: None,
                retention_policy_id: None,
                service_scope: None,
            },
            event_digest: None,
            retained_digests: None,
            seal_inclusion: None,
            redaction_authorization_ref: None,
            legal_hold_ref: None,
            receipt_id: "ak:receipt:01970e58-0004-7000-8000-000000000099".to_owned(),
            completed_at: Utc::now(),
        };
        let mut receipt = receipt(&stub);
        receipt.receipt_id = "ak:receipt:01970e58-0004-7000-8000-000000000010".to_owned();
        receipt.proofs[0].payload_digest = receipt.canonical_payload_digest().unwrap();

        let error = receipt
            .validate_with_retained_stub(&stub)
            .expect_err("digest-valid stub for another receipt must fail closed");
        assert!(error.to_string().contains("stub_binding_mismatch"));
    }
}
