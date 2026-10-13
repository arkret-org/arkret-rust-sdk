//! Erasure receipt wire shapes (`erasure-receipt.schema.json#/properties/peer_receipts/items`,
//! `ak.audit.erasure_receipt`): subject/scope/outcome enums, per-peer
//! fanout acknowledgement records, and the canonical proof-input
//! digest rules shared by receipt issuers and verifiers.

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_wire::{
    AccountStatusRecordId, DidCoreId, DidUrl, Hash, PolicyId, ProtocolSignature, RealmId, Result,
    SchemaId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::events_payloads::event_wire::VerificationStub;

pub const ERASURE_RECEIPT_DIGEST_DOMAIN: &[u8] = b"ak.erasure-receipt.v1\n";
pub const ERASURE_RECEIPT_ACCEPTANCE_DOMAIN: &[u8] = b"ak.erasure-receipt-acceptance.v1\n";

/// Deterministic receipt id for one account-status record/storage-boundary execution.
/// Retries and crash recovery therefore address the same resource without a
/// second operation id namespace.
pub fn account_erasure_receipt_id(
    triggering_status_record_id: &AccountStatusRecordId,
    storage_boundary: ErasureStorageBoundary,
) -> String {
    let mut input = triggering_status_record_id.as_str().as_bytes().to_vec();
    input.push(0);
    input.extend_from_slice(
        serde_json::to_value(storage_boundary)
            .expect("erasure storage boundary serializes")
            .as_str()
            .expect("erasure storage boundary is a string")
            .as_bytes(),
    );
    let digest = Sha256::digest(input);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!("ak:receipt:{}", uuid::Uuid::from_bytes(bytes))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptPackage {
    pub receipt: ErasureReceipt,
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
        if self.receipt.retained_stub.is_some() {
            return Err(WireError::Protocol(
                "erasure receipt package forbids nested retained_stub".to_owned(),
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
    pub issuer_id: DidCoreId,
    pub receiver_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: ProtocolSignature,
}

impl ErasureReceiptAcceptance {
    pub fn signing_input_bytes(&self) -> Result<Vec<u8>> {
        let value = canonical::unsigned_value(self, &["proof"])?;
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
#[serde(deny_unknown_fields)]
pub struct ErasureSubject {
    pub kind: ErasureSubjectKind,
    pub subject_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
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

/// Cross-Station erasure-receipt fanout aggregate status tracked by
/// the issuing server (mirrors `erasure-receipt.schema.json#/properties/peer_receipts/items`
/// `fanout_status`; models/realm-and-space.md §2.6.2). Replaces the dropped point-dotted pseudo
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

/// Per-peer fanout acknowledgement status (mirrors
/// `erasure-receipt.schema.json#/properties/peer_receipts/items` `peer_receipts[].status`).
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasureReceipt {
    pub receipt_id: String,
    pub trigger: crate::events_payloads::event_wire::ErasureTrigger,
    pub schema: String,
    pub issuer_id: DidCoreId,
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
    /// Cross-Station erasure fanout aggregate status. Absent on
    /// receipts that do not drive fanout tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_status: Option<ErasureFanoutStatus>,
    /// Per-peer fanout acknowledgement records backing `fanout_status`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_receipts: Vec<ErasurePeerReceipt>,
}

impl ErasureReceipt {
    pub const SCHEMA: &'static str = SchemaId::ERASURE_RECEIPT_V1;

    pub fn validate_minimal(&self) -> Result<()> {
        let valid_id = self
            .receipt_id
            .strip_prefix("ak:receipt:")
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .is_some_and(|id| {
                id.get_version_num() == 7
                    && id.get_variant() == uuid::Variant::RFC4122
                    && self.receipt_id == format!("ak:receipt:{id}")
            });
        if !valid_id
            || self.subject.subject_ref.is_empty()
            || self.scope.target_refs.iter().any(String::is_empty)
            || self
                .scope
                .service_scope
                .as_ref()
                .is_some_and(String::is_empty)
            || self
                .erased_classes
                .iter()
                .enumerate()
                .any(|(index, class)| self.erased_classes[..index].contains(class))
        {
            return Err(WireError::Protocol(
                "erasure receipt violates its closed schema constraints".into(),
            ));
        }
        if self.schema != SchemaId::ERASURE_RECEIPT_V1 {
            return Err(WireError::Protocol(
                "erasure receipt schema mismatch".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "erasure receipt proofs must not be empty".to_owned(),
            ));
        }
        if matches!(self.outcome, ErasureOutcome::BlockedByLegalHold)
            && self.legal_hold_ref.is_none()
        {
            return Err(WireError::Protocol(
                "blocked erasure receipt requires legal_hold_ref".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical bytes signed by every receipt proof. The `proofs` array is
    /// excluded so proof payload digests cannot recursively depend on their
    /// own signatures.
    pub fn canonical_proof_input(&self) -> Result<Vec<u8>> {
        let value = canonical::unsigned_value(self, &["proofs"])?;
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
                return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "erasure_receipt_stub_digest_mismatch".to_owned(),
            ));
        }
        if retained_stub.stub_schema != SchemaId::ERASURE_VERIFICATION_STUB_V1
            || retained_stub.receipt_id != self.receipt_id
            || retained_stub.trigger != self.trigger
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
            return Err(WireError::Protocol(
                "erasure_receipt_stub_binding_mismatch".to_owned(),
            ));
        }
        self.validate_proof_payload_digests()?;
        Ok(())
    }

    /// Validate a receipt that carries its verification stub inline.
    pub fn validate_with_inline_retained_stub(&self) -> Result<()> {
        let retained_stub = self.retained_stub.as_ref().ok_or_else(|| {
            WireError::Protocol("erasure receipt retained_stub is required".to_owned())
        })?;
        self.validate_with_retained_stub(retained_stub)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> ErasureReceipt {
        let mut receipt = ErasureReceipt {
            receipt_id: format!("ak:receipt:{}", uuid::Uuid::now_v7()),
            trigger: crate::events_payloads::event_wire::ErasureTrigger::Event {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [3; 32],
                ),
            },
            schema: ErasureReceipt::SCHEMA.into(),
            issuer_id: DidCoreId::new("ak:did_core:web:issuer.example").unwrap(),
            subject: ErasureSubject {
                kind: ErasureSubjectKind::Principal,
                subject_ref: "ak:did_core:web:alice.example".into(),
            },
            scope: ErasureScope {
                storage_boundary: ErasureStorageBoundary::ServiceDefined,
                realm_id: None,
                target_refs: Vec::new(),
                retention_policy_id: None,
                service_scope: Some("schema verification".into()),
            },
            outcome: ErasureOutcome::PartiallyCompleted,
            erased_classes: Vec::new(),
            retained_stub_digest: Hash::new(arkret_canonical::sha256_digest(
                b"schema-only stub identity",
            ))
            .unwrap(),
            retained_stub: None,
            legal_hold_ref: None,
            completed_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
            issued_at: None,
            proofs: Vec::new(),
            fanout_status: None,
            peer_receipts: Vec::new(),
        };
        receipt.proofs.push(ErasureReceiptProof {
            verification_method: DidUrl::new("did:web:issuer.example#notary-key").unwrap(),
            payload_digest: receipt.canonical_payload_digest().unwrap(),
            signature: "schema test does not exercise signature acceptance".into(),
            extra: BTreeMap::new(),
        });
        receipt
    }

    #[test]
    fn receipt_subject_and_scope_preserve_closed_schema_boundaries() {
        let value = serde_json::to_value(receipt()).unwrap();
        assert!(serde_json::from_value::<ErasureReceipt>(value.clone()).is_ok());
        for path in [Vec::<&str>::new(), vec!["subject"], vec!["scope"]] {
            let mut corrupt = value.clone();
            let mut row = &mut corrupt;
            for field in path {
                row = &mut row[field];
            }
            row.as_object_mut()
                .unwrap()
                .insert("undocumented".into(), Value::Bool(true));
            assert!(serde_json::from_value::<ErasureReceipt>(corrupt).is_err());
        }
    }

    #[test]
    fn receipt_identity_and_erased_classes_follow_the_registered_schema() {
        let valid = receipt();
        valid.validate_minimal().unwrap();
        let mut invalid = valid.clone();
        invalid.receipt_id = "ak:receipt:01904100-0000-4000-8000-000000000001".into();
        assert!(invalid.validate_minimal().is_err());
        invalid = valid;
        invalid.erased_classes = vec![ErasedClass::BlobBytes, ErasedClass::BlobBytes];
        assert!(invalid.validate_minimal().is_err());
    }
}

include!("generated/erasure_contracts.rs");
