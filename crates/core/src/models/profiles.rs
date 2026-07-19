//! Account-status projection and erasure receipts retained by
//! `arkret-core`.
//!
//! The strand-track profiles, Morph object, identity-link binding,
//! audit RYW receipts, moderation report, and federation actor
//! validation class migrated to `arkret-models-collaboration`
//! (re-exported below). The `AccountStatus` projection stays pending an
//! `arkret-state` placement decision; the erasure-receipt family stays
//! because it embeds the (not yet migrated) `VerificationStub` artifact
//! type.

pub use arkret_models_collaboration::governance::audit::{
    ABSOLUTE_HARD_CEILING_MS, AuditAssurance, AuditRywReceipt,
    E2EE_RELAXED_INCOMPATIBLE_COMPLIANCE_PROFILES, PROFILE_E2EE_RELAXED, ReceiptIndependence,
    RywActorFrontierEntry, RywFrontier, RywIssuerRole, is_e2ee_relaxed_compatible_with_compliance,
    validate_relaxed_window_ms,
};
pub use arkret_models_collaboration::objects::profiles::*;

use super::*;

/// Account lifecycle status (account-lifecycle.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::SoftLoggedOut => "soft_logged_out",
            AccountStatus::Locked => "locked",
            AccountStatus::Suspended => "suspended",
            AccountStatus::Deactivated => "deactivated",
            AccountStatus::ErasurePending => "erasure_pending",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "active" => Some(AccountStatus::Active),
            "soft_logged_out" => Some(AccountStatus::SoftLoggedOut),
            "locked" => Some(AccountStatus::Locked),
            "suspended" => Some(AccountStatus::Suspended),
            "deactivated" => Some(AccountStatus::Deactivated),
            "erasure_pending" => Some(AccountStatus::ErasurePending),
            _ => None,
        }
    }

    /// Strictness order from account-lifecycle.md §3.
    pub fn severity_rank(self) -> u8 {
        match self {
            AccountStatus::Active => 0,
            AccountStatus::SoftLoggedOut => 1,
            AccountStatus::Locked => 2,
            AccountStatus::Suspended => 3,
            AccountStatus::Deactivated => 4,
            AccountStatus::ErasurePending => 5,
        }
    }

    pub fn is_stricter_than(self, other: Self) -> bool {
        self.severity_rank() > other.severity_rank()
    }

    pub fn is_less_strict_than(self, other: Self) -> bool {
        self.severity_rank() < other.severity_rank()
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, AccountStatus::ErasurePending)
    }

    pub fn can_transition_to(self, to: Self) -> bool {
        use AccountStatus::{
            Active, Deactivated, ErasurePending, Locked, SoftLoggedOut, Suspended,
        };

        if self == to {
            return true;
        }

        match (self, to) {
            (Active, SoftLoggedOut | Locked | Suspended | Deactivated | ErasurePending)
            | (SoftLoggedOut, Active | Locked | Suspended | Deactivated | ErasurePending)
            | (Locked, Active | SoftLoggedOut | Suspended | Deactivated | ErasurePending)
            | (Suspended, Active | SoftLoggedOut | Locked | Deactivated | ErasurePending)
            | (Deactivated, ErasurePending) => true,
            (Deactivated, Active | SoftLoggedOut | Locked | Suspended)
            | (ErasurePending, Active | SoftLoggedOut | Locked | Suspended | Deactivated) => false,
            _ => false,
        }
    }

    pub fn validate_transition_to(
        self,
        to: Self,
        supersedes_status_event_visible: bool,
    ) -> std::result::Result<(), AccountStatusTransitionRejection> {
        if self == AccountStatus::ErasurePending && to != AccountStatus::ErasurePending {
            return Err(AccountStatusTransitionRejection::ErasurePendingIsTerminal);
        }

        if !self.can_transition_to(to) {
            return Err(AccountStatusTransitionRejection::TransitionInvalid);
        }

        if to.is_less_strict_than(self) && !supersedes_status_event_visible {
            return Err(AccountStatusTransitionRejection::TransitionInvalid);
        }

        Ok(())
    }

    /// Return whether new writes are allowed in this state.
    pub fn allows_writes(self) -> bool {
        matches!(self, AccountStatus::Active)
    }

    /// Return whether refresh / re-auth is the only allowed transition.
    pub fn requires_reauth(self) -> bool {
        matches!(self, AccountStatus::SoftLoggedOut | AccountStatus::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatusTransitionRejection {
    ErasurePendingIsTerminal,
    TransitionInvalid,
}

impl AccountStatusTransitionRejection {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::ErasurePendingIsTerminal => crate::ReasonCode::ERASURE_PENDING_IS_TERMINAL,
            Self::TransitionInvalid => crate::ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjectionCandidate {
    pub event_id: EventId,
    pub status: AccountStatus,
    pub effective_at: DateTime<Utc>,
    pub event_digest: Hash,
    pub supersedes_status_event_id: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjection<'a> {
    pub current: Option<&'a AccountStatusProjectionCandidate>,
    pub rejected: Vec<AccountStatusProjectionRejected>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjectionRejected {
    pub event_id: EventId,
    pub reason_code: &'static str,
}

pub fn project_account_status_heads<'a>(
    heads: &'a [AccountStatusProjectionCandidate],
    visible_status_event_ids: &BTreeSet<EventId>,
) -> AccountStatusProjection<'a> {
    let mut rejected = Vec::new();
    let mut suppressed = BTreeSet::new();

    for candidate in heads {
        if let Some(superseded_id) = candidate.supersedes_status_event_id.as_ref() {
            if !visible_status_event_ids.contains(superseded_id) {
                continue;
            }

            if let Some(superseded) = heads.iter().find(|head| &head.event_id == superseded_id)
                && candidate.status.is_less_strict_than(superseded.status)
            {
                match superseded
                    .status
                    .validate_transition_to(candidate.status, true)
                {
                    Ok(()) => {
                        suppressed.insert(superseded.event_id.clone());
                    }
                    Err(rejection) => rejected.push(AccountStatusProjectionRejected {
                        event_id: candidate.event_id.clone(),
                        reason_code: rejection.reason_code(),
                    }),
                }
            }
        }
    }

    let current = heads
        .iter()
        .filter(|candidate| !suppressed.contains(&candidate.event_id))
        .filter(|candidate| {
            !rejected
                .iter()
                .any(|rejection| rejection.event_id == candidate.event_id)
        })
        .max_by(|left, right| {
            left.status
                .severity_rank()
                .cmp(&right.status.severity_rank())
                .then_with(|| left.effective_at.cmp(&right.effective_at))
                .then_with(|| left.event_digest.as_str().cmp(right.event_digest.as_str()))
        });

    AccountStatusProjection { current, rejected }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureOutcome {
    Completed,
    PartiallyCompleted,
    BlockedByLegalHold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureSubject {
    pub kind: ErasureSubjectKind,
    pub subject_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureReceiptProof {
    pub verification_method: String,
    pub payload_digest: Hash,
    pub signature: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Cross-Principal-Server erasure-receipt fanout aggregate status tracked by
/// the issuing server (mirrors `erasure-receipt.schema.json` `fanout_status`;
/// models/realm-and-space.md §2.6.2). Replaces the dropped point-dotted pseudo
/// kind `ak.audit.erasure_receipt.fanout_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasurePeerReceipt {
    /// Peer Principal Server DID.
    pub peer: Did,
    pub status: ErasurePeerStatus,
    /// The peer's own feedback receipt id, when received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureReceipt {
    pub receipt_id: String,
    pub schema: String,
    pub issuer: Did,
    pub subject: ErasureSubject,
    pub scope: ErasureScope,
    pub outcome: ErasureOutcome,
    pub erased_classes: Vec<ErasedClass>,
    pub retained_stub_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub retained_stub: Option<VerificationStub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<String>,
    pub completed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub const SCHEMA: &'static str = "ak.schema.erasure_receipt.v1";
    pub const EVENT_KIND: &'static str = "ak.audit.erasure_receipt";

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
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

    fn receipt(stub: &VerificationStub) -> ErasureReceipt {
        let mut receipt = ErasureReceipt {
            receipt_id: "ak:receipt:01970e58-0004-7000-8000-000000000010".to_owned(),
            schema: ErasureReceipt::SCHEMA.to_owned(),
            issuer: Did::new("did:webvh:z6mkfixture:erasure.example".to_owned()).unwrap(),
            subject: ErasureSubject {
                kind: ErasureSubjectKind::Event,
                subject_ref: "ak:event:01970e58-0004-7000-8000-000000000004".to_owned(),
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
            completed_at: Utc::now(),
            issued_at: None,
            proofs: vec![ErasureReceiptProof {
                verification_method: "did:webvh:z6mkfixture:erasure.example#key-1".to_owned(),
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
                subject_ref: "ak:event:01970e58-0004-7000-8000-000000000004".to_owned(),
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
        tampered.subject.subject_ref = "ak:event:01970e58-0004-7000-8000-ffffffffffff".to_owned();
        assert!(receipt.validate_with_retained_stub(&tampered).is_err());
    }
}
