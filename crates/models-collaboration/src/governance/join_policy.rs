//! Profile-private wire records for `ak.profile.candidate.join_policy.v1`.
//!
//! These DTOs are transported by the registered join-application operations.
//! They are deliberately not Event payloads and must never be inserted into
//! shared Realm history.

use arkret_canonical as canonical;
use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    DeviceId, DidCoreId, DidFullId, Error, EventId, GrantId, Hash, PayloadProof, ProofContextId,
    RealmId, Result, project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MEMBER_APPLICATION_CANDIDATE_KIND: &str = "member.application";
pub const MEMBER_APPLICATION_REVIEW_CANDIDATE_KIND: &str = "member.application.review";
pub const MEMBER_APPLICATION_CANCEL_CANDIDATE_KIND: &str = "member.application.cancel";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(untagged)]
pub enum JoinApplicationAnswerValue {
    String(String),
    Strings(Vec<String>),
    Boolean(bool),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationAnswer {
    pub question_id: String,
    pub value: JoinApplicationAnswerValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationEnvelopeRecipient {
    pub reviewer_actor_id: DidCoreId,
    pub device_id: DeviceId,
    pub recipient_hpke_kid: String,
    pub enc: String,
    pub wrapped_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationEncryptionEnvelope {
    pub scheme: String,
    pub ciphertext: String,
    pub recipients: Vec<JoinApplicationEnvelopeRecipient>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum JoinApplicationPrivateBody {
    ServerProtected {
        answers: Vec<JoinApplicationAnswer>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
        gate_proofs: Vec<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        applicant_note: Option<String>,
    },
    ReviewerEnvelope {
        encryption_envelope: JoinApplicationEncryptionEnvelope,
    },
}

impl JoinApplicationPrivateBody {
    pub fn canonical_digest(&self) -> Result<Hash> {
        canonical_hash(self)
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ServerProtected {
                answers,
                gate_proofs,
                applicant_note,
            } => {
                if answers.len() > 64 {
                    return protocol_error("join application answers exceed the 64-item limit");
                }
                if gate_proofs.len() > 16 {
                    return protocol_error("join application gate_proofs exceed the 16-item limit");
                }
                if applicant_note
                    .as_deref()
                    .is_some_and(|note| note.is_empty() || note.chars().count() > 2000)
                {
                    return protocol_error("join application applicant_note length is invalid");
                }
                for answer in answers {
                    if answer.question_id.is_empty() || answer.question_id.len() > 128 {
                        return protocol_error(
                            "join application answer question_id length is invalid",
                        );
                    }
                }
            }
            Self::ReviewerEnvelope {
                encryption_envelope,
            } => {
                if encryption_envelope.scheme != "ak.hpke_x25519_aead_chacha20poly1305.v1" {
                    return protocol_error("join application HPKE suite is unsupported");
                }
                if encryption_envelope.recipients.is_empty()
                    || encryption_envelope.recipients.len() > 64
                {
                    return protocol_error(
                        "join application envelope recipients must contain 1..=64 devices",
                    );
                }
            }
        }
        Ok(())
    }
}

pub fn join_application_revision_digest(
    answers: &[JoinApplicationAnswer],
    gate_proofs: &[Value],
    policy_version_digest: &Hash,
) -> Result<Hash> {
    canonical_hash(&serde_json::json!({
        "answers": answers,
        "gate_proofs": gate_proofs,
        "policy_version_digest": policy_version_digest,
    }))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationReceiptUnsigned {
    pub candidate_kind: String,
    pub realm_id: RealmId,
    pub applicant_actor_id: DidCoreId,
    pub knock_ref: EventId,
    pub policy_version_digest: Hash,
    pub application_revision_digest: Hash,
    pub private_body_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub submitted_at: DateTime<Utc>,
}

impl JoinApplicationReceiptUnsigned {
    pub fn canonical_digest(&self) -> Result<Hash> {
        canonical_hash(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationReceipt {
    pub candidate_kind: String,
    pub realm_id: RealmId,
    pub applicant_actor_id: DidCoreId,
    pub knock_ref: EventId,
    pub policy_version_digest: Hash,
    pub application_revision_digest: Hash,
    pub private_body_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub submitted_at: DateTime<Utc>,
    pub application_receipt_digest: Hash,
    pub proof: PayloadProof,
}

impl JoinApplicationReceipt {
    pub fn new(unsigned: JoinApplicationReceiptUnsigned, proof: PayloadProof) -> Result<Self> {
        let digest = unsigned.canonical_digest()?;
        let receipt = Self {
            candidate_kind: unsigned.candidate_kind,
            realm_id: unsigned.realm_id,
            applicant_actor_id: unsigned.applicant_actor_id,
            knock_ref: unsigned.knock_ref,
            policy_version_digest: unsigned.policy_version_digest,
            application_revision_digest: unsigned.application_revision_digest,
            private_body_digest: unsigned.private_body_digest,
            submitted_at: unsigned.submitted_at,
            application_receipt_digest: digest,
            proof,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn unsigned(&self) -> JoinApplicationReceiptUnsigned {
        JoinApplicationReceiptUnsigned {
            candidate_kind: self.candidate_kind.clone(),
            realm_id: self.realm_id.clone(),
            applicant_actor_id: self.applicant_actor_id.clone(),
            knock_ref: self.knock_ref.clone(),
            policy_version_digest: self.policy_version_digest.clone(),
            application_revision_digest: self.application_revision_digest.clone(),
            private_body_digest: self.private_body_digest.clone(),
            submitted_at: self.submitted_at,
        }
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.unsigned().canonical_digest()
    }

    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        validate_receipt_proof(
            &self.proof,
            &self.application_receipt_digest,
            &self.applicant_actor_id,
            self.submitted_at,
        )?;
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::JOIN_APPLICATION_RECEIPT_PROOF_V1,
            "receipt_digest": self.application_receipt_digest,
            "realm_id": self.realm_id,
            "actor_id": self.applicant_actor_id,
            "verification_method": self.proof.verification_method,
            "created_at": self.proof.created_at,
        }))
        .map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        if self.candidate_kind != MEMBER_APPLICATION_CANDIDATE_KIND {
            return protocol_error("join application candidate_kind is invalid");
        }
        let digest = self.canonical_digest()?;
        if digest != self.application_receipt_digest {
            return protocol_error("join application receipt digest mismatch");
        }
        validate_receipt_proof(
            &self.proof,
            &digest,
            &self.applicant_actor_id,
            self.submitted_at,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationSubmitRequestBody {
    pub receipt: JoinApplicationReceipt,
    pub private_body: JoinApplicationPrivateBody,
}

impl JoinApplicationSubmitRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.receipt.validate()?;
        self.private_body.validate()?;
        if self.private_body.canonical_digest()? != self.receipt.private_body_digest {
            return protocol_error("join application private_body digest mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JoinApplicationDecision {
    Accept,
    Reject,
    RequestChanges,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JoinApplicationReasonCode {
    Ok,
    IncompleteAnswers,
    PolicyViolation,
    ClaimInvalid,
    ChallengeFailed,
    Duplicate,
    TtlExpired,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationReviewerCapabilityProof {
    pub grant_id: GrantId,
    pub frontier_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationReviewReceiptUnsigned {
    pub candidate_kind: String,
    pub realm_id: RealmId,
    pub application_ref: Hash,
    pub application_revision_digest: Hash,
    pub reviewer_actor_id: DidCoreId,
    pub reviewer_principal_server_id: DidCoreId,
    pub decision: JoinApplicationDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<JoinApplicationReasonCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<Hash>,
    pub reviewer_capability_proof: JoinApplicationReviewerCapabilityProof,
    #[serde(with = "canonical_timestamp")]
    pub reviewed_at: DateTime<Utc>,
}

impl JoinApplicationReviewReceiptUnsigned {
    pub fn canonical_digest(&self) -> Result<Hash> {
        canonical_hash(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationReviewReceipt {
    pub candidate_kind: String,
    pub realm_id: RealmId,
    pub application_ref: Hash,
    pub application_revision_digest: Hash,
    pub reviewer_actor_id: DidCoreId,
    pub reviewer_principal_server_id: DidCoreId,
    pub decision: JoinApplicationDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<JoinApplicationReasonCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<Hash>,
    pub reviewer_capability_proof: JoinApplicationReviewerCapabilityProof,
    #[serde(with = "canonical_timestamp")]
    pub reviewed_at: DateTime<Utc>,
    pub review_receipt_digest: Hash,
    pub proof: PayloadProof,
}

impl JoinApplicationReviewReceipt {
    pub fn new(
        unsigned: JoinApplicationReviewReceiptUnsigned,
        proof: PayloadProof,
    ) -> Result<Self> {
        let digest = unsigned.canonical_digest()?;
        let receipt = Self {
            candidate_kind: unsigned.candidate_kind,
            realm_id: unsigned.realm_id,
            application_ref: unsigned.application_ref,
            application_revision_digest: unsigned.application_revision_digest,
            reviewer_actor_id: unsigned.reviewer_actor_id,
            reviewer_principal_server_id: unsigned.reviewer_principal_server_id,
            decision: unsigned.decision,
            reason_code: unsigned.reason_code,
            reason_text: unsigned.reason_text,
            evidence_refs: unsigned.evidence_refs,
            reviewer_capability_proof: unsigned.reviewer_capability_proof,
            reviewed_at: unsigned.reviewed_at,
            review_receipt_digest: digest,
            proof,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn unsigned(&self) -> JoinApplicationReviewReceiptUnsigned {
        JoinApplicationReviewReceiptUnsigned {
            candidate_kind: self.candidate_kind.clone(),
            realm_id: self.realm_id.clone(),
            application_ref: self.application_ref.clone(),
            application_revision_digest: self.application_revision_digest.clone(),
            reviewer_actor_id: self.reviewer_actor_id.clone(),
            reviewer_principal_server_id: self.reviewer_principal_server_id.clone(),
            decision: self.decision.clone(),
            reason_code: self.reason_code.clone(),
            reason_text: self.reason_text.clone(),
            evidence_refs: self.evidence_refs.clone(),
            reviewer_capability_proof: self.reviewer_capability_proof.clone(),
            reviewed_at: self.reviewed_at,
        }
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.unsigned().canonical_digest()
    }

    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        validate_receipt_proof(
            &self.proof,
            &self.review_receipt_digest,
            &self.reviewer_actor_id,
            self.reviewed_at,
        )?;
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::JOIN_APPLICATION_REVIEW_RECEIPT_PROOF_V1,
            "receipt_digest": self.review_receipt_digest,
            "realm_id": self.realm_id,
            "application_ref": self.application_ref,
            "application_revision_digest": self.application_revision_digest,
            "actor_id": self.reviewer_actor_id,
            "principal_server_id": self.reviewer_principal_server_id,
            "verification_method": self.proof.verification_method,
            "created_at": self.proof.created_at,
        }))
        .map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        if self.candidate_kind != MEMBER_APPLICATION_REVIEW_CANDIDATE_KIND {
            return protocol_error("join application review candidate_kind is invalid");
        }
        if matches!(
            self.decision,
            JoinApplicationDecision::Reject | JoinApplicationDecision::RequestChanges
        ) && self.reason_code.is_none()
        {
            return protocol_error("join application review reason_code is required");
        }
        if self
            .reason_text
            .as_deref()
            .is_some_and(|text| text.is_empty() || text.chars().count() > 1000)
        {
            return protocol_error("join application review reason_text length is invalid");
        }
        let digest = self.canonical_digest()?;
        if digest != self.review_receipt_digest {
            return protocol_error("join application review receipt digest mismatch");
        }
        validate_receipt_proof(
            &self.proof,
            &digest,
            &self.reviewer_actor_id,
            self.reviewed_at,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationReviewRequestBody {
    pub receipt: JoinApplicationReviewReceipt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationCancelReceiptUnsigned {
    pub candidate_kind: String,
    pub realm_id: RealmId,
    pub application_ref: Hash,
    pub cancelled_by: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub cancelled_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
}

impl JoinApplicationCancelReceiptUnsigned {
    pub fn canonical_digest(&self) -> Result<Hash> {
        canonical_hash(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationCancelReceipt {
    pub candidate_kind: String,
    pub realm_id: RealmId,
    pub application_ref: Hash,
    pub cancelled_by: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub cancelled_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    pub cancel_receipt_digest: Hash,
    pub proof: PayloadProof,
}

impl JoinApplicationCancelReceipt {
    pub fn new(
        unsigned: JoinApplicationCancelReceiptUnsigned,
        proof: PayloadProof,
    ) -> Result<Self> {
        let digest = unsigned.canonical_digest()?;
        let receipt = Self {
            candidate_kind: unsigned.candidate_kind,
            realm_id: unsigned.realm_id,
            application_ref: unsigned.application_ref,
            cancelled_by: unsigned.cancelled_by,
            cancelled_at: unsigned.cancelled_at,
            reason_text: unsigned.reason_text,
            cancel_receipt_digest: digest,
            proof,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn unsigned(&self) -> JoinApplicationCancelReceiptUnsigned {
        JoinApplicationCancelReceiptUnsigned {
            candidate_kind: self.candidate_kind.clone(),
            realm_id: self.realm_id.clone(),
            application_ref: self.application_ref.clone(),
            cancelled_by: self.cancelled_by.clone(),
            cancelled_at: self.cancelled_at,
            reason_text: self.reason_text.clone(),
        }
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.unsigned().canonical_digest()
    }

    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        validate_receipt_proof(
            &self.proof,
            &self.cancel_receipt_digest,
            &self.cancelled_by,
            self.cancelled_at,
        )?;
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::JOIN_APPLICATION_CANCEL_RECEIPT_PROOF_V1,
            "receipt_digest": self.cancel_receipt_digest,
            "realm_id": self.realm_id,
            "application_ref": self.application_ref,
            "actor_id": self.cancelled_by,
            "verification_method": self.proof.verification_method,
            "created_at": self.proof.created_at,
        }))
        .map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        if self.candidate_kind != MEMBER_APPLICATION_CANCEL_CANDIDATE_KIND {
            return protocol_error("join application cancel candidate_kind is invalid");
        }
        if self
            .reason_text
            .as_deref()
            .is_some_and(|text| text.is_empty() || text.chars().count() > 1000)
        {
            return protocol_error("join application cancel reason_text length is invalid");
        }
        let digest = self.canonical_digest()?;
        if digest != self.cancel_receipt_digest {
            return protocol_error("join application cancel receipt digest mismatch");
        }
        validate_receipt_proof(&self.proof, &digest, &self.cancelled_by, self.cancelled_at)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationCancelRequestBody {
    pub receipt: JoinApplicationCancelReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JoinApplicationStatus {
    AwaitingReview,
    ChangesRequested,
    Accepted,
    Rejected,
    Canceled,
    Expired,
    Consumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationMutationOutcome {
    pub realm_id: RealmId,
    pub application_ref: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<Hash>,
    pub status: JoinApplicationStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationEntry {
    pub application_ref: Hash,
    pub realm_id: RealmId,
    pub applicant_actor_id: DidCoreId,
    pub application_revision_digest: Hash,
    pub policy_version_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub submitted_at: DateTime<Utc>,
    pub status: JoinApplicationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_body: Option<JoinApplicationPrivateBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_review_ref: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationListOutcome {
    pub realm_id: RealmId,
    pub viewer_is_reviewer: bool,
    pub applications: Vec<JoinApplicationEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationGetOutcome {
    pub application: JoinApplicationEntry,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JoinApplicationAuditAction {
    Submitted,
    Read,
    Reviewed,
    Canceled,
    InviteConsumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationAuditEntry {
    pub action: JoinApplicationAuditAction,
    pub actor_id: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub occurred_at: DateTime<Utc>,
    pub receipt_ref: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JoinApplicationAuditOutcome {
    pub realm_id: RealmId,
    pub application_ref: Hash,
    pub entries: Vec<JoinApplicationAuditEntry>,
}

fn canonical_hash(value: &impl Serialize) -> Result<Hash> {
    Ok(Hash::new(canonical::sha256_digest(
        &canonical::canonical_json_bytes(value)?,
    ))?)
}

fn validate_receipt_proof(
    proof: &PayloadProof,
    digest: &Hash,
    actor: &DidCoreId,
    created_at: DateTime<Utc>,
) -> Result<()> {
    proof.validate_production()?;
    if proof.payload_digest != *digest {
        return protocol_error("join application proof payload_digest mismatch");
    }
    if proof.created_at != created_at {
        return protocol_error("join application proof created_at mismatch");
    }
    let controller = proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            Error::Protocol("join application proof signer is not a DID URL".to_owned())
        })?;
    let controller = DidFullId::new(controller.to_owned())?;
    if project_full_id_to_core_id(&controller)? != *actor {
        return protocol_error("join application proof signer does not match actor");
    }
    Ok(())
}

fn protocol_error<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(message.into()))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Audience, DidUrl};

    use super::*;

    fn proof(digest: Hash, actor: &DidCoreId, created_at: DateTime<Utc>) -> PayloadProof {
        let controller = match actor.as_str() {
            "ak:did_core:webvh:zexamplealice" => "did:webvh:zexamplealice:alice.example",
            other => panic!("missing full-DID fixture for {other}"),
        };
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new(format!("{controller}#device-key")).unwrap(),
            payload_digest: digest,
            created_at,
            domain: None,
            audience: None::<Audience>,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
        }
    }

    #[test]
    fn application_receipt_digest_and_binding_are_stable() {
        let actor = DidCoreId::new("ak:did_core:webvh:zexamplealice").unwrap();
        let created_at = DateTime::parse_from_rfc3339("2026-07-24T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let unsigned = JoinApplicationReceiptUnsigned {
            candidate_kind: MEMBER_APPLICATION_CANDIDATE_KIND.to_owned(),
            realm_id: RealmId::new(
                "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            )
            .unwrap(),
            applicant_actor_id: actor.clone(),
            knock_ref: EventId::new(
                "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            )
            .unwrap(),
            policy_version_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            application_revision_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            private_body_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            submitted_at: created_at,
        };
        let digest = unsigned.canonical_digest().unwrap();
        let receipt =
            JoinApplicationReceipt::new(unsigned, proof(digest.clone(), &actor, created_at))
                .unwrap();
        assert_eq!(receipt.canonical_digest().unwrap(), digest);
        let binding: Value =
            serde_json::from_slice(&receipt.canonical_proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(
            binding["context"],
            ProofContextId::JOIN_APPLICATION_RECEIPT_PROOF_V1
        );
        assert_eq!(binding["receipt_digest"], digest.as_str());
    }

    #[test]
    fn private_body_digest_is_bound_by_submit_request() {
        let body = JoinApplicationPrivateBody::ServerProtected {
            answers: vec![JoinApplicationAnswer {
                question_id: "q1".to_owned(),
                value: JoinApplicationAnswerValue::String("hello".to_owned()),
            }],
            gate_proofs: Vec::new(),
            applicant_note: None,
        };
        let actor = DidCoreId::new("ak:did_core:webvh:zexamplealice").unwrap();
        let created_at = DateTime::parse_from_rfc3339("2026-07-24T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let unsigned = JoinApplicationReceiptUnsigned {
            candidate_kind: MEMBER_APPLICATION_CANDIDATE_KIND.to_owned(),
            realm_id: RealmId::new(
                "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            )
            .unwrap(),
            applicant_actor_id: actor.clone(),
            knock_ref: EventId::new(
                "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            )
            .unwrap(),
            policy_version_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            application_revision_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            private_body_digest: body.canonical_digest().unwrap(),
            submitted_at: created_at,
        };
        let digest = unsigned.canonical_digest().unwrap();
        let request = JoinApplicationSubmitRequestBody {
            receipt: JoinApplicationReceipt::new(unsigned, proof(digest, &actor, created_at))
                .unwrap(),
            private_body: body,
        };
        request.validate().unwrap();
    }

    #[test]
    fn review_receipt_binds_exact_reviewer_authority_pair() {
        let actor = DidCoreId::new("ak:did_core:webvh:zexamplealice").unwrap();
        let principal_server_id = DidCoreId::new("ak:did_core:web:principal.example").unwrap();
        let created_at = DateTime::parse_from_rfc3339("2026-07-24T00:00:01.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let unsigned = JoinApplicationReviewReceiptUnsigned {
            candidate_kind: MEMBER_APPLICATION_REVIEW_CANDIDATE_KIND.to_owned(),
            realm_id: RealmId::new(
                "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            )
            .unwrap(),
            application_ref: Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
            application_revision_digest: Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
            reviewer_actor_id: actor.clone(),
            reviewer_principal_server_id: principal_server_id.clone(),
            decision: JoinApplicationDecision::Accept,
            reason_code: None,
            reason_text: None,
            evidence_refs: Vec::new(),
            reviewer_capability_proof: JoinApplicationReviewerCapabilityProof {
                grant_id: GrantId::new(
                    "ak:grant:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo".to_owned(),
                )
                .unwrap(),
                frontier_digest: Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap(),
            },
            reviewed_at: created_at,
        };
        let digest = unsigned.canonical_digest().unwrap();
        let receipt = JoinApplicationReviewReceipt::new(
            unsigned.clone(),
            proof(digest.clone(), &actor, created_at),
        )
        .unwrap();
        let binding: Value =
            serde_json::from_slice(&receipt.canonical_proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(binding["actor_id"], actor.as_str());
        assert_eq!(binding["principal_server_id"], principal_server_id.as_str());

        let mut another_authority = unsigned;
        another_authority.reviewer_principal_server_id =
            DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert_ne!(another_authority.canonical_digest().unwrap(), digest);

        let mut missing_pair = serde_json::to_value(receipt).unwrap();
        missing_pair
            .as_object_mut()
            .unwrap()
            .remove("reviewer_principal_server_id");
        assert!(serde_json::from_value::<JoinApplicationReviewReceipt>(missing_pair).is_err());
    }
}
