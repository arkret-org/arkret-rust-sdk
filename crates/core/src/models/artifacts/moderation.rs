//! Moderation schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json`.
pub type ModerationAppeal = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/actor_ref`.
pub type ActorRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/appeal_id`.
pub type AppealId = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/close_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosePayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub closer: Value,
    pub closed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_closed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/decision_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub reviewer: ActorRef,
    pub verdict: String,
    pub reason_text_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_decision_ref: Option<EventId>,
    pub decided_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/decision_ref`.
pub type DecisionRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/evidence_visibility`.
pub type EvidenceVisibility = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/review_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub reviewer: ActorRef,
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_ref: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/submit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitPayload {
    pub appeal_id: AppealId,
    pub realm_id: RealmId,
    pub decision_ref: DecisionRef,
    pub target_ref: TargetRef,
    pub appellant: Value,
    pub reason_text_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_visibility: Option<Value>,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/target_ref`.
pub type TargetRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-report.schema.json#/$defs/franking_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrankingProofSenderClaim {
    pub actor_id: Did,
    pub device_id: String,
    pub mls_group_id_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrankingProof {
    pub kind: String,
    pub franking_proof_id: String,
    pub realm_id: RealmId,
    pub event_id: EventRef,
    pub routing_metadata_digest: Value,
    pub ciphertext_digest: Hash,
    pub aad_digest: Hash,
    pub sender_claim: FrankingProofSenderClaim,
    pub received_by: Did,
    pub received_at: DateTime<Utc>,
    pub replay_nonce: String,
    pub signature: String,
}
