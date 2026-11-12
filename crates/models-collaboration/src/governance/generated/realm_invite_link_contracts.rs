// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-invite-link.schema.json
// sha256=6d144a134c62df7c2942ffd42694f387d312b6f026e652b017af28389156a816
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/realm-join-intake.schema.json
// sha256=cb687e509069f1fbb51f994d67db65147340c90190894272b49b322641827f12
//
// Bindings: tools/closed-model-bindings.json
// sha256=bb8c3350621b1f35ac031f7e6919326951b3576cd3c52db20323ba3e6e740687

/// Counterpart: `realm-invite-link.schema.json#/$defs/proof/properties/signature_algorithm`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmInviteLinkProofAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/proof`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkProof {
    pub signature_algorithm: RealmInviteLinkProofAlgorithm,
    pub transcript_digest: arkret_wire::Hash,
    pub signature: String,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/limits`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkLimits {
    pub max_lifetime_seconds: u32,
    pub max_use_count_per_link: u32,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/lifecycle_value`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmInviteLinkLifecycle {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "revoked")]
    Revoked,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/status`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmInviteLinkStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "revoked")]
    Revoked,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "exhausted")]
    Exhausted,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/create_payload`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkCreatePayload {
    pub public_key: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub max_use_count: u32,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/revoke_payload`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkRevokePayload {
    pub realm_invite_link_id: arkret_wire::RealmInviteLinkId,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/accept_payload`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkAcceptPayload {
    pub realm_invite_link_id: arkret_wire::RealmInviteLinkId,
    pub subject_account_id: arkret_wire::AccountId,
    pub request_id: arkret_wire::RequestId,
    pub link_proof: RealmInviteLinkProof,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/definition_value`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkDefinitionValue {
    pub public_key: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub max_use_count: u32,
    pub create_event_id: arkret_wire::EventId,
    pub creator_actor_id: arkret_wire::ActorId,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/use_record`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkUseRecord {
    pub realm_invite_link_id: arkret_wire::RealmInviteLinkId,
    pub subject_account_id: arkret_wire::AccountId,
    pub accept_event_id: arkret_wire::EventId,
}

/// Counterpart: `realm-invite-link.schema.json#/$defs/view`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkView {
    pub realm_invite_link_id: arkret_wire::RealmInviteLinkId,
    pub realm_id: arkret_wire::RealmId,
    pub inviter_account_id: arkret_wire::AccountId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub max_use_count: u32,
    pub use_count: u32,
    pub status: RealmInviteLinkStatus,
    pub create_event_id: arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
}
