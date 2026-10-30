// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-invite-link.schema.json
// sha256=096c348e5ea0f673dffc01e14830d77d974073fc96702e7426206a27bf471311
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=dd0891cd81e0fc2caaf499fd178468a13da86ea101d8780b59ca3e5c661eeecd

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
    pub max_uses_per_link: u32,
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
    pub max_uses: u32,
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
    pub max_uses: u32,
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
    pub max_uses: u32,
    pub use_count: u32,
    pub status: RealmInviteLinkStatus,
    pub create_event_id: arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: chrono::DateTime<chrono::Utc>,
}
