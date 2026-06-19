//! List-reorder, message-redact/revise, MIMI-room-binding, and MLS payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/list_reorder_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReorderPayloadExpectedPosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReorderPayload {
    pub board_space_id: SpaceId,
    pub space_id: SpaceId,
    pub rank: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_position: Option<ListReorderPayloadExpectedPosition>,
}

// `membership_payload` now has a strong type:
// `models::operation_payloads::MembershipPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; carries the
// `MembershipPayloadState` enum and enforces the join/routable conditional
// required fields).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_metadata_fields`.
pub type MessageMetadataFields = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_redact_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRedactPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserve: Option<Vec<String>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_revise_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRevisePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_of: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mimi_room_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Value>,
    pub mimi_room_uri: String,
    pub binding_scope: MimiRoomBindingPayloadBindingScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_provider: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_provider_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_providers: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_component_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_commit_failed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCommitFailedPayload {
    pub mls_group_id: String,
    pub commit_ref: EventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<EventRef>,
    pub epoch: u64,
    pub failure_stage: Value,
    pub reporter_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_digest: Option<Hash>,
    pub failed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_epoch_range`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsEpochRange {
    pub first_epoch: u64,
    pub last_epoch: u64,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_genesis_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGenesisPayload {
    pub mls_group_id: String,
    pub effective_scope: Value,
    pub epoch: u64,
    pub creator_principal_id: Did,
    pub creator_device_id: String,
    pub cipher_suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_keypackage_refs: Option<Vec<ObjectRef>>,
    pub governance_binding: MlsGovernanceBinding,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_governance_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceBinding {
    pub binding_version: u64,
    pub encoding_profile: String,
    pub realm_id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<Value>,
    pub effective_scope: Value,
    pub mls_group_id: String,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub membership_frontier: Vec<EventRef>,
    pub policy_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discussion_metadata_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer_profile: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_keypackage_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsKeypackagePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_id: Option<String>,
    pub principal_id: Did,
    pub device_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Value,
    pub cipher_suites: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    pub state: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub device_signature: SignatureMaterial,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_proposal_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsProposalPayload {
    pub mls_group_id: String,
    pub base_epoch: u64,
    pub proposal_type: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_message_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_binding: Option<MlsGovernanceBinding>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_welcome_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomePayloadClaimRef {
    pub claim_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub capabilities_digest: Hash,
    pub ssk_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeClaimEnvelope {
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub intended_realm_id: RealmId,
    pub claim_id: String,
    pub requester_did: Did,
    pub ssk_generation: u64,
    pub nonce: String,
    pub welcome_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub signature: Signature2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeClaimEnvelopeSigningInput {
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub intended_realm_id: RealmId,
    pub claim_id: String,
    pub requester_did: Did,
    pub ssk_generation: u64,
    pub nonce: String,
    pub welcome_digest: Hash,
    pub created_at: DateTime<Utc>,
}

impl MlsWelcomeClaimEnvelope {
    pub fn signing_input(&self) -> MlsWelcomeClaimEnvelopeSigningInput {
        MlsWelcomeClaimEnvelopeSigningInput {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_did: self.requester_did.clone(),
            ssk_generation: self.ssk_generation,
            nonce: self.nonce.clone(),
            welcome_digest: self.welcome_digest.clone(),
            created_at: self.created_at,
        }
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(&self.signing_input())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomePayload {
    pub mls_group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<String>,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Value,
    pub claim_id: String,
    pub claim_ref: MlsWelcomePayloadClaimRef,
    pub claim_envelope: MlsWelcomeClaimEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_welcome_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_binding: Option<MlsGovernanceBinding>,
    pub expires_at: DateTime<Utc>,
}

pub fn validate_mls_welcome_claim_envelope(
    welcome: &MlsWelcomePayload,
    claim: &KeypackageClaimRecord,
    published: &MlsKeypackagePayload,
    intended_realm_id: &RealmId,
    requester_did: &Did,
    welcome_digest: &Hash,
    claim_nonce: &str,
    current_ssk_generation: u64,
) -> std::result::Result<(), &'static str> {
    let Some(welcome_keypackage_digest) = welcome.keypackage_digest.as_str() else {
        return Err(error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    };
    let Some(published_keypackage_digest) = published.keypackage_digest.as_str() else {
        return Err(error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    };
    if welcome.keypackage_ref != claim.keypackage_ref
        || welcome.claim_id != claim.claim_id
        || welcome.claim_ref.claim_id != claim.claim_id
        || welcome.claim_ref.keypackage_ref != claim.keypackage_ref
        || published.keypackage_ref != claim.keypackage_ref
        || welcome_keypackage_digest != claim.keypackage_digest.as_str()
        || welcome.claim_ref.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
        || published_keypackage_digest != claim.keypackage_digest.as_str()
        || welcome.claim_ref.capabilities_digest.as_str() != claim.capabilities_digest.as_str()
        || welcome.claim_ref.ssk_generation != claim.ssk_generation
        || welcome.claim_ref.ssk_generation != current_ssk_generation
    {
        return Err(error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }

    let envelope = &welcome.claim_envelope;
    if envelope.keypackage_ref != claim.keypackage_ref
        || envelope.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
        || envelope.intended_realm_id != *intended_realm_id
        || envelope.claim_id != claim.claim_id
        || envelope.requester_did != *requester_did
        || envelope.ssk_generation != claim.ssk_generation
        || envelope.ssk_generation != current_ssk_generation
        || envelope.nonce != claim_nonce
        || envelope.welcome_digest.as_str() != welcome_digest.as_str()
        || envelope.signature.kid.is_empty()
        || !envelope.signature.kid.starts_with(requester_did.as_str())
        || envelope.signature.sig.is_empty()
    {
        return Err(error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    if envelope.created_at > claim.expires_at || welcome.expires_at > claim.expires_at {
        return Err(error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}
