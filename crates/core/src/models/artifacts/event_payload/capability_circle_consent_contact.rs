//! Capability, circle, consent, contact, container-position, and content-kind payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<CapabilityGrant>,
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRevokePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<GrantId>,
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_seal_commit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleSealCommitPayload {
    pub circle_id: CircleId,
    pub sub_seal_head_digest: Hash,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleCreatePayload {
    pub object: Circle,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_member_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleMemberStatePayload {
    pub circle_id: CircleId,
    pub actor_id: Did,
    pub membership: MembershipState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_membership: Option<MembershipState>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CirclePatchPayload {
    pub circle_id: CircleId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/consent_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantPayload {
    pub consent_id: String,
    pub peer: Did,
    pub consent_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptedPayload {
    pub request_id: EventId,
    pub requester: Did,
    pub granted_scopes: ContactConsentScopes,
    pub consent_grant_refs: ContactEventRefs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded_scope_reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scope`.
pub type ContactConsentScope = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scopes`.
pub type ContactConsentScopes = Vec<ContactConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_event_refs`.
pub type ContactEventRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRejectedPayload {
    pub request_id: EventId,
    pub requester: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_requested_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestedPayload {
    pub request_id: EventId,
    pub target: Did,
    pub requested_scopes: ContactConsentScopes,
    pub requester_consent_refs: ContactEventRefs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_tombstoned_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactTombstonedPayload {
    pub peer: Did,
    pub revoke_scopes: ContactConsentScopes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_revoke_refs: Option<ContactEventRefs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_peer_revoke: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/container_position_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerPositionPayload {
    pub source_ref: ObjectRef,
    pub target_ref: ObjectRef,
    pub container_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
    pub rank: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/content_kind`.
pub type ContentKind = String;
