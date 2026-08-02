//! Capability event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantPayload {
    /// The one canonical v1 grant artifact. Flat subject/actions/resources
    /// payloads cannot carry issuer proofs or authority refs and are not v1.
    pub grant: CapabilityGrant,
    pub grant_id: GrantId,
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
/// `event-payload.schema.json#/$defs/capability_relinquish_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRelinquishPayload {
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
