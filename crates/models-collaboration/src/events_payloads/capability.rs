//! Capability event payloads.

use arkret_wire::DidCoreId;

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantCreateBody {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer: DidCoreId,
    pub subject: CapabilitySubject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_principal_server_id: Option<DidCoreId>,
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_action_registry_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    pub issuer_authority_refs: Vec<IssuerAuthorityRef>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantPayload {
    /// Genesis body omits the id. The reducer retypes the accepted EventId
    /// into a GrantId and inserts it into the projected CapabilityGrant.
    pub grant: CapabilityGrantCreateBody,
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
