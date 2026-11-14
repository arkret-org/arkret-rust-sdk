// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=110f3442df382c602cece0f2f5e0b4f2af3a0374f493911960b3cf6216f99a95
//
// Input: schemas/capability-grant.schema.json
// sha256=0e50a23ee38519d805799c4f511744f2c54ec4fb397640090c5c65e2cb66432c
//
// Input: schemas/common-ids.schema.json
// sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc73c01cf2bfb7cc6d4969c8f2f7faa6e44275c4a585ad81f3c94ac408daab8c

/// Counterpart: `event-payload.schema.json#/$defs/capability_revoke_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRevokePayload {
    pub grant_id: GrantId,
    pub expected_commit_id: RealmCommitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/capability_relinquish_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/capability_relinquish_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRelinquishPayload {
    pub grant_id: GrantId,
    pub expected_commit_id: RealmCommitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/capability_grant_payload/properties/grant`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantCreateBody {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub realm_id: Option<RealmId>,
    pub issuer_id: ActorId,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub issuer_authority_refs: Vec<IssuerAuthorityRef>,
}
