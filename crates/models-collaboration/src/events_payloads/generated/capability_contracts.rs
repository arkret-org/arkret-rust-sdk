// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=6e557b3350ecfe34a8c4836bb00abf61dce039fa6a5fbbc58b07ec74dbaaba7f
//
// Input: schemas/capability-grant.schema.json
// sha256=7c70c7991062566c0299f79cb7a80e0e93bdd3a2e18861a28d065e121e668835
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

/// Counterpart: `event-payload.schema.json#/$defs/capability_revoke_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRevokePayload {
    pub grant_id: GrantId,
    pub expected_revision: CurrentRevision,
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
    pub expected_revision: CurrentRevision,
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
