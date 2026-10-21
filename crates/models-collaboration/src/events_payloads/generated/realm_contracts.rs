// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=51122d20a1426cc7e23a5e93ea307be964a90e3eaa9e5980d051ae67c2634887
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/account-operations.schema.json
// sha256=b4be514e16b4a5154a4cb3bd56cf062f9ffb2cfc29ef25a26777a29f1e3d7644
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

/// Counterpart: `event-payload.schema.json#/$defs/realm_owner_transfer_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/realm_owner_transfer_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferPayload {
    pub realm_id: RealmId,
    pub expected_state_digest: Hash,
    pub patch: RealmOwnerTransferPatch,
    pub successor_acceptance: SignatureMaterial,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCreatePayload {
    pub object: RealmGenesis,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_freeze_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_search_policy_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSearchPolicyPayload {
    pub enabled_profile_refs: Vec<String>,
    pub allowed_service_ids: Vec<DidCoreId>,
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub index_retention_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub revocation_behavior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub leakage_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub token_rotation_cadence_ms: Option<u64>,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_organization_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_organization_payload`.
///
/// Organization-side endorsement or revocation for a Realm relationship. The
/// reducer cell subject is `(organization_id, relationship)` â€” `statement_id`
/// is audit identity, not the cell subject. Field order mirrors the spec schema
/// `properties` ordering.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationPayload {
    pub statement_id: String,
    pub realm_id: RealmId,
    pub organization_id: DidCoreId,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub supersedes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub revokes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub realm_commit_ref: Option<RealmCommitId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub organization_policy_ref: Option<ObjectRef>,
    pub authorization: RealmOrganizationAuthorization,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_authority_reset_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/realm_authority_reset_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityResetPayload {
    pub realm_id: RealmId,
    pub expected_state_digest: Hash,
}

/// Counterpart:
/// `event-payload.schema.json#/$defs/realm_organization_payload/properties/authorization`.
/// Counterpart for the inner `authorization` object of
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_organization_payload`.
///
/// This is the organization-side authorization proof, independent of the
/// Realm-side `ak.realm.admin` authorization required to write the event into
/// Realm history.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationAuthorization {
    pub issuer_id: DidCoreId,
    pub issuer_role: RealmOrganizationIssuerRole,
    pub verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub delegation_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub executed_by: Option<ActorId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub signed_at: DateTime<Utc>,
    pub proof: SignatureMaterial,
}
