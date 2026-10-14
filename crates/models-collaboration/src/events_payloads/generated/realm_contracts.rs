// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

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
/// reducer cell subject is `(organization_id, relationship)` — `statement_id`
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
