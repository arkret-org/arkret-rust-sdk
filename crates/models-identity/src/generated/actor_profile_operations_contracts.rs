// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile-operations.schema.json
// sha256=ea5683d043e1d8daa86a2c6e710e642ad219efbac44e79fbca16367a987f2da6
//
// Bindings: tools/closed-model-bindings.json
// sha256=f8598148149e81024ca07d8b02d6f7c48f1dc0672c100b2e8e4103790a652e46

/// Counterpart: `actor-profile-operations.schema.json#/$defs/account_status_projection`.
/// `actor-profile-operations.schema.json#/$defs/account_status_projection`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusProjection {
    pub account_id: AccountId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub status: ActorStatus,
    pub status_sequence: u64,
    pub account_status_record_id: AccountStatusRecordId,
}
