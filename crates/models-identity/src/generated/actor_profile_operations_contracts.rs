// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile-operations.schema.json
// sha256=ea5683d043e1d8daa86a2c6e710e642ad219efbac44e79fbca16367a987f2da6
//
// Bindings: tools/closed-model-bindings.json
// sha256=8754dda4399255a8d93502ff99e0f2e245ea00988a5263e7f64cf21d1eada652

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
