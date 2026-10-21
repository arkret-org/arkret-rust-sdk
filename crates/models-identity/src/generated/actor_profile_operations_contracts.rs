// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile-operations.schema.json
// sha256=6539611fb17fb638d9f0d32115ced737ded18dd929394583a796f44bc5bf6b80
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

/// Counterpart: `actor-profile-operations.schema.json#/$defs/account_status_projection`.
/// `actor-profile-operations.schema.json#/$defs/account_status_projection`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusProjection {
    pub account_id: AccountId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub status: ActorStatus,
    pub status_seq: u64,
    pub account_status_record_id: AccountStatusRecordId,
}
