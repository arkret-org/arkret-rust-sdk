// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile-operations.schema.json
// sha256=6539611fb17fb638d9f0d32115ced737ded18dd929394583a796f44bc5bf6b80
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

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
