// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/principal-operations.schema.json
// sha256=d20daf5798bec9d03e5c36c21b63f77844c021e545c55d3d7f85ddb2377d2217
//
// Input: schemas/common-ids.schema.json
// sha256=dadc47194ca411baa38f3a7f44ae8115bec7cbcd98e68a2fffd389fdfc039713
//
// Input: schemas/agent-operations.schema.json
// sha256=9aa8e4ac8e3674122e0db9ede934930c6a5b515932794fb4e352562d8ba1cf26
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `principal-operations.schema.json#/$defs/participation_bits`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationBits {
    pub message_creation_allowed: bool,
    pub reaction_addition_allowed: bool,
    pub reaction_removal_allowed: bool,
    pub third_party_mention_delivery_allowed: bool,
    pub acting_on_behalf_allowed: bool,
}

/// Counterpart: `principal-operations.schema.json#/$defs/participation_scope`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ParticipationScope {
    #[serde(rename = "realm")]
    Realm { realm_id: arkret_wire::RealmId },
    #[serde(rename = "strand")]
    Strand {
        realm_id: arkret_wire::RealmId,
        strand_id: arkret_wire::StrandId,
    },
}
