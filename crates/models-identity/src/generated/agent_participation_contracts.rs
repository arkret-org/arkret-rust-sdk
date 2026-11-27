// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/principal-operations.schema.json
// sha256=51276d41d5ca6dde5257d686a51b678c57467c4377417653060861c8ec8fb854
//
// Input: schemas/common-ids.schema.json
// sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//
// Input: schemas/agent-operations.schema.json
// sha256=9aa8e4ac8e3674122e0db9ede934930c6a5b515932794fb4e352562d8ba1cf26
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

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
    #[serde(rename = "circle")]
    Circle {
        realm_id: arkret_wire::RealmId,
        circle_id: arkret_wire::CircleId,
    },
    #[serde(rename = "strand")]
    Strand {
        realm_id: arkret_wire::RealmId,
        strand_id: arkret_wire::StrandId,
    },
}
