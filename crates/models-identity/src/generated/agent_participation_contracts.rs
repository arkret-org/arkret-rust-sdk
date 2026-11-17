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
// sha256=6e3c5ec888a579f338abc03d4aa7789d04efbd445f2e0620cce10243dca5bb0c
//
// Bindings: tools/closed-model-bindings.json
// sha256=6f2298d507cfeaf587b0a77d565af971535b7d029bf667f2e4b743448bcc016f

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
