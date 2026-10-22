// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=2b2d0ce9fa804d2ae258c0145cea673b09dfe7ee09e445fcfb07e6c9b23559d9
//
// Bindings: tools/closed-model-bindings.json
// sha256=c47c2cf65d6369093f5d7c6c29aaabfd64872c6277db759f4cd74b82db0a8236

/// Counterpart: `event-payload.schema.json#/$defs/plaintext_visible_services_payload`.
/// Strong type for `ak.realm.plaintext_visible_services` payloads
/// (`event-payload.schema.json#/$defs/plaintext_visible_services_payload`).
///
/// `{ services: [...] }`, top-level `additionalProperties:false`. Declares the
/// services allowed to receive plaintext / reversible-derived content outside
/// the E2EE boundary.
///
/// The event-payload resolver binds this type to the registered named def.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextVisibleServicesPayload {
    pub services: Vec<PlaintextVisibleService>,
}
