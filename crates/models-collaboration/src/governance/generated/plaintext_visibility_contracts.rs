// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=deec42771ac61327cec2794982e07dbd345c0dc58de617248bcfc6331ba020ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c0dd616b73cb58355247f04ec903123c52cd61b038fe2b7df35029d0b6802c1

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
