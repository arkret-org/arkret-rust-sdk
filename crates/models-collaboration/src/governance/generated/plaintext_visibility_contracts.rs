// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

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
