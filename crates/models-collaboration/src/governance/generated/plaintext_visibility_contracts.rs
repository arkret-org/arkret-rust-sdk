// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=b42ab7eb500df851ff7e7c4ad9383751d8e8dd62ccae338246d81a59bf646259
//
// Bindings: tools/closed-model-bindings.json
// sha256=14ce06e703487b8afdca6c0a5335ef346a965acc5f9443d89af8470d63109b0f

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
