// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Bindings: tools/closed-model-bindings.json
// sha256=c5c717d42040392233cf38e4f3236cfeed2d38c2b642d4cf765ba04cf371a3ee

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
