// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Bindings: tools/closed-model-bindings.json
// sha256=a78e63d1f3a48c87115a3e40e578dc4aeb5f619833613e5eb9fae1be319bff29

/// Counterpart: `event-payload.schema.json#/$defs/sidecar_create_payload`.
/// Controller-signed association with the source project.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarCreatePayload {
    pub source_realm_id: arkret_wire::RealmId,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_sidecar_exchange_control_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/agent_sidecar_exchange_control_payload`.
///
/// Outer payload of `ak.agent.sidecar.exchange.control`. `sidecar_id` and
/// `source_context_ref` route the Event inside a native Sidecar scope; the
/// plaintext inside `encrypted_payload` is
/// [`crate::agent_sidecar::AgentSidecarExchangeControl`], which only the
/// Sidecar controller can open.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSidecarExchangeControlPayload {
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub encrypted_payload: EncryptedEnvelope,
}

/// Counterpart: `event-payload.schema.json#/$defs/sidecar_context_attach_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/sidecar_context_attach_payload`.
///
/// Controller-signed versioned attachment of a source Realm context to an
/// existing native Sidecar. It creates no Strand and no Relation protocol
/// object. `version` 1 opens the chain and carries no predecessor; every later
/// version names the attach Event it supersedes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarContextAttachPayload {
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub predecessor_event_ref: Option<EventId>,
}
