// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=ad0a6afcb615a15924cab022e1c499da750e70b2f9c1bcc0cc6b25a3de3e450e
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Bindings: tools/closed-model-bindings.json
// sha256=c118dc80d3979cf43e74a8ebd793a80ebb67f13c08db276c8d2c87279bae1b20

/// Counterpart: `event-payload.schema.json#/$defs/sidecar_create_payload`.
/// Counterpart for `event-payload.schema.json#/$defs/sidecar_create_payload`.
///
/// The payload is empty: `sidecar_id` is derived from the Event id, and
/// `realm_id`, `controller_account_id`, `state` and the timestamps are
/// reducer-derived from the accepted envelope. The Sidecar scope activates
/// standard RFC 9420 through its own accepted `ak.mls.genesis`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarCreatePayload {}

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
