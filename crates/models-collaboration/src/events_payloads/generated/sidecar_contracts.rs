// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=b42ab7eb500df851ff7e7c4ad9383751d8e8dd62ccae338246d81a59bf646259
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Bindings: tools/closed-model-bindings.json
// sha256=6fcfadb0c7e06a31e4528be5ebd9b087cda5b2394c144df9292de9b946c7d7a8

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
