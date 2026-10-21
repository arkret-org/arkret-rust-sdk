// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=a4c646467cc0e400d6cb24a119fe6791612dcf3a3a8d77fd355f9429600679bc
//
// Input: schemas/account-operations.schema.json
// sha256=b4be514e16b4a5154a4cb3bd56cf062f9ffb2cfc29ef25a26777a29f1e3d7644
//
// Bindings: tools/closed-model-bindings.json
// sha256=493cae310937341f71c829355ac772a12a878b5f7c2e20a5e915ba45fda6c2aa

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
