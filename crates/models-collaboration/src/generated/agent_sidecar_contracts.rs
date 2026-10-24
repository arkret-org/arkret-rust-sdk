// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-sidecar-view-state.schema.json
// sha256=6a0a647dfc477e52508f9b5cbc04a7c12a614f0b7bc5b0a5ad1282312a5e0698
//
// Input: schemas/agent-sidecar-exchange-projection.schema.json
// sha256=952900cbdbafc71f26a703a9cf423fa07fc67d9741e833df9ad949fce0db9508
//
// Input: schemas/agent-operations.schema.json
// sha256=57acbc5881e4ce66c0742968ae383fe5bda77fe0461abc395560e10fcdca637a
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/decimal-integers.schema.json
// sha256=7ea09c46f777e010c72a1fd069b7fbefc7d66924e7b3ad5a5961ce9914858987
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/current-state.schema.json
// sha256=7f7c4f2664ee79f2bda622abea13f8bbb119a2387d89cbe4eeb9af4f3c087428
//
// Input: schemas/agent-sidecar-exchange-control.schema.json
// sha256=0c1ecd7521ba0c11819ccefe10ce224c13cd432e2da463bf1cb2548132603b38
//
// Input: schemas/agent-sidecar-event-exchange-binding.schema.json
// sha256=6652f814405afb672ebc20ca69bdd58f47a3847606d5f5b890b3306b5949d947
//
// Bindings: tools/closed-model-bindings.json
// sha256=7ef2bac74ff32b9de78cac5bb9318e8c3d600fb7d2d320e1f3fd2fa3d5a5493c

/// Counterpart: `agent-sidecar-view-state.schema.json`.
/// Controller-private encrypted account-data plaintext for one hosted Sidecar
/// context. It changes only private presentation and never mutates a Strand,
/// Track, access, read state, notification, search index, or event ownership.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarViewState {
    pub schema: String,
    pub controller_account_id: AccountId,
    pub sidecar_id: SidecarId,
    pub context_ref: SidecarStrandContextRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub collapsed: Option<bool>,
    pub updated_hlc: Hlc,
    pub origin_device_id: DeviceId,
}

/// Counterpart: `agent-sidecar-view-state.schema.json#/$defs/strand_context_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarStrandContextRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

/// Counterpart: `agent-sidecar-exchange-projection.schema.json#/$defs/folded_checkpoint`.
/// Local cache coverage. `event_ids` are the canonical sorted maximal causal
/// heads of every contributing accepted exchange fact; `event_set_digest`
/// commits to the canonical sorted complete contributing Event-id set;
/// `max_hlc` is display/cache metadata and never proves causal dominance.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarFoldedCheckpoint {
    pub event_ids: Vec<EventId>,
    pub event_set_digest: Hash,
    pub max_hlc: Hlc,
}

/// Counterpart: `agent-sidecar-exchange-projection.schema.json#/$defs/source_track_ref`.
/// Track coordinate of the source-routed exchange. The same closed shape backs
/// agent-sidecar-exchange-projection.schema.json#/$defs/source_track_ref and
/// agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context/
/// properties/source_track_ref.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarSourceTrackRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub track_name: String,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_sidecar_mls_context`.
/// MLS coordinates of one Sidecar scope. The MLS scope is plaintext before its
/// own accepted `ak.mls.genesis` and irreversibly activates to standard
/// RFC 9420 afterwards.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarMlsContext {
    pub participant_authority_digest: Hash,
    pub authority_stream_head: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub genesis_event_ref: Option<String>,
    pub current_controller_device_ready: bool,
}

/// Counterpart: `agent-operations.schema.json#/$defs/pending_sidecar_access_reconciliation`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSidecarAccessReconciliation {
    pub agent_id: DidCoreId,
    pub provisioning_phase: SidecarAccessProvisioningPhase,
}

/// Counterpart:
/// `current-state.schema.json#/$defs/agent_sidecar_exchange_controls_value/properties/assertions/
/// items`. One accepted encrypted control carrier, identified by the Event's only
/// registered keyed-set write (`current-state.schema.json`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControlAssertion {
    pub tag_id: crate::exact_current_state::CanonicalEventDot,
    pub value: crate::events_payloads::sidecar::AgentSidecarExchangeControlPayload,
}

/// Counterpart: `agent-sidecar-exchange-control.schema.json`.
/// Closed plaintext encrypted inside the payload of
/// `ak.agent.sidecar.exchange.control`. Only the Sidecar controller may author
/// this durable private-Strand Event; it is the sole source of coordinator
/// reassignment and terminal exchange state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControl {
    pub schema: String,
    pub exchange_id: String,
    pub request_event_id: EventId,
    pub basis_event_ids: Vec<EventId>,
    pub action: AgentSidecarExchangeAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub response_event_ids: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub failure_reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_coordinator_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub coordinator_agent_id: Option<DidCoreId>,
}

/// Counterpart: `agent-sidecar-exchange-projection.schema.json`.
/// Disposable controller-device-local cache for one source-routed native
/// Sidecar exchange. Every member is a deterministic fold of accepted
/// Sidecar-scoped Events: this is not wire truth, not Account Data, never
/// merged across devices, and may always be deleted and rebuilt.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeProjection {
    pub schema: String,
    pub controller_account_id: AccountId,
    pub sidecar_id: SidecarId,
    pub exchange_id: String,
    pub source_track_ref: SidecarSourceTrackRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub source_event_id: Option<EventId>,
    pub source_hlc: Hlc,
    pub client_order_key: String,
    pub addressed_agent_ids: Vec<DidCoreId>,
    pub coordinator_agent_id: DidCoreId,
    pub coordinator_assignment_event_id: EventId,
    pub participating_agent_ids: Vec<DidCoreId>,
    pub private_request_event_id: EventId,
    pub user_facing_response_event_ids: Vec<EventId>,
    pub status: AgentSidecarExchangeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub failure_reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub terminal_event_id: Option<EventId>,
    pub folded_checkpoint: AgentSidecarFoldedCheckpoint,
}

/// Counterpart: `agent-sidecar-event-exchange-binding.schema.json`.
/// Closed typed binding tying one native-Sidecar-scoped Message event to one
/// source-routed exchange. It is legal only inside encrypted metadata plaintext
/// of an event whose `scope_ref.kind` is `sidecar`, and it is the only
/// normative way to declare an explicit user-facing response; invalid or absent
/// bindings are non-echo.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarEventExchangeBinding {
    pub schema: String,
    pub exchange_id: String,
    pub role: AgentSidecarExchangeRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub request_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub completes_exchange: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub coordinator_assignment_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub request_context: Option<AgentSidecarExchangeRequestContext>,
}

/// Counterpart: `agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context`.
/// Write-once exchange identity carried only on `role=request`. Any controller
/// device rebuilding the projection copies these values verbatim, so
/// cross-device bit-identity is anchored to the accepted request Event instead
/// of device-local state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeRequestContext {
    pub source_track_ref: SidecarSourceTrackRef,
    pub source_hlc: Hlc,
    pub client_order_key: String,
    pub addressed_agent_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub coordinator_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub source_checkpoint_anchor_id: Option<EventId>,
}
