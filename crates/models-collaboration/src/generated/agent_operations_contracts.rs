// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=61dfc936d4795906bf2eaa2ab39f5a0ad8833d024e53eddfdd2a3500fee90e8e
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/authenticated-signer-resolution-evidence.schema.json
// sha256=c73d83e394428b8904c887a7fa64fc18ea902a19ef0d974b7bbc3f6755c2f11c
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Bindings: tools/closed-model-bindings.json
// sha256=c5c717d42040392233cf38e4f3236cfeed2d38c2b642d4cf765ba04cf371a3ee

/// Counterpart: `agent-operations.schema.json#/$defs/agent_projection`.
/// Read projection of one Agent.
///
/// Field declaration order is byte-for-byte the properties order of
/// `agent-operations.schema.json#/$defs/agent_projection`. The definition is
/// closed (`additionalProperties: false`), so the projection carries no commit
/// coordinate: durable coordinates reach callers through the operation outcome
/// that accepted the Event, never through this read projection.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProjection {
    pub agent_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub lifecycle: AgentLifecycleState,
    pub readiness: AgentReadiness,
    pub presence: AgentPresence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_list`.
/// Field declaration order is byte-for-byte the properties order of
/// `agent-operations.schema.json#/$defs/agent_list`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentList {
    pub agents: Vec<AgentProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_view`.
/// Field declaration order is byte-for-byte the properties order of
/// `agent-operations.schema.json#/$defs/agent_view`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentView {
    pub agent: AgentProjection,
    #[serde(default)]
    pub grants: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub key_state: Option<KeyState>,
}

/// Counterpart: `agent-operations.schema.json#/$defs/key_state`.
/// Controller-private key, pairing-handle and authorization material for a
/// generic Agent view.
///
/// It deliberately carries no lifecycle, readiness, presence, runtime_state or
/// backup-readiness member: the three generic status axes are siblings on
/// `AgentProjection`, and the operation-local `runtime_state` diagnostic is
/// exposed only by the pairing poll.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyState {
    pub agent_id: DidCoreId,
    pub controller_account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub requested_scope: AgentKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub pairing_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub pairing_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub approval_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub pending_runtime_key_request: Option<AgentRuntimeApprovalControllerProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub approval_requested_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub authorized_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub authorized_public_key_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_authorizations: Vec<AgentKeyAuthorizationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub current_signer_evidence: Option<KeyStateCurrentSignerEvidence>,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_runtime_approval_controller_projection`.
/// Authenticated minimal frozen candidate projection delivered to the
/// controller. It carries neither the full possession proof nor the pairing
/// secret; the controller inspects the exact Agent, key fingerprint, scope,
/// expiry and supersedes in the Event before signing.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalControllerProjection {
    pub pairing_request_id: OpaqueLocalId,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: Hash,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_sidecar_view`.
/// Read projection of one hosted Sidecar at its stream's committed head.
///
/// `desired_agent_ids` and `effective_agent_ids` are derived, never authored:
/// the effective set is a subset of the desired set, and the controller is
/// represented by `sidecar.controller_account_id` rather than being duplicated
/// into either array.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarView {
    pub sidecar: AgentSidecar,
    pub desired_agent_ids: Vec<DidCoreId>,
    pub effective_agent_ids: Vec<DidCoreId>,
    pub mls_context: AgentSidecarMlsContext,
    pub access_readiness: AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<PendingSidecarAccessReconciliation>,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_sidecar_list`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarList {
    pub sidecars: Vec<AgentSidecarView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<NonEmptyString>,
}

/// Counterpart: `agent-operations.schema.json#/$defs/agent_lifecycle_state`.
/// Closed lifecycle operation response:
/// `agent-operations.schema.json#/$defs/agent_lifecycle_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleOutcome {
    pub status: AgentLifecycleState,
}

/// Counterpart: `agent-operations.schema.json#/$defs/key_state/properties/current_signer_evidence`.
/// Complete content-addressed Agent signer root for the currently authorized
/// runtime key. `signer_resolution_evidence_ref` is the registered
/// `ak:signer_evidence` form of `SHA-256(RFC8785-JCS(authenticated_signer_evidence))`
/// and equals the sibling `KeyState::signer_resolution_evidence_ref` byte for
/// byte.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyStateCurrentSignerEvidence {
    pub signer_resolution_evidence_ref: SignerEvidenceRef,
    pub authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
}
