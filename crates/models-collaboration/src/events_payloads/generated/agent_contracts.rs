// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
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
// Input: schemas/typed-current-result.schema.json
// sha256=fec530d3711c83b9a3bf0c4bc9bb5bee2c350c552440b12a98c5e723f7740529
//
// Input: schemas/agent-provision.schema.json
// sha256=4d82da00b1a80c01ca4ce46938ae687ea60b1aff59c31f9e2211e496eed6070c
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

/// Counterpart: `event-payload.schema.json#/$defs/agent_action_approve_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_approve_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionApprovePayload {
    pub approval_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub draft_id: Option<String>,
    pub agent_id: DidCoreId,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub approved_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub draft_content_digest: Option<Hash>,
    pub approval_nonce: String,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_action_reject_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_reject_payload`.
/// The only rejection target is one action request; a draft's workflow
/// state is controller-encrypted Account Data, never a Station target.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionRejectPayload {
    pub rejection_id: String,
    pub request_id: String,
    pub agent_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<AuditReasonText>,
    #[serde(with = "canonical_timestamp")]
    pub rejected_at: DateTime<Utc>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_action_request_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_request_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionRequestPayload {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub draft_id: Option<String>,
    pub agent_id: DidCoreId,
    pub controller_account_id: AccountId,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub request_canonical_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_deactivate_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_deactivate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivatePayload {
    pub transition: String,
    pub previous_status: String,
    #[serde(with = "canonical_timestamp")]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<AuditReasonText>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_draft_propose_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_draft_propose_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftProposePayload {
    pub draft_id: String,
    pub agent_id: DidCoreId,
    pub controller_account_id: AccountId,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    pub content_handoff: AgentDraftContentHandoff,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub summary: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_key_scope`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`
/// (also `agent-operations.schema.json#/$defs/agent_key_scope` via `$ref`).
///
/// Scope object used as the required immutable provision ceiling and as a
/// narrower per-key ceiling. `actions` may include service operation ids and
/// content capability action tokens. Provisioning records it but grants no
/// Realm access; later key scopes, Realm grants, participation and sessions
/// must remain subsets, and provision constraints stay mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyScope {
    pub actions: Vec<String>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub resources: Vec<AgentKeyScopeResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub constraints: Vec<GrantConstraint>,
}

/// Counterpart:
/// `event-payload.schema.json#/$defs/agent_key_authorize_payload/properties/runtime_attestation`.
/// Closed runtime attestation carried by an Agent key authorize Event.
///
/// `event-payload.schema.json#/$defs/agent_key_authorize_payload/properties/runtime_attestation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyAuthorizePayloadRuntimeAttestation {
    pub kind: AgentKeyRuntimeAttestationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub software: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub attestation_ref: Option<BlobRef>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_key_authorize_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayload {
    pub agent_id: DidCoreId,
    pub key_id: NonEmptyString,
    pub verification_method: DidUrl,
    pub public_key: crate::governance::agent_artifacts::PublicKey,
    pub accountable_principal_id: DidCoreId,
    pub agent_key_scope: AgentKeyScope,
    pub audience: Vec<String>,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub approval_evidence: AgentKeyApprovalEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<AgentKeySupersession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub revocation_check_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_key_revoke_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyRevokePayload {
    pub agent_id: DidCoreId,
    pub key_id: NonEmptyString,
    pub revoked_by: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<AuditReasonText>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_pause_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_pause_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPausePayload {
    pub transition: String,
    pub previous_status: String,
    #[serde(with = "canonical_timestamp")]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<AuditReasonText>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_resume_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_resume_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResumePayload {
    pub transition: String,
    pub previous_status: String,
    #[serde(with = "canonical_timestamp")]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<AuditReasonText>,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/agent_provisioning_value`.
/// Value of the `agent_provisioning` typed current result
/// (`typed-current-result.schema.json#/$defs/agent_provisioning_value`): the
/// create-locked members a reader holding only the Agent DID needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisioningValue {
    pub controller_principal_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub requested_scope_digest: Hash,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/agent_pcr_genesis_declaration_value`.
/// Value of the `agent_pcr_genesis_declaration` typed current result
/// (`typed-current-result.schema.json#/$defs/agent_pcr_genesis_declaration_value`):
/// the index from a forward-declared Agent PCR id to its Agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPcrGenesisDeclarationValue {
    pub agent_id: DidCoreId,
}

/// Counterpart: `agent-provision.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/agent-provision.schema.json`.
///
/// The containing Event proof is the only signature. Receivers project the
/// provision, accountability and selector cells atomically from this payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionPayload {
    pub schema: AgentProvisionSchema,
    pub agent_id: DidCoreId,
    pub controller_principal_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub agent_slug: String,
    pub accountability_scope: AgentProvisionAccountabilityScope,
    pub requested_scope_digest: Hash,
    pub selector_visibility: HandleVisibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub selector_audience: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_action_target`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionTarget {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub object_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub account_data_key: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_key_approval_evidence`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyApprovalEvidence {
    pub kind: AgentKeyApprovalEvidenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub evidence_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub pairing_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub approved_by: Option<DidCoreId>,
}

/// Counterpart: `event-payload.schema.json#/$defs/agent_key_scope/properties/resources/items`.
/// Counterpart for the `agent_key_scope.resources[]` item shape in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyScopeResource {
    pub kind: AgentKeyScopeResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub resource_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub service_id: Option<DidCoreId>,
}
