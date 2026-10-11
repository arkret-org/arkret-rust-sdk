//! Current Agent lifecycle HTTP DTOs.
//!
//! All durable mutations carry producer Events for submission to the governing
//! authority. There is no prepare/reservation phase and no client-authored
//! acceptance or history checkpoint.

use arkret_models_identity::{AuthenticatedSignerResolutionEvidence, ResolutionCommitment};
use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, AuditReasonText, BlobRef, Did, DidCoreId, DidUrl, EventAdmissionSubmission, EventId,
    Hash, IdempotencyKey, NonEmptyString, OpaqueLocalId, ProtocolOpaqueId, ProtocolOperationId,
    RealmId, Result, SignerEvidenceRef, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::agent_scope::AgentKeyPairRequestBody;
use crate::agent_sidecar::{
    AgentSidecar, AgentSidecarAccessReadiness, AgentSidecarMlsContext,
    PendingSidecarAccessReconciliation,
};
use crate::events_payloads::agent::{AgentKeyAuthorizePayloadRuntimeAttestation, AgentKeyScope};
use crate::governance::agent_artifacts::{AgentKeyAuthorizationState, PublicKey};
use crate::string_marker;

/// Canonical `kind` of the controller approval binding object defined by
/// `key-management.md` §3.6.2.
pub const AGENT_KEY_PAIRING_REQUEST_BINDING_KIND: &str = "ak.agent.key_pairing_request_binding.v1";

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleState {
    #[default]
    Active,
    Paused,
    Deactivated,
}

impl AgentLifecycleState {
    /// The `agent_status` wire token, spelled exactly once here.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deactivated => "deactivated",
        }
    }

    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "deactivated" => Some(Self::Deactivated),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairOutcome {
    pub activation_state: AgentKeyPairActivationState,
    pub authorize_event_ref: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyPairActivationState {
    AwaitingSourceCommit,
    Active,
    Cancelled,
}

string_marker!(AgentProvisionPreparePhase, Prepare, "prepare");
string_marker!(AgentProvisionCommitPhase, Commit, "commit");
string_marker!(
    AgentProvisionAwaitingControllerEventStatus,
    AwaitingControllerEvent,
    "awaiting_controller_event"
);
string_marker!(
    AgentProvisionAwaitingPcrGenesisStatus,
    AwaitingPcrGenesis,
    "awaiting_pcr_genesis"
);
string_marker!(
    AgentProvisionAwaitingDidBindingStatus,
    AwaitingDidBinding,
    "awaiting_did_binding"
);
string_marker!(AgentProvisionCompleteStatus, Complete, "complete");

/// The controller first presents a PCR-independent accepted DID inception.
/// The governing Station allocates a handle but does not author a provision Event.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionPrepareRequestBody {
    pub phase: AgentProvisionPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub did: Did,
    pub slug: String,
    pub requested_scope: AgentKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
    pub controller_station_id: DidCoreId,
}

/// The controller freezes PCR genesis locally and authors the exact Event.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionCommitRequestBody {
    pub phase: AgentProvisionCommitPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub agent_id: DidCoreId,
    pub did: Did,
    pub principal_control_realm_id: RealmId,
    pub slug: String,
    pub requested_scope: AgentKeyScope,
    pub allocation_handle: ProtocolOpaqueId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub provision_event: EventAdmissionSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AgentProvisionRequestBody {
    Prepare(AgentProvisionPrepareRequestBody),
    Commit(AgentProvisionCommitRequestBody),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionAwaitingControllerEvent {
    pub status: AgentProvisionAwaitingControllerEventStatus,
    pub agent_id: DidCoreId,
    pub did: Did,
    pub initial_resolution: ResolutionCommitment,
    pub controller_realm_id: RealmId,
    pub allocation_handle: ProtocolOpaqueId,
    pub controller_authorization_ref: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionAwaitingPcrGenesis {
    pub status: AgentProvisionAwaitingPcrGenesisStatus,
    pub agent_id: DidCoreId,
    pub did: Did,
    pub initial_resolution: ResolutionCommitment,
    pub principal_control_realm_id: RealmId,
    pub allocation_handle: ProtocolOpaqueId,
    pub controller_authorization_ref: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionAwaitingDidBinding {
    pub status: AgentProvisionAwaitingDidBindingStatus,
    pub agent_id: DidCoreId,
    pub did: Did,
    pub initial_resolution: ResolutionCommitment,
    pub principal_control_realm_id: RealmId,
    pub allocation_handle: ProtocolOpaqueId,
    pub controller_authorization_ref: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionComplete {
    pub status: AgentProvisionCompleteStatus,
    pub agent_id: DidCoreId,
    pub did: Did,
    pub initial_resolution: ResolutionCommitment,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub pairing_request_id: OpaqueLocalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Closed four-stage transport result; only `Complete` exposes a pairing handle.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentProvisionOutcome {
    AwaitingControllerEvent(AgentProvisionAwaitingControllerEvent),
    AwaitingPcrGenesis(AgentProvisionAwaitingPcrGenesis),
    AwaitingDidBinding(AgentProvisionAwaitingDidBinding),
    Complete(AgentProvisionComplete),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingOutcome {
    pub agent_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub requested_scope_digest: Hash,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPauseRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventAdmissionSubmission,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResumeRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventAdmissionSubmission,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivateRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventAdmissionSubmission,
}

/// Closed lifecycle operation response:
/// `agent-operations.schema.json#/$defs/agent_lifecycle_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleOutcome {
    pub status: AgentLifecycleState,
}

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
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub lifecycle: AgentLifecycleState,
    pub readiness: AgentReadiness,
    pub presence: AgentPresence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentRuntimeState {
    PendingRuntimeKey,
    Ready,
    Replacing,
    PairingExpired,
}

impl AgentRuntimeState {
    /// The `agent_runtime_state` wire token, spelled exactly once here.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::PendingRuntimeKey => "pending_runtime_key",
            Self::Ready => "ready",
            Self::Replacing => "replacing",
            Self::PairingExpired => "pairing_expired",
        }
    }

    pub fn derive(has_active_authorization: bool, has_open_pairing_handle: bool) -> Self {
        match (has_active_authorization, has_open_pairing_handle) {
            (true, true) => Self::Replacing,
            (true, false) => Self::Ready,
            (false, true) => Self::PendingRuntimeKey,
            (false, false) => Self::PairingExpired,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentReadinessState {
    Ready,
    NotReady,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentReadinessBlocker {
    RuntimeKeyMissing,
    PairingOpen,
    RecoveryStale,
    SessionMissing,
    KeypackageEmpty,
    ReplyCapabilityMissing,
    MlsRejoinRequired,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReadiness {
    pub state: AgentReadinessState,
    pub blockers: Vec<AgentReadinessBlocker>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPresenceState {
    Online,
    Offline,
    Unknown,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPresence {
    pub state: AgentPresenceState,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub refresh_after: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingRuntimeIdentity {
    pub controller_account_id: AccountId,
    pub verification_method: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingBootstrap {
    pub arkret_base_url: String,
    pub service_id: DidCoreId,
    pub agent_id: DidCoreId,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub pairing_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<AgentPairingRuntimeIdentity>,
}

impl AgentPairingBootstrap {
    pub const SCHEMA: &'static str = arkret_wire::SchemaId::AGENT_PAIRING_BOOTSTRAP_V1;

    pub fn validated_runtime_identity(
        &self,
    ) -> std::result::Result<&AgentPairingRuntimeIdentity, String> {
        let identity = self.runtime_identity.as_ref().ok_or_else(|| {
            "Pairing service did not provide runtime identity; resolve a new pairing link"
                .to_owned()
        })?;
        identity
            .controller_account_id
            .validate()
            .map_err(|error| error.to_string())?;
        let (controller, _) = identity
            .verification_method
            .as_str()
            .rsplit_once('#')
            .filter(|(_, fragment)| !fragment.is_empty())
            .ok_or_else(|| {
                "Pairing runtime verification method must be a complete DID URL".to_owned()
            })?;
        let did = Did::new(controller.to_owned()).map_err(|error| error.to_string())?;
        if arkret_wire::project_did_to_core_id(&did).map_err(|error| error.to_string())?
            != self.agent_id
        {
            return Err(
                "Pairing runtime verification method does not belong to the paired Agent"
                    .to_owned(),
            );
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingResolveRequestBody {
    pub pairing_token: String,
}

/// Authenticated minimal frozen candidate projection delivered to the
/// controller. It carries neither the full possession proof nor the pairing
/// secret; the controller inspects the exact Agent, key fingerprint, scope,
/// expiry and supersedes in the Event before signing.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/agent_runtime_approval_controller_projection.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalControllerProjection {
    pub pairing_request_id: OpaqueLocalId,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: Hash,
}

/// Runtime receipt for submitting a stable pending key candidate.
/// agent-operations.schema.json#/$defs/agent_runtime_approval_outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalOutcome {
    pub approval_request_id: OpaqueLocalId,
    pub status: AgentLifecycleState,
}

/// Runtime-side status credential; all three members are required in the
/// body, never a URL path or query parameter.
/// agent-operations.schema.json#/$defs/agent_runtime_approval_status_request_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalStatusRequestBody {
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: NonEmptyString,
    pub agent_id: DidCoreId,
}

impl AgentRuntimeApprovalStatusRequestBody {
    pub fn validate(&self) -> Result<()> {
        let code = self.pairing_code.as_str();
        if code.len() != 8 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(WireError::Protocol(
                "Agent pairing code must contain exactly eight ASCII decimal digits".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Operation-local status; key activation requires the complete authenticated
/// signer root in addition to the provenance Event reference.
/// agent-operations.schema.json#/$defs/agent_runtime_approval_status_outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalStatusOutcome {
    pub lifecycle: AgentLifecycleState,
    pub runtime_state: AgentRuntimeState,
    pub readiness: AgentReadiness,
    pub presence: AgentPresence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_public_key_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_signer_evidence: Option<KeyStateCurrentSignerEvidence>,
}

impl AgentRuntimeApprovalStatusOutcome {
    pub fn validate_signer_evidence_delivery(&self) -> Result<()> {
        let all = [
            self.authorized_event_ref.is_some(),
            self.authorized_verification_method.is_some(),
            self.authorized_public_key_digest.is_some(),
            self.signer_resolution_evidence_ref.is_some(),
            self.current_signer_evidence.is_some(),
        ];
        if all.iter().any(|present| *present != all[0]) {
            return Err(WireError::Protocol(
                "Agent runtime approval status must carry the complete authorization and signer evidence closure".to_owned(),
            ));
        }
        if let (Some(reference), Some(evidence)) = (
            &self.signer_resolution_evidence_ref,
            &self.current_signer_evidence,
        ) {
            evidence.validate_against(reference)?;
        }
        Ok(())
    }
}

/// Complete content-addressed Agent signer root for the currently authorized
/// runtime key. `signer_resolution_evidence_ref` is the registered
/// `ak:signer_evidence` form of `SHA-256(RFC8785-JCS(authenticated_signer_evidence))`
/// and equals the sibling `KeyState::signer_resolution_evidence_ref` byte for
/// byte.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/key_state/properties/current_signer_evidence.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyStateCurrentSignerEvidence {
    pub signer_resolution_evidence_ref: SignerEvidenceRef,
    pub authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
}

impl KeyStateCurrentSignerEvidence {
    /// Recompute the content address and require it to equal both the carried
    /// member and the sibling `KeyState` reference.
    pub fn validate_against(&self, sibling_ref: &SignerEvidenceRef) -> Result<()> {
        let recomputed = self.authenticated_signer_evidence.signer_evidence_ref()?;
        if recomputed != self.signer_resolution_evidence_ref || &recomputed != sibling_ref {
            return Err(WireError::Protocol(
                "Agent signer evidence reference does not address its carried evidence".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Controller-private key, pairing-handle and authorization material for a
/// generic Agent view.
///
/// It deliberately carries no lifecycle, readiness, presence, runtime_state or
/// backup-readiness member: the three generic status axes are siblings on
/// `AgentProjection`, and the operation-local `runtime_state` diagnostic is
/// exposed only by the pairing poll.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/key_state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyState {
    pub agent_id: DidCoreId,
    pub controller_account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    /// Immutable global Agent ceiling captured by provisioning. It is not a
    /// grant: later key scopes, Realm grants and sessions may only narrow it.
    pub requested_scope: AgentKeyScope,
    /// Current unconsumed, unexpired pairing handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<OpaqueLocalId>,
    /// Present exactly when `pairing_request_id` and `pairing_expires_at` are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub pairing_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_runtime_key_request: Option<AgentRuntimeApprovalControllerProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub approval_requested_at: Option<DateTime<Utc>>,
    /// Provenance only; activation authority comes from the signer evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_verification_method: Option<DidUrl>,
    /// SHA-256 of the decoded 32-byte Ed25519 public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_public_key_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_authorizations: Vec<AgentKeyAuthorizationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_signer_evidence: Option<KeyStateCurrentSignerEvidence>,
}

impl KeyState {
    /// An active authorization delivers the complete activation closure; an
    /// Agent with no active authorization delivers none.
    pub fn validate_signer_evidence_delivery(&self) -> Result<()> {
        let has_reference = self.signer_resolution_evidence_ref.is_some();
        if has_reference != self.current_signer_evidence.is_some()
            || has_reference == self.active_authorizations.is_empty()
        {
            return Err(WireError::Protocol(
                "active Agent key state must carry its complete signer evidence and reference"
                    .to_owned(),
            ));
        }
        if let (Some(evidence_ref), Some(evidence)) = (
            &self.signer_resolution_evidence_ref,
            &self.current_signer_evidence,
        ) {
            evidence.validate_against(evidence_ref)?;
        }
        Ok(())
    }
}

/// Sole SDK helper for the controller approval digest defined by
/// `key-management.md` §3.6.2. It binds the frozen candidate and the approval
/// instance; refreshing the possession proof does not alter the approved
/// intent, and the object carries neither the pairing secret nor a proof
/// digest.
#[allow(clippy::too_many_arguments)]
pub fn agent_key_pairing_request_binding_digest(
    operation_id: &str,
    controller_principal_id: &DidCoreId,
    agent_id: &DidCoreId,
    pairing_request_id: &OpaqueLocalId,
    approval_request_id: &OpaqueLocalId,
    pairing_expires_at: DateTime<Utc>,
    audience: &DidCoreId,
    runtime_key_binding_digest: &Hash,
) -> Result<Hash> {
    let value = serde_json::json!({
        "kind": AGENT_KEY_PAIRING_REQUEST_BINDING_KIND,
        "operation_id": operation_id,
        "controller_principal_id": controller_principal_id,
        "agent_id": agent_id,
        "pairing_request_id": pairing_request_id,
        "approval_request_id": approval_request_id,
        // §3.6.2: the binding, the projection and the transcript all use the
        // byte-identical canonical UTC millisecond spelling of this instant.
        "expires_at": canonical::format_timestamp_canonical(pairing_expires_at),
        "audience_id": audience,
        "runtime_key_binding_digest": runtime_key_binding_digest,
    });
    Hash::new(canonical::canonical_sha256(&value)?)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

/// Field declaration order is byte-for-byte the properties order of
/// `agent-operations.schema.json#/$defs/agent_list`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentList {
    pub agents: Vec<AgentProjection>,
    /// Opaque continuation token in the `ak:cursor:` wire form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl AgentList {
    /// Wire prefix every `next_cursor` token carries
    /// (`agent-operations.schema.json#/$defs/agent_list`).
    pub const CURSOR_PREFIX: &'static str = "ak:cursor:";

    /// Reject a continuation token that is not the opaque `ak:cursor:` form the
    /// closed schema pattern admits.
    pub fn validate(&self) -> Result<()> {
        let Some(cursor) = self.next_cursor.as_deref() else {
            return Ok(());
        };
        let body = cursor.strip_prefix(Self::CURSOR_PREFIX).unwrap_or_default();
        if body.is_empty()
            || !body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(WireError::Protocol(
                "Agent list next_cursor is not an ak:cursor: continuation token".to_owned(),
            ));
        }
        Ok(())
    }
}

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
    pub key_state: Option<KeyState>,
}

/// Read projection of one hosted Sidecar at its stream's committed head.
///
/// `desired_agent_ids` and `effective_agent_ids` are derived, never authored:
/// the effective set is a subset of the desired set, and the controller is
/// represented by `sidecar.controller_account_id` rather than being duplicated
/// into either array.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/agent_sidecar_view.
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

impl AgentSidecarView {
    pub fn validate(&self) -> Result<()> {
        self.sidecar.validate_shape()?;
        self.mls_context.validate_shape()?;
        let desired: std::collections::BTreeSet<_> = self.desired_agent_ids.iter().collect();
        let effective: std::collections::BTreeSet<_> = self.effective_agent_ids.iter().collect();
        if desired.len() != self.desired_agent_ids.len()
            || effective.len() != self.effective_agent_ids.len()
            || !effective.is_subset(&desired)
        {
            return Err(WireError::Protocol(
                "Sidecar effective Agents must be a unique subset of desired Agents".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/agent_sidecar_list.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarList {
    pub sidecars: Vec<AgentSidecarView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<NonEmptyString>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_approval_status_requires_complete_authorization_closure() {
        let now = Utc::now();
        let mut outcome = AgentRuntimeApprovalStatusOutcome {
            lifecycle: AgentLifecycleState::Active,
            runtime_state: AgentRuntimeState::PairingExpired,
            readiness: AgentReadiness {
                state: AgentReadinessState::NotReady,
                blockers: vec![AgentReadinessBlocker::RuntimeKeyMissing],
            },
            presence: AgentPresence {
                state: AgentPresenceState::Unknown,
                expires_at: now,
                refresh_after: now,
            },
            approval_request_id: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            signer_resolution_evidence_ref: None,
            current_signer_evidence: None,
        };
        outcome.validate_signer_evidence_delivery().unwrap();
        outcome.authorized_event_ref = Some(EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x44; 32],
        ));
        assert!(outcome.validate_signer_evidence_delivery().is_err());
    }

    #[test]
    fn runtime_approval_status_request_requires_closed_pairing_secret() {
        let request = |pairing_code: &str| -> AgentRuntimeApprovalStatusRequestBody {
            serde_json::from_value(serde_json::json!({
                "pairing_request_id": "pairing_request:01964137-0000-7000-8000-000000000000",
                "pairing_code": pairing_code,
                "agent_id": "ak:did_core:webvh:z6mkagent"
            }))
            .unwrap()
        };
        request("01234567").validate().unwrap();
        request("99999999").validate().unwrap();
        for rejected in [
            "1234567",
            "123456789",
            "1234567a",
            "１２３４５６７８",
            "ABCDEFGHIJKLMNOPQRSTUV",
        ] {
            assert!(request(rejected).validate().is_err(), "{rejected}");
        }
    }

    fn runtime_key_binding_vector() -> Value {
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/agent-vectors-fixture.json")
                .unwrap();
        fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["vector_id"] == "ak.vector.agent.runtime_key_binding.v1")
            .cloned()
            .unwrap()
    }

    fn vector_pairing_request_binding_digest(vector: &Value, expires_at: &str) -> Result<Hash> {
        let input = &vector["pairing_request_binding_input"];
        let text = |key: &str| input[key].as_str().unwrap();
        agent_key_pairing_request_binding_digest(
            "ak.gate.account.command.pair_agent_key.v1",
            &DidCoreId::new(text("controller_principal_id")).unwrap(),
            &DidCoreId::new(text("agent_id")).unwrap(),
            &OpaqueLocalId::new(text("pairing_request_id")).unwrap(),
            &OpaqueLocalId::new(text("approval_request_id")).unwrap(),
            expires_at.parse().unwrap(),
            &DidCoreId::new(text("audience_id")).unwrap(),
            &Hash::new(vector["expected_binding_digest"].as_str().unwrap()).unwrap(),
        )
    }

    /// `spec/v1/artifacts/fixtures/agent-vectors-fixture.json`, vector
    /// `ak.vector.agent.runtime_key_binding.v1`.
    #[test]
    fn pairing_request_binding_digest_matches_the_spec_vector() {
        let vector = runtime_key_binding_vector();
        for expires_at in vector["pairing_request_binding_input"]["pairing_expires_at_inputs"]
            .as_array()
            .unwrap()
        {
            let digest =
                vector_pairing_request_binding_digest(&vector, expires_at.as_str().unwrap())
                    .unwrap();
            assert_eq!(
                digest.as_str(),
                vector["expected_pairing_request_binding_digest"]
                    .as_str()
                    .unwrap()
            );
        }
    }

    /// A sub-millisecond instant is floored, then spelled with exactly three
    /// fractional digits, so the binding never depends on the caller's
    /// timestamp precision (`key-management.md` §3.6.2).
    #[test]
    fn pairing_request_binding_digest_uses_the_canonical_millisecond_spelling() {
        let vector = runtime_key_binding_vector();
        let canonical = vector["canonical_pairing_expires_at"].as_str().unwrap();
        let expected = vector_pairing_request_binding_digest(&vector, canonical).unwrap();
        for instant in [
            "2026-07-17T13:50:07.734997Z",
            "2026-07-17T21:50:07.734+08:00",
        ] {
            assert_eq!(
                vector_pairing_request_binding_digest(&vector, instant).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn lifecycle_and_runtime_wire_tokens_round_trip() {
        for state in [
            AgentLifecycleState::Active,
            AgentLifecycleState::Paused,
            AgentLifecycleState::Deactivated,
        ] {
            assert_eq!(
                AgentLifecycleState::from_wire_str(state.as_wire_str()),
                Some(state)
            );
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                Value::String(state.as_wire_str().to_owned())
            );
        }
        for state in [
            AgentRuntimeState::PendingRuntimeKey,
            AgentRuntimeState::Ready,
            AgentRuntimeState::Replacing,
            AgentRuntimeState::PairingExpired,
        ] {
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                Value::String(state.as_wire_str().to_owned())
            );
        }
    }

    /// The generic Agent projections carry no lifecycle, readiness, presence or
    /// runtime-state member: those three axes are siblings on
    /// `AgentProjection` and the runtime-state diagnostic belongs to the
    /// pairing poll alone.
    #[test]
    fn key_state_carries_no_status_axis() {
        let value = serde_json::json!({
            "agent_id": "ak:did_core:webvh:z6mkagent",
            "controller_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkcontroller",
                "station_id": "ak:did_core:web:station.example"
            },
            "principal_control_realm_id": "ak:realm:01964137-0000-7000-8000-000000000001",
            "controller_authorization_ref": "did:webvh:z6mkagent:agent.example#controller-1",
            "requested_scope": { "actions": ["ak.self.committed_event.read.scan.v1"] },
            "runtime_state": "ready"
        });
        assert!(serde_json::from_value::<KeyState>(value).is_err());
    }

    fn agent_projection_value() -> Value {
        serde_json::json!({
            "agent_id": "ak:did_core:webvh:z6mkagent",
            "slug": "summary",
            "lifecycle": "active",
            "readiness": { "state": "ready", "blockers": [] },
            "presence": {
                "state": "unknown",
                "expires_at": "2026-07-18T00:15:00.000Z",
                "refresh_after": "2026-07-18T00:00:00.000Z"
            }
        })
    }

    /// `agent_list` names its array `agents`; the closed
    /// `agent-operations.schema.json#/$defs/agent_list` admits no other member.
    #[test]
    fn an_agent_list_names_its_array_agents() {
        let list: AgentList = serde_json::from_value(serde_json::json!({
            "agents": [agent_projection_value()],
            "has_more": false
        }))
        .expect("the spec member name deserializes");
        assert_eq!(list.agents.len(), 1);
        list.validate().unwrap();

        assert!(
            serde_json::from_value::<AgentList>(serde_json::json!({
                "agent_projections": [agent_projection_value()],
                "has_more": false
            }))
            .is_err(),
            "the pre-migration member name must not deserialize"
        );
    }

    /// The projection is a read view, not a commit coordinate carrier: the
    /// closed schema has no `provision_ref`; callers track their own accepted
    /// Event/RealmCommit coordinates from the governance submit path.
    #[test]
    fn an_agent_projection_carries_no_commit_coordinate() {
        serde_json::from_value::<AgentProjection>(agent_projection_value())
            .expect("the closed projection deserializes");
        let mut value = agent_projection_value();
        value["provision_ref"] = serde_json::json!({
            "event_id": "ak:event:sha256:AAAA",
            "commit_id": "ak:realm_commit:AAAA",
            "stream_ref": { "kind": "realm", "realm_id": "ak:realm:AAAA" },
            "stream_position": 1
        });
        assert!(serde_json::from_value::<AgentProjection>(value).is_err());
    }

    #[test]
    fn a_next_cursor_outside_the_ak_cursor_form_is_rejected() {
        let mut list: AgentList = serde_json::from_value(serde_json::json!({
            "agents": [agent_projection_value()],
            "next_cursor": "ak:cursor:aGVsbG8-_",
            "has_more": true
        }))
        .unwrap();
        list.validate().unwrap();

        for rejected in ["", "ak:cursor:", "opaque", "ak:cursor:has space"] {
            list.next_cursor = Some(rejected.to_owned());
            assert!(
                list.validate().is_err(),
                "{rejected:?} is not an ak:cursor: token"
            );
        }
    }
}
