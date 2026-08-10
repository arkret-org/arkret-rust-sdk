//! Current and historical portable Native Agent signer-evidence wire models.
//!
//! Current admission and historical verification are deliberately different
//! enum branches. Historical validity is carried by the destination-signed
//! Event admission receipt and is never reconstructed from a later snapshot.

use arkret_wire::{
    Base64UrlString, DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString, ProtocolOperationId,
    RealmId, RequestId, SchemaId, Seal, SealId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const AGENT_SIGNING_KEY_BINDING_CONTEXT: &str = "ak.agent-signing-key-binding-v1\n";
pub const AGENT_KEY_COMPONENT: &str = arkret_wire::CellFamilyId::AGENT_KEY_V1;
pub const AGENT_STATUS_COMPONENT: &str = arkret_wire::CellFamilyId::AGENT_STATUS_V1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSigningPublicKey {
    pub kty: NonEmptyString,
    pub algorithm: NonEmptyString,
    pub key: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentControllerProof {
    pub kind: NonEmptyString,
    pub verification_method: DidUrl,
    pub jws: NonEmptyString,
}

/// Digest-covered public core of an Agent signing-key binding.
///
/// The authorizing Event commits only this value. The Event identity and the
/// controller proof are appended after the Event has been finalized, so they
/// cannot create an Event-digest fixed-point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSigningKeyBindingCore {
    pub schema: NonEmptyString,
    pub agent_id: DidCoreId,
    pub agent_key_id: NonEmptyString,
    pub verification_method: DidUrl,
    pub public_key: AgentSigningPublicKey,
    pub public_key_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub controller_id: DidCoreId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSigningKeyBinding {
    #[serde(flatten)]
    pub core: AgentSigningKeyBindingCore,
    pub agent_key_authorize_event_id: EventId,
    pub controller_proof: AgentControllerProof,
}

// Serde does not support combining deny_unknown_fields with flatten.
// Decode through an explicit closed carrier so the public wire shape remains
// flat while unknown members are still rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSigningKeyBindingWire {
    schema: NonEmptyString,
    agent_id: DidCoreId,
    agent_key_id: NonEmptyString,
    verification_method: DidUrl,
    public_key: AgentSigningPublicKey,
    public_key_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
    controller_id: DidCoreId,
    agent_key_authorize_event_id: EventId,
    controller_proof: AgentControllerProof,
}

impl<'de> Deserialize<'de> for AgentSigningKeyBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgentSigningKeyBindingWire::deserialize(deserializer)?;
        Ok(Self {
            core: AgentSigningKeyBindingCore {
                schema: wire.schema,
                agent_id: wire.agent_id,
                agent_key_id: wire.agent_key_id,
                verification_method: wire.verification_method,
                public_key: wire.public_key,
                public_key_digest: wire.public_key_digest,
                issued_at: wire.issued_at,
                expires_at: wire.expires_at,
                controller_id: wire.controller_id,
            },
            agent_key_authorize_event_id: wire.agent_key_authorize_event_id,
            controller_proof: wire.controller_proof,
        })
    }
}

impl core::ops::Deref for AgentSigningKeyBinding {
    type Target = AgentSigningKeyBindingCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationStatus {
    Active,
    Revoked,
    Superseded,
    Expired,
    Conflicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationEvidence {
    pub status: AgentAuthorizationStatus,
    pub authorized_event_id: EventId,
    pub accepted_seal_id: SealId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_seal_id: Option<SealId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyCellEntry {
    pub tag: NonEmptyString,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationStateWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub authorization_event_id: EventId,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: Vec<AgentKeyCellEntry>,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationTransitionWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub authorization_event_id: EventId,
    pub transition_event_id: EventId,
    pub transition_key_id: NonEmptyString,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: Vec<AgentKeyCellEntry>,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentLifecycleStatus {
    Active,
    Paused,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentLifecycleProvenance {
    DelegatedPcrGenesis {
        realm_create_event_id: EventId,
        agent_provision_event_id: EventId,
    },
    PauseAccepted {
        pause_event_id: EventId,
        predecessor_active_event_id: EventId,
    },
    ResumeAccepted {
        resume_event_id: EventId,
        predecessor_pause_event_id: EventId,
    },
    DeactivateAccepted {
        deactivate_event_id: EventId,
        predecessor_status_event_id: EventId,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentLifecycleWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub status: AgentLifecycleStatus,
    pub provenance: AgentLifecycleProvenance,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accepted_status_event: Event,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: AgentLifecycleStatus,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentDetachedJws {
    pub kind: NonEmptyString,
    pub jws: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSnapshotLease {
    pub authority_kind: NonEmptyString,
    pub authority_service_id: DidCoreId,
    pub verification_method: DidUrl,
    pub snapshot_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthoritySnapshotCore {
    pub authority_service_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub frontier_seal_id: SealId,
    pub frontier_state_root: Hash,
    pub signing_key_binding: AgentSigningKeyBinding,
    pub authorization: AgentAuthorizationEvidence,
    pub key_state_witness: AgentAuthorizationStateWitness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_transition_witness: Option<AgentAuthorizationTransitionWitness>,
    pub agent_lifecycle_witness: AgentLifecycleWitness,
    pub seal_lineage: Vec<Seal>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthoritySnapshot {
    pub core: AgentAuthoritySnapshotCore,
    pub snapshot_digest: Hash,
    pub lease: AgentSnapshotLease,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountGateBasis {
    AccountBindingDefault {
        binding_version: u64,
        binding_frontier_digest: Hash,
    },
    AccountStatusEvent {
        status_event_id: EventId,
        status_event_digest: Hash,
        status_frontier_digest: Hash,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountEligibility {
    Active,
    Inactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestation {
    pub schema: NonEmptyString,
    pub principal_id: DidCoreId,
    pub eligibility: ControllerAccountEligibility,
    pub status: ControllerAccountStatus,
    pub basis: ControllerAccountGateBasis,
    pub basis_digest: Hash,
    pub authority_service_id: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

/// Authenticated S2S request used by a Native Agent PCR authority to obtain
/// the Account Authority-owned controller lifecycle gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueRequestBody {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub agent_authority_service_id: DidCoreId,
    pub agent_authority_service_resolution: crate::AuthenticatedServiceResolution,
}

/// Byte-stable result of controller gate attestation issuance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueOutcome {
    pub request_id: RequestId,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAdmissionEvidence {
    pub agent_authority_snapshot: AgentAuthoritySnapshot,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
    pub admission_evidence_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentCurrentObservation {
    pub operation_id: ProtocolOperationId,
    pub request_digest: Hash,
    pub verifier_id: DidCoreId,
    pub audience: DidCoreId,
    pub challenge: NonEmptyString,
    pub agent_snapshot_digest: Hash,
    pub agent_key_seal_id: SealId,
    pub agent_status_seal_id: SealId,
    pub controller_gate_attestation_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentEventAdmissionReceipt {
    pub schema: NonEmptyString,
    pub event_id: EventId,
    pub event_digest: Hash,
    pub realm_id: RealmId,
    pub event_admitted_seal_id: SealId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub agent_key_authorize_event_id: EventId,
    pub admission_evidence_digest: Hash,
    pub agent_snapshot_digest: Hash,
    pub agent_key_seal_id: SealId,
    pub agent_status_seal_id: SealId,
    pub controller_gate_attestation_digest: Hash,
    pub receiver_service_id: DidCoreId,
    pub proof: AgentDetachedJws,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentEvidenceOuterAttestation {
    pub domain: NonEmptyString,
    pub core_digest: Hash,
    pub source_service_id: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentEvidenceTransparency {
    pub profile: NonEmptyString,
    pub log_id: NonEmptyString,
    pub leaf_count: u64,
    pub tree_root: Hash,
    pub inclusion_proof: Vec<Hash>,
    pub consistency_proof: Vec<Hash>,
    pub witness_signatures: Vec<NonEmptyString>,
}

/// Closed `current_admission_evidence` branch used when a peer KeyPackage
/// response must carry target Native Agent authority without permitting the
/// historical-event branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentAgentSignerEvidence {
    pub schema: NonEmptyString,
    pub admission_evidence: AgentAdmissionEvidence,
    pub current_observation: AgentCurrentObservation,
    pub outer_attestation: AgentEvidenceOuterAttestation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<AgentEvidenceTransparency>,
}

impl From<CurrentAgentSignerEvidence> for AgentSignerEvidence {
    fn from(value: CurrentAgentSignerEvidence) -> Self {
        Self::CurrentAdmission {
            schema: value.schema,
            admission_evidence: value.admission_evidence,
            current_observation: value.current_observation,
            outer_attestation: value.outer_attestation,
            transparency: value.transparency,
        }
    }
}

impl From<&CurrentAgentSignerEvidence> for AgentSignerEvidence {
    fn from(value: &CurrentAgentSignerEvidence) -> Self {
        value.clone().into()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentSignerEvidence {
    CurrentAdmission {
        schema: NonEmptyString,
        admission_evidence: AgentAdmissionEvidence,
        current_observation: AgentCurrentObservation,
        outer_attestation: AgentEvidenceOuterAttestation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
    HistoricalEvent {
        schema: NonEmptyString,
        admission_evidence: AgentAdmissionEvidence,
        event_admission_receipt: AgentEventAdmissionReceipt,
        outer_attestation: AgentEvidenceOuterAttestation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentSignerEvidenceQuerySelector {
    CurrentAdmission {
        agent_id: DidCoreId,
        verification_method: DidUrl,
        operation_id: ProtocolOperationId,
        request_digest: Hash,
        verifier_id: DidCoreId,
        audience: DidCoreId,
        challenge: NonEmptyString,
    },
    HistoricalEvent {
        agent_id: DidCoreId,
        verification_method: DidUrl,
        event_id: EventId,
        event_digest: Hash,
        receiver_service_id: DidCoreId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerEvidenceQueryRequestBodyBody {
    pub realm_id: RealmId,
    pub queries: Vec<AgentSignerEvidenceQuerySelector>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentSignerEvidenceQueryFailureReason {
    AgentSignerEvidenceMissing,
    AgentSignerEvidenceStale,
    AgentAuthorizationInactive,
    AgentAuthorizationConflicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerEvidenceQueryFailure {
    pub selector: AgentSignerEvidenceQuerySelector,
    pub reason: AgentSignerEvidenceQueryFailureReason,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerEvidenceQueryOutcome {
    pub evidence: Vec<AgentSignerEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<AgentSignerEvidenceQueryFailure>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerEvidenceBundle {
    pub schema: SchemaId,
    pub evidence: Vec<AgentSignerEvidence>,
}

impl AgentSignerEvidenceBundle {
    pub const SCHEMA: SchemaId = SchemaId::AgentSignerEvidenceBundleV1;
}
