//! Current and historical portable Agent signer-evidence wire models.
//!
//! Current admission and historical verification are deliberately different
//! enum branches. Historical validity uses the original Station admission or
//! a distinct receiver receipt and never reconstructs authority from later state.

use arkret_wire::{
    Base64UrlString, DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString, RealmId, RequestId,
    SchemaId, Seal, SealId, SignerEvidenceRef,
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
    pub controller_principal_id: DidCoreId,
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
    controller_principal_id: DidCoreId,
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
                controller_principal_id: wire.controller_principal_id,
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
    DelegatedPcrGenesis { realm_create_event_id: EventId },
    PauseAccepted { pause_event_id: EventId },
    ResumeAccepted { resume_event_id: EventId },
    DeactivateAccepted { deactivate_event_id: EventId },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentLifecycleWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub provenance: AgentLifecycleProvenance,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accepted_status_event: Event,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: AgentLifecycleStatus,
    /// The cell's complete active head set, in `event-auth-state-resolution.md`
    /// §6.2.1 order.
    ///
    /// `ak.component.agent.status.v1` is an `fsm` and therefore a causal
    /// register (§9.3.1.5), so its `state_root` leaf hashes `{"heads":[…]}`
    /// rather than the settled value — a verifier cannot rebuild `leaf_digest`
    /// from `cell_value` alone. `cell_value` stays because it is the state the
    /// authorization check reads; it MUST be the state these heads settle to.
    pub cell_heads: Vec<AgentLifecycleHead>,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

/// One still-active transition write on an `fsm` cell, in its §6.2.1 wire form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentLifecycleHead {
    pub event_id: EventId,
    pub value: AgentLifecycleStatus,
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
pub struct AgentAuthorityStateLease {
    pub authority_kind: NonEmptyString,
    pub authority_id: DidCoreId,
    pub verification_method: DidUrl,
    pub state_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthorityState {
    pub authority_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub pcr_genesis_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub key_authorization_event: Event,
    pub frontier_seal_id: SealId,
    pub frontier_state_root: Hash,
    pub signing_key_binding: AgentSigningKeyBinding,
    pub authorization: AgentAuthorizationEvidence,
    pub key_state_witness: AgentAuthorizationStateWitness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_transition_witness: Option<AgentAuthorizationTransitionWitness>,
    pub agent_lifecycle_witness: AgentLifecycleWitness,
    pub seal_lineages: Vec<Seal>,
    pub accepted_delegated_notary_signers: Vec<arkret_wire::NotarySignerDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthorityStateEvidence {
    pub state: AgentAuthorityState,
    pub state_digest: Hash,
    pub lease: AgentAuthorityStateLease,
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
    pub authority_id: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

/// Authenticated S2S request used by an Agent PCR authority to obtain
/// the Account Authority-owned controller lifecycle gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueRequestBody {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub agent_authority_id: DidCoreId,
    pub agent_authority_resolution: crate::AuthenticatedServiceResolution,
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
    pub agent_authority_state_evidence: AgentAuthorityStateEvidence,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
    pub admission_evidence_digest: Hash,
}

impl AgentAdmissionEvidence {
    /// Earliest instant at which all independently signed sources apply.
    pub fn valid_from(&self) -> DateTime<Utc> {
        let state = &self.agent_authority_state_evidence;
        [
            state.lease.issued_at,
            self.controller_account_gate_attestation.issued_at,
            state.state.signing_key_binding.issued_at,
            state.state.authorization.accepted_at,
            state.state.authorization.not_before,
        ]
        .into_iter()
        .max()
        .expect("authority lease has an observation time")
    }
    /// A new wrapper, connection, or gate cannot extend a source's lifetime.
    pub fn expires_at(&self) -> DateTime<Utc> {
        let state = &self.agent_authority_state_evidence;
        [
            Some(state.lease.expires_at),
            Some(self.controller_account_gate_attestation.expires_at),
            state.state.signing_key_binding.expires_at,
            state.state.authorization.expires_at,
        ]
        .into_iter()
        .flatten()
        .min()
        .expect("authority lease has an expiry")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentEventAdmissionReceipt {
    pub schema: NonEmptyString,
    pub event_id: EventId,
    pub realm_id: RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub producer_accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub producer_signer_resolution_evidence_ref: SignerEvidenceRef,
    pub receiver_id: DidCoreId,
    pub proof: AgentDetachedJws,
}

impl AgentEventAdmissionReceipt {
    pub fn event_digest(&self) -> Hash {
        self.event_id.event_digest()
    }
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
/// response must carry target Agent authority without permitting the
/// historical-event branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename = "current_admission",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentAgentSignerEvidence {
    pub schema: NonEmptyString,
    pub admission_evidence: AgentAdmissionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<AgentEvidenceTransparency>,
}

impl From<CurrentAgentSignerEvidence> for AgentSignerEvidence {
    fn from(value: CurrentAgentSignerEvidence) -> Self {
        Self::CurrentAdmission {
            schema: value.schema,
            admission_evidence: value.admission_evidence,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
    HistoricalEvent {
        schema: NonEmptyString,
        admission_evidence: AgentAdmissionEvidence,
        event_admission: AgentEventAdmission,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
}

/// Proof of the exact durable acceptance, reusing the original Station proof
/// for the original same-Station acceptance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentEventAdmission {
    StationAdmission {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        accepted_event: Event,
    },
    ReceiverReceipt {
        receipt: AgentEventAdmissionReceipt,
    },
}

impl AgentEventAdmission {
    pub fn event_id(&self) -> &EventId {
        match self {
            Self::StationAdmission { accepted_event } => &accepted_event.event_id,
            Self::ReceiverReceipt { receipt } => &receipt.event_id,
        }
    }

    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::StationAdmission { accepted_event } => &accepted_event.realm_id,
            Self::ReceiverReceipt { receipt } => &receipt.realm_id,
        }
    }
    pub fn agent_id(&self) -> &DidCoreId {
        match self {
            Self::StationAdmission { accepted_event } => accepted_event
                .executed_by
                .as_ref()
                .unwrap_or(&accepted_event.actor_id)
                .signing_principal_id(),
            Self::ReceiverReceipt { receipt } => &receipt.agent_id,
        }
    }
    pub fn station_admission(&self) -> arkret_wire::Result<&arkret_wire::StationAdmissionProof> {
        let Self::StationAdmission { accepted_event } = self else {
            return Err(arkret_wire::WireError::Protocol(
                "acceptance is a receiver receipt".to_owned(),
            ));
        };
        accepted_event
            .proofs
            .iter()
            .find_map(arkret_wire::EventProof::as_station_admission)
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol("accepted Event omitted Station proof".to_owned())
            })
    }
    pub fn verification_method(&self) -> arkret_wire::Result<&DidUrl> {
        match self {
            Self::StationAdmission { .. } => {
                Ok(&self.station_admission()?.producer_verification_method)
            }
            Self::ReceiverReceipt { receipt } => Ok(&receipt.verification_method),
        }
    }
    pub fn producer_accepted_at(&self) -> arkret_wire::Result<DateTime<Utc>> {
        match self {
            Self::StationAdmission { .. } => Ok(self.station_admission()?.accepted_at),
            Self::ReceiverReceipt { receipt } => Ok(receipt.producer_accepted_at),
        }
    }
    pub fn receiver_accepted_at(&self) -> arkret_wire::Result<DateTime<Utc>> {
        match self {
            Self::StationAdmission { .. } => Ok(self.station_admission()?.accepted_at),
            Self::ReceiverReceipt { receipt } => Ok(receipt.accepted_at),
        }
    }
    pub fn producer_signer_resolution_evidence_ref(
        &self,
    ) -> arkret_wire::Result<&SignerEvidenceRef> {
        match self {
            Self::StationAdmission { .. } => self
                .station_admission()?
                .producer_signer_resolution_evidence_ref
                .as_ref()
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "accepted Agent Event omitted producer evidence ref".to_owned(),
                    )
                }),
            Self::ReceiverReceipt { receipt } => {
                Ok(&receipt.producer_signer_resolution_evidence_ref)
            }
        }
    }

    pub fn receiver_id(&self) -> arkret_wire::Result<DidCoreId> {
        match self {
            Self::StationAdmission { accepted_event } => {
                let admission = accepted_event
                    .proofs
                    .iter()
                    .find_map(|proof| match proof {
                        arkret_wire::EventProof::StationAdmission(value) => Some(value),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        arkret_wire::WireError::Protocol(
                            "historical Agent evidence has no Station admission".to_owned(),
                        )
                    })?;
                let did = admission
                    .verification_method
                    .as_str()
                    .split('#')
                    .next()
                    .unwrap_or_default();
                Ok(arkret_wire::project_did_to_core_id(
                    &arkret_wire::Did::new(did.to_owned())?,
                )?)
            }
            Self::ReceiverReceipt { receipt } => Ok(receipt.receiver_id.clone()),
        }
    }
}

impl AgentSignerEvidence {
    pub fn admission_evidence(&self) -> &AgentAdmissionEvidence {
        match self {
            Self::CurrentAdmission {
                admission_evidence, ..
            }
            | Self::HistoricalEvent {
                admission_evidence, ..
            } => admission_evidence,
        }
    }
    pub fn required_historical_signer_refs(&self) -> Vec<&SignerEvidenceRef> {
        let state = &self
            .admission_evidence()
            .agent_authority_state_evidence
            .state;
        [
            &state.pcr_genesis_event,
            &state.key_authorization_event,
            &state.agent_lifecycle_witness.accepted_status_event,
        ]
        .into_iter()
        .filter_map(|event| {
            event
                .proofs
                .iter()
                .find_map(arkret_wire::EventProof::as_station_admission)
        })
        .map(|proof| &proof.signer_resolution_evidence_ref)
        .collect()
    }
}

/// A signing key returned by the authenticated recipient's own Station.
/// The key bytes may be cached; a current authorization result may not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct StationSigningKey {
    pub actor: arkret_wire::ActorId,
    pub verification_method: DidUrl,
    pub public_key_b64u: Base64UrlString,
    pub authorization_ref: EventId,
}
impl StationSigningKey {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.actor.validate()?;
        let did = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or_else(|| {
                self_signer_error(
                    arkret_wire::ErrorCode::SchemaViolation,
                    "signing method requires a fragment",
                )
            })?;
        let did = arkret_wire::Did::new(did.to_owned())?;
        if arkret_wire::project_did_to_core_id(&did)? != *self.actor.signing_principal_id() {
            return Err(self_signer_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "signing method principal mismatch",
            ));
        }
        let value = self.public_key_b64u.as_str();
        if !matches!(self.actor, arkret_wire::ActorId::Account { .. })
            || value.len() != 43
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !b"AEIMQUYcgkosw048".contains(&value.as_bytes()[42])
        {
            return Err(self_signer_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "invalid Station signing key",
            ));
        }
        Ok(())
    }
}
pub const SELF_SIGNER_REQUEST_MAX_BYTES: usize = 64 * 1024;
pub const SELF_SIGNER_OUTCOME_MAX_BYTES: usize = 1024 * 1024;
pub const SELF_SIGNER_RESULT_MAX_BYTES: usize = 16 * 1024;
pub fn self_signer_error(code: arkret_wire::ErrorCode, message: &str) -> arkret_wire::WireError {
    arkret_wire::WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}
pub fn validate_self_signer_bytes<T: Serialize>(
    value: &T,
    limit: usize,
    request: bool,
) -> arkret_wire::Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > limit {
        return Err(self_signer_error(
            if request {
                arkret_wire::ErrorCode::PayloadTooLarge
            } else {
                arkret_wire::ErrorCode::LimitExceeded
            },
            "self signer canonical byte budget exceeded",
        ));
    }
    Ok(())
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
        actor: arkret_wire::ActorId,
        verification_method: DidUrl,
    },
    HistoricalEvent {
        actor: arkret_wire::ActorId,
        verification_method: DidUrl,
        event_id: EventId,
        receiver_id: DidCoreId,
    },
}
impl AgentSignerEvidenceQuerySelector {
    pub fn actor(&self) -> &arkret_wire::ActorId {
        match self {
            Self::CurrentAdmission { actor, .. } | Self::HistoricalEvent { actor, .. } => actor,
        }
    }
    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::CurrentAdmission {
                verification_method,
                ..
            }
            | Self::HistoricalEvent {
                verification_method,
                ..
            } => verification_method,
        }
    }
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.actor().validate()?;
        if !matches!(self.actor(), arkret_wire::ActorId::Account { .. }) {
            return Err(self_signer_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "Agent selector requires an Account actor",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerEvidenceQueryRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: arkret_wire::AccountId,
    pub queries: Vec<AgentSignerEvidenceQuerySelector>,
}
impl AgentSignerEvidenceQueryRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_REQUEST_MAX_BYTES, true)?;
        self.recipient_account_id.validate()?;
        if self.queries.is_empty() || self.queries.len() > 64 {
            return Err(self_signer_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "self query requires 1..=64 selectors",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for selector in &self.queries {
            selector.validate()?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(selector)?) {
                return Err(self_signer_error(
                    arkret_wire::ErrorCode::SchemaViolation,
                    "duplicate selector",
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerEvidenceResolvedStatus {
    Resolved,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerEvidenceUnavailableStatus {
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentSignerEvidenceQueryResult {
    CurrentResolved {
        selector: AgentSignerEvidenceQuerySelector,
        status: SignerEvidenceResolvedStatus,
        key: StationSigningKey,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        checked_at: DateTime<Utc>,
    },
    HistoricalResolved {
        selector: AgentSignerEvidenceQuerySelector,
        status: SignerEvidenceResolvedStatus,
        key: StationSigningKey,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        accepted_at: DateTime<Utc>,
        signer_evidence_ref: SignerEvidenceRef,
    },
    Unavailable {
        selector: AgentSignerEvidenceQuerySelector,
        status: SignerEvidenceUnavailableStatus,
    },
}
impl AgentSignerEvidenceQueryResult {
    pub fn selector(&self) -> &AgentSignerEvidenceQuerySelector {
        match self {
            Self::CurrentResolved { selector, .. }
            | Self::HistoricalResolved { selector, .. }
            | Self::Unavailable { selector, .. } => selector,
        }
    }
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_RESULT_MAX_BYTES, false)?;
        self.selector().validate()?;
        let key = match self {
            Self::CurrentResolved {
                selector: AgentSignerEvidenceQuerySelector::CurrentAdmission { .. },
                key,
                ..
            }
            | Self::HistoricalResolved {
                selector: AgentSignerEvidenceQuerySelector::HistoricalEvent { .. },
                key,
                ..
            } => Some(key),
            Self::Unavailable { .. } => None,
            _ => {
                return Err(self_signer_error(
                    arkret_wire::ErrorCode::SchemaViolation,
                    "result mode mismatch",
                ));
            }
        };
        if let Some(key) = key {
            key.validate()?;
            if &key.actor != self.selector().actor()
                || &key.verification_method != self.selector().verification_method()
            {
                return Err(self_signer_error(
                    arkret_wire::ErrorCode::SchemaViolation,
                    "result key binding mismatch",
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerEvidenceQueryOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: arkret_wire::AccountId,
    pub results: Vec<AgentSignerEvidenceQueryResult>,
}
impl AgentSignerEvidenceQueryOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_OUTCOME_MAX_BYTES, false)?;
        if self.results.is_empty() || self.results.len() > 64 {
            return Err(self_signer_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "invalid result count",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for item in &self.results {
            item.validate()?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(item.selector())?) {
                return Err(self_signer_error(
                    arkret_wire::ErrorCode::SchemaViolation,
                    "duplicate result",
                ));
            }
        }
        Ok(())
    }
    pub fn validate_for_request(
        &self,
        request: &AgentSignerEvidenceQueryRequestBody,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        self.validate()?;
        let requested = request
            .queries
            .iter()
            .map(arkret_canonical::canonical_json_bytes)
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let returned = self
            .results
            .iter()
            .map(|r| arkret_canonical::canonical_json_bytes(r.selector()))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.recipient_account_id != request.recipient_account_id
            || requested != returned
        {
            return Err(self_signer_error(
                arkret_wire::ErrorCode::SchemaViolation,
                "self signer response binding mismatch",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod self_signer_tests {
    use super::*;
    fn request() -> AgentSignerEvidenceQueryRequestBody {
        serde_json::from_value(serde_json::json!({
            "request_id":"ak:request:0196419b-0000-7000-8000-00000000000a",
            "realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "recipient_account_id":{"principal_id":"ak:did_core:web:reader.example","station_id":"ak:did_core:web:station.example"},
            "queries":[{"verification_mode":"current_admission","actor":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:agent.example","station_id":"ak:did_core:web:station.example"}},"verification_method":"did:web:agent.example#agent-key"}]
        })).unwrap()
    }
    fn key(request: &AgentSignerEvidenceQueryRequestBody) -> StationSigningKey {
        StationSigningKey {
            actor: request.queries[0].actor().clone(),
            verification_method: request.queries[0].verification_method().clone(),
            public_key_b64u: Base64UrlString::new("A".repeat(43)).unwrap(),
            authorization_ref: EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .unwrap(),
        }
    }
    fn outcome(request: &AgentSignerEvidenceQueryRequestBody) -> AgentSignerEvidenceQueryOutcome {
        AgentSignerEvidenceQueryOutcome {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            recipient_account_id: request.recipient_account_id.clone(),
            results: vec![AgentSignerEvidenceQueryResult::CurrentResolved {
                selector: request.queries[0].clone(),
                status: SignerEvidenceResolvedStatus::Resolved,
                key: key(request),
                checked_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
            }],
        }
    }
    #[test]
    fn self_signer_results_bind_account_station_and_exact_request_set() {
        let request = request();
        let mut result = outcome(&request);
        result.validate_for_request(&request).unwrap();
        let saved = result.clone();
        result.recipient_account_id.station_id =
            DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(result.validate_for_request(&request).is_err());
        result = saved.clone();
        result.results.push(result.results[0].clone());
        assert!(result.validate_for_request(&request).is_err());
        result = saved;
        if let AgentSignerEvidenceQueryResult::CurrentResolved { key, .. } = &mut result.results[0]
        {
            let account = arkret_wire::AccountId::new(
                key.actor.signing_principal_id().clone(),
                DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            );
            key.actor = arkret_wire::ActorId::account(account);
        }
        assert!(result.validate_for_request(&request).is_err());
    }
    #[test]
    fn self_signer_historical_shape_cannot_authorize_current_selector() {
        let request = request();
        let mut result = outcome(&request);
        result.results[0] = AgentSignerEvidenceQueryResult::HistoricalResolved {
            selector: request.queries[0].clone(),
            status: SignerEvidenceResolvedStatus::Resolved,
            key: key(&request),
            accepted_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
            signer_evidence_ref: SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
        };
        assert!(result.validate_for_request(&request).is_err());
        let mut encoded = serde_json::to_value(&request).unwrap();
        encoded["known_signer_evidence_refs"] = serde_json::json!([]);
        assert!(serde_json::from_value::<AgentSignerEvidenceQueryRequestBody>(encoded).is_err());
    }
    #[test]
    fn self_signer_key_rejects_wrong_method_principal_and_noncanonical_padding_bits() {
        let request = request();
        let mut value = key(&request);
        value.verification_method = DidUrl::new("did:web:other.example#agent-key").unwrap();
        assert!(value.validate().is_err());
        value = key(&request);
        if let Ok(noncanonical) = Base64UrlString::new(format!("{}B", "A".repeat(42))) {
            value.public_key_b64u = noncanonical;
            assert!(value.validate().is_err());
        }
    }
    #[test]
    fn self_signer_request_bytes_take_precedence_over_selector_count() {
        let mut request = request();
        request.queries = vec![request.queries[0].clone(); 1000];
        assert_eq!(
            request.validate().unwrap_err().error_code(),
            Some(arkret_wire::ErrorCode::PayloadTooLarge)
        );
        request.queries.truncate(2);
        assert_eq!(
            request.validate().unwrap_err().error_code(),
            Some(arkret_wire::ErrorCode::SchemaViolation)
        );
    }
}
