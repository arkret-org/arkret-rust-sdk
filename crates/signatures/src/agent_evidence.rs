//! Agent signing-key binding and portable signer-evidence verification.
//!
//! Current admission and historical Event verification intentionally expose
//! different entry points. Callers cannot pass current state as a substitute
//! for a destination-signed historical admission receipt.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::{base64url_decode, canonical};
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_SIGNING_KEY_BINDING_CONTEXT, AGENT_STATUS_COMPONENT,
    AgentAdmissionEvidence, AgentAuthorizationStatus, AgentControllerProof,
    AgentCurrentObservation, AgentDetachedJws, AgentEventAdmissionReceipt,
    AgentEvidenceOuterAttestation, AgentHistoricalEvidenceOuterAttestation, AgentLifecycleStatus,
    AgentLifecycleWitness, AgentSignerEvidence, AgentSigningKeyBinding, AgentSigningKeyBindingCore,
    AgentSigningPublicKey, ControllerAccountEligibility, ControllerAccountStatus,
};
use arkret_wire::{
    ActorId, CellRef, Did, DidCoreId, DidUrl, DomainSeparationId, EventId, Hash, NonEmptyString,
    ProfileId, ProtocolOperationId, RealmId, SchemaId, Seal, SealId, SignerEvidenceRef,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent::{
    ValidatedAgentRuntimePublicKey, agent_runtime_public_key_digest,
    validate_agent_runtime_public_key,
};
use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_ed25519_detached_jws};

const AUTHORITY_STATE_LEASE_DOMAIN: &str = DomainSeparationId::AGENT_AUTHORITY_STATE_EVIDENCE_V1;
const CONTROLLER_GATE_DOMAIN: &str = DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1;
const EVENT_ADMISSION_RECEIPT_DOMAIN: &str = DomainSeparationId::AGENT_SIGNER_ADMISSION_RECEIPT_V1;
const OUTER_ATTESTATION_DOMAIN: &str = DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1;
const DETACHED_JWS_KIND: &str = "detached_jws";
const MAX_SEAL_LINEAGE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum AgentEvidenceSigningError {
    #[error("agent evidence JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("agent evidence canonicalization failed: {0}")]
    Canonical(#[from] arkret_canonical::CanonicalError),
    #[error("agent evidence detached JWS construction failed: {0}")]
    Jws(#[from] crate::SignerError),
    #[error("agent evidence proof shape is invalid: {0}")]
    InvalidProofShape(&'static str),
    #[error("agent evidence identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("agent evidence signing mode does not match the evidence variant")]
    WrongEvidenceMode,
    #[error("agent event admission receipt receiver does not match the signing method")]
    ReceiverMismatch,
}

/// Canonical Account Authority signing bytes for the controller lifecycle
/// gate. `proof.jws` is excluded while every other closed field, including
/// the proof kind, remains covered.
pub fn controller_account_gate_attestation_signing_bytes(
    attestation: &arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation,
) -> Result<Vec<u8>, AgentEvidenceSigningError> {
    let mut value = serde_json::to_value(attestation)?;
    remove_nested_jws_for_signing(&mut value)?;
    let canonical = canonical::canonical_json_value_bytes(&value)?;
    let mut signing_bytes = Vec::with_capacity(CONTROLLER_GATE_DOMAIN.len() + 1 + canonical.len());
    signing_bytes.extend_from_slice(CONTROLLER_GATE_DOMAIN.as_bytes());
    signing_bytes.push(b'\n');
    signing_bytes.extend_from_slice(&canonical);
    Ok(signing_bytes)
}

/// Finish an Account Authority controller gate with the canonical Ed25519
/// detached JWS used by all independent evidence verifiers.
pub fn sign_controller_account_gate_attestation(
    attestation: &mut arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation,
    signing_key: &SigningKey,
) -> Result<(), AgentEvidenceSigningError> {
    let bytes = controller_account_gate_attestation_signing_bytes(attestation)?;
    let jws = sign_ed25519_detached_jws(signing_key, &bytes)?;
    attestation.proof.jws = NonEmptyString::new(jws)
        .map_err(|error| AgentEvidenceSigningError::InvalidIdentifier(error.to_owned()))?;
    Ok(())
}

/// Sign the short-lived Agent Authority lease after `state_digest` has
/// been computed from the complete snapshot core.
pub fn sign_agent_authority_state_lease(
    lease: &mut arkret_models_identity::agent_signer_evidence::AgentAuthorityStateLease,
    signing_key: &SigningKey,
) -> Result<(), AgentEvidenceSigningError> {
    lease.proof.jws = domain_proof_jws(AUTHORITY_STATE_LEASE_DOMAIN, lease, signing_key)?;
    Ok(())
}

/// Finalize the outer attestation over an already complete evidence value.
/// The digest excludes the whole outer-attestation object, while its detached
/// JWS covers every outer field except `proof.jws`.
pub fn sign_agent_evidence_outer_attestation(
    evidence: &mut AgentSignerEvidence,
    signing_key: &SigningKey,
) -> Result<(), AgentEvidenceSigningError> {
    let digest = outer_core_digest_for_signing(evidence)?;
    let outer = match evidence {
        AgentSignerEvidence::CurrentAdmission {
            outer_attestation, ..
        } => outer_attestation,
        AgentSignerEvidence::HistoricalEvent { .. } => {
            return Err(AgentEvidenceSigningError::WrongEvidenceMode);
        }
    };
    outer.core_digest = digest;
    outer.proof.jws = domain_proof_jws(OUTER_ATTESTATION_DOMAIN, outer, signing_key)?;
    Ok(())
}

pub fn sign_agent_historical_evidence_outer_attestation(
    evidence: &mut AgentSignerEvidence,
    signing_key: &SigningKey,
) -> Result<(), AgentEvidenceSigningError> {
    let digest = outer_core_digest_for_signing(evidence)?;
    let AgentSignerEvidence::HistoricalEvent {
        outer_attestation, ..
    } = evidence
    else {
        return Err(AgentEvidenceSigningError::WrongEvidenceMode);
    };
    outer_attestation.core_digest = digest;
    outer_attestation.proof.jws =
        domain_proof_jws(OUTER_ATTESTATION_DOMAIN, outer_attestation, signing_key)?;
    Ok(())
}

pub fn sign_agent_event_admission_receipt(
    receipt: &mut AgentEventAdmissionReceipt,
    receiver_verification_method: &DidUrl,
    signing_key: &SigningKey,
) -> Result<(), AgentEvidenceSigningError> {
    let receiver_id =
        did_url_controller_core_id(receiver_verification_method).map_err(|reason| {
            AgentEvidenceSigningError::InvalidIdentifier(reason.as_str().to_owned())
        })?;
    if receipt.receiver_id != receiver_id {
        return Err(AgentEvidenceSigningError::ReceiverMismatch);
    }
    receipt.proof.jws = domain_proof_jws_with_kid(
        EVENT_ADMISSION_RECEIPT_DOMAIN,
        receipt,
        receiver_verification_method.as_str(),
        signing_key,
    )?;
    Ok(())
}

pub fn verify_agent_event_admission_receipt(
    receipt: &AgentEventAdmissionReceipt,
    receiver_public_key: &PublicKeyMaterial,
) -> Result<(), AgentEvidenceRejectedReason> {
    let method = historical_receipt_verification_method(receipt)?;
    if did_url_controller_core_id(&method)? != receipt.receiver_id {
        return Err(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    }
    verify_domain_proof(
        EVENT_ADMISSION_RECEIPT_DOMAIN,
        receipt,
        &receipt.proof,
        receiver_public_key,
    )
    .map_err(|_| AgentEvidenceRejectedReason::HistoricalReceiptMismatch)
}

fn domain_proof_jws(
    domain: &str,
    value: &impl Serialize,
    signing_key: &SigningKey,
) -> Result<NonEmptyString, AgentEvidenceSigningError> {
    let mut value = serde_json::to_value(value)?;
    remove_nested_jws_for_signing(&mut value)?;
    let canonical = canonical::canonical_json_value_bytes(&value)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&canonical);
    let jws = sign_ed25519_detached_jws(signing_key, &bytes)?;
    NonEmptyString::new(jws)
        .map_err(|error| AgentEvidenceSigningError::InvalidIdentifier(error.to_owned()))
}

fn domain_proof_jws_with_kid(
    domain: &str,
    value: &impl Serialize,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<NonEmptyString, AgentEvidenceSigningError> {
    let mut value = serde_json::to_value(value)?;
    remove_nested_jws_for_signing(&mut value)?;
    let canonical = canonical::canonical_json_value_bytes(&value)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&canonical);
    let input = crate::proof::ed25519_detached_jws_signing_input(&bytes, Some(kid))?;
    let signature = signing_key.sign(input.as_bytes());
    let jws = crate::proof::ed25519_detached_jws_from_signature(&signature.to_bytes(), Some(kid))?;
    NonEmptyString::new(jws)
        .map_err(|error| AgentEvidenceSigningError::InvalidIdentifier(error.to_owned()))
}

/// Independently verify the Account Authority-owned gate before an Agent PCR
/// includes it in portable evidence. The private projection behind
/// `basis_digest` is authority-owned; the verifier checks the closed shape,
/// exact expected identities, registered DID projection, time window and
/// detached service proof.
pub fn verify_controller_account_gate_attestation(
    attestation: &arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation,
    expected_principal_id: &DidCoreId,
    expected_authority_id: &DidCoreId,
    authority_public_key: &PublicKeyMaterial,
    now: DateTime<Utc>,
) -> Result<(), AgentEvidenceRejectedReason> {
    let method_base = attestation
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(base, _)| base)
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let did = Did::new(method_base.to_owned())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let projected = project_did_to_core_id(&did)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let status_active = attestation.status == ControllerAccountStatus::Active;
    let eligibility_active = attestation.eligibility == ControllerAccountEligibility::Active;
    if attestation.schema.as_str() != SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1
        || &attestation.principal_id != expected_principal_id
        || &attestation.authority_id != expected_authority_id
        || projected != attestation.authority_id
        || status_active != eligibility_active
        || attestation.issued_at >= attestation.expires_at
        || attestation.expires_at - attestation.issued_at > chrono::Duration::minutes(5)
        || now < attestation.issued_at
        || now >= attestation.expires_at
        || verify_domain_proof(
            CONTROLLER_GATE_DOMAIN,
            attestation,
            &attestation.proof,
            authority_public_key,
        )
        .is_err()
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentSigningKey {
    signer: DidCoreId,
    authority_id: DidCoreId,
    key: [u8; 32],
    authorization_ref: EventId,
    state_digest: Hash,
    admission_evidence_digest: Hash,
}

impl VerifiedAgentSigningKey {
    pub fn signer(&self) -> &DidCoreId {
        &self.signer
    }

    pub const fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn authority_id(&self) -> &DidCoreId {
        &self.authority_id
    }

    pub fn authorization_ref(&self) -> &EventId {
        &self.authorization_ref
    }

    pub fn state_digest(&self) -> &Hash {
        &self.state_digest
    }

    pub fn admission_evidence_digest(&self) -> &Hash {
        &self.admission_evidence_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentEvidenceUnresolvedReason {
    Missing,
    Stale,
}

impl AgentEvidenceUnresolvedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "agent_signer_evidence_missing",
            Self::Stale => "agent_signer_evidence_stale",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentEvidenceRejectedReason {
    WrongVerificationMode,
    AuthorizationInactive,
    AuthorizationConflicted,
    SigningKeyMismatch,
    RequestBindingMismatch,
    HistoricalReceiptMismatch,
    MlsLeafBindingMismatch,
}

impl AgentEvidenceRejectedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongVerificationMode => "agent_evidence_verification_mode_mismatch",
            Self::AuthorizationInactive => "agent_authorization_inactive",
            Self::AuthorizationConflicted => "agent_authorization_conflicted",
            Self::SigningKeyMismatch => "agent_signing_key_mismatch",
            Self::RequestBindingMismatch => "agent_current_request_binding_mismatch",
            Self::HistoricalReceiptMismatch => "agent_historical_receipt_mismatch",
            Self::MlsLeafBindingMismatch => "agent_mls_leaf_binding_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentSignerEvidenceVerdict {
    Verified(VerifiedAgentSigningKey),
    Unresolved(AgentEvidenceUnresolvedReason),
    Rejected(AgentEvidenceRejectedReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentEvidenceState {
    admission_evidence_digest: Hash,
    state_digest: Hash,
    signer_id: DidCoreId,
    authorization_event_id: EventId,
    key_seal_id: SealId,
    lifecycle_seal_id: SealId,
}

pub struct AgentEvidenceStateVerificationContext<'a> {
    pub signer_id: &'a DidCoreId,
    /// Complete Account identity of the Agent whose lifecycle cell is proven.
    /// The Station component is identity-bearing and must never be collapsed to
    /// the signing principal DID.
    pub signer_actor_id: &'a ActorId,
    pub agent_key_id: &'a NonEmptyString,
    pub controller_principal_id: &'a DidCoreId,
    pub agent_key_authorize_event_id: &'a EventId,
    pub authorize_public_key_digest: &'a Hash,
    pub authorize_signing_key_binding_digest: &'a Hash,
    pub verify_seal_signature: &'a dyn Fn(&Seal) -> Result<(), AgentEvidenceRejectedReason>,
    pub verify_lifecycle_reducer:
        &'a dyn Fn(&AgentLifecycleWitness) -> Result<(), AgentEvidenceRejectedReason>,
}

/// Independently established trust inputs shared by both verification modes.
/// The verified-state token has a private constructor and is bound to the
/// exact admission/snapshot/witness digests.
pub struct AgentEvidenceCommonContext<'a> {
    pub signer_id: &'a DidCoreId,
    pub agent_key_id: &'a NonEmptyString,
    pub controller_principal_id: &'a DidCoreId,
    pub verification_method: &'a DidUrl,
    pub agent_key_authorize_event_id: &'a EventId,
    pub authorize_public_key_digest: &'a Hash,
    pub authorize_signing_key_binding_digest: &'a Hash,
    pub expected_authority_id: &'a DidCoreId,
    pub expected_authority_verification_method: &'a DidUrl,
    pub expected_account_authority_id: &'a DidCoreId,
    pub expected_account_authority_verification_method: &'a DidUrl,
    pub controller_public_key: &'a PublicKeyMaterial,
    pub authority_public_key: &'a PublicKeyMaterial,
    pub account_authority_public_key: &'a PublicKeyMaterial,
    pub verified_state: &'a VerifiedAgentEvidenceState,
    pub require_transparency: bool,
    pub transparency_verified: bool,
    pub now: DateTime<Utc>,
}

pub struct CurrentAgentSignerEvidenceValidationContext<'a> {
    pub common: AgentEvidenceCommonContext<'a>,
    pub operation_id: &'a ProtocolOperationId,
    pub request_digest: &'a Hash,
    pub verifier_id: &'a DidCoreId,
    pub audience: &'a DidCoreId,
    pub challenge: &'a NonEmptyString,
}

pub struct HistoricalAgentSignerEvidenceValidationContext<'a> {
    pub common: AgentEvidenceCommonContext<'a>,
    pub event_id: &'a EventId,
    pub realm_id: &'a RealmId,
    pub producer_accepted_at: DateTime<Utc>,
    pub producer_signer_resolution_evidence_ref: &'a SignerEvidenceRef,
    pub receiver_id: &'a DidCoreId,
    /// Resolve the exact receiver assertion key identified by the detached
    /// JWS protected `kid` at the receipt acceptance time.
    pub resolve_receiver_historical_key:
        &'a dyn Fn(&DidUrl, DateTime<Utc>) -> Option<PublicKeyMaterial>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerPrincipalKind {
    Device,
    Agent,
    Applet,
    Service,
    Integration,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRegime {
    MinimalMetadata,
    OrdinaryDevice,
    OrdinaryAgent,
    AppletOrService,
}

pub fn dispatch_signer_regime(
    minimal_metadata_realm: bool,
    principal_kind: SignerPrincipalKind,
) -> Result<SignerRegime, AgentEvidenceRejectedReason> {
    if minimal_metadata_realm {
        return Ok(SignerRegime::MinimalMetadata);
    }
    match principal_kind {
        SignerPrincipalKind::Device => Ok(SignerRegime::OrdinaryDevice),
        SignerPrincipalKind::Agent => Ok(SignerRegime::OrdinaryAgent),
        SignerPrincipalKind::Applet
        | SignerPrincipalKind::Service
        | SignerPrincipalKind::Integration => Ok(SignerRegime::AppletOrService),
        SignerPrincipalKind::Unknown => Err(AgentEvidenceRejectedReason::SigningKeyMismatch),
    }
}

fn agent_signing_key_binding_transcript_bytes(
    value: &impl Serialize,
) -> Result<Vec<u8>, AgentEvidenceRejectedReason> {
    let canonical = canonical::canonical_json_bytes(value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let mut bytes = Vec::with_capacity(AGENT_SIGNING_KEY_BINDING_CONTEXT.len() + canonical.len());
    bytes.extend_from_slice(AGENT_SIGNING_KEY_BINDING_CONTEXT.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

/// Compute the controller-proof transcript from a finalized binding.
///
/// The JWS itself is excluded while the complete authorize Event identity
/// and controller verification method remain covered.
pub fn agent_signing_key_binding_signing_bytes(
    binding: &AgentSigningKeyBinding,
) -> Result<Vec<u8>, AgentEvidenceRejectedReason> {
    agent_signing_key_binding_transcript_bytes(&AgentSigningKeyBindingProofInput {
        core: &binding.core,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        controller_proof: AgentControllerProofInput {
            kind: binding.controller_proof.kind.as_str(),
            verification_method: &binding.controller_proof.verification_method,
        },
    })
}

/// Digest of the Event-covered binding core.
pub fn agent_signing_key_binding_core_digest(
    core: &AgentSigningKeyBindingCore,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    canonical_digest(core)
}

/// Digest committed by `ak.agent.key.authorize.payload.signing_key_binding_digest`.
///
/// This deliberately excludes both the containing Event identity and the
/// controller proof. Use [`agent_signing_key_binding_signing_bytes`] for the
/// later controller-proof transcript.
pub fn agent_signing_key_binding_digest(
    binding: &AgentSigningKeyBinding,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    agent_signing_key_binding_core_digest(&binding.core)
}

#[derive(Serialize)]
struct AgentControllerProofInput<'a> {
    kind: &'a str,
    verification_method: &'a DidUrl,
}

#[derive(Serialize)]
struct AgentSigningKeyBindingProofInput<'a> {
    #[serde(flatten)]
    core: &'a AgentSigningKeyBindingCore,
    agent_key_authorize_event_id: &'a EventId,
    controller_proof: AgentControllerProofInput<'a>,
}

/// Opaque, finalized controller-proof input. It can only be produced after the
/// authorize Event's complete identity is known and cannot be serialized as a
/// wire `AgentSigningKeyBinding` without a real controller JWS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSigningKeyBindingToSign {
    core: AgentSigningKeyBindingCore,
    agent_key_authorize_event_id: EventId,
    controller_verification_method: DidUrl,
}

pub fn agent_signing_key_binding_to_sign_bytes(
    binding: &AgentSigningKeyBindingToSign,
) -> Result<Vec<u8>, AgentEvidenceRejectedReason> {
    agent_signing_key_binding_transcript_bytes(&AgentSigningKeyBindingProofInput {
        core: &binding.core,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        controller_proof: AgentControllerProofInput {
            kind: DETACHED_JWS_KIND,
            verification_method: &binding.controller_verification_method,
        },
    })
}

pub fn agent_authorization_cell_ref(
    agent_id: &DidCoreId,
    agent_key_id: &NonEmptyString,
) -> Result<NonEmptyString, AgentEvidenceRejectedReason> {
    let subject = arkret_wire::composite_subject(&[agent_id.as_str(), agent_key_id.as_str()])
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    NonEmptyString::new(format!("ak:cell:{AGENT_KEY_COMPONENT}:{subject}"))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn agent_lifecycle_cell_ref(
    agent_actor_id: &ActorId,
) -> Result<NonEmptyString, AgentEvidenceRejectedReason> {
    if agent_actor_id.as_account_id().is_none() {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let canonical_actor = agent_actor_id
        .canonical_key()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let subject = arkret_wire::composite_subject(&[canonical_actor.as_str()])
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    NonEmptyString::new(format!("ak:cell:{AGENT_STATUS_COMPONENT}:{subject}"))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

pub fn agent_authorization_dot_matches_event(dot: &str, event_id: &str) -> bool {
    let Some((dot_event_id, write_index)) = dot.rsplit_once(':') else {
        return false;
    };
    dot_event_id == event_id
        && EventId::new(dot_event_id.to_owned()).is_ok()
        && write_index
            .parse::<usize>()
            .is_ok_and(|parsed| parsed.to_string() == write_index)
}

/// Verify the exact key/lifecycle witnesses and complete signed Seal lineage,
/// returning an evidence-bound token whose fields cannot be constructed by
/// downstream callers.
pub fn verify_agent_evidence_state(
    admission: &AgentAdmissionEvidence,
    context: &AgentEvidenceStateVerificationContext<'_>,
) -> Result<VerifiedAgentEvidenceState, AgentEvidenceRejectedReason> {
    let snapshot = &admission.agent_authority_state_evidence;
    if canonical_digest(&snapshot.state)? != snapshot.state_digest
        || agent_admission_evidence_digest(
            snapshot,
            &admission.controller_account_gate_attestation,
        )? != admission.admission_evidence_digest
        || !validate_state_witnesses(admission, context)?
        || !validate_seal_lineage(admission, context)?
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    (context.verify_lifecycle_reducer)(&snapshot.state.agent_lifecycle_witness)?;
    Ok(VerifiedAgentEvidenceState {
        admission_evidence_digest: admission.admission_evidence_digest.clone(),
        state_digest: snapshot.state_digest.clone(),
        signer_id: context.signer_id.clone(),
        authorization_event_id: context.agent_key_authorize_event_id.clone(),
        key_seal_id: snapshot.state.key_state_witness.seal_id.clone(),
        lifecycle_seal_id: snapshot.state.agent_lifecycle_witness.seal_id.clone(),
    })
}

/// Compute the canonical digest that binds an Agent authority snapshot to its
/// controller-account gate attestation.
///
/// Producers and verifiers must share this exact two-field projection; local
/// look-alike structs risk changing the signed evidence contract independently.
pub fn agent_admission_evidence_digest(
    snapshot: &arkret_models_identity::agent_signer_evidence::AgentAuthorityStateEvidence,
    gate: &arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    #[derive(Serialize)]
    struct AdmissionCore<'a> {
        agent_authority_state_evidence:
            &'a arkret_models_identity::agent_signer_evidence::AgentAuthorityStateEvidence,
        controller_account_gate_attestation:
            &'a arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation,
    }

    canonical_digest(&AdmissionCore {
        agent_authority_state_evidence: snapshot,
        controller_account_gate_attestation: gate,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_agent_signing_key_binding(
    agent_id: DidCoreId,
    agent_key_id: NonEmptyString,
    verification_method: DidUrl,
    agent_public_key: [u8; 32],
    agent_key_authorize_event_id: EventId,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    controller_principal_id: DidCoreId,
    controller_verification_method: DidUrl,
    controller_signing_key: &SigningKey,
) -> Result<AgentSigningKeyBinding, AgentEvidenceRejectedReason> {
    let runtime_public_key = arkret_models_collaboration::governance::agent_artifacts::PublicKey {
        kty: NonEmptyString::new("OKP".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        kid: NonEmptyString::new(verification_method.as_str().to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        algorithm: NonEmptyString::new("Ed25519".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            agent_public_key,
        ))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        key_digest: None,
    };
    let core = prepare_agent_signing_key_binding_core(
        agent_id,
        agent_key_id,
        verification_method,
        &runtime_public_key,
        issued_at,
        expires_at,
        controller_principal_id,
    )?;
    let binding = materialize_agent_signing_key_binding(
        core,
        agent_key_authorize_event_id,
        controller_verification_method,
    )?;
    let jws = sign_ed25519_detached_jws(
        controller_signing_key,
        &agent_signing_key_binding_to_sign_bytes(&binding)?,
    )
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    finish_agent_signing_key_binding(binding, &jws)
}

/// Prepare the digest-covered binding core from a validated runtime key.
///
/// This stage intentionally has no Event identity or controller proof input.
/// Its digest can therefore be placed in the authorize Event payload before
/// that Event's content-bound identity exists.
#[allow(clippy::too_many_arguments)]
pub fn prepare_agent_signing_key_binding_core(
    agent_id: DidCoreId,
    agent_key_id: NonEmptyString,
    verification_method: DidUrl,
    runtime_public_key: &arkret_models_collaboration::governance::agent_artifacts::PublicKey,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    controller_principal_id: DidCoreId,
) -> Result<AgentSigningKeyBindingCore, AgentEvidenceRejectedReason> {
    let validated = validate_agent_runtime_public_key(runtime_public_key, &verification_method)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let public_key = AgentSigningPublicKey {
        kty: NonEmptyString::new("OKP".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        algorithm: NonEmptyString::new("Ed25519".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        key: validated.public_key.key,
    };
    if did_url_controller_core_id(&verification_method)? != agent_id {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ok(AgentSigningKeyBindingCore {
        schema: NonEmptyString::new(SchemaId::AGENT_SIGNING_KEY_BINDING_V1.to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        agent_id,
        agent_key_id,
        verification_method,
        public_key,
        public_key_digest: validated.authorization_digest,
        issued_at,
        expires_at,
        controller_principal_id,
    })
}

/// Append the already-finalized authorize Event identity and select the
/// controller method whose JWS will cover the resulting final transcript.
pub fn materialize_agent_signing_key_binding(
    core: AgentSigningKeyBindingCore,
    agent_key_authorize_event_id: EventId,
    controller_verification_method: DidUrl,
) -> Result<AgentSigningKeyBindingToSign, AgentEvidenceRejectedReason> {
    if core.schema.as_str() != SchemaId::AGENT_SIGNING_KEY_BINDING_V1
        || did_url_controller_core_id(&core.verification_method)? != core.agent_id
        || did_url_controller_core_id(&controller_verification_method)?
            != core.controller_principal_id
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ok(AgentSigningKeyBindingToSign {
        core,
        agent_key_authorize_event_id,
        controller_verification_method,
    })
}

/// Attach the controller-produced JWS and produce the only wire-serializable
/// final binding. No placeholder proof state is representable.
pub fn finish_agent_signing_key_binding(
    binding: AgentSigningKeyBindingToSign,
    controller_jws: &str,
) -> Result<AgentSigningKeyBinding, AgentEvidenceRejectedReason> {
    Ok(AgentSigningKeyBinding {
        core: binding.core,
        agent_key_authorize_event_id: binding.agent_key_authorize_event_id,
        controller_proof: AgentControllerProof {
            kind: NonEmptyString::new(DETACHED_JWS_KIND.to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
            verification_method: binding.controller_verification_method,
            jws: NonEmptyString::new(controller_jws.to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        },
    })
}

/// Validate that the private runtime-request DTO and the public authorization
/// binding carry the same Ed25519 key while preserving their two distinct
/// digest domains.
pub fn validate_agent_pairing_key_material(
    runtime_public_key: &arkret_models_collaboration::governance::agent_artifacts::PublicKey,
    expected_verification_method: &DidUrl,
    binding: &AgentSigningKeyBinding,
) -> Result<ValidatedAgentRuntimePublicKey, AgentEvidenceRejectedReason> {
    let validated =
        validate_agent_runtime_public_key(runtime_public_key, expected_verification_method)
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    if binding.public_key.key != validated.public_key.key {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    validate_agent_signing_key_binding_digest_domains(
        binding,
        expected_verification_method,
        &validated.runtime_request_digest,
        &validated.authorization_digest,
    )?;
    Ok(validated)
}

/// Verify both named digest domains for a persisted pairing where only the
/// digests and public signing-key binding remain available.
pub fn validate_agent_signing_key_binding_digest_domains(
    binding: &AgentSigningKeyBinding,
    expected_verification_method: &DidUrl,
    expected_runtime_request_digest: &Hash,
    expected_authorization_digest: &Hash,
) -> Result<[u8; 32], AgentEvidenceRejectedReason> {
    if binding.verification_method != *expected_verification_method
        || binding.public_key.kty.as_str() != "OKP"
        || binding.public_key.algorithm.as_str() != "Ed25519"
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let authorization_digest = agent_signing_public_key_digest(&binding.public_key)?;
    let runtime_request_digest = agent_signing_public_key_runtime_request_digest(
        expected_verification_method,
        &binding.public_key,
    )?;
    if binding.public_key_digest != authorization_digest
        || authorization_digest != *expected_authorization_digest
        || runtime_request_digest != *expected_runtime_request_digest
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let raw = base64url_decode(binding.public_key.key.as_str())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    raw.try_into()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_agent_signing_key_binding(
    binding: &AgentSigningKeyBinding,
    expected_agent_id: &DidCoreId,
    expected_agent_key_id: &NonEmptyString,
    expected_controller_principal_id: &DidCoreId,
    expected_verification_method: &DidUrl,
    expected_authorize_event_id: &EventId,
    expected_public_key_digest: &Hash,
    expected_binding_digest: &Hash,
    controller_public_key: &PublicKeyMaterial,
) -> Result<[u8; 32], AgentEvidenceRejectedReason> {
    let method_agent_id = did_url_controller_core_id(&binding.verification_method)?;
    let proof_controller_principal_id =
        did_url_controller_core_id(&binding.controller_proof.verification_method)?;
    if binding.schema.as_str() != SchemaId::AGENT_SIGNING_KEY_BINDING_V1
        || &binding.agent_id != expected_agent_id
        || &binding.agent_key_id != expected_agent_key_id
        || &binding.controller_principal_id != expected_controller_principal_id
        || &binding.verification_method != expected_verification_method
        || &binding.agent_key_authorize_event_id != expected_authorize_event_id
        || method_agent_id != binding.agent_id
        || proof_controller_principal_id != binding.controller_principal_id
        || binding.controller_proof.kind.as_str() != DETACHED_JWS_KIND
        || binding.public_key.kty.as_str() != "OKP"
        || binding.public_key.algorithm.as_str() != "Ed25519"
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let raw = base64url_decode(binding.public_key.key.as_str())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let binding_public_key_digest = agent_signing_public_key_digest(&binding.public_key)?;
    if binding_public_key_digest != binding.public_key_digest
        || &binding_public_key_digest != expected_public_key_digest
        || agent_signing_key_binding_digest(binding)? != *expected_binding_digest
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            binding.controller_proof.jws.as_str(),
            &agent_signing_key_binding_signing_bytes(binding)?,
            controller_public_key,
        )
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(key)
}

pub fn validate_current_agent_signer_evidence(
    evidence: Option<&AgentSignerEvidence>,
    context: &CurrentAgentSignerEvidenceValidationContext<'_>,
) -> AgentSignerEvidenceVerdict {
    let Some(evidence) = evidence else {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
    };
    let AgentSignerEvidence::CurrentAdmission {
        schema,
        admission_evidence,
        current_observation,
        outer_attestation,
        transparency,
    } = evidence
    else {
        return rejected(AgentEvidenceRejectedReason::WrongVerificationMode);
    };
    if schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_V1
        || !current_observation_matches(current_observation, context)
    {
        return rejected(AgentEvidenceRejectedReason::RequestBindingMismatch);
    }
    match validate_common_evidence(
        evidence,
        admission_evidence,
        OuterAttestationRef::Current(outer_attestation),
        transparency.is_some(),
        context.common.now,
        context.common.now,
        &context.common,
    ) {
        Ok(verified) => {
            let snapshot = &admission_evidence.agent_authority_state_evidence;
            let gate_digest =
                match canonical_digest(&admission_evidence.controller_account_gate_attestation) {
                    Ok(digest) => digest,
                    Err(reason) => return rejected(reason),
                };
            if current_observation.agent_authority_state_digest != snapshot.state_digest
                || current_observation.agent_key_seal_id != snapshot.state.key_state_witness.seal_id
                || current_observation.agent_status_seal_id
                    != snapshot.state.agent_lifecycle_witness.seal_id
                || current_observation.controller_gate_attestation_digest != gate_digest
                || current_observation.evaluated_at > context.common.now
            {
                return rejected(AgentEvidenceRejectedReason::RequestBindingMismatch);
            }
            if context.common.now >= current_observation.expires_at {
                return AgentSignerEvidenceVerdict::Unresolved(
                    AgentEvidenceUnresolvedReason::Stale,
                );
            }
            AgentSignerEvidenceVerdict::Verified(verified)
        }
        Err(CommonEvidenceFailure::Unresolved(reason)) => {
            AgentSignerEvidenceVerdict::Unresolved(reason)
        }
        Err(CommonEvidenceFailure::Rejected(reason)) => rejected(reason),
    }
}

pub fn validate_historical_agent_signer_evidence(
    evidence: Option<&AgentSignerEvidence>,
    context: &HistoricalAgentSignerEvidenceValidationContext<'_>,
) -> AgentSignerEvidenceVerdict {
    let Some(evidence) = evidence else {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
    };
    let AgentSignerEvidence::HistoricalEvent {
        schema,
        admission_evidence,
        event_admission_receipt,
        outer_attestation,
        transparency,
    } = evidence
    else {
        return rejected(AgentEvidenceRejectedReason::WrongVerificationMode);
    };
    if schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_V1
        || !historical_receipt_matches(event_admission_receipt, context)
    {
        return rejected(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    }
    let receipt_method = match historical_receipt_verification_method(event_admission_receipt) {
        Ok(method) => method,
        Err(reason) => return rejected(reason),
    };
    if !did_url_controller_core_id(&receipt_method)
        .is_ok_and(|service_id| service_id == *context.receiver_id)
    {
        return rejected(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    }
    let Some(receiver_key) = (context.resolve_receiver_historical_key)(
        &receipt_method,
        event_admission_receipt.accepted_at,
    ) else {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale);
    };
    if verify_domain_proof(
        EVENT_ADMISSION_RECEIPT_DOMAIN,
        event_admission_receipt,
        &event_admission_receipt.proof,
        &receiver_key,
    )
    .is_err()
    {
        return rejected(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    }
    match validate_common_evidence(
        evidence,
        admission_evidence,
        OuterAttestationRef::Historical(outer_attestation),
        transparency.is_some(),
        event_admission_receipt.producer_accepted_at,
        event_admission_receipt.accepted_at,
        &context.common,
    ) {
        Ok(verified) => AgentSignerEvidenceVerdict::Verified(verified),
        Err(CommonEvidenceFailure::Unresolved(reason)) => {
            AgentSignerEvidenceVerdict::Unresolved(reason)
        }
        Err(CommonEvidenceFailure::Rejected(reason)) => rejected(reason),
    }
}

enum CommonEvidenceFailure {
    Unresolved(AgentEvidenceUnresolvedReason),
    Rejected(AgentEvidenceRejectedReason),
}

#[derive(Clone, Copy)]
enum OuterAttestationRef<'a> {
    Current(&'a AgentEvidenceOuterAttestation),
    Historical(&'a AgentHistoricalEvidenceOuterAttestation),
}

impl From<AgentEvidenceRejectedReason> for CommonEvidenceFailure {
    fn from(reason: AgentEvidenceRejectedReason) -> Self {
        Self::Rejected(reason)
    }
}

fn validate_common_evidence(
    evidence: &AgentSignerEvidence,
    admission: &AgentAdmissionEvidence,
    outer: OuterAttestationRef<'_>,
    has_transparency: bool,
    basis_time: DateTime<Utc>,
    outer_not_before: DateTime<Utc>,
    context: &AgentEvidenceCommonContext<'_>,
) -> Result<VerifiedAgentSigningKey, CommonEvidenceFailure> {
    let snapshot = &admission.agent_authority_state_evidence;
    let core = &snapshot.state;
    let binding = &core.signing_key_binding;
    let authorization = &core.authorization;
    let key_witness = &core.key_state_witness;
    let lifecycle = &core.agent_lifecycle_witness;
    let gate = &admission.controller_account_gate_attestation;

    let expected_state_digest = canonical_digest(&snapshot.state)?;
    let expected_admission_digest = agent_admission_evidence_digest(snapshot, gate)?;
    let expected_outer_core_digest = outer_core_digest(evidence)?;
    let (outer_domain, outer_core_digest_value, outer_source_id_value, outer_method) = match outer {
        OuterAttestationRef::Current(value) => (
            &value.domain,
            &value.core_digest,
            &value.source_id,
            &value.verification_method,
        ),
        OuterAttestationRef::Historical(value) => (
            &value.domain,
            &value.core_digest,
            &value.source_id,
            &value.verification_method,
        ),
    };
    let lease_authority_id = did_url_controller_core_id(&snapshot.lease.verification_method)?;
    let outer_source_id = did_url_controller_core_id(outer_method)?;
    let outer_time_valid = match outer {
        OuterAttestationRef::Current(value) => {
            value.issued_at < value.expires_at && context.now >= value.issued_at
        }
        OuterAttestationRef::Historical(value) => {
            value.attested_at >= outer_not_before && value.attested_at <= context.now
        }
    };
    let outer_proof_valid = match outer {
        OuterAttestationRef::Current(value) => verify_domain_proof(
            OUTER_ATTESTATION_DOMAIN,
            value,
            &value.proof,
            context.authority_public_key,
        ),
        OuterAttestationRef::Historical(value) => verify_domain_proof(
            OUTER_ATTESTATION_DOMAIN,
            value,
            &value.proof,
            context.authority_public_key,
        ),
    }
    .is_ok();
    if snapshot.state_digest != expected_state_digest
        || admission.admission_evidence_digest != expected_admission_digest
        || snapshot.lease.authority_kind.as_str() != "agent_authority"
        || snapshot.lease.authority_id != core.authority_id
        || snapshot.lease.authority_id != *context.expected_authority_id
        || snapshot.lease.verification_method != *context.expected_authority_verification_method
        || snapshot.lease.state_digest != snapshot.state_digest
        || lease_authority_id != snapshot.lease.authority_id
        || snapshot.lease.issued_at >= snapshot.lease.expires_at
        || outer_domain.as_str() != OUTER_ATTESTATION_DOMAIN
        || *outer_core_digest_value != expected_outer_core_digest
        || *outer_source_id_value != *context.expected_authority_id
        || *outer_method != *context.expected_authority_verification_method
        || outer_source_id != *outer_source_id_value
        || !outer_time_valid
        || basis_time < snapshot.lease.issued_at
        || verify_domain_proof(
            AUTHORITY_STATE_LEASE_DOMAIN,
            &snapshot.lease,
            &snapshot.lease.proof,
            context.authority_public_key,
        )
        .is_err()
        || !outer_proof_valid
    {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::SigningKeyMismatch,
        ));
    }
    let current_outer_stale = match outer {
        OuterAttestationRef::Current(value) => context.now >= value.expires_at,
        OuterAttestationRef::Historical(_) => false,
    };
    if current_outer_stale || basis_time >= snapshot.lease.expires_at {
        return Err(CommonEvidenceFailure::Unresolved(
            AgentEvidenceUnresolvedReason::Stale,
        ));
    }
    let key = verify_agent_signing_key_binding(
        binding,
        context.signer_id,
        context.agent_key_id,
        context.controller_principal_id,
        context.verification_method,
        context.agent_key_authorize_event_id,
        context.authorize_public_key_digest,
        context.authorize_signing_key_binding_digest,
        context.controller_public_key,
    )?;
    if authorization.status == AgentAuthorizationStatus::Conflicted {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::AuthorizationConflicted,
        ));
    }
    if authorization.status != AgentAuthorizationStatus::Active
        || authorization.authorized_event_id != *context.agent_key_authorize_event_id
        || authorization.accepted_seal_id != key_witness.seal_id
        || basis_time < authorization.accepted_at
        || basis_time < authorization.not_before
        || basis_time < binding.issued_at
        || authorization
            .expires_at
            .is_some_and(|expires_at| basis_time >= expires_at)
        || binding
            .expires_at
            .is_some_and(|expires_at| basis_time >= expires_at)
        || core.key_transition_witness.is_some()
        || lifecycle.status != AgentLifecycleStatus::Active
        || lifecycle.cell_value != AgentLifecycleStatus::Active
        || gate.schema.as_str() != SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1
        || gate.principal_id.as_str() != context.controller_principal_id.as_str()
        || gate.authority_id != *context.expected_account_authority_id
        || gate.verification_method != *context.expected_account_authority_verification_method
        || gate.eligibility != ControllerAccountEligibility::Active
        || gate.status != ControllerAccountStatus::Active
        || basis_time < gate.issued_at
        || basis_time >= gate.expires_at
    {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::AuthorizationInactive,
        ));
    }
    let verified_state = context.verified_state;
    if verified_state.admission_evidence_digest != admission.admission_evidence_digest
        || verified_state.state_digest != snapshot.state_digest
        || verified_state.signer_id != *context.signer_id
        || verified_state.authorization_event_id != *context.agent_key_authorize_event_id
        || verified_state.key_seal_id != key_witness.seal_id
        || verified_state.lifecycle_seal_id != lifecycle.seal_id
        || project_did_to_core_id(
            &Did::new(did_url_controller(&gate.verification_method).to_owned()).map_err(|_| {
                CommonEvidenceFailure::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
            })?,
        )
        .map_err(|_| {
            CommonEvidenceFailure::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
        })? != gate.authority_id
        || verify_domain_proof(
            CONTROLLER_GATE_DOMAIN,
            gate,
            &gate.proof,
            context.account_authority_public_key,
        )
        .is_err()
    {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::SigningKeyMismatch,
        ));
    }
    if context.require_transparency && (!has_transparency || !context.transparency_verified) {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::AuthorizationConflicted,
        ));
    }
    if let Some(transparency) = match evidence {
        AgentSignerEvidence::CurrentAdmission { transparency, .. }
        | AgentSignerEvidence::HistoricalEvent { transparency, .. } => transparency.as_ref(),
    } && (transparency.profile.as_str() != ProfileId::KEY_TRANSPARENCY_V1
        || !context.transparency_verified)
    {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::AuthorizationConflicted,
        ));
    }
    Ok(VerifiedAgentSigningKey {
        signer: context.signer_id.clone(),
        authority_id: context.expected_authority_id.clone(),
        key,
        authorization_ref: context.agent_key_authorize_event_id.clone(),
        state_digest: snapshot.state_digest.clone(),
        admission_evidence_digest: admission.admission_evidence_digest.clone(),
    })
}

fn current_observation_matches(
    observation: &AgentCurrentObservation,
    context: &CurrentAgentSignerEvidenceValidationContext<'_>,
) -> bool {
    observation.operation_id == *context.operation_id
        && observation.request_digest == *context.request_digest
        && observation.verifier_id == *context.verifier_id
        && observation.audience_id == *context.audience
        && observation.challenge == *context.challenge
        && (16..=512).contains(&observation.challenge.as_str().chars().count())
        && observation.evaluated_at < observation.expires_at
}

/// Extract and strictly validate the destination assertion method carried in
/// the receipt's protected detached-JWS header. Missing `kid`, non-Ed25519,
/// non-canonical headers, unsupported extensions, and malformed DIDs fail
/// closed before historical key resolution.
pub fn historical_receipt_verification_method(
    receipt: &AgentEventAdmissionReceipt,
) -> Result<DidUrl, AgentEvidenceRejectedReason> {
    historical_receipt_protected_method(receipt)?
        .ok_or(AgentEvidenceRejectedReason::HistoricalReceiptMismatch)
}

fn historical_receipt_protected_method(
    receipt: &AgentEventAdmissionReceipt,
) -> Result<Option<DidUrl>, AgentEvidenceRejectedReason> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProtectedHeader {
        alg: String,
        kid: Option<String>,
        #[serde(default)]
        typ: Option<String>,
        #[serde(default)]
        crit: Option<Value>,
    }

    let mut parts = receipt.proof.jws.as_str().split('.');
    let (Some(protected), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    };
    if !payload.is_empty() || signature.is_empty() || base64url_decode(signature).is_err() {
        return Err(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    }
    let protected = base64url_decode(protected)
        .map_err(|_| AgentEvidenceRejectedReason::HistoricalReceiptMismatch)?;
    let header: ProtectedHeader = canonical::from_canonical_json_slice(&protected)
        .map_err(|_| AgentEvidenceRejectedReason::HistoricalReceiptMismatch)?;
    if header.alg != "Ed25519" || header.typ.is_some() || header.crit.is_some() {
        return Err(AgentEvidenceRejectedReason::HistoricalReceiptMismatch);
    }
    header
        .kid
        .map(DidUrl::new)
        .transpose()
        .map_err(|_| AgentEvidenceRejectedReason::HistoricalReceiptMismatch)
}

fn historical_receipt_matches(
    receipt: &AgentEventAdmissionReceipt,
    context: &HistoricalAgentSignerEvidenceValidationContext<'_>,
) -> bool {
    receipt.schema.as_str() == SchemaId::AGENT_SIGNER_ADMISSION_RECEIPT_V1
        && receipt.event_id == *context.event_id
        && receipt.realm_id == *context.realm_id
        && receipt.producer_accepted_at == context.producer_accepted_at
        && receipt.agent_id == *context.common.signer_id
        && receipt.verification_method == *context.common.verification_method
        && receipt.producer_signer_resolution_evidence_ref
            == *context.producer_signer_resolution_evidence_ref
        && receipt.receiver_id == *context.receiver_id
        && receipt.proof.kind.as_str() == DETACHED_JWS_KIND
}

fn validate_state_witnesses(
    admission: &AgentAdmissionEvidence,
    context: &AgentEvidenceStateVerificationContext<'_>,
) -> Result<bool, AgentEvidenceRejectedReason> {
    let snapshot = &admission.agent_authority_state_evidence;
    let key = &snapshot.state.key_state_witness;
    let lifecycle = &snapshot.state.agent_lifecycle_witness;
    let binding = &snapshot.state.signing_key_binding;
    let key_value = serde_json::to_value(&key.cell_value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let lifecycle_value = serde_json::to_value(lifecycle.cell_value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(key.component.as_str() == AGENT_KEY_COMPONENT
        && context.signer_actor_id.as_account_id().is_some()
        && context.signer_actor_id.signing_principal_id() == context.signer_id
        && key.agent_id == *context.signer_id
        && key.authorization_event_id == *context.agent_key_authorize_event_id
        && key.seal.id == key.seal_id
        && key.seal.state_root == key.state_root
        && key.seal.realm_id == snapshot.state.principal_control_realm_id
        && agent_authorization_cell_ref(context.signer_id, context.agent_key_id).ok()
            == Some(key.cell_ref.clone())
        && value_contains_authorization_record(
            &key_value,
            binding,
            context.authorize_public_key_digest,
            context.authorize_signing_key_binding_digest,
        )
        && verify_witness_branch(
            &key.cell_ref,
            &key_value,
            &key.leaf_digest,
            key.leaf_index,
            key.leaf_count,
            &key.inclusion_proof,
            &key.state_root,
        )
        && lifecycle.component.as_str() == AGENT_STATUS_COMPONENT
        && lifecycle.agent_id == *context.signer_id
        && lifecycle.accepted_status_event.actor_id == *context.signer_actor_id
        && lifecycle
            .accepted_status_event
            .executed_by
            .as_ref()
            .is_some_and(|controller_actor_id| {
                controller_actor_id.signing_principal_id() == context.controller_principal_id
            })
        && lifecycle.seal.id == lifecycle.seal_id
        && lifecycle.seal.state_root == lifecycle.state_root
        && lifecycle.seal.realm_id == snapshot.state.principal_control_realm_id
        && agent_lifecycle_cell_ref(context.signer_actor_id).ok()
            == Some(lifecycle.cell_ref.clone())
        && verify_witness_branch(
            &lifecycle.cell_ref,
            &lifecycle_value,
            &lifecycle.leaf_digest,
            lifecycle.leaf_index,
            lifecycle.leaf_count,
            &lifecycle.inclusion_proof,
            &lifecycle.state_root,
        ))
}

fn validate_seal_lineage(
    admission: &AgentAdmissionEvidence,
    context: &AgentEvidenceStateVerificationContext<'_>,
) -> Result<bool, AgentEvidenceRejectedReason> {
    let snapshot = &admission.agent_authority_state_evidence;
    let core = &snapshot.state;
    if core.seal_lineages.is_empty() || core.seal_lineages.len() > MAX_SEAL_LINEAGE {
        return Ok(false);
    }
    let mut seals = BTreeMap::<String, &Seal>::new();
    for seal in &core.seal_lineages {
        if seal.realm_id != core.principal_control_realm_id
            || seal.validate_structural().is_err()
            || (context.verify_seal_signature)(seal).is_err()
            || seals.insert(seal.id.as_str().to_owned(), seal).is_some()
        {
            return Ok(false);
        }
    }
    let mut referenced = BTreeSet::new();
    for seal in seals.values() {
        for predecessor_id in &seal.predecessor_refs {
            let Some(predecessor) = seals.get(predecessor_id.as_str()) else {
                return Ok(false);
            };
            if predecessor_id == &seal.id || predecessor.sealed_at > seal.sealed_at {
                return Err(AgentEvidenceRejectedReason::AuthorizationConflicted);
            }
            referenced.insert(predecessor_id.as_str().to_owned());
        }
    }
    let heads = seals
        .keys()
        .filter(|seal_id| !referenced.contains(seal_id.as_str()))
        .collect::<Vec<_>>();
    Ok(heads.len() == 1
        && heads[0].as_str() == core.frontier_seal_id.as_str()
        && seals
            .get(core.frontier_seal_id.as_str())
            .is_some_and(|seal| seal.state_root == core.frontier_state_root)
        && seal_is_ancestor(
            &seals,
            core.key_state_witness.seal_id.as_str(),
            core.frontier_seal_id.as_str(),
        )?
        && seal_is_ancestor(
            &seals,
            core.agent_lifecycle_witness.seal_id.as_str(),
            core.frontier_seal_id.as_str(),
        )?)
}

fn seal_is_ancestor(
    seals: &BTreeMap<String, &Seal>,
    ancestor_id: &str,
    descendant_id: &str,
) -> Result<bool, AgentEvidenceRejectedReason> {
    let mut pending = vec![descendant_id.to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(seal_id) = pending.pop() {
        if !seen.insert(seal_id.clone()) {
            continue;
        }
        if seal_id == ancestor_id {
            return Ok(true);
        }
        let Some(seal) = seals.get(&seal_id) else {
            return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
        };
        pending.extend(
            seal.predecessor_refs
                .iter()
                .map(SealId::as_str)
                .map(ToOwned::to_owned),
        );
    }
    Ok(false)
}

fn verify_witness_branch(
    cell_ref: &NonEmptyString,
    cell_value: &Value,
    declared_leaf_digest: &Hash,
    leaf_index: u64,
    leaf_count: u64,
    inclusion_proof: &[Hash],
    state_root: &Hash,
) -> bool {
    let Ok(cell_ref) = CellRef::new(cell_ref.as_str().to_owned()) else {
        return false;
    };
    let Some((suite, _)) = state_root.as_str().split_once(':') else {
        return false;
    };
    let Ok(digest_suite) = arkret_canonical::digest_suite(suite) else {
        return false;
    };
    let Ok(computed_leaf_digest) =
        arkret_state::state_value_leaf_digest(&cell_ref, cell_value, digest_suite)
    else {
        return false;
    };
    computed_leaf_digest == *declared_leaf_digest
        && arkret_state::verify_state_inclusion_proof(
            declared_leaf_digest,
            leaf_index,
            leaf_count,
            inclusion_proof,
            state_root,
            digest_suite,
        )
        .unwrap_or(false)
}

pub fn agent_signing_public_key_digest(
    public_key: &AgentSigningPublicKey,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    if public_key.kty.as_str() != "OKP" || public_key.algorithm.as_str() != "Ed25519" {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let raw = base64url_decode(public_key.key.as_str())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    if arkret_canonical::base64url_encode(raw) != public_key.key.as_str() {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Hash::new(canonical::sha256_digest(raw))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

/// Reconstruct the canonical runtime-request JWK digest from a public signing
/// binding. This digest belongs only to the private pairing request domain; it
/// is deliberately distinct from [`agent_signing_public_key_digest`], which
/// hashes the 32-byte Ed25519 key used by the public authorization contract.
pub fn agent_signing_public_key_runtime_request_digest(
    verification_method: &DidUrl,
    public_key: &AgentSigningPublicKey,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    agent_runtime_public_key_digest(&serde_json::json!({
        "kty": public_key.kty,
        "kid": verification_method,
        "algorithm": "Ed25519",
        "key": public_key.key,
    }))
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn canonical_digest(value: &impl Serialize) -> Result<Hash, AgentEvidenceRejectedReason> {
    Hash::new(
        canonical::canonical_sha256(value)
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
    )
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn outer_core_digest(evidence: &AgentSignerEvidence) -> Result<Hash, AgentEvidenceRejectedReason> {
    let mut value = serde_json::to_value(evidence)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    value
        .as_object_mut()
        .and_then(|object| object.remove("outer_attestation"))
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    canonical_digest(&value)
}

fn outer_core_digest_for_signing(
    evidence: &AgentSignerEvidence,
) -> Result<Hash, AgentEvidenceSigningError> {
    let mut value = serde_json::to_value(evidence)?;
    value
        .as_object_mut()
        .and_then(|object| object.remove("outer_attestation"))
        .ok_or(AgentEvidenceSigningError::InvalidProofShape(
            "outer_attestation is missing",
        ))?;
    let digest = canonical::canonical_sha256(&value)?;
    Hash::new(digest)
        .map_err(|error| AgentEvidenceSigningError::InvalidIdentifier(error.to_string()))
}

fn verify_domain_proof(
    domain: &str,
    value: &impl Serialize,
    proof: &AgentDetachedJws,
    public_key: &PublicKeyMaterial,
) -> Result<(), AgentEvidenceRejectedReason> {
    if proof.kind.as_str() != DETACHED_JWS_KIND {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let mut value =
        serde_json::to_value(value).map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    remove_nested_jws(&mut value)?;
    let canonical = canonical::canonical_json_value_bytes(&value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let mut signing_bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    signing_bytes.extend_from_slice(domain.as_bytes());
    signing_bytes.push(b'\n');
    signing_bytes.extend_from_slice(&canonical);
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(proof.jws.as_str(), &signing_bytes, public_key)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn remove_nested_jws(value: &mut Value) -> Result<(), AgentEvidenceRejectedReason> {
    let object = value
        .as_object_mut()
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let proof = if object.contains_key("proof") {
        object.get_mut("proof")
    } else {
        object.get_mut("controller_proof")
    }
    .and_then(Value::as_object_mut)
    .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    proof
        .remove("jws")
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(())
}

fn remove_nested_jws_for_signing(value: &mut Value) -> Result<(), AgentEvidenceSigningError> {
    let object = value
        .as_object_mut()
        .ok_or(AgentEvidenceSigningError::InvalidProofShape(
            "signed value is not an object",
        ))?;
    let proof = if object.contains_key("proof") {
        object.get_mut("proof")
    } else {
        object.get_mut("controller_proof")
    }
    .and_then(Value::as_object_mut)
    .ok_or(AgentEvidenceSigningError::InvalidProofShape(
        "proof object is missing",
    ))?;
    proof
        .remove("jws")
        .ok_or(AgentEvidenceSigningError::InvalidProofShape(
            "proof.jws is missing",
        ))?;
    Ok(())
}

fn rejected(reason: AgentEvidenceRejectedReason) -> AgentSignerEvidenceVerdict {
    AgentSignerEvidenceVerdict::Rejected(reason)
}

fn did_url_controller(method: &DidUrl) -> &str {
    method.as_str().split_once('#').map_or("", |(did, _)| did)
}

fn did_url_controller_core_id(method: &DidUrl) -> Result<DidCoreId, AgentEvidenceRejectedReason> {
    let controller = Did::new(did_url_controller(method).to_owned())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    project_did_to_core_id(&controller).map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn value_contains_authorization_record(
    value: &Value,
    binding: &AgentSigningKeyBinding,
    authorize_public_key_digest: &Hash,
    binding_digest: &Hash,
) -> bool {
    match value {
        Value::Object(values) => {
            let exact_record = values
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|event_dot| {
                    agent_authorization_dot_matches_event(
                        event_dot,
                        binding.agent_key_authorize_event_id.as_str(),
                    ) && values
                        .get("value")
                        .and_then(Value::as_object)
                        .is_some_and(|record| {
                            authorization_record_fields_match(
                                record,
                                binding,
                                authorize_public_key_digest,
                                binding_digest,
                            )
                        })
                });
            exact_record
                || values.values().any(|nested| {
                    value_contains_authorization_record(
                        nested,
                        binding,
                        authorize_public_key_digest,
                        binding_digest,
                    )
                })
        }
        Value::Array(values) => values.iter().any(|nested| {
            value_contains_authorization_record(
                nested,
                binding,
                authorize_public_key_digest,
                binding_digest,
            )
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[cfg(test)]
mod producer_tests {
    use arkret_models_identity::agent_signer_evidence::AgentAuthorityStateLease;
    use serde_json::json;

    use super::*;

    #[test]
    fn signed_authority_state_lease_rejects_evidence_tamper() {
        let signing_key = SigningKey::from_bytes(&[29_u8; 32]);
        let mut lease: AgentAuthorityStateLease = serde_json::from_value(json!({
            "authority_kind": "agent_authority",
            "authority_id": "ak:did_core:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "verification_method": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "state_digest": format!("sha256:{}", "11".repeat(32)),
            "issued_at": "2026-08-10T00:00:00.000Z",
            "expires_at": "2026-08-10T00:02:00.000Z",
            "proof": {"kind": "detached_jws", "jws": "pending"}
        }))
        .unwrap();
        sign_agent_authority_state_lease(&mut lease, &signing_key).unwrap();
        let material = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        verify_domain_proof(
            AUTHORITY_STATE_LEASE_DOMAIN,
            &lease,
            &lease.proof,
            &material,
        )
        .unwrap();

        lease.state_digest = Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap();
        assert!(
            verify_domain_proof(
                AUTHORITY_STATE_LEASE_DOMAIN,
                &lease,
                &lease.proof,
                &material
            )
            .is_err()
        );
    }
}

fn authorization_record_fields_match(
    record: &serde_json::Map<String, Value>,
    binding: &AgentSigningKeyBinding,
    authorize_public_key_digest: &Hash,
    binding_digest: &Hash,
) -> bool {
    record.get("agent_id").and_then(Value::as_str) == Some(binding.agent_id.as_str())
        && record.get("key_id").and_then(Value::as_str) == Some(binding.agent_key_id.as_str())
        && record.get("verification_method").and_then(Value::as_str)
            == Some(binding.verification_method.as_str())
        && record.get("public_key_digest").and_then(Value::as_str)
            == Some(authorize_public_key_digest.as_str())
        && record
            .get("signing_key_binding_digest")
            .and_then(Value::as_str)
            == Some(binding_digest.as_str())
}

#[cfg(test)]
mod digest_domain_tests {
    use super::*;

    #[test]
    fn authorization_digest_hashes_raw_key_not_runtime_jwk() {
        let public_key = AgentSigningPublicKey {
            kty: NonEmptyString::new("OKP").unwrap(),
            algorithm: NonEmptyString::new("Ed25519").unwrap(),
            key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([42_u8; 32]))
                .unwrap(),
        };
        let verification_method = DidUrl::new("did:web:agent.example#runtime-key-1").unwrap();

        let authorization_digest = agent_signing_public_key_digest(&public_key).unwrap();
        let runtime_request_digest =
            agent_signing_public_key_runtime_request_digest(&verification_method, &public_key)
                .unwrap();

        assert_eq!(
            authorization_digest.as_str(),
            "sha256:544e62cee8033709e389e5b2755343d0d0fa8c4850215cfb6331717e80d1aea3"
        );
        assert_ne!(authorization_digest, runtime_request_digest);
    }

    #[test]
    fn lifecycle_cell_subject_binds_complete_agent_account_identity() {
        let agent_id =
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixture:agent.example").unwrap())
                .unwrap();
        let station_a = DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
        let station_b = DidCoreId::new("ak:did_core:web:station-b.example").unwrap();
        let actor_a = ActorId::account(arkret_wire::AccountId::new(agent_id.clone(), station_a));
        let actor_b = ActorId::account(arkret_wire::AccountId::new(agent_id.clone(), station_b));

        assert_ne!(
            agent_lifecycle_cell_ref(&actor_a).unwrap(),
            agent_lifecycle_cell_ref(&actor_b).unwrap()
        );
        assert!(agent_lifecycle_cell_ref(&ActorId::service(agent_id)).is_err());
    }
}
