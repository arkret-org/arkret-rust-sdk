//! Agent authorization Event and portable signer-evidence verification.
//!
//! Current admission and historical Event verification intentionally expose
//! different entry points. Callers cannot pass current state as a substitute
//! for an authenticated historical acceptance.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::{base64url_decode, canonical};
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthorizationStatus,
    AgentAuthorizedSigningKey, AgentDetachedJws, AgentLifecycleProvenance, AgentLifecycleStatus,
    AgentLifecycleWitness, AgentSignerEvidence, AgentSigningPublicKey,
    ControllerAccountEligibility, ControllerAccountStatus,
};
use arkret_wire::{
    ActorId, CellRef, Did, DidCoreId, DidUrl, DomainSeparationId, EventId, Hash, NonEmptyString,
    ProfileId, SchemaId, Seal, SealId, project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::Value;

use crate::agent::agent_runtime_public_key_digest;
use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_ed25519_detached_jws};

const AUTHORITY_STATE_LEASE_DOMAIN: &str = DomainSeparationId::AGENT_AUTHORITY_STATE_EVIDENCE_V1;
const CONTROLLER_GATE_DOMAIN: &str = DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1;
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
    expires_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    signer_actor_id: ActorId,
    verification_method: DidUrl,
    verified_state: VerifiedAgentEvidenceState,
    controller_public_key: PublicKeyMaterial,
    authority_public_key: PublicKeyMaterial,
    account_authority_public_key: PublicKeyMaterial,
    lease_digest: Hash,
    gate_digest: Hash,
}

impl VerifiedAgentSigningKey {
    pub fn verified_state(&self) -> &VerifiedAgentEvidenceState {
        &self.verified_state
    }

    pub fn permits(&self, actor: &ActorId, method: &DidUrl, now: DateTime<Utc>) -> bool {
        &self.signer_actor_id == actor
            && &self.verification_method == method
            && now >= self.not_before
            && now < self.expires_at
    }

    pub fn signer_actor_id(&self) -> &ActorId {
        &self.signer_actor_id
    }
    pub fn verification_method(&self) -> &DidUrl {
        &self.verification_method
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

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
    HistoricalClosureMismatch,
    MlsLeafBindingMismatch,
}

impl AgentEvidenceRejectedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongVerificationMode => "agent_evidence_verification_mode_mismatch",
            Self::AuthorizationInactive => "agent_authorization_inactive",
            Self::AuthorizationConflicted => "agent_authorization_conflicted",
            Self::SigningKeyMismatch => "agent_signing_key_mismatch",
            Self::HistoricalClosureMismatch => "agent_historical_closure_mismatch",
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
    signer_actor_id: ActorId,
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
    pub verify_seal_signature: &'a dyn Fn(&Seal) -> Result<(), AgentEvidenceRejectedReason>,
    pub verify_control_event_signature:
        &'a dyn Fn(&arkret_wire::Event) -> Result<(), AgentEvidenceRejectedReason>,
}

/// Independently established trust inputs shared by both verification modes.
/// The verified-state token has a private constructor and is bound to the
/// exact stable state and witnessed identity.
pub struct AgentEvidenceCommonContext<'a> {
    pub signer_id: &'a DidCoreId,
    pub agent_key_id: &'a NonEmptyString,
    pub controller_principal_id: &'a DidCoreId,
    pub verification_method: &'a DidUrl,
    pub agent_key_authorize_event_id: &'a EventId,
    pub authorize_public_key_digest: &'a Hash,
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
}

pub struct HistoricalAgentSignerEvidenceValidationContext<'a> {
    pub common: AgentEvidenceCommonContext<'a>,
    pub observed_at: DateTime<Utc>,
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
    for event in [
        &snapshot.state.pcr_genesis_event,
        &snapshot.state.key_authorization_event,
        &snapshot.state.agent_lifecycle_witness.accepted_status_event,
    ] {
        (context.verify_control_event_signature)(event)?;
    }
    Ok(VerifiedAgentEvidenceState {
        signer_actor_id: context.signer_actor_id.clone(),
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

/// Check the inline key and identity against independently established authority.
#[allow(clippy::too_many_arguments)]
pub fn verify_agent_authorized_signing_key(
    key: &AgentAuthorizedSigningKey,
    expected_agent_id: &DidCoreId,
    expected_agent_key_id: &NonEmptyString,
    expected_controller_principal_id: &DidCoreId,
    expected_verification_method: &DidUrl,
    expected_authorize_event_id: &EventId,
    expected_public_key_digest: &Hash,
) -> Result<[u8; 32], AgentEvidenceRejectedReason> {
    if &key.agent_id != expected_agent_id
        || &key.agent_key_id != expected_agent_key_id
        || &key.controller_principal_id != expected_controller_principal_id
        || &key.verification_method != expected_verification_method
        || &key.agent_key_authorize_event_id != expected_authorize_event_id
        || did_url_controller_core_id(&key.verification_method)? != key.agent_id
        || agent_signing_public_key_digest(&key.public_key)? != *expected_public_key_digest
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    base64url_decode(key.public_key.key.as_str())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?
        .try_into()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

pub fn validate_current_agent_signer_evidence(
    evidence: Option<&AgentSignerEvidence>,
    context: &CurrentAgentSignerEvidenceValidationContext<'_>,
) -> AgentSignerEvidenceVerdict {
    refresh_current_agent_signer_evidence(evidence, context, None)
}

pub fn refresh_current_agent_signer_evidence(
    evidence: Option<&AgentSignerEvidence>,
    context: &CurrentAgentSignerEvidenceValidationContext<'_>,
    previous: Option<&VerifiedAgentSigningKey>,
) -> AgentSignerEvidenceVerdict {
    let Some(evidence) = evidence else {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
    };
    let AgentSignerEvidence::CurrentAdmission {
        schema,
        admission_evidence,
        transparency,
    } = evidence
    else {
        return rejected(AgentEvidenceRejectedReason::WrongVerificationMode);
    };
    if schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_V1 {
        return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    common_verdict(validate_common_evidence(
        evidence,
        admission_evidence,
        transparency.is_some(),
        context.common.now,
        &context.common,
        previous,
    ))
}

fn common_verdict(
    result: Result<VerifiedAgentSigningKey, CommonEvidenceFailure>,
) -> AgentSignerEvidenceVerdict {
    match result {
        Ok(key) => AgentSignerEvidenceVerdict::Verified(key),
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
        authorization_closure_refs,
        transparency,
    } = evidence
    else {
        return rejected(AgentEvidenceRejectedReason::WrongVerificationMode);
    };
    if schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_V1 {
        return rejected(AgentEvidenceRejectedReason::HistoricalClosureMismatch);
    }
    if authorization_closure_refs
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return rejected(AgentEvidenceRejectedReason::HistoricalClosureMismatch);
    }
    common_verdict(validate_common_evidence(
        evidence,
        admission_evidence,
        transparency.is_some(),
        context.observed_at,
        &context.common,
        None,
    ))
}

enum CommonEvidenceFailure {
    Unresolved(AgentEvidenceUnresolvedReason),
    Rejected(AgentEvidenceRejectedReason),
}

impl From<AgentEvidenceRejectedReason> for CommonEvidenceFailure {
    fn from(reason: AgentEvidenceRejectedReason) -> Self {
        Self::Rejected(reason)
    }
}

fn validate_common_evidence(
    evidence: &AgentSignerEvidence,
    admission: &AgentAdmissionEvidence,
    has_transparency: bool,
    basis_time: DateTime<Utc>,
    context: &AgentEvidenceCommonContext<'_>,
    previous: Option<&VerifiedAgentSigningKey>,
) -> Result<VerifiedAgentSigningKey, CommonEvidenceFailure> {
    let snapshot = &admission.agent_authority_state_evidence;
    let core = &snapshot.state;
    let binding = AgentAuthorizedSigningKey::from_event(&core.key_authorization_event)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let authorization = &core.authorization;
    let key_witness = &core.key_state_witness;
    let lifecycle = &core.agent_lifecycle_witness;
    let gate = &admission.controller_account_gate_attestation;

    let expected_state_digest = canonical_digest(&snapshot.state)?;
    let expected_admission_digest = agent_admission_evidence_digest(snapshot, gate)?;
    let lease_digest = canonical_digest(&snapshot.lease)?;
    let gate_digest = canonical_digest(gate)?;
    let unchanged_lease = previous.is_some_and(|key| {
        key.lease_digest == lease_digest
            && key.authority_public_key == *context.authority_public_key
    });
    let unchanged_gate = previous.is_some_and(|key| {
        key.gate_digest == gate_digest
            && key.account_authority_public_key == *context.account_authority_public_key
    });
    let lease_authority_id = did_url_controller_core_id(&snapshot.lease.verification_method)?;
    if snapshot.state_digest != expected_state_digest
        || admission.admission_evidence_digest != expected_admission_digest
        || snapshot.lease.authority_kind.as_str() != "agent_authority"
        || snapshot.lease.authority_id != core.authority_id
        || snapshot.lease.authority_id != *context.expected_authority_id
        || snapshot.lease.verification_method != *context.expected_authority_verification_method
        || snapshot.lease.state_digest != snapshot.state_digest
        || lease_authority_id != snapshot.lease.authority_id
        || snapshot.lease.issued_at >= snapshot.lease.expires_at
        || snapshot.lease.expires_at > snapshot.lease.issued_at + chrono::Duration::seconds(300)
        || basis_time < snapshot.lease.issued_at
        || (!unchanged_lease
            && verify_domain_proof(
                AUTHORITY_STATE_LEASE_DOMAIN,
                &snapshot.lease,
                &snapshot.lease.proof,
                context.authority_public_key,
            )
            .is_err())
    {
        return Err(CommonEvidenceFailure::Rejected(
            AgentEvidenceRejectedReason::SigningKeyMismatch,
        ));
    }
    if basis_time >= snapshot.lease.expires_at || basis_time >= gate.expires_at {
        return Err(CommonEvidenceFailure::Unresolved(
            AgentEvidenceUnresolvedReason::Stale,
        ));
    }
    let key = if let Some(previous) = previous.filter(|key| {
        key.state_digest == snapshot.state_digest
            && key.signer == *context.signer_id
            && key.verification_method == *context.verification_method
            && key.controller_public_key == *context.controller_public_key
    }) {
        previous.key
    } else {
        verify_agent_authorized_signing_key(
            &binding,
            context.signer_id,
            context.agent_key_id,
            context.controller_principal_id,
            context.verification_method,
            context.agent_key_authorize_event_id,
            context.authorize_public_key_digest,
        )?
    };
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
        || lifecycle.cell_value != AgentLifecycleStatus::Active
        || gate.schema.as_str() != SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1
        || gate.principal_id.as_str() != context.controller_principal_id.as_str()
        || gate.authority_id != *context.expected_account_authority_id
        || gate.authority_id != *context.verified_state.signer_actor_id.route_service_id()
        || gate.verification_method != *context.expected_account_authority_verification_method
        || gate.issued_at >= gate.expires_at
        || gate.expires_at - gate.issued_at > chrono::Duration::seconds(300)
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
    if verified_state.state_digest != snapshot.state_digest
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
        || (!unchanged_gate
            && verify_domain_proof(
                CONTROLLER_GATE_DOMAIN,
                gate,
                &gate.proof,
                context.account_authority_public_key,
            )
            .is_err())
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
        verified_state: context.verified_state.clone(),
        controller_public_key: context.controller_public_key.clone(),
        authority_public_key: context.authority_public_key.clone(),
        account_authority_public_key: context.account_authority_public_key.clone(),
        lease_digest,
        gate_digest,
        signer: context.signer_id.clone(),
        authority_id: context.expected_authority_id.clone(),
        key,
        authorization_ref: context.agent_key_authorize_event_id.clone(),
        state_digest: snapshot.state_digest.clone(),
        admission_evidence_digest: admission.admission_evidence_digest.clone(),
        signer_actor_id: context.verified_state.signer_actor_id.clone(),
        verification_method: context.verification_method.clone(),
        not_before: admission.valid_from(),
        expires_at: admission.expires_at(),
    })
}

fn validate_state_witnesses(
    admission: &AgentAdmissionEvidence,
    context: &AgentEvidenceStateVerificationContext<'_>,
) -> Result<bool, AgentEvidenceRejectedReason> {
    let snapshot = &admission.agent_authority_state_evidence;
    let key = &snapshot.state.key_state_witness;
    let lifecycle = &snapshot.state.agent_lifecycle_witness;
    let binding = AgentAuthorizedSigningKey::from_event(&snapshot.state.key_authorization_event)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let key_value = serde_json::to_value(&key.cell_value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let lifecycle_value = serde_json::to_value(lifecycle.cell_value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let genesis = &snapshot.state.pcr_genesis_event;
    let authorize = &snapshot.state.key_authorization_event;
    let expected_controller = ActorId::account(arkret_wire::AccountId::new(
        context.controller_principal_id.clone(),
        context.signer_actor_id.route_service_id().clone(),
    ));
    let authorization_payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            authorize,
        )
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(genesis.kind == arkret_wire::EventKind::RealmCreate
        && genesis.event_id == snapshot.state.principal_control_realm_id.event_id()
        && authorize.event_id == *context.agent_key_authorize_event_id
        && [genesis, authorize, &lifecycle.accepted_status_event]
            .iter()
            .all(|event| {
                event.actor_id == *context.signer_actor_id
                    && event.realm_id == snapshot.state.principal_control_realm_id
                    && event.executed_by.as_ref() == Some(&expected_controller)
                    && event.authorization_ref == genesis.authorization_ref
            })
        && binding.public_key_digest == *context.authorize_public_key_digest
        && authorization_payload.agent_id == binding.agent_id
        && authorization_payload.key_id == binding.agent_key_id
        && authorization_payload.issued_at == binding.issued_at
        && authorization_payload.expires_at == binding.expires_at
        && authorization_payload.verification_method == binding.verification_method
        && authorization_payload.accountable_principal_id == *context.controller_principal_id
        && key.component.as_str() == AGENT_KEY_COMPONENT
        && context.signer_actor_id.as_account_id().is_some()
        && snapshot.state.authority_id == *context.signer_actor_id.route_service_id()
        && context.signer_actor_id.signing_principal_id() == context.signer_id
        && key.agent_id == *context.signer_id
        && key.authorization_event_id == *context.agent_key_authorize_event_id
        && key.seal.id == key.seal_id
        && snapshot.state.authorization.accepted_at == key.seal.sealed_at
        && key.seal.state_root == key.state_root
        && key.seal.realm_id == snapshot.state.principal_control_realm_id
        && agent_authorization_cell_ref(context.signer_id, context.agent_key_id).ok()
            == Some(key.cell_ref.clone())
        && key
            .cell_value
            .iter()
            .filter(|entry| {
                agent_authorization_dot_matches_event(
                    entry.tag.as_str(),
                    authorize.event_id.as_str(),
                )
            })
            .count()
            == 1
        && key.cell_value.iter().any(|entry| {
            agent_authorization_dot_matches_event(entry.tag.as_str(), authorize.event_id.as_str())
                && entry.value == Value::Object(authorize.payload.clone().into_iter().collect())
        })
        && verify_witness_branch(
            &key.cell_ref,
            &key.authorization_event_id,
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
        && verify_lifecycle_branch(lifecycle, &lifecycle_value)
        && lifecycle_provenance_matches(lifecycle, &snapshot.state.seal_lineages))
}

/// Verify an accepted lifecycle Event with its producer key.
pub fn verify_agent_lifecycle_event_signature(
    witness: &AgentLifecycleWitness,
    resolve_key: &dyn Fn(&DidUrl) -> Option<PublicKeyMaterial>,
) -> Result<(), AgentEvidenceRejectedReason> {
    verify_agent_accepted_event_signature(&witness.accepted_status_event, resolve_key)
}

pub fn verify_agent_accepted_event_signature(
    event: &arkret_wire::Event,
    resolve_key: &dyn Fn(&DidUrl) -> Option<PublicKeyMaterial>,
) -> Result<(), AgentEvidenceRejectedReason> {
    let reject = || AgentEvidenceRejectedReason::SigningKeyMismatch;
    let controller = event.executed_by.as_ref().ok_or_else(reject)?;
    let suite = event
        .event_id
        .event_digest()
        .digest_suite()
        .map_err(|_| reject())?;
    event
        .validate_for_direct_history_structural()
        .map_err(|_| reject())?;
    let [producer] = event.proofs.as_slice() else {
        return Err(reject());
    };
    if did_url_controller_core_id(&producer.verification_method)
        .ok()
        .as_ref()
        != Some(controller.signing_principal_id())
    {
        return Err(reject());
    }
    let key = resolve_key(&producer.verification_method).ok_or_else(reject)?;
    let payload = event.digest_payload().map_err(|_| reject())?;
    let bytes = arkret_canonical::canonical_json_bytes(&payload).map_err(|_| reject())?;
    crate::verify_ed25519_detached_jws_proof_with_digest_suite(
        producer,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(|_| reject())
}

/// Cross-bind the reducer head to the exact lifecycle Event and its accepted
/// ancestry. Signature/lineage verification remains mandatory in the caller.
fn lifecycle_provenance_matches(witness: &AgentLifecycleWitness, lineage: &[Seal]) -> bool {
    let event = &witness.accepted_status_event;
    if event.realm_id != witness.seal.realm_id {
        return false;
    }
    let digest = event.event_id.event_digest();
    let Ok(suite) = digest.digest_suite() else {
        return false;
    };
    if event.event_digest_with_digest_suite(suite).ok().as_deref() != Some(digest.as_str()) {
        return false;
    }
    let Ok(writes) = arkret_schema::project_registered_cell_writes(event, suite) else {
        return false;
    };
    let mut status_writes = writes
        .iter()
        .filter(|write| write.cell_id.as_str() == witness.cell_ref.as_str());
    let Some(write) = status_writes.next() else {
        return false;
    };
    let Ok(expected) = serde_json::to_value(witness.cell_value) else {
        return false;
    };
    let matches = match &write.op {
        arkret_wire::ProjectedOp::Direct(op) => {
            op.op_type == arkret_wire::LatticeOpType::Transition
                && op.to.as_ref() == Some(&expected)
        }
        arkret_wire::ProjectedOp::TransitionTo { to } => to == &expected,
        _ => false,
    };
    if !matches || status_writes.next().is_some() {
        return false;
    }
    let seals = lineage
        .iter()
        .map(|seal| (seal.id.to_string(), seal))
        .collect::<BTreeMap<_, _>>();
    if !lineage.iter().any(|seal| {
        (seal.delta.contains(&digest) || seal.covered_event_digests.contains(&digest))
            && seal_is_ancestor(&seals, seal.id.as_str(), witness.seal_id.as_str()).unwrap_or(false)
    }) {
        return false;
    }
    match (&witness.cell_value, &witness.provenance) {
        (
            AgentLifecycleStatus::Active,
            AgentLifecycleProvenance::DelegatedPcrGenesis {
                realm_create_event_id,
            },
        ) => {
            event.kind == arkret_wire::EventKind::RealmCreate
                && event
                    .payload
                    .get("object")
                    .and_then(|object| object.get("purpose"))
                    .and_then(Value::as_str)
                    == Some("agent_control")
                && event.event_id == *realm_create_event_id
                && !event
                    .refs
                    .iter()
                    .any(|reference| reference.role == "agent_provision")
        }
        (
            AgentLifecycleStatus::Paused,
            AgentLifecycleProvenance::PauseAccepted { pause_event_id },
        ) => {
            event.kind == arkret_wire::EventKind::SelfAgentPause
                && event.event_id == *pause_event_id
                && event.payload.get("transition").and_then(Value::as_str) == Some("pause")
                && event.payload.get("previous_status").and_then(Value::as_str) == Some("active")
        }
        (
            AgentLifecycleStatus::Active,
            AgentLifecycleProvenance::ResumeAccepted { resume_event_id },
        ) => {
            event.kind == arkret_wire::EventKind::SelfAgentResume
                && event.event_id == *resume_event_id
                && event.payload.get("transition").and_then(Value::as_str) == Some("resume")
                && event.payload.get("previous_status").and_then(Value::as_str) == Some("paused")
        }
        (
            AgentLifecycleStatus::Deactivated,
            AgentLifecycleProvenance::DeactivateAccepted {
                deactivate_event_id,
            },
        ) => {
            event.kind == arkret_wire::EventKind::SelfAgentDeactivate
                && event.event_id == *deactivate_event_id
                && event.payload.get("transition").and_then(Value::as_str) == Some("deactivate")
                && matches!(
                    event.payload.get("previous_status").and_then(Value::as_str),
                    Some("active" | "paused")
                )
        }
        _ => false,
    }
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
        for predecessor_id in seal.predecessor_ref.iter() {
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
            seal.predecessor_ref
                .iter()
                .map(SealId::as_str)
                .map(ToOwned::to_owned),
        );
    }
    Ok(false)
}

/// Verify the sequenced-state leaf against the exact accepted status revision.
fn verify_lifecycle_branch(lifecycle: &AgentLifecycleWitness, settled: &Value) -> bool {
    let Ok(cell_ref) = CellRef::new(lifecycle.cell_ref.as_str().to_owned()) else {
        return false;
    };
    let Some((suite, _)) = lifecycle.state_root.as_str().split_once(':') else {
        return false;
    };
    let Ok(digest_suite) = arkret_canonical::digest_suite(suite) else {
        return false;
    };
    let Ok(computed) = arkret_state::state::state_root::state_leaf_hash_from_state_object(
        &cell_ref,
        serde_json::json!({
            "revision_event_id": lifecycle.accepted_status_event.event_id,
            "value": settled,
        }),
        digest_suite,
    ) else {
        return false;
    };
    computed == lifecycle.leaf_digest
        && arkret_state::verify_state_inclusion_proof(
            &lifecycle.leaf_digest,
            lifecycle.leaf_index,
            lifecycle.leaf_count,
            &lifecycle.inclusion_proof,
            &lifecycle.state_root,
            digest_suite,
        )
        .unwrap_or(false)
}

fn verify_witness_branch(
    cell_ref: &NonEmptyString,
    revision_event_id: &EventId,
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
    let Ok(computed_leaf_digest) = arkret_state::state_leaf_hash_from_state_object(
        &cell_ref,
        serde_json::json!({
            "revision_event_id": revision_event_id,
            "value": cell_value,
        }),
        digest_suite,
    ) else {
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
    ed25519_dalek::VerifyingKey::from_bytes(&raw)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
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
    let proof = object
        .get_mut("proof")
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
    let proof = object
        .get_mut("proof")
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

#[cfg(test)]
mod digest_domain_tests {
    use super::*;

    #[test]
    fn agent_key_digest_domains_reject_non_curve_points() {
        let verification_method = DidUrl::new("did:web:agent.example#runtime-key-1").unwrap();
        let valid = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        for (raw, accepted) in [([7_u8; 32], false), (valid, true)] {
            let public_key = AgentSigningPublicKey {
                kty: NonEmptyString::new("OKP").unwrap(),
                algorithm: NonEmptyString::new("Ed25519").unwrap(),
                key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(raw))
                    .unwrap(),
            };
            assert_eq!(
                agent_signing_public_key_digest(&public_key).is_ok(),
                accepted
            );
            assert_eq!(
                agent_signing_public_key_runtime_request_digest(&verification_method, &public_key)
                    .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn both_runtime_key_projections_hash_the_same_raw_key() {
        // v1 has one Agent runtime key digest domain: the raw 32-byte key. The request and
        // authorization projections therefore agree by construction, and a digest taken over the
        // runtime JWK is not that domain. Two domains used to exist, and comparing across them
        // made every server answer look like a different runtime, so the equality is the guard.
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
        assert_eq!(authorization_digest, runtime_request_digest);
        assert_ne!(
            authorization_digest.as_str(),
            arkret_canonical::canonical_sha256(&public_key).unwrap()
        );
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

#[cfg(test)]
mod reusable_authority_tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn verified_key_reuses_exact_account_and_method_until_original_expiry() {
        let actor = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let method = DidUrl::new("did:web:agent.example#runtime").unwrap();
        let expires_at = Utc.with_ymd_and_hms(2026, 9, 9, 0, 5, 0).unwrap();
        let key = VerifiedAgentSigningKey {
            verified_state: VerifiedAgentEvidenceState {
                signer_actor_id: actor.clone(),
                state_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                signer_id: actor.signing_principal_id().clone(),
                authorization_event_id: EventId::new(
                    "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g",
                )
                .unwrap(),
                key_seal_id: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
                lifecycle_seal_id: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                    .unwrap(),
            },
            controller_public_key: PublicKeyMaterial::Ed25519Raw { bytes: vec![7; 32] },
            authority_public_key: PublicKeyMaterial::Ed25519Raw { bytes: vec![7; 32] },
            account_authority_public_key: PublicKeyMaterial::Ed25519Raw { bytes: vec![7; 32] },
            lease_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            gate_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            signer: actor.signing_principal_id().clone(),
            authority_id: actor.route_service_id().clone(),
            key: [7; 32],
            authorization_ref: EventId::new(
                "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g",
            )
            .unwrap(),
            state_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            admission_evidence_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            expires_at,
            not_before: expires_at - chrono::Duration::seconds(300),
            signer_actor_id: actor.clone(),
            verification_method: method.clone(),
        };
        for seconds in [1, 30, 299] {
            assert!(key.permits(
                &actor,
                &method,
                expires_at - chrono::Duration::seconds(seconds)
            ));
        }
        assert!(!key.clone().permits(&actor, &method, expires_at));
        assert!(!key.permits(&actor, &method, expires_at - chrono::Duration::seconds(301)));
        let other_station = ActorId::account(arkret_wire::AccountId::new(
            actor.signing_principal_id().clone(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        assert!(!key.permits(
            &other_station,
            &method,
            expires_at - chrono::Duration::seconds(1)
        ));
        assert!(!key.permits(
            &actor,
            &DidUrl::new("did:web:agent.example#replacement").unwrap(),
            expires_at - chrono::Duration::seconds(1)
        ));
    }
}
