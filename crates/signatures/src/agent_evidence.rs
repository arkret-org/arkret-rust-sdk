//! Native Agent signer-binding, evidence, and ordinary-MLS verification.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::{base64url_decode, canonical};
use arkret_models_collaboration::agent_signer_evidence::{
    AGENT_EVIDENCE_FRESHNESS_CONTEXT, AGENT_KEY_COMPONENT, AGENT_SIGNING_KEY_BINDING_CONTEXT,
    AgentAuthorizationStatus, AgentControllerProof, AgentEvidenceFreshnessAttestation,
    AgentEvidenceSourceProof, AgentSignerEvidence, AgentSigningKeyBinding, AgentSigningPublicKey,
};
use arkret_wire::{
    CellRef, Did, DidUrl, Event, EventId, Hash, NonEmptyString, ProfileId, RealmId, SchemaId,
    SealId,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::agent::agent_runtime_public_key_digest;
use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_eddsa_detached_jws};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentSigningKey {
    pub signer: Did,
    pub key: [u8; 32],
    pub authorization_ref: EventId,
    pub accepted_frontier: NonEmptyString,
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
    AuthorizationInactive,
    AuthorizationConflicted,
    SigningKeyMismatch,
    MlsLeafBindingMismatch,
}

impl AgentEvidenceRejectedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationInactive => "agent_authorization_inactive",
            Self::AuthorizationConflicted => "agent_authorization_conflicted",
            Self::SigningKeyMismatch => "agent_signing_key_mismatch",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontierRelation {
    Covers,
    Behind,
    Conflict,
}

/// Position of the Event's accepted frontier within the authorization's
/// authenticated validity interval.
///
/// Frontier identifiers are opaque protocol values, so the SDK must not infer
/// ordering from their string representation.  The caller computes this
/// relation while verifying the state witness / Seal lineage and supplies the
/// result explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationIntervalRelation {
    Contains,
    Before,
    After,
    Conflict,
}

pub struct AgentSignerEvidenceValidationContext<'a> {
    pub signer_id: &'a Did,
    pub agent_key_id: &'a NonEmptyString,
    pub authorization_realm_id: &'a RealmId,
    pub controller_id: &'a Did,
    pub verification_method: &'a DidUrl,
    pub agent_key_authorize_event_id: &'a EventId,
    pub authorize_public_key_digest: &'a Hash,
    pub authorize_signing_key_binding_digest: &'a Hash,
    pub event_accepted_frontier: &'a NonEmptyString,
    pub event_accepted_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub controller_public_key: &'a PublicKeyMaterial,
    pub seal_lineage_signatures_verified: bool,
    pub freshness_signature_verified: bool,
    pub require_transparency: bool,
    pub transparency_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerPrincipalKind {
    Device,
    NativeAgent,
    Applet,
    Service,
    Integration,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRegime {
    MinimalMetadata,
    OrdinaryDevice,
    OrdinaryNativeAgent,
    AppletOrService,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSignerBinding {
    pub binding_actor_id: Did,
    pub signer_id: Did,
}

pub fn event_signer_binding(event: &Event) -> EventSignerBinding {
    EventSignerBinding {
        binding_actor_id: event.actor_id.clone(),
        signer_id: event
            .executed_by
            .clone()
            .unwrap_or_else(|| event.actor_id.clone()),
    }
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
        SignerPrincipalKind::NativeAgent => Ok(SignerRegime::OrdinaryNativeAgent),
        SignerPrincipalKind::Applet
        | SignerPrincipalKind::Service
        | SignerPrincipalKind::Integration => Ok(SignerRegime::AppletOrService),
        SignerPrincipalKind::Unknown => Err(AgentEvidenceRejectedReason::SigningKeyMismatch),
    }
}

pub fn verify_event_signer_controller(
    event: &Event,
    verification_method: &DidUrl,
) -> Result<EventSignerBinding, AgentEvidenceRejectedReason> {
    let binding = event_signer_binding(event);
    if did_url_controller(verification_method) != binding.signer_id.as_str() {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ok(binding)
}

pub fn agent_signing_key_binding_signing_bytes(
    binding: &AgentSigningKeyBinding,
) -> Result<Vec<u8>, AgentEvidenceRejectedReason> {
    let mut value = serde_json::to_value(binding)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let proof = value
        .get_mut("controller_proof")
        .and_then(Value::as_object_mut)
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    proof
        .remove("jws")
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let canonical = canonical::canonical_json_bytes(&value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let mut bytes = Vec::with_capacity(AGENT_SIGNING_KEY_BINDING_CONTEXT.len() + canonical.len());
    bytes.extend_from_slice(AGENT_SIGNING_KEY_BINDING_CONTEXT.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn agent_signing_key_binding_digest(
    binding: &AgentSigningKeyBinding,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    Hash::new(
        canonical::canonical_sha256(binding)
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
    )
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

/// Canonical `ak.component.agent.key.v1` cell addressed by an authorization
/// binding.  The key cell subject is the registry-declared composite
/// `(agent_id, verification_method)`.
pub fn agent_authorization_cell_ref(
    agent_id: &Did,
    agent_key_id: &NonEmptyString,
) -> Result<NonEmptyString, AgentEvidenceRejectedReason> {
    let subject = arkret_wire::composite_subject(&[agent_id.as_str(), agent_key_id.as_str()])
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    NonEmptyString::new(format!("ak:cell:{AGENT_KEY_COMPONENT}:{subject}"))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

/// Returns true when `dot` is the canonical OR-Set dot produced by one of the
/// registered cell writes of `event_id`.
///
/// Agent authorization witnesses name the durable Event separately from the
/// cell element. The element tag is never the bare Event id: it is the
/// protocol-wide `<event_id>:<write_index>` dot, where `write_index` is a
/// canonical base-10 registry `cell_writes[]` index.
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

pub fn agent_evidence_freshness_signing_bytes(
    attestation: &AgentEvidenceFreshnessAttestation,
) -> Result<Vec<u8>, AgentEvidenceRejectedReason> {
    let mut value = serde_json::to_value(attestation)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let proof = value
        .get_mut("source_proof")
        .and_then(Value::as_object_mut)
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    proof
        .remove("jws")
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let canonical = canonical::canonical_json_bytes(&value)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let mut bytes = Vec::with_capacity(AGENT_EVIDENCE_FRESHNESS_CONTEXT.len() + canonical.len());
    bytes.extend_from_slice(AGENT_EVIDENCE_FRESHNESS_CONTEXT.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn build_agent_evidence_freshness_attestation(
    source_service_id: Did,
    observed_frontier: NonEmptyString,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    source_verification_method: DidUrl,
    source_signing_key: &SigningKey,
) -> Result<AgentEvidenceFreshnessAttestation, AgentEvidenceRejectedReason> {
    if did_url_controller(&source_verification_method) != source_service_id.as_str()
        || expires_at <= issued_at
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let mut attestation = AgentEvidenceFreshnessAttestation {
        source_service_id,
        observed_frontier,
        issued_at,
        expires_at,
        source_proof: AgentEvidenceSourceProof {
            kind: NonEmptyString::new("detached_jws".to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
            verification_method: source_verification_method,
            jws: NonEmptyString::new("pending".to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        },
    };
    let jws = sign_eddsa_detached_jws(
        source_signing_key,
        &agent_evidence_freshness_signing_bytes(&attestation)?,
    )
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    attestation.source_proof.jws =
        NonEmptyString::new(jws).map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(attestation)
}

pub fn verify_agent_evidence_freshness_attestation(
    attestation: &AgentEvidenceFreshnessAttestation,
    source_public_key: &PublicKeyMaterial,
) -> Result<(), AgentEvidenceRejectedReason> {
    if attestation.source_proof.kind.as_str() != "detached_jws"
        || did_url_controller(&attestation.source_proof.verification_method)
            != attestation.source_service_id.as_str()
        || attestation.expires_at <= attestation.issued_at
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            attestation.source_proof.jws.as_str(),
            &agent_evidence_freshness_signing_bytes(attestation)?,
            source_public_key,
        )
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

#[allow(clippy::too_many_arguments)]
pub fn build_agent_signing_key_binding(
    agent_id: Did,
    agent_key_id: NonEmptyString,
    verification_method: DidUrl,
    agent_public_key: [u8; 32],
    agent_key_authorize_event_id: EventId,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    controller_id: Did,
    controller_verification_method: DidUrl,
    controller_signing_key: &SigningKey,
) -> Result<AgentSigningKeyBinding, AgentEvidenceRejectedReason> {
    let public_key = AgentSigningPublicKey {
        kty: NonEmptyString::new("OKP".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        alg: NonEmptyString::new("Ed25519".to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            agent_public_key,
        ))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
    };
    let public_key_digest = agent_signing_public_key_digest(&verification_method, &public_key)?;
    let mut binding = AgentSigningKeyBinding {
        schema: NonEmptyString::new(SchemaId::AGENT_SIGNING_KEY_BINDING_V1.to_owned())
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        agent_id,
        agent_key_id,
        verification_method,
        public_key,
        public_key_digest,
        agent_key_authorize_event_id,
        issued_at,
        expires_at,
        controller_id,
        controller_proof: AgentControllerProof {
            kind: NonEmptyString::new("detached_jws".to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
            verification_method: controller_verification_method,
            jws: NonEmptyString::new("pending".to_owned())
                .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?,
        },
    };
    let signing_bytes = agent_signing_key_binding_signing_bytes(&binding)?;
    let jws = sign_eddsa_detached_jws(controller_signing_key, &signing_bytes)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    binding.controller_proof.jws =
        NonEmptyString::new(jws).map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    Ok(binding)
}

// Each `expected_*` parameter is a separate value the caller must have
// established independently; bundling them would let one unverified field ride
// in on another's provenance.
#[allow(clippy::too_many_arguments)]
pub fn verify_agent_signing_key_binding(
    binding: &AgentSigningKeyBinding,
    expected_agent_id: &Did,
    expected_agent_key_id: &NonEmptyString,
    expected_controller_id: &Did,
    expected_verification_method: &DidUrl,
    expected_authorize_event_id: &EventId,
    expected_public_key_digest: &Hash,
    expected_binding_digest: &Hash,
    controller_public_key: &PublicKeyMaterial,
) -> Result<[u8; 32], AgentEvidenceRejectedReason> {
    if binding.schema.as_str() != SchemaId::AGENT_SIGNING_KEY_BINDING_V1
        || &binding.agent_id != expected_agent_id
        || &binding.agent_key_id != expected_agent_key_id
        || &binding.controller_id != expected_controller_id
        || &binding.verification_method != expected_verification_method
        || &binding.agent_key_authorize_event_id != expected_authorize_event_id
        || did_url_controller(&binding.verification_method) != binding.agent_id.as_str()
        || did_url_controller(&binding.controller_proof.verification_method)
            != binding.controller_id.as_str()
        || binding.controller_proof.kind.as_str() != "detached_jws"
        || binding.public_key.kty.as_str() != "OKP"
        || binding.public_key.alg.as_str() != "Ed25519"
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let raw = base64url_decode(binding.public_key.key.as_str())
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let public_key_digest =
        agent_signing_public_key_digest(&binding.verification_method, &binding.public_key)?;
    if public_key_digest != binding.public_key_digest
        || &public_key_digest != expected_public_key_digest
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

pub fn validate_agent_signer_evidence(
    evidence: Option<&AgentSignerEvidence>,
    context: &AgentSignerEvidenceValidationContext<'_>,
) -> AgentSignerEvidenceVerdict {
    let Some(evidence) = evidence else {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
    };
    if evidence.schema.as_str() != SchemaId::AGENT_SIGNER_EVIDENCE_V1 {
        return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let binding = &evidence.signing_key_binding;
    let key = match verify_agent_signing_key_binding(
        binding,
        context.signer_id,
        context.agent_key_id,
        context.controller_id,
        context.verification_method,
        context.agent_key_authorize_event_id,
        context.authorize_public_key_digest,
        context.authorize_signing_key_binding_digest,
        context.controller_public_key,
    ) {
        Ok(key) => key,
        Err(reason) => return rejected(reason),
    };
    let authorization = &evidence.authorization;
    let witness = &evidence.state_witness;
    let (authorization_interval_relation, freshness_relation_to_event) =
        match validate_seal_lineage(evidence, context) {
            Ok(relations) => relations,
            Err(reason) => return rejected(reason),
        };
    let state_witness_branch_verified = verify_witness_branch(
        &witness.cell_ref,
        &witness.cell_value,
        &witness.leaf_digest,
        witness.leaf_index,
        witness.leaf_count,
        &witness.inclusion_proof,
        &witness.state_root,
    );
    if authorization.authorized_event_id != *context.agent_key_authorize_event_id
        || witness.component.as_str() != AGENT_KEY_COMPONENT
        || witness.agent_id != *context.signer_id
        || witness.authorization_event_id != *context.agent_key_authorize_event_id
        || witness.accepted_frontier != authorization.accepted_frontier
        || witness.seal.id != witness.seal_id
        || witness.seal.state_root != witness.state_root
        || witness.seal.realm_id != *context.authorization_realm_id
        || agent_authorization_cell_ref(context.signer_id, &binding.agent_key_id).ok()
            != Some(witness.cell_ref.clone())
        || !value_contains_authorization_record(
            &witness.cell_value,
            binding,
            context.authorize_signing_key_binding_digest,
        )
        || witness.leaf_count == 0
        || witness.leaf_index >= witness.leaf_count
        || !state_witness_branch_verified
        || !context.freshness_signature_verified
    {
        return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    if authorization.status == AgentAuthorizationStatus::Conflicted
        || authorization_interval_relation == AuthorizationIntervalRelation::Conflict
        || freshness_relation_to_event == FrontierRelation::Conflict
    {
        return rejected(AgentEvidenceRejectedReason::AuthorizationConflicted);
    }
    if authorization_interval_relation != AuthorizationIntervalRelation::Contains
        || context.event_accepted_at < authorization.accepted_at
        || context.event_accepted_at < authorization.not_before
        || context.event_accepted_at < binding.issued_at
        || binding
            .expires_at
            .is_some_and(|expires_at| context.event_accepted_at >= expires_at)
        || authorization
            .expires_at
            .is_some_and(|expires_at| context.event_accepted_at >= expires_at)
    {
        return rejected(AgentEvidenceRejectedReason::AuthorizationInactive);
    }
    match authorization.status {
        AgentAuthorizationStatus::Revoked | AgentAuthorizationStatus::Superseded => {
            let (Some(valid_until_frontier), Some(transition_event_id), Some(transition_witness)) = (
                authorization.valid_until_frontier.as_ref(),
                authorization.transition_event_id.as_ref(),
                evidence.transition_witness.as_ref(),
            ) else {
                return rejected(AgentEvidenceRejectedReason::AuthorizationInactive);
            };
            let transition_witness_branch_verified = verify_witness_branch(
                &transition_witness.cell_ref,
                &transition_witness.cell_value,
                &transition_witness.leaf_digest,
                transition_witness.leaf_index,
                transition_witness.leaf_count,
                &transition_witness.inclusion_proof,
                &transition_witness.state_root,
            );
            if transition_witness.component.as_str() != AGENT_KEY_COMPONENT
                || transition_witness.agent_id != *context.signer_id
                || transition_witness.authorization_event_id
                    != *context.agent_key_authorize_event_id
                || &transition_witness.transition_event_id != transition_event_id
                || &transition_witness.accepted_frontier != valid_until_frontier
                || transition_witness.seal.id != transition_witness.seal_id
                || transition_witness.seal.state_root != transition_witness.state_root
                || transition_witness.seal.realm_id != *context.authorization_realm_id
                || agent_authorization_cell_ref(
                    context.signer_id,
                    &transition_witness.transition_key_id,
                )
                .ok()
                    != Some(transition_witness.cell_ref.clone())
                || !value_contains_event_dot(
                    &transition_witness.cell_value,
                    transition_event_id.as_str(),
                )
                || !value_contains_field_pair(
                    &transition_witness.cell_value,
                    "key_id",
                    transition_witness.transition_key_id.as_str(),
                )
                || transition_witness.leaf_count == 0
                || transition_witness.leaf_index >= transition_witness.leaf_count
                || !transition_witness_branch_verified
            {
                return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
            }
        }
        AgentAuthorizationStatus::Expired if authorization.expires_at.is_none() => {
            return rejected(AgentEvidenceRejectedReason::AuthorizationInactive);
        }
        AgentAuthorizationStatus::Active | AgentAuthorizationStatus::Expired
            if evidence.transition_witness.is_some() =>
        {
            return rejected(AgentEvidenceRejectedReason::SigningKeyMismatch);
        }
        _ => {}
    }
    let freshness = &evidence.freshness_attestation;
    if freshness.issued_at > context.now
        || freshness.expires_at <= freshness.issued_at
        || freshness.expires_at <= context.now
        || freshness_relation_to_event == FrontierRelation::Behind
    {
        return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale);
    }
    if context.require_transparency {
        let Some(transparency) = evidence.transparency.as_ref() else {
            return AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing);
        };
        if transparency.profile.as_str() != ProfileId::KEY_TRANSPARENCY_V1
            || !context.transparency_verified
        {
            return rejected(AgentEvidenceRejectedReason::AuthorizationConflicted);
        }
    }
    AgentSignerEvidenceVerdict::Verified(VerifiedAgentSigningKey {
        signer: context.signer_id.clone(),
        key,
        authorization_ref: context.agent_key_authorize_event_id.clone(),
        accepted_frontier: authorization.accepted_frontier.clone(),
    })
}

fn validate_seal_lineage(
    evidence: &AgentSignerEvidence,
    context: &AgentSignerEvidenceValidationContext<'_>,
) -> Result<(AuthorizationIntervalRelation, FrontierRelation), AgentEvidenceRejectedReason> {
    const MAX_SEAL_LINEAGE: usize = 4096;
    if !context.seal_lineage_signatures_verified
        || evidence.seal_lineage.is_empty()
        || evidence.seal_lineage.len() > MAX_SEAL_LINEAGE
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let mut seals = BTreeMap::<String, &arkret_wire::Seal>::new();
    for seal in &evidence.seal_lineage {
        if seal.realm_id != *context.authorization_realm_id
            || seal.validate_structural().is_err()
            || seal.validate_id().is_err()
            || seals.insert(seal.id.as_str().to_owned(), seal).is_some()
        {
            return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
        }
    }
    let mut referenced = BTreeSet::new();
    for seal in seals.values() {
        for predecessor_id in &seal.predecessor_refs {
            let Some(predecessor) = seals.get(predecessor_id.as_str()) else {
                return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
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
    if heads.len() != 1
        || heads[0].as_str() != evidence.freshness_attestation.observed_frontier.as_str()
    {
        return Err(AgentEvidenceRejectedReason::AuthorizationConflicted);
    }
    let start_id = evidence.state_witness.seal_id.as_str();
    let event_id = context.event_accepted_frontier.as_str();
    let observed_id = evidence.freshness_attestation.observed_frontier.as_str();
    if !seals.contains_key(start_id)
        || !seals.contains_key(event_id)
        || !seals.contains_key(observed_id)
        || evidence.authorization.accepted_frontier.as_str() != start_id
        || evidence.authorization.valid_from_frontier.as_str() != start_id
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let start_covers_event = seal_is_ancestor(&seals, start_id, event_id)?;
    let event_covers_start = seal_is_ancestor(&seals, event_id, start_id)?;
    let authorization_relation = if start_covers_event {
        if let Some(transition) = evidence.transition_witness.as_ref() {
            let transition_id = transition.seal_id.as_str();
            if !seals.contains_key(transition_id)
                || evidence
                    .authorization
                    .valid_until_frontier
                    .as_ref()
                    .map(NonEmptyString::as_str)
                    != Some(transition_id)
            {
                return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
            }
            if seal_is_ancestor(&seals, transition_id, event_id)? {
                AuthorizationIntervalRelation::After
            } else if seal_is_ancestor(&seals, event_id, transition_id)? {
                AuthorizationIntervalRelation::Contains
            } else {
                AuthorizationIntervalRelation::Conflict
            }
        } else {
            AuthorizationIntervalRelation::Contains
        }
    } else if event_covers_start {
        AuthorizationIntervalRelation::Before
    } else {
        AuthorizationIntervalRelation::Conflict
    };
    let freshness_relation = if seal_is_ancestor(&seals, event_id, observed_id)? {
        FrontierRelation::Covers
    } else if seal_is_ancestor(&seals, observed_id, event_id)? {
        FrontierRelation::Behind
    } else {
        FrontierRelation::Conflict
    };
    Ok((authorization_relation, freshness_relation))
}

fn seal_is_ancestor(
    seals: &BTreeMap<String, &arkret_wire::Seal>,
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
    let Ok(computed_leaf_digest) = arkret_state::state_value_leaf_digest(&cell_ref, cell_value)
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
        )
        .unwrap_or(false)
}

pub fn agent_signing_public_key_digest(
    verification_method: &DidUrl,
    public_key: &AgentSigningPublicKey,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    agent_runtime_public_key_digest(&serde_json::json!({
        "kty": public_key.kty,
        "kid": verification_method,
        "alg": public_key.alg,
        "key": public_key.key,
    }))
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

pub fn agent_signing_public_key_runtime_digest(
    verification_method: &DidUrl,
    public_key: &AgentSigningPublicKey,
) -> Result<Hash, AgentEvidenceRejectedReason> {
    // The public binding names the concrete primitive (`Ed25519`), while the
    // runtime pairing JWK uses the JOSE algorithm (`EdDSA`). Normalize only
    // for comparison with the runtime request's public-key digest.
    agent_runtime_public_key_digest(&serde_json::json!({
        "kty": public_key.kty,
        "kid": verification_method,
        "alg": "EdDSA",
        "key": public_key.key,
    }))
    .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn rejected(reason: AgentEvidenceRejectedReason) -> AgentSignerEvidenceVerdict {
    AgentSignerEvidenceVerdict::Rejected(reason)
}

fn did_url_controller(method: &DidUrl) -> &str {
    method.as_str().split_once('#').map_or("", |(did, _)| did)
}

fn value_contains_event_dot(value: &Value, event_id: &str) -> bool {
    match value {
        Value::String(value) => agent_authorization_dot_matches_event(value, event_id),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_event_dot(value, event_id)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_event_dot(value, event_id)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn value_contains_authorization_record(
    value: &Value,
    binding: &AgentSigningKeyBinding,
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
                            authorization_record_fields_match(record, binding, binding_digest)
                        })
                });
            exact_record
                || values.values().any(|nested| {
                    value_contains_authorization_record(nested, binding, binding_digest)
                })
        }
        Value::Array(values) => values
            .iter()
            .any(|nested| value_contains_authorization_record(nested, binding, binding_digest)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn authorization_record_fields_match(
    record: &serde_json::Map<String, Value>,
    binding: &AgentSigningKeyBinding,
    binding_digest: &Hash,
) -> bool {
    record.get("agent_id").and_then(Value::as_str) == Some(binding.agent_id.as_str())
        && record.get("key_id").and_then(Value::as_str) == Some(binding.agent_key_id.as_str())
        && record.get("verification_method").and_then(Value::as_str)
            == Some(binding.verification_method.as_str())
        && record.get("public_key_digest").and_then(Value::as_str)
            == Some(binding.public_key_digest.as_str())
        && record
            .get("signing_key_binding_digest")
            .and_then(Value::as_str)
            == Some(binding_digest.as_str())
}

fn value_contains_field_pair(value: &Value, field: &str, expected: &str) -> bool {
    match value {
        Value::Object(values) => {
            values.get(field).and_then(Value::as_str) == Some(expected)
                || values
                    .values()
                    .any(|nested| value_contains_field_pair(nested, field, expected))
        }
        Value::Array(values) => values
            .iter()
            .any(|nested| value_contains_field_pair(nested, field, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_decode;
    use arkret_models_collaboration::agent_signer_evidence::{
        AgentAuthorizationEvidence, AgentAuthorizationStateWitness,
        AgentAuthorizationTransitionWitness, AgentEvidenceFreshnessAttestation,
        AgentEvidenceTransparency,
    };
    use arkret_wire::{Hlc, RealmId, Seal};
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn agent_authorization_witness_requires_canonical_event_dot() {
        let event_id = "ak:event:01964137-0000-7000-8000-000000000001";
        assert!(agent_authorization_dot_matches_event(
            &format!("{event_id}:1"),
            event_id,
        ));
        assert!(!agent_authorization_dot_matches_event(event_id, event_id));
        assert!(!agent_authorization_dot_matches_event(
            &format!("{event_id}:01"),
            event_id,
        ));
        assert!(!agent_authorization_dot_matches_event(
            "ak:event:01964137-0000-7000-8000-000000000002:1",
            event_id,
        ));
    }

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn fixture_seal(state_root: Hash, hlc: &str, predecessor_refs: Vec<SealId>) -> Seal {
        let notary_id = did("did:webvh:z6mkservice:service.example");
        let signer = crate::Ed25519PayloadSigner::from_did_key_seed(
            [24; 32],
            notary_id.clone(),
            DidUrl::new(format!("{notary_id}#notary-key")).unwrap(),
        );
        Seal::sign_single(
            RealmId::new("ak:realm:01964137-0000-7000-8000-000000000007").unwrap(),
            predecessor_refs,
            vec![],
            state_root,
            Hlc::new(hlc).unwrap(),
            &signer,
        )
        .unwrap()
    }

    fn fixture_binding() -> AgentSigningKeyBinding {
        serde_json::from_value(serde_json::json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": "did:webvh:z6mkagent:agent.example",
            "agent_key_id": "did:webvh:z6mkagent:agent.example#runtime-1",
            "verification_method": "did:webvh:z6mkagent:agent.example#runtime-1",
            "public_key": {
                "kty": "OKP",
                "alg": "Ed25519",
                "key": "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
            },
            "public_key_digest": "sha256:bbeb7e8a892586b86114ab88cc60807dc588f3f5f29a428e69b46808f573bfa3",
            "agent_key_authorize_event_id": "ak:event:01964137-0000-7000-8000-000000000001",
            "issued_at": "2026-07-25T00:00:00.000Z",
            "controller_id": "did:webvh:z6mkcontroller:controller.example",
            "controller_proof": {
                "kind": "detached_jws",
                "verification_method": "did:webvh:z6mkcontroller:controller.example#ak:device:01964137-0000-7000-8000-000000000002",
                "jws": "eyJhbGciOiJFZERTQSJ9..H4Oa3vvlPEV7ufZM_NgzfVWL17tQqeE9FnliAzjua66xfy5V7XSzSiyL4IcmqfsXo1ue2FfdMzaRzV1PYldPDA"
            }
        }))
        .unwrap()
    }

    fn fixture_evidence(binding: AgentSigningKeyBinding) -> AgentSignerEvidence {
        let cell_ref =
            agent_authorization_cell_ref(&binding.agent_id, &binding.agent_key_id).unwrap();
        let binding_digest = agent_signing_key_binding_digest(&binding).unwrap();
        let cell_value = serde_json::json!([{
            "tag": format!("{}:1", binding.agent_key_authorize_event_id.as_str()),
            "value": {
                "agent_id": binding.agent_id,
                "key_id": binding.agent_key_id,
                "verification_method": binding.verification_method,
                "public_key_digest": binding.public_key_digest,
                "signing_key_binding_digest": binding_digest
            }
        }]);
        let leaf_digest = arkret_state::state_value_leaf_digest(
            &CellRef::new(cell_ref.as_str().to_owned()).unwrap(),
            &cell_value,
        )
        .unwrap();
        let authorization_seal =
            fixture_seal(leaf_digest.clone(), "01970e589d21-0004-a13f9c2e", vec![]);
        let authorization_frontier =
            NonEmptyString::new(authorization_seal.id.as_str().to_owned()).unwrap();
        AgentSignerEvidence {
            schema: NonEmptyString::new(SchemaId::AGENT_SIGNER_EVIDENCE_V1.to_owned()).unwrap(),
            authorization: AgentAuthorizationEvidence {
                status: AgentAuthorizationStatus::Active,
                authorized_event_id: binding.agent_key_authorize_event_id.clone(),
                accepted_frontier: authorization_frontier.clone(),
                accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 0, 0).unwrap(),
                valid_from_frontier: authorization_frontier.clone(),
                not_before: Utc.with_ymd_and_hms(2026, 7, 25, 0, 0, 0).unwrap(),
                valid_until_frontier: None,
                expires_at: None,
                transition_event_id: None,
            },
            state_witness: AgentAuthorizationStateWitness {
                component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned()).unwrap(),
                agent_id: binding.agent_id.clone(),
                authorization_event_id: binding.agent_key_authorize_event_id.clone(),
                accepted_frontier: authorization_frontier,
                seal_id: authorization_seal.id.clone(),
                state_root: authorization_seal.state_root.clone(),
                seal: authorization_seal.clone(),
                cell_ref,
                cell_value,
                leaf_digest,
                leaf_index: 0,
                leaf_count: 1,
                inclusion_proof: vec![],
            },
            transition_witness: None,
            seal_lineage: vec![authorization_seal.clone()],
            freshness_attestation: AgentEvidenceFreshnessAttestation {
                source_service_id: did("did:webvh:z6mkservice:service.example"),
                observed_frontier: NonEmptyString::new(authorization_seal.id.as_str().to_owned())
                    .unwrap(),
                issued_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
                expires_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 3, 0).unwrap(),
                source_proof: AgentEvidenceSourceProof {
                    kind: NonEmptyString::new("detached_jws".to_owned()).unwrap(),
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkservice:service.example#notary-key",
                    )
                    .unwrap(),
                    jws: NonEmptyString::new("sig".to_owned()).unwrap(),
                },
            },
            signing_key_binding: binding,
            transparency: None,
        }
    }

    fn attach_transition(
        evidence: &mut AgentSignerEvidence,
        status: AgentAuthorizationStatus,
        transition_event_id: EventId,
    ) {
        let transition_key_id = evidence.signing_key_binding.agent_key_id.clone();
        let predecessor = evidence.state_witness.seal.id.clone();
        let cell_ref = agent_authorization_cell_ref(
            &evidence.signing_key_binding.agent_id,
            &transition_key_id,
        )
        .unwrap();
        let cell_value = serde_json::json!([{
            "tag": format!("{}:1", transition_event_id.as_str()),
            "value": {
                "key_id": transition_key_id
            }
        }]);
        let leaf_digest = arkret_state::state_value_leaf_digest(
            &CellRef::new(cell_ref.as_str().to_owned()).unwrap(),
            &cell_value,
        )
        .unwrap();
        let transition_seal = fixture_seal(
            leaf_digest.clone(),
            "01970e589d21-0005-a13f9c2e",
            vec![predecessor],
        );
        let frontier = NonEmptyString::new(transition_seal.id.as_str().to_owned()).unwrap();
        evidence.authorization.status = status;
        evidence.authorization.valid_until_frontier = Some(frontier.clone());
        evidence.authorization.transition_event_id = Some(transition_event_id.clone());
        evidence.transition_witness = Some(AgentAuthorizationTransitionWitness {
            component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned()).unwrap(),
            agent_id: evidence.signing_key_binding.agent_id.clone(),
            authorization_event_id: evidence
                .signing_key_binding
                .agent_key_authorize_event_id
                .clone(),
            transition_event_id,
            transition_key_id,
            accepted_frontier: frontier,
            seal_id: transition_seal.id.clone(),
            state_root: transition_seal.state_root.clone(),
            seal: transition_seal.clone(),
            cell_ref,
            cell_value,
            leaf_digest,
            leaf_index: 0,
            leaf_count: 1,
            inclusion_proof: vec![],
        });
        evidence.seal_lineage.push(transition_seal.clone());
        evidence.freshness_attestation.observed_frontier =
            NonEmptyString::new(transition_seal.id.as_str().to_owned()).unwrap();
    }

    struct FixtureValidationContext {
        signer_id: Did,
        agent_key_id: NonEmptyString,
        authorization_realm_id: RealmId,
        controller_id: Did,
        verification_method: DidUrl,
        authorization_event_id: EventId,
        public_key_digest: Hash,
        binding_digest: Hash,
        event_accepted_frontier: NonEmptyString,
        event_accepted_at: DateTime<Utc>,
        now: DateTime<Utc>,
        controller_key: PublicKeyMaterial,
        seal_lineage_signatures_verified: bool,
        freshness_signature_verified: bool,
        require_transparency: bool,
        transparency_verified: bool,
    }

    impl FixtureValidationContext {
        fn new(binding: &AgentSigningKeyBinding, evidence: &AgentSignerEvidence) -> Self {
            Self {
                signer_id: binding.agent_id.clone(),
                agent_key_id: binding.agent_key_id.clone(),
                authorization_realm_id: RealmId::new(
                    "ak:realm:01964137-0000-7000-8000-000000000007",
                )
                .unwrap(),
                controller_id: binding.controller_id.clone(),
                verification_method: binding.verification_method.clone(),
                authorization_event_id: binding.agent_key_authorize_event_id.clone(),
                public_key_digest: binding.public_key_digest.clone(),
                binding_digest: agent_signing_key_binding_digest(binding).unwrap(),
                event_accepted_frontier: evidence.state_witness.accepted_frontier.clone(),
                event_accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
                now: Utc.with_ymd_and_hms(2026, 7, 25, 0, 2, 0).unwrap(),
                controller_key: PublicKeyMaterial::Ed25519Raw {
                    bytes: base64url_decode("7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E").unwrap(),
                },
                seal_lineage_signatures_verified: true,
                freshness_signature_verified: true,
                require_transparency: false,
                transparency_verified: false,
            }
        }

        fn validate(&self, evidence: Option<&AgentSignerEvidence>) -> AgentSignerEvidenceVerdict {
            validate_agent_signer_evidence(
                evidence,
                &AgentSignerEvidenceValidationContext {
                    signer_id: &self.signer_id,
                    agent_key_id: &self.agent_key_id,
                    authorization_realm_id: &self.authorization_realm_id,
                    controller_id: &self.controller_id,
                    verification_method: &self.verification_method,
                    agent_key_authorize_event_id: &self.authorization_event_id,
                    authorize_public_key_digest: &self.public_key_digest,
                    authorize_signing_key_binding_digest: &self.binding_digest,
                    event_accepted_frontier: &self.event_accepted_frontier,
                    event_accepted_at: self.event_accepted_at,
                    now: self.now,
                    controller_public_key: &self.controller_key,
                    seal_lineage_signatures_verified: self.seal_lineage_signatures_verified,
                    freshness_signature_verified: self.freshness_signature_verified,
                    require_transparency: self.require_transparency,
                    transparency_verified: self.transparency_verified,
                },
            )
        }
    }

    #[test]
    fn binding_matches_byte_exact_spec_vector() {
        let binding = fixture_binding();
        let expected = base64url_decode("YWsuYWdlbnQtc2lnbmluZy1rZXktYmluZGluZy12MQp7ImFnZW50X2lkIjoiZGlkOndlYnZoOno2bWthZ2VudDphZ2VudC5leGFtcGxlIiwiYWdlbnRfa2V5X2F1dGhvcml6ZV9ldmVudF9pZCI6ImFrOmV2ZW50OjAxOTY0MTM3LTAwMDAtNzAwMC04MDAwLTAwMDAwMDAwMDAwMSIsImFnZW50X2tleV9pZCI6ImRpZDp3ZWJ2aDp6Nm1rYWdlbnQ6YWdlbnQuZXhhbXBsZSNydW50aW1lLTEiLCJjb250cm9sbGVyX2lkIjoiZGlkOndlYnZoOno2bWtjb250cm9sbGVyOmNvbnRyb2xsZXIuZXhhbXBsZSIsImNvbnRyb2xsZXJfcHJvb2YiOnsia2luZCI6ImRldGFjaGVkX2p3cyIsInZlcmlmaWNhdGlvbl9tZXRob2QiOiJkaWQ6d2Vidmg6ejZta2NvbnRyb2xsZXI6Y29udHJvbGxlci5leGFtcGxlI2FrOmRldmljZTowMTk2NDEzNy0wMDAwLTcwMDAtODAwMC0wMDAwMDAwMDAwMDIifSwiaXNzdWVkX2F0IjoiMjAyNi0wNy0yNVQwMDowMDowMC4wMDBaIiwicHVibGljX2tleSI6eyJhbGciOiJFZDI1NTE5Iiwia2V5IjoiNmtwc1ktS2NVZ3EtOVZCN0V5N0YtWlZIZHE2LXZudVNRaDdxYVJSRzBpdyIsImt0eSI6Ik9LUCJ9LCJwdWJsaWNfa2V5X2RpZ2VzdCI6InNoYTI1NjpiYmViN2U4YTg5MjU4NmI4NjExNGFiODhjYzYwODA3ZGM1ODhmM2Y1ZjI5YTQyOGU2OWI0NjgwOGY1NzNiZmEzIiwic2NoZW1hIjoiYWsuc2NoZW1hLmFnZW50X3NpZ25pbmdfa2V5X2JpbmRpbmcudjEiLCJ2ZXJpZmljYXRpb25fbWV0aG9kIjoiZGlkOndlYnZoOno2bWthZ2VudDphZ2VudC5leGFtcGxlI3J1bnRpbWUtMSJ9").unwrap();
        assert_eq!(
            agent_signing_key_binding_signing_bytes(&binding).unwrap(),
            expected
        );
        assert_eq!(
            agent_signing_key_binding_digest(&binding).unwrap().as_str(),
            "sha256:6214dbe074a0a8ab5c15bf5621c1de7db7efc2136dbacab5ead55aeca88d3a30"
        );
        let controller_key: [u8; 32] =
            base64url_decode("7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E")
                .unwrap()
                .try_into()
                .unwrap();
        let verified = verify_agent_signing_key_binding(
            &binding,
            &binding.agent_id,
            &binding.agent_key_id,
            &binding.controller_id,
            &binding.verification_method,
            &binding.agent_key_authorize_event_id,
            &binding.public_key_digest,
            &agent_signing_key_binding_digest(&binding).unwrap(),
            &PublicKeyMaterial::Ed25519Raw {
                bytes: controller_key.to_vec(),
            },
        )
        .unwrap();
        assert_eq!(
            arkret_canonical::base64url_encode(verified),
            binding.public_key.key.as_str()
        );
    }

    #[test]
    fn delegated_signer_keeps_actor_binding_separate() {
        let actor = did("did:webvh:z6mkcontroller:controller.example");
        let signer = did("did:webvh:z6mkagent:agent.example");
        let mut event = Event::new(
            arkret_wire::EventKind::MESSAGE_CREATE,
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000009").unwrap(),
            },
            actor.clone(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        event.executed_by = Some(signer.clone());
        let binding = verify_event_signer_controller(
            &event,
            &DidUrl::new(format!("{signer}#runtime-1")).unwrap(),
        )
        .unwrap();
        assert_eq!(binding.binding_actor_id, actor);
        assert_eq!(binding.signer_id, signer);
    }

    #[test]
    fn signer_regime_dispatch_is_explicit_and_non_overlapping() {
        assert_eq!(
            dispatch_signer_regime(true, SignerPrincipalKind::NativeAgent),
            Ok(SignerRegime::MinimalMetadata)
        );
        assert_eq!(
            dispatch_signer_regime(false, SignerPrincipalKind::Device),
            Ok(SignerRegime::OrdinaryDevice)
        );
        assert_eq!(
            dispatch_signer_regime(false, SignerPrincipalKind::NativeAgent),
            Ok(SignerRegime::OrdinaryNativeAgent)
        );
        for kind in [
            SignerPrincipalKind::Applet,
            SignerPrincipalKind::Service,
            SignerPrincipalKind::Integration,
        ] {
            assert_eq!(
                dispatch_signer_regime(false, kind),
                Ok(SignerRegime::AppletOrService)
            );
        }
        assert_eq!(
            dispatch_signer_regime(false, SignerPrincipalKind::Unknown),
            Err(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );
    }

    #[test]
    fn valid_evidence_verifies_and_missing_evidence_stays_unresolved() {
        let binding = fixture_binding();
        let evidence = fixture_evidence(binding.clone());
        let context = FixtureValidationContext::new(&binding, &evidence);
        assert!(matches!(
            context.validate(Some(&evidence)),
            AgentSignerEvidenceVerdict::Verified(_)
        ));
        assert_eq!(
            context.validate(None),
            AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing)
        );
    }

    #[test]
    fn freshness_attestation_is_portable_and_source_signed() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let service_id = did("did:webvh:z6mkservice:service.example");
        let attestation = build_agent_evidence_freshness_attestation(
            service_id,
            NonEmptyString::new("frontier:8".to_owned()).unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 7, 25, 0, 3, 0).unwrap(),
            DidUrl::new("did:webvh:z6mkservice:service.example#notary-key").unwrap(),
            &signing_key,
        )
        .unwrap();
        let source_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        verify_agent_evidence_freshness_attestation(&attestation, &source_key).unwrap();

        let mut tampered = attestation;
        tampered.observed_frontier = NonEmptyString::new("frontier:7".to_owned()).unwrap();
        assert_eq!(
            verify_agent_evidence_freshness_attestation(&tampered, &source_key),
            Err(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );
    }

    #[test]
    fn every_public_binding_dimension_is_cryptographically_bound() {
        let binding = fixture_binding();
        let base = fixture_evidence(binding.clone());
        let context = FixtureValidationContext::new(&binding, &base);
        let mutations = [
            (
                "/schema",
                serde_json::json!("ak.schema.agent_signing_key_binding.v2"),
            ),
            (
                "/agent_id",
                serde_json::json!("did:webvh:z6mkother:agent.example"),
            ),
            (
                "/agent_key_id",
                serde_json::json!("did:webvh:z6mkagent:agent.example#runtime-2"),
            ),
            (
                "/verification_method",
                serde_json::json!("did:webvh:z6mkagent:agent.example#runtime-2"),
            ),
            (
                "/public_key/key",
                serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            (
                "/public_key_digest",
                serde_json::json!(format!("sha256:{}", "a".repeat(64))),
            ),
            (
                "/agent_key_authorize_event_id",
                serde_json::json!("ak:event:01964137-0000-7000-8000-000000000099"),
            ),
            (
                "/controller_id",
                serde_json::json!("did:webvh:z6mkother:controller.example"),
            ),
            (
                "/controller_proof/kind",
                serde_json::json!("service_attestation"),
            ),
            (
                "/controller_proof/verification_method",
                serde_json::json!(
                    "did:webvh:z6mkcontroller:controller.example#ak:device:01964137-0000-7000-8000-000000000099"
                ),
            ),
        ];
        for (path, replacement) in mutations {
            let mut value = serde_json::to_value(&binding).unwrap();
            *value.pointer_mut(path).expect("fixture mutation path") = replacement;
            let mutated: AgentSigningKeyBinding = serde_json::from_value(value).unwrap();
            let evidence = fixture_evidence(mutated);
            assert_eq!(
                context.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::SigningKeyMismatch
                ),
                "binding mutation at {path} must reject"
            );
        }
    }

    #[test]
    fn state_witness_and_freshness_verification_fail_closed() {
        let binding = fixture_binding();
        let base = fixture_evidence(binding.clone());

        let mut wrong_agent = base.clone();
        wrong_agent.state_witness.agent_id = did("did:webvh:z6mkother:agent.example");
        let context = FixtureValidationContext::new(&binding, &base);
        assert_eq!(
            context.validate(Some(&wrong_agent)),
            AgentSignerEvidenceVerdict::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );

        let mut wrong_event = base.clone();
        wrong_event.state_witness.authorization_event_id =
            EventId::new("ak:event:01964137-0000-7000-8000-000000000099").unwrap();
        assert_eq!(
            context.validate(Some(&wrong_event)),
            AgentSignerEvidenceVerdict::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );

        let mut wrong_frontier = base.clone();
        wrong_frontier.state_witness.accepted_frontier =
            NonEmptyString::new("frontier:6".to_owned()).unwrap();
        assert_eq!(
            context.validate(Some(&wrong_frontier)),
            AgentSignerEvidenceVerdict::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );

        let mut unverified_witness = FixtureValidationContext::new(&binding, &base);
        unverified_witness.seal_lineage_signatures_verified = false;
        assert_eq!(
            unverified_witness.validate(Some(&base)),
            AgentSignerEvidenceVerdict::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );

        let mut bad_freshness_signature = FixtureValidationContext::new(&binding, &base);
        bad_freshness_signature.freshness_signature_verified = false;
        assert_eq!(
            bad_freshness_signature.validate(Some(&base)),
            AgentSignerEvidenceVerdict::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch)
        );
    }

    #[test]
    fn authorization_interval_matrix_preserves_history_and_rejects_new_old_key_writes() {
        let binding = fixture_binding();
        let transition = EventId::new("ak:event:01964137-0000-7000-8000-000000000009").unwrap();

        for status in [
            AgentAuthorizationStatus::Revoked,
            AgentAuthorizationStatus::Superseded,
        ] {
            let mut evidence = fixture_evidence(binding.clone());
            attach_transition(&mut evidence, status, transition.clone());

            let historical = FixtureValidationContext::new(&binding, &evidence);
            assert!(
                matches!(
                    historical.validate(Some(&evidence)),
                    AgentSignerEvidenceVerdict::Verified(_)
                ),
                "historical Event inside {status:?} interval must remain verifiable"
            );

            let mut after_transition = FixtureValidationContext::new(&binding, &evidence);
            after_transition.event_accepted_frontier = evidence
                .transition_witness
                .as_ref()
                .unwrap()
                .accepted_frontier
                .clone();
            assert_eq!(
                after_transition.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::AuthorizationInactive
                ),
                "new Event after {status:?} boundary must reject"
            );
        }

        let mut active = fixture_evidence(binding.clone());
        let mut conflict = FixtureValidationContext::new(&binding, &active);
        let disconnected = fixture_seal(hash('8'), "01970e589d21-0006-a13f9c2e", vec![]);
        conflict.event_accepted_frontier =
            NonEmptyString::new(disconnected.id.as_str().to_owned()).unwrap();
        active.seal_lineage.push(disconnected);
        assert_eq!(
            conflict.validate(Some(&active)),
            AgentSignerEvidenceVerdict::Rejected(
                AgentEvidenceRejectedReason::AuthorizationConflicted
            )
        );
    }

    #[test]
    fn expiry_and_freshness_boundaries_do_not_fail_open() {
        let binding = fixture_binding();
        let mut expired = fixture_evidence(binding.clone());
        expired.authorization.status = AgentAuthorizationStatus::Expired;
        expired.authorization.expires_at =
            Some(Utc.with_ymd_and_hms(2026, 7, 25, 0, 2, 0).unwrap());
        assert!(matches!(
            FixtureValidationContext::new(&binding, &expired).validate(Some(&expired)),
            AgentSignerEvidenceVerdict::Verified(_)
        ));

        let mut after_expiry = FixtureValidationContext::new(&binding, &expired);
        after_expiry.event_accepted_at = Utc.with_ymd_and_hms(2026, 7, 25, 0, 2, 0).unwrap();
        assert_eq!(
            after_expiry.validate(Some(&expired)),
            AgentSignerEvidenceVerdict::Rejected(
                AgentEvidenceRejectedReason::AuthorizationInactive
            )
        );

        let active = fixture_evidence(binding.clone());
        let mut stale = FixtureValidationContext::new(&binding, &active);
        stale.now = Utc.with_ymd_and_hms(2026, 7, 25, 0, 3, 0).unwrap();
        assert_eq!(
            stale.validate(Some(&active)),
            AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale)
        );

        let mut rollback_evidence = active;
        let rollback_head = fixture_seal(hash('9'), "01970e589d21-0006-a13f9c2e", vec![]);
        rollback_evidence.seal_lineage.push(rollback_head);
        let rollback = FixtureValidationContext::new(&binding, &rollback_evidence);
        assert_eq!(
            rollback.validate(Some(&rollback_evidence)),
            AgentSignerEvidenceVerdict::Rejected(
                AgentEvidenceRejectedReason::AuthorizationConflicted
            )
        );
    }

    #[test]
    fn high_assurance_profile_requires_verified_transparency() {
        let binding = fixture_binding();
        let mut evidence = fixture_evidence(binding.clone());
        let mut context = FixtureValidationContext::new(&binding, &evidence);
        context.require_transparency = true;
        assert_eq!(
            context.validate(Some(&evidence)),
            AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing)
        );

        evidence.transparency = Some(AgentEvidenceTransparency {
            profile: NonEmptyString::new(ProfileId::KEY_TRANSPARENCY_V1.to_owned()).unwrap(),
            log_id: NonEmptyString::new("agent-key-log".to_owned()).unwrap(),
            leaf_count: 1,
            tree_root: hash('4'),
            inclusion_proof: vec![],
            consistency_proof: vec![],
            witness_signatures: vec![NonEmptyString::new("witness-signature".to_owned()).unwrap()],
        });
        assert_eq!(
            context.validate(Some(&evidence)),
            AgentSignerEvidenceVerdict::Rejected(
                AgentEvidenceRejectedReason::AuthorizationConflicted
            )
        );
        context.transparency_verified = true;
        assert!(matches!(
            context.validate(Some(&evidence)),
            AgentSignerEvidenceVerdict::Verified(_)
        ));
    }

    #[test]
    fn stale_evidence_never_verifies() {
        let binding = fixture_binding();
        let mut evidence = fixture_evidence(binding.clone());
        evidence.freshness_attestation.expires_at =
            Utc.with_ymd_and_hms(2026, 7, 25, 0, 2, 0).unwrap();
        let verdict = FixtureValidationContext::new(&binding, &evidence).validate(Some(&evidence));
        assert_eq!(
            verdict,
            AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale)
        );

        attach_transition(
            &mut evidence,
            AgentAuthorizationStatus::Superseded,
            EventId::new("ak:event:01964137-0000-7000-8000-000000000009").unwrap(),
        );
        evidence.freshness_attestation.expires_at =
            Utc.with_ymd_and_hms(2026, 7, 25, 0, 4, 0).unwrap();
        let historical =
            FixtureValidationContext::new(&binding, &evidence).validate(Some(&evidence));
        assert!(matches!(
            historical,
            AgentSignerEvidenceVerdict::Verified(_)
        ));
    }
}
