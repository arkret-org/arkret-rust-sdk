//! Offline verification of complete portable Agent producer evidence.

use std::collections::BTreeSet;

use arkret_models_identity::agent_signer_evidence::ControllerAccountEligibility;
use arkret_models_identity::{
    AgentAuthorityState, AgentProducerEvidence, AgentSignerDependency,
    AuthenticatedServiceResolution, AuthenticatedSignerKind,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, EventProofBuilder, PublicKeyMaterial};
use arkret_wire::{
    AccountId, Did, DidCoreId, DidUrl, ErrorCode, Event, SignerEvidenceRef, WireError,
};
use chrono::{DateTime, Utc};

use crate::realm_authority_chain::{RealmAuthorityKeyMap, verify_accepted_agent_authority_bundle};
use crate::{DidVerificationRelationship, IdentityError, Result};

/// Construction requires the complete offline proof checks. This result says
/// nothing about current participation, membership, capability or target policy.
#[derive(Clone, Debug)]
pub struct VerifiedAgentProducer {
    account: AccountId,
    reference: SignerEvidenceRef,
    key: PublicKeyMaterial,
    evidence: AgentProducerEvidence,
}

impl VerifiedAgentProducer {
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    pub fn reference(&self) -> &SignerEvidenceRef {
        &self.reference
    }
    pub fn key(&self) -> &PublicKeyMaterial {
        &self.key
    }
    pub fn evidence(&self) -> &AgentProducerEvidence {
        &self.evidence
    }
}

/// A compact body may use only a locally verified exact state. No resolver or
/// network callback is available on this path.
pub fn verify_forwarded_agent_producer(
    event: &Event,
    evidence: &AgentProducerEvidence,
    source_station: &DidCoreId,
    now: DateTime<Utc>,
    verified_state: Option<&AgentAuthorityState>,
) -> Result<VerifiedAgentProducer> {
    let account = event.actual_signer().as_account_id().ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "Agent producer must be an Account",
        )
    })?;
    if &account.station_id != source_station || event.human_device_producer()?.is_some() {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Agent producer Source-Service-ID or class differs",
        ));
    }
    let mut full = evidence.clone();
    full.agent_authority_state_evidence
        .restore(verified_state)?;
    let key = verify_closure(&mut full, account, now, &mut BTreeSet::new())?;
    verify_event(event, &key)?;
    if event
        .producer_proof
        .as_ref()
        .map(|p| &p.verification_method)
        != Some(&full.authenticated_signer_evidence.verification_method)
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Agent producer method differs from resolved key",
        ));
    }
    let state = full
        .agent_authority_state_evidence
        .state
        .as_ref()
        .expect("restored above");
    if event.created_at < state.authorization.accepted_at
        || event.created_at < state.authorization.issued_at
        || state
            .authorization
            .expires_at
            .is_some_and(|expiry| event.created_at >= expiry)
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Agent key was not effective at Event creation",
        ));
    }
    Ok(VerifiedAgentProducer {
        account: account.clone(),
        reference: full.authenticated_signer_evidence.signer_evidence_ref()?,
        key,
        evidence: full,
    })
}

fn verify_closure(
    carrier: &mut AgentProducerEvidence,
    account: &AccountId,
    at: DateTime<Utc>,
    visiting: &mut BTreeSet<SignerEvidenceRef>,
) -> Result<PublicKeyMaterial> {
    carrier.agent_authority_state_evidence.restore(None)?;
    let reference = carrier
        .authenticated_signer_evidence
        .signer_evidence_ref()?;
    if !visiting.insert(reference.clone()) {
        return Err(rejected(
            ErrorCode::SchemaViolation,
            "cyclic Agent signer evidence",
        ));
    }
    let state = carrier
        .agent_authority_state_evidence
        .state
        .as_ref()
        .expect("restored above");
    state.validate_binding(account)?;
    validate_accepted_payloads(state, account)?;
    let leaf = &carrier.agent_authority_state_evidence.attestation;
    if leaf.proof.kind.as_str() != arkret_wire::proof_kind::DETACHED_JWS
        || leaf.issued_at > at
        || at >= leaf.expires_at
        || leaf.issued_at >= leaf.expires_at
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Agent state attestation is outside its validity window",
        ));
    }
    let authority_key = service_key(
        &carrier.authority_resolution,
        &account.station_id,
        &leaf.verification_method,
        leaf.issued_at,
    )?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            leaf.proof.jws.as_str(),
            &leaf.signing_bytes()?,
            &authority_key,
        )
        .map_err(signature)?;

    let gate = &carrier.controller_account_gate_attestation;
    let gate_key = service_key(
        &carrier.authority_resolution,
        &account.station_id,
        &gate.verification_method,
        gate.issued_at,
    )?;
    arkret_signatures::agent_evidence::verify_controller_account_gate_attestation(
        gate,
        &state.authorization.controller_principal_id,
        &account.station_id,
        &gate_key,
        at,
    )
    .map_err(signature)?;
    if gate.eligibility != ControllerAccountEligibility::Active {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "controller account gate denies Agent signing",
        ));
    }

    let mut keys = RealmAuthorityKeyMap::new();
    let mut used_histories = BTreeSet::new();
    let mut signatures = state
        .commits
        .iter()
        .map(|c| &c.signature)
        .collect::<Vec<_>>();
    for transition in &state.authority_bundle.authority_transitions {
        signatures.push(&transition.handoff.old_authority_signature);
        signatures.push(&transition.handoff.new_authority_acceptance_signature);
        if !state.commits.iter().any(|c| c == &transition.change_commit) {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "authority transition is beyond or outside the accepted cut",
            ));
        }
    }
    for signed in signatures {
        let station = method_subject(&signed.verification_method)?;
        let (index, resolution) = state
            .authority_bundle
            .signer_histories
            .iter()
            .enumerate()
            .find(|(_, r)| r.service_id == station)
            .ok_or_else(|| {
                rejected(
                    ErrorCode::DependencyMissing,
                    "missing authority signer history",
                )
            })?;
        used_histories.insert(index);
        let key = service_key(
            resolution,
            &station,
            &signed.verification_method,
            signed.created_at,
        )?;
        if keys
            .insert_at(&signed.verification_method, signed.created_at, key.clone())
            .is_some_and(|old| old != key)
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "conflicting historical authority key",
            ));
        }
    }
    if used_histories.len() != state.authority_bundle.signer_histories.len() {
        return Err(rejected(
            ErrorCode::SchemaViolation,
            "surplus authority signer history",
        ));
    }
    let authority = verify_accepted_agent_authority_bundle(&state.authority_bundle, &keys)
        .map_err(signature)?;
    for commit in &state.commits {
        authority.verify_commit(commit, &keys).map_err(signature)?;
    }
    if state
        .commits
        .last()
        .and_then(|c| authority.authority_service_at(c.governance_generation))
        != Some(&account.station_id)
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "source cut is governed by another Agent Station",
        ));
    }

    let events = [
        &state.pcr_genesis_event,
        &state.key_authorization_event,
        &state.agent_lifecycle_witness.accepted_status_event,
    ]
    .into_iter()
    .chain(
        state
            .authority_bundle
            .authority_transitions
            .iter()
            .map(|t| &t.change_event),
    )
    .collect::<Vec<_>>();
    for binding in &state.producer_bindings {
        let event = events
            .iter()
            .find(|e| e.event_id == binding.event_ref)
            .expect("validated binding");
        let accepted = state
            .commits
            .iter()
            .find(|c| c.commit_id == binding.accepted_commit_id)
            .expect("validated binding");
        let dependency = state
            .signer_dependencies
            .iter()
            .find(|d| d.reference() == &binding.signer_resolution_evidence_ref)
            .expect("validated binding");
        verify_dependency(event, dependency, accepted.committed_at, visiting)?;
    }

    let signer = &carrier.authenticated_signer_evidence;
    signer.validate()?;
    let binding = &state.authorization;
    let arkret_wire::TypedCurrentResult::Value { value, .. } =
        &state.agent_lifecycle_witness.result;
    if signer.signer_kind != AuthenticatedSignerKind::Agent
        || signer.subject_id != account.principal_id
        || signer.verification_method != binding.verification_method
        || signer.authority_commit_id != state.source_commit_id
        || signer.resolved_at < state.commits.last().expect("validated chain").committed_at
        || signer.resolved_at > leaf.issued_at
        || value.as_str() != Some("active")
        || at < binding.accepted_at
        || at < binding.issued_at
        || binding.expires_at.is_some_and(|end| at >= end)
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Agent signer is not active at the attested source cut",
        ));
    }
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(binding.public_key.key.as_str())?,
    };
    bind_jwk(&signer.public_key_jwk, &key)?;
    visiting.remove(&reference);
    Ok(key)
}

fn verify_dependency(
    event: &Event,
    dependency: &AgentSignerDependency,
    accepted_at: DateTime<Utc>,
    visiting: &mut BTreeSet<SignerEvidenceRef>,
) -> Result<()> {
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "missing historical producer proof",
        )
    })?;
    let key = match dependency {
        AgentSignerDependency::AccountDevice {
            account_device_signer_evidence,
            ..
        } => {
            let producer = event.human_device_producer()?.ok_or_else(|| {
                rejected(
                    ErrorCode::SignatureInvalid,
                    "historical signer is not a human device",
                )
            })?;
            crate::account_device_signer_evidence::verify_historical_account_device_signer_evidence(account_device_signer_evidence, &producer.account_id, &producer.device_id)?;
            let core = &account_device_signer_evidence
                .device_projection_attestation
                .attestation;
            let covers = |time| {
                time >= core.authorization_window.not_before
                    && core
                        .authorization_window
                        .expires_at
                        .is_none_or(|end| time < end)
            };
            if !core.device_status.is_active()
                || !covers(event.created_at)
                || !covers(accepted_at)
                || core.attested_at > accepted_at
                || accepted_at >= core.expires_at
            {
                return Err(rejected(
                    ErrorCode::SignatureInvalid,
                    "historical device authorization does not cover original acceptance",
                ));
            }
            PublicKeyMaterial::Ed25519Multibase {
                value: core
                    .device_signing_key_did
                    .as_str()
                    .strip_prefix("did:key:")
                    .ok_or_else(|| {
                        rejected(
                            ErrorCode::SignatureInvalid,
                            "historical device key is not did:key",
                        )
                    })?
                    .to_owned(),
            }
        }
        AgentSignerDependency::Service {
            authenticated_signer_evidence,
            service_resolution,
            ..
        } => {
            let signer = authenticated_signer_evidence;
            if event.actual_signer().as_account_id().is_some()
                || signer.signer_kind != AuthenticatedSignerKind::Service
                || &signer.subject_id != event.actual_signer().signing_principal_id()
                || signer.verification_method != proof.verification_method
            {
                return Err(rejected(
                    ErrorCode::SignatureInvalid,
                    "historical Service signer class or identity differs",
                ));
            }
            let key = service_key(
                service_resolution,
                &signer.subject_id,
                &signer.verification_method,
                proof.created_at,
            )?;
            bind_jwk(&signer.public_key_jwk, &key)?;
            key
        }
        AgentSignerDependency::Agent { agent_evidence, .. } => {
            let account = event.actual_signer().as_account_id().ok_or_else(|| {
                rejected(
                    ErrorCode::SignatureInvalid,
                    "historical Agent signer is not an Account",
                )
            })?;
            let mut full = (**agent_evidence).clone();
            let key = verify_closure(&mut full, account, accepted_at, visiting)?;
            let authorization = &full
                .agent_authority_state_evidence
                .state
                .as_ref()
                .expect("restored closure")
                .authorization;
            if event.created_at < authorization.accepted_at
                || event.created_at < authorization.issued_at
                || authorization
                    .expires_at
                    .is_some_and(|end| event.created_at >= end)
                || event.human_device_producer()?.is_some()
            {
                return Err(rejected(
                    ErrorCode::SignatureInvalid,
                    "historical Agent key was not effective at Event creation",
                ));
            }
            if proof.verification_method != full.authenticated_signer_evidence.verification_method {
                return Err(rejected(
                    ErrorCode::SignatureInvalid,
                    "historical Agent method differs",
                ));
            }
            key
        }
    };
    verify_event(event, &key)
}

fn verify_event(event: &Event, key: &PublicKeyMaterial) -> Result<()> {
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())?;
    event.verify_event_id_matches_content_with_digest_suite(suite)?;
    event.verify_producer_proof_self_consistency(suite)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected(ErrorCode::SchemaViolation, "missing producer proof"))?;
    let envelope = EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(signature)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope,
        &event.actor_id,
        key,
        suite,
    )
    .map_err(signature)
}

fn service_key(
    resolution: &AuthenticatedServiceResolution,
    station: &DidCoreId,
    method: &DidUrl,
    at: DateTime<Utc>,
) -> Result<PublicKeyMaterial> {
    if method_subject(method)? != *station {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "service method belongs to another authority",
        ));
    }
    let document = crate::authenticated_service_document_at(resolution, station, at)?;
    crate::validate_verification_method_relationship(
        &document,
        method,
        &document.id,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(signature)?;
    crate::public_key_material_from_document(&document, method).map_err(signature)
}

fn method_subject(method: &DidUrl) -> Result<DidCoreId> {
    let (did, _) = method
        .as_str()
        .split_once('#')
        .ok_or_else(|| rejected(ErrorCode::SchemaViolation, "method has no fragment"))?;
    Ok(arkret_wire::project_did_to_core_id(&Did::new(
        did.to_owned(),
    )?)?)
}

fn bind_jwk(jwk: &arkret_wire::NonEmptyJsonObject, key: &PublicKeyMaterial) -> Result<()> {
    let material = serde_json::to_value(jwk)?;
    let PublicKeyMaterial::Ed25519Raw { bytes } = key else {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "resolved key is not raw Ed25519",
        ));
    };
    if material.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
        || material.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
        || material.get("x").and_then(serde_json::Value::as_str)
            != Some(arkret_canonical::base64url_encode(bytes).as_str())
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "signer JWK differs from authenticated original key",
        ));
    }
    Ok(())
}

fn rejected(code: ErrorCode, message: &str) -> IdentityError {
    IdentityError::Wire(WireError::ProtocolCode {
        code,
        message: message.into(),
    })
}
fn signature(error: impl std::fmt::Display) -> IdentityError {
    rejected(ErrorCode::SignatureInvalid, &error.to_string())
}

fn validate_accepted_payloads(state: &AgentAuthorityState, account: &AccountId) -> Result<()> {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyAuthorizePayload, AgentKeyRevokePayload,
    };
    use arkret_models_collaboration::events_payloads::realm::{RealmCreatePayload, RealmPurpose};
    let genesis: RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&state.pcr_genesis_event.payload)?)?;
    genesis.object.validate()?;
    if genesis.object.purpose != RealmPurpose::AgentControl
        || genesis
            .object
            .initial_resolution
            .as_ref()
            .and_then(|r| arkret_wire::project_did_to_core_id(&r.did).ok())
            .as_ref()
            != Some(&account.principal_id)
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "PCR genesis identity differs from Agent",
        ));
    }
    AgentKeyAuthorizePayload::try_from(&state.key_authorization_event)
        .map_err(|e| rejected(ErrorCode::SchemaViolation, &e.to_string()))?;
    let controller = AccountId::new(
        state.authorization.controller_principal_id.clone(),
        account.station_id.clone(),
    );
    for original in [&state.pcr_genesis_event, &state.key_authorization_event] {
        if original.actor_id.as_account_id() != Some(account)
            || original
                .executed_by
                .as_ref()
                .and_then(arkret_wire::ActorId::as_account_id)
                != Some(&controller)
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "Agent PCR control producer is not the exact executing controller",
            ));
        }
    }
    let arkret_wire::TypedCurrentResult::Value { value, .. } = &state.key_state_witness.result;
    let entries = value
        .get("authorizations")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            rejected(
                ErrorCode::SchemaViolation,
                "key result has no authorization set",
            )
        })?;
    if value.as_object().is_none_or(|o| o.len() != 1) {
        return Err(rejected(
            ErrorCode::SchemaViolation,
            "key result is not a closed authorization set",
        ));
    }
    let mut previous = None;
    for entry in entries {
        let tag = entry
            .get("tag_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| rejected(ErrorCode::SchemaViolation, "authorization dot has no tag"))?;
        let dot: arkret_models_collaboration::exact_current_results::CanonicalEventDot =
            serde_json::from_value(serde_json::Value::String(tag.to_owned()))?;
        if entry.as_object().is_none_or(|o| o.len() != 2)
            || previous.as_ref().is_some_and(|prior| prior >= &dot)
        {
            return Err(rejected(
                ErrorCode::SchemaViolation,
                "authorization dots are malformed or duplicated",
            ));
        }
        previous = Some(dot);
        let payload = entry.get("value").cloned().ok_or_else(|| {
            rejected(ErrorCode::SchemaViolation, "authorization dot has no value")
        })?;
        let (agent_id, key_id) = if payload.get("verification_method").is_some() {
            let payload: AgentKeyAuthorizePayload = serde_json::from_value(payload)?;
            (payload.agent_id, payload.key_id)
        } else {
            let payload: AgentKeyRevokePayload = serde_json::from_value(payload)?;
            (payload.agent_id, payload.key_id)
        };
        if agent_id != state.agent_id
            || key_id.as_str() != state.authorization.agent_key_id.as_str()
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "authorization result contains another key locator",
            ));
        }
    }
    let status = &state.agent_lifecycle_witness.accepted_status_event;
    if status.kind != arkret_wire::EventKind::RealmCreate {
        let value = serde_json::to_value(&status.payload)?;
        let (transition, previous, changed) = match status.kind {
            arkret_wire::EventKind::SelfAgentPause => {
                let p: arkret_models_collaboration::events_payloads::agent::AgentPausePayload =
                    serde_json::from_value(value)?;
                (p.transition, p.previous_status, p.status_changed_at)
            }
            arkret_wire::EventKind::SelfAgentResume => {
                let p: arkret_models_collaboration::events_payloads::agent::AgentResumePayload =
                    serde_json::from_value(value)?;
                (p.transition, p.previous_status, p.status_changed_at)
            }
            arkret_wire::EventKind::SelfAgentDeactivate => {
                let p: arkret_models_collaboration::events_payloads::agent::AgentDeactivatePayload =
                    serde_json::from_value(value)?;
                (p.transition, p.previous_status, p.status_changed_at)
            }
            _ => {
                return Err(rejected(
                    ErrorCode::SchemaViolation,
                    "invalid lifecycle provenance kind",
                ));
            }
        };
        let valid = match status.kind {
            arkret_wire::EventKind::SelfAgentPause => transition == "pause" && previous == "active",
            arkret_wire::EventKind::SelfAgentResume => {
                transition == "resume" && previous == "paused"
            }
            _ => transition == "deactivate" && matches!(previous.as_str(), "active" | "paused"),
        };
        if !valid
            || changed != status.created_at
            || status.actor_id.as_account_id() != Some(account)
            || status.actual_signer().as_account_id()
                != Some(&AccountId::new(
                    state.authorization.controller_principal_id.clone(),
                    account.station_id.clone(),
                ))
        {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "lifecycle provenance differs from controller transition",
            ));
        }
    }
    Ok(())
}
