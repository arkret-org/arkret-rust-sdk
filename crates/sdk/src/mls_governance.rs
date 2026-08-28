use std::collections::{BTreeMap, BTreeSet, VecDeque};

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector, governance_attester_evidence_selectors,
    governance_runtime_dependency_selectors_for_replay,
};
use arkret_models_collaboration::history_key::{
    AuthorizationIncarnation, HistoryKeyResponseSendRequest,
};
use arkret_models_collaboration::objects::realm::AvailabilityEvidenceScope;
use arkret_models_crypto::mls_governance_proof::{
    MlsGovernanceProofBundle, MlsGovernanceProofRequestBody, MlsSecurityFrontierLeaf,
};
use arkret_models_identity::{
    AgentEvidenceTransparency, AgentLifecycleWitness, AgentSignerEvidence,
    AuthenticatedSignerResolutionEvidence,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_state::mls_governance_proof::{
    MlsGovernanceVerificationCheckpoint, MlsGroupGenesisBinding, SealAvailabilityReplayAuthority,
    SealDependencyReplayContext, VerifiedMlsGovernanceFrontier,
};
use arkret_wire::{
    CellRef, CircleId, Event, EventProof, Hash, RealmId, Seal, SealBasis, WireError,
};

/// Result of verifying raw complete governance material without trusting a
/// caller-supplied target digest suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceClosure {
    pub checkpoint: MlsGovernanceVerificationCheckpoint,
    pub event_digest_suites: BTreeMap<Hash, arkret_canonical::DigestSuite>,
}

fn project_governance_cell_writes(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    authority_audits: &arkret_schema::CapabilityAuthorityAuditIndex,
) -> Result<Vec<arkret_wire::cba::ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes_with_authority_resolver(
        event,
        digest_suite,
        &|grant_id| authority_audits.resolve(grant_id),
    )
    .map_err(|error| error.to_string())
}

/// Derive the exact current membership incarnation from a fully verified
/// reducer checkpoint for use in an MLS Add proposal.
pub fn current_authorization_incarnation_from_verified_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    target: &arkret_wire::DidCoreId,
    circle_id: Option<&CircleId>,
) -> Result<AuthorizationIncarnation, WireError> {
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS authorization-incarnation registry construction failed: {error}"
        ))
    })?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&checkpoint.accepted_events);
    let winning_join = |cell: &CellRef| {
        arkret_state::mls_governance_proof::winning_membership_join_event_from_verified_checkpoint(
            checkpoint,
            cell,
            &registry,
            |event, digest_suite| {
                project_governance_cell_writes(event, digest_suite, &authority_audits)
            },
        )
    };
    let realm_cell = CellRef::new(arkret_wire::cell::subject_cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        target.as_str(),
    ))?;
    let realm_membership_incarnation_ref = winning_join(&realm_cell)?;
    let Some(circle_id) = circle_id else {
        return Ok(AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        });
    };
    let circle_subject = arkret_wire::cell::composite_subject(&[
        serde_json::Value::String(circle_id.as_str().to_owned()),
        serde_json::Value::String(target.as_str().to_owned()),
    ])?;
    let circle_cell = CellRef::new(arkret_wire::cell::subject_cell(
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
        &circle_subject,
    ))?;
    Ok(AuthorizationIncarnation::Circle {
        realm_membership_incarnation_ref,
        circle_membership_incarnation_ref: winning_join(&circle_cell)?,
    })
}

/// The only Native Agent historical-evidence checks that cannot be derived
/// from the retained evidence/dependency closure itself.
pub enum NativeAgentHistoricalTrustRequest<'a> {
    /// Verify this embedded PCR Seal against independently pinned historical
    /// notary authority.
    PcrSeal(&'a Seal),
    /// Verify the accepted lifecycle Event/provenance against the PCR reducer.
    LifecycleWitness(&'a AgentLifecycleWitness),
    /// Verify the optional transparency statement against an independently
    /// pinned transparency log/witness policy.
    Transparency(&'a AgentEvidenceTransparency),
}

/// Return the single Event digest claim carried by its proof set. This is a
/// content-addressing coordinate only; it does not authenticate the Event or
/// choose a digest suite.
pub fn signed_event_digest_claim(event: &Event) -> Result<Hash, WireError> {
    let mut digest = None;
    for proof in &event.proofs {
        let current = match proof {
            EventProof::Producer(proof) => &proof.event_digest,
            EventProof::PrincipalServerAdmission(proof) => &proof.event_digest,
        };
        if digest.as_ref().is_some_and(|previous| previous != current) {
            return Err(WireError::Protocol(
                "Event proofs disagree on event_digest".to_owned(),
            ));
        }
        digest.get_or_insert_with(|| current.clone());
    }
    digest.ok_or_else(|| WireError::Protocol("Event has no signed digest claim".to_owned()))
}

/// Read the digest suite declared by a Realm-create Event for construction of
/// an unverified genesis checkpoint candidate. Full replay must validate the
/// create Event and the genesis bridge before trusting the returned suite.
pub fn declared_genesis_live_digest_suite(
    event: &Event,
) -> Result<arkret_canonical::DigestSuite, WireError> {
    serde_json::from_value(
        event
            .payload
            .get("object")
            .and_then(|object| object.get("digest_algorithm"))
            .cloned()
            .ok_or_else(|| {
                WireError::Protocol("Realm create Event omits object.digest_algorithm".to_owned())
            })?,
    )
    .map_err(Into::into)
}

fn evidence_by_digest<'a>(
    dependencies: &'a [GovernanceDependency],
    digest: &Hash,
) -> Result<&'a AuthenticatedSignerResolutionEvidence, WireError> {
    let mut found = None;
    for dependency in dependencies {
        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector,
            authenticated_signer_resolution_evidence,
        } = dependency
        else {
            continue;
        };
        if selector
            == &(GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: digest.clone(),
            })
            && found
                .replace(authenticated_signer_resolution_evidence.as_ref())
                .is_some()
        {
            return Err(WireError::Protocol(
                "duplicate signer-resolution evidence dependency".to_owned(),
            ));
        }
    }
    found.ok_or_else(|| {
        WireError::Protocol("missing signer-resolution evidence dependency".to_owned())
    })
}

pub(crate) fn authenticated_document_key(
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    at: chrono::DateTime<chrono::Utc>,
) -> Result<PublicKeyMaterial, WireError> {
    evidence.validate_attester_binding()?;
    let document = match evidence {
        AuthenticatedSignerResolutionEvidence::Service {
            signer_id,
            authenticated_resolution,
            ..
        } => arkret_identity::authenticated_service_document_at(
            authenticated_resolution,
            signer_id,
            at,
        )
        .map_err(|error| WireError::Protocol(error.to_string()))?,
        AuthenticatedSignerResolutionEvidence::Principal {
            signer_id,
            public_resolution,
            normalized_did_document,
            attester_signer_evidence_digest,
            ..
        } => {
            let attester = evidence_by_digest(dependencies, attester_signer_evidence_digest)?;
            let AuthenticatedSignerResolutionEvidence::Service {
                signer_id: attester_id,
                authenticated_resolution,
                ..
            } = attester
            else {
                return Err(WireError::Protocol(
                    "principal signer evidence attester must be a service".to_owned(),
                ));
            };
            if public_resolution.principal_server_id != *attester_id
                || public_resolution.principal_id != *signer_id
                || public_resolution.resolution_projection.full_id != normalized_did_document.id
                || public_resolution
                    .method_history_evidence
                    .evidence()
                    .document_digest
                    != Hash::new(arkret_canonical::canonical_sha256(normalized_did_document)?)?
            {
                return Err(WireError::Protocol(
                    "principal signer evidence projection does not bind its normalized document"
                        .to_owned(),
                ));
            }
            arkret_identity::verify_authenticated_service_resolution_history(
                authenticated_resolution,
                attester_id,
                at,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            arkret_signatures::service_resolution::verify_public_principal_resolution(
                public_resolution,
                &authenticated_resolution.normalized_did_document,
                at,
            )?;
            normalized_did_document.clone()
        }
        AuthenticatedSignerResolutionEvidence::NativeAgent { .. } => {
            return Err(WireError::Protocol(
                "native-agent signer evidence requires the explicit historical-authority verifier"
                    .to_owned(),
            ));
        }
    };
    arkret_identity::public_key_material_from_document(&document, evidence.verification_method())
        .map_err(|error| WireError::Protocol(error.to_string()))
}

pub(crate) fn bound_evidence_by_digest<'a>(
    dependencies: &'a [GovernanceDependency],
    evidence_ref: &arkret_wire::SignerEvidenceRef,
    evidence_digest: &Hash,
    signer_id: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
) -> Result<&'a AuthenticatedSignerResolutionEvidence, WireError> {
    let evidence = evidence_by_digest(dependencies, evidence_digest)?;
    if &evidence.evidence_ref()? != evidence_ref
        || evidence.signer_id() != signer_id
        || evidence.verification_method() != verification_method
    {
        return Err(WireError::Protocol(
            "historical signer evidence does not match its bound identity and method".to_owned(),
        ));
    }
    Ok(evidence)
}

/// Assemble the only valid content-addressed Native Agent signer-resolution
/// root from an Agent evidence object and its four already authenticated
/// dependency leaves. Callers persist this returned root and the supplied
/// leaves byte-exactly; they never mirror the wrapper construction rules.
pub fn build_native_agent_signer_resolution_evidence(
    agent_signer_evidence: AgentSignerEvidence,
    authority_evidence: &AuthenticatedSignerResolutionEvidence,
    controller_evidence: &AuthenticatedSignerResolutionEvidence,
    account_authority_evidence: &AuthenticatedSignerResolutionEvidence,
    receiver_evidence: &AuthenticatedSignerResolutionEvidence,
) -> Result<AuthenticatedSignerResolutionEvidence, WireError> {
    let (signer_id, verification_method, receiver_id, receiver_method) =
        match &agent_signer_evidence {
            AgentSignerEvidence::CurrentAdmission {
                admission_evidence,
                current_observation,
                ..
            } => {
                let binding = &admission_evidence
                    .agent_authority_snapshot
                    .core
                    .signing_key_binding;
                (
                    binding.agent_id.clone(),
                    binding.verification_method.clone(),
                    current_observation.verifier_id.clone(),
                    None,
                )
            }
            AgentSignerEvidence::HistoricalEvent {
                admission_evidence,
                event_admission_receipt,
                ..
            } => {
                let binding = &admission_evidence
                    .agent_authority_snapshot
                    .core
                    .signing_key_binding;
                (
                    binding.agent_id.clone(),
                    binding.verification_method.clone(),
                    event_admission_receipt.receiver_service_id.clone(),
                    Some(
                        arkret_signatures::agent_evidence::historical_receipt_verification_method(
                            event_admission_receipt,
                        )
                        .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?,
                    ),
                )
            }
        };
    let admission_evidence = match &agent_signer_evidence {
        AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        }
        | AgentSignerEvidence::HistoricalEvent {
            admission_evidence, ..
        } => admission_evidence,
    };
    let snapshot = &admission_evidence.agent_authority_snapshot;
    let binding = &snapshot.core.signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;
    for evidence in [
        authority_evidence,
        controller_evidence,
        account_authority_evidence,
        receiver_evidence,
    ] {
        evidence.validate_attester_binding()?;
    }
    if authority_evidence.signer_id() != &snapshot.core.authority_service_id
        || authority_evidence.verification_method() != &snapshot.lease.verification_method
        || controller_evidence.signer_id() != &binding.controller_id
        || controller_evidence.verification_method()
            != &binding.controller_proof.verification_method
        || account_authority_evidence.signer_id() != &gate.authority_service_id
        || account_authority_evidence.verification_method() != &gate.verification_method
        || receiver_evidence.signer_id() != &receiver_id
        || receiver_method
            .as_ref()
            .is_some_and(|method| receiver_evidence.verification_method() != method)
        || !matches!(
            authority_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
        || !matches!(
            account_authority_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
        || !matches!(
            receiver_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
    {
        return Err(WireError::Protocol(
            "Native Agent signer-resolution dependency leaves do not match the evidence".to_owned(),
        ));
    }
    let result = AuthenticatedSignerResolutionEvidence::NativeAgent {
        signer_id,
        verification_method,
        agent_signer_evidence: Box::new(agent_signer_evidence),
        attester_signer_evidence_ref: authority_evidence.evidence_ref()?,
        attester_signer_evidence_digest: authority_evidence.canonical_sha256_digest()?,
        controller_signer_evidence_ref: controller_evidence.evidence_ref()?,
        controller_signer_evidence_digest: controller_evidence.canonical_sha256_digest()?,
        account_authority_signer_evidence_ref: account_authority_evidence.evidence_ref()?,
        account_authority_signer_evidence_digest: account_authority_evidence
            .canonical_sha256_digest()?,
        receiver_signer_evidence_ref: receiver_evidence.evidence_ref()?,
        receiver_signer_evidence_digest: receiver_evidence.canonical_sha256_digest()?,
    };
    result.validate_attester_binding()?;
    Ok(result)
}

/// Verify the complete Native Agent historical-event evidence state machine
/// and return the exact Ed25519 Event key. Historical controller, Agent
/// Authority, Account Authority, and receiver keys are resolved only from the
/// typed signer-evidence dependency closure. The caller supplies one narrow
/// callback for PCR notary/lifecycle/transparency trust anchors that the
/// portable evidence does not self-authenticate.
pub fn verify_native_agent_historical_event_key<VerifyExternalTrust>(
    event: &Event,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    verify_external_trust: VerifyExternalTrust,
) -> Result<PublicKeyMaterial, WireError>
where
    VerifyExternalTrust: Fn(NativeAgentHistoricalTrustRequest<'_>) -> Result<(), WireError> + Copy,
{
    evidence.validate_attester_binding()?;
    let AuthenticatedSignerResolutionEvidence::NativeAgent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        attester_signer_evidence_ref,
        attester_signer_evidence_digest,
        controller_signer_evidence_ref,
        controller_signer_evidence_digest,
        account_authority_signer_evidence_ref,
        account_authority_signer_evidence_digest,
        receiver_signer_evidence_ref,
        receiver_signer_evidence_digest,
    } = evidence
    else {
        return Err(WireError::Protocol(
            "Native Agent historical key verifier received non-agent evidence".to_owned(),
        ));
    };
    let AgentSignerEvidence::HistoricalEvent {
        admission_evidence,
        event_admission_receipt,
        transparency,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        return Err(WireError::Protocol(
            "Native Agent signer evidence is not historical_event".to_owned(),
        ));
    };
    let snapshot = &admission_evidence.agent_authority_snapshot;
    let core = &snapshot.core;
    let binding = &core.signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;

    let authority_evidence = bound_evidence_by_digest(
        dependencies,
        attester_signer_evidence_ref,
        attester_signer_evidence_digest,
        &core.authority_service_id,
        &snapshot.lease.verification_method,
    )?;
    let controller_evidence = bound_evidence_by_digest(
        dependencies,
        controller_signer_evidence_ref,
        controller_signer_evidence_digest,
        &binding.controller_id,
        &binding.controller_proof.verification_method,
    )?;
    let controller_public_key =
        authenticated_document_key(controller_evidence, dependencies, binding.issued_at)?;
    let authority_public_key =
        authenticated_document_key(authority_evidence, dependencies, snapshot.lease.issued_at)?;
    let account_authority_evidence = bound_evidence_by_digest(
        dependencies,
        account_authority_signer_evidence_ref,
        account_authority_signer_evidence_digest,
        &gate.authority_service_id,
        &gate.verification_method,
    )?;
    let account_authority_public_key =
        authenticated_document_key(account_authority_evidence, dependencies, gate.issued_at)?;
    let receipt_method = arkret_signatures::agent_evidence::historical_receipt_verification_method(
        event_admission_receipt,
    )
    .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let receiver_evidence = bound_evidence_by_digest(
        dependencies,
        receiver_signer_evidence_ref,
        receiver_signer_evidence_digest,
        &event_admission_receipt.receiver_service_id,
        &receipt_method,
    )?;
    let receiver_public_key = authenticated_document_key(
        receiver_evidence,
        dependencies,
        event_admission_receipt.accepted_at,
    )?;

    let public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let verify_pcr_seal = |seal: &Seal| {
        verify_external_trust(NativeAgentHistoricalTrustRequest::PcrSeal(seal)).map_err(|_| {
            arkret_signatures::agent_evidence::AgentEvidenceRejectedReason::SigningKeyMismatch
        })
    };
    let verify_lifecycle = |witness: &AgentLifecycleWitness| {
        verify_external_trust(NativeAgentHistoricalTrustRequest::LifecycleWitness(witness))
            .map_err(|_| {
                arkret_signatures::agent_evidence::AgentEvidenceRejectedReason::AuthorizationConflicted
            })
    };
    let verified_state = arkret_signatures::agent_evidence::verify_agent_evidence_state(
        admission_evidence,
        &arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
            signer_id,
            agent_key_id: &binding.agent_key_id,
            controller_id: &binding.controller_id,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            authorize_public_key_digest: &public_key_digest,
            authorize_signing_key_binding_digest: &binding_digest,
            verify_seal_signature: &verify_pcr_seal,
            verify_lifecycle_reducer: &verify_lifecycle,
        },
    )
    .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let transparency_verified = if let Some(transparency) = transparency {
        verify_external_trust(NativeAgentHistoricalTrustRequest::Transparency(
            transparency,
        ))?;
        true
    } else {
        false
    };
    let origin_admission = event
        .proofs
        .iter()
        .find_map(|proof| match proof {
            EventProof::PrincipalServerAdmission(value) => Some(value),
            EventProof::Producer(_) => None,
        })
        .ok_or_else(|| WireError::Protocol("Agent Event omitted origin admission".to_owned()))?;
    let producer_evidence_ref = origin_admission
        .producer_signer_resolution_evidence_ref
        .as_ref()
        .ok_or_else(|| {
            WireError::Protocol("Agent Event omitted producer evidence ref".to_owned())
        })?;
    let producer_evidence_digest = origin_admission
        .producer_signer_resolution_evidence_digest
        .as_ref()
        .ok_or_else(|| {
            WireError::Protocol("Agent Event omitted producer evidence digest".to_owned())
        })?;
    let resolve_receiver = |method: &arkret_wire::DidUrl, at| {
        (method == &receipt_method && at == event_admission_receipt.accepted_at)
            .then(|| receiver_public_key.clone())
    };
    let verdict = arkret_signatures::agent_evidence::validate_historical_agent_signer_evidence(
        Some(agent_signer_evidence),
        &arkret_signatures::agent_evidence::HistoricalAgentSignerEvidenceValidationContext {
            common: arkret_signatures::agent_evidence::AgentEvidenceCommonContext {
                signer_id,
                agent_key_id: &binding.agent_key_id,
                controller_id: &binding.controller_id,
                verification_method,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &public_key_digest,
                authorize_signing_key_binding_digest: &binding_digest,
                expected_authority_service_id: &core.authority_service_id,
                expected_authority_verification_method: &snapshot.lease.verification_method,
                expected_account_authority_service_id: &gate.authority_service_id,
                expected_account_authority_verification_method: &gate.verification_method,
                controller_public_key: &controller_public_key,
                authority_public_key: &authority_public_key,
                account_authority_public_key: &account_authority_public_key,
                verified_state: &verified_state,
                require_transparency: transparency.is_some(),
                transparency_verified,
                now: chrono::Utc::now(),
            },
            event_id: &event.event_id,
            realm_id: &event.realm_id,
            producer_accepted_at: origin_admission.accepted_at,
            producer_signer_resolution_evidence_ref: producer_evidence_ref,
            producer_signer_resolution_evidence_digest: producer_evidence_digest,
            receiver_service_id: &event_admission_receipt.receiver_service_id,
            resolve_receiver_historical_key: &resolve_receiver,
        },
    );
    match verdict {
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Verified(key) => {
            Ok(PublicKeyMaterial::Ed25519Raw {
                bytes: key.key().to_vec(),
            })
        }
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Unresolved(reason) => {
            Err(WireError::Protocol(reason.as_str().to_owned()))
        }
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Rejected(reason) => {
            Err(WireError::Protocol(reason.as_str().to_owned()))
        }
    }
}

/// Verify the complete Native Agent current-admission evidence state machine
/// for a history response source proof and return its exact Ed25519 key.
/// Current observation request binding uses the dedicated non-cyclic history
/// source digest; all authority keys come from the exact dependency closure.
pub fn verify_native_agent_history_source_key<VerifyExternalTrust>(
    source: &HistoryKeyResponseSendRequest,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    verify_external_trust: VerifyExternalTrust,
) -> Result<PublicKeyMaterial, WireError>
where
    VerifyExternalTrust: Fn(NativeAgentHistoricalTrustRequest<'_>) -> Result<(), WireError> + Copy,
{
    source.validate()?;
    evidence.validate_attester_binding()?;
    let AuthenticatedSignerResolutionEvidence::NativeAgent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        attester_signer_evidence_ref,
        attester_signer_evidence_digest,
        controller_signer_evidence_ref,
        controller_signer_evidence_digest,
        account_authority_signer_evidence_ref,
        account_authority_signer_evidence_digest,
        receiver_signer_evidence_ref,
        receiver_signer_evidence_digest,
    } = evidence
    else {
        return Err(WireError::Protocol(
            "Native Agent history source verifier received non-agent evidence".to_owned(),
        ));
    };
    let AgentSignerEvidence::CurrentAdmission {
        admission_evidence,
        current_observation,
        transparency,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        return Err(WireError::Protocol(
            "Native Agent history source evidence is not current_admission".to_owned(),
        ));
    };
    if signer_id != &source.source_actor_id
        || verification_method != &source.source_proof.verification_method
        || current_observation.request_digest != source.history_source_agent_observation_digest()?
        || current_observation.verifier_id != current_observation.audience
    {
        return Err(WireError::Protocol(
            "Native Agent history source observation binding mismatch".to_owned(),
        ));
    }

    let snapshot = &admission_evidence.agent_authority_snapshot;
    let core = &snapshot.core;
    let binding = &core.signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;
    let authority_evidence = bound_evidence_by_digest(
        dependencies,
        attester_signer_evidence_ref,
        attester_signer_evidence_digest,
        &core.authority_service_id,
        &snapshot.lease.verification_method,
    )?;
    let controller_evidence = bound_evidence_by_digest(
        dependencies,
        controller_signer_evidence_ref,
        controller_signer_evidence_digest,
        &binding.controller_id,
        &binding.controller_proof.verification_method,
    )?;
    let account_authority_evidence = bound_evidence_by_digest(
        dependencies,
        account_authority_signer_evidence_ref,
        account_authority_signer_evidence_digest,
        &gate.authority_service_id,
        &gate.verification_method,
    )?;
    let receiver_evidence = evidence_by_digest(dependencies, receiver_signer_evidence_digest)?;
    if &receiver_evidence.evidence_ref()? != receiver_signer_evidence_ref
        || receiver_evidence.signer_id() != &current_observation.verifier_id
        || !matches!(
            receiver_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
    {
        return Err(WireError::Protocol(
            "Native Agent history source receiver evidence mismatch".to_owned(),
        ));
    }
    let controller_public_key =
        authenticated_document_key(controller_evidence, dependencies, binding.issued_at)?;
    let authority_public_key =
        authenticated_document_key(authority_evidence, dependencies, snapshot.lease.issued_at)?;
    let account_authority_public_key =
        authenticated_document_key(account_authority_evidence, dependencies, gate.issued_at)?;
    authenticated_document_key(
        receiver_evidence,
        dependencies,
        current_observation.evaluated_at,
    )?;

    let public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let verify_pcr_seal = |seal: &Seal| {
        verify_external_trust(NativeAgentHistoricalTrustRequest::PcrSeal(seal)).map_err(|_| {
            arkret_signatures::agent_evidence::AgentEvidenceRejectedReason::SigningKeyMismatch
        })
    };
    let verify_lifecycle = |witness: &AgentLifecycleWitness| {
        verify_external_trust(NativeAgentHistoricalTrustRequest::LifecycleWitness(witness))
            .map_err(|_| {
                arkret_signatures::agent_evidence::AgentEvidenceRejectedReason::AuthorizationConflicted
            })
    };
    let verified_state = arkret_signatures::agent_evidence::verify_agent_evidence_state(
        admission_evidence,
        &arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
            signer_id,
            agent_key_id: &binding.agent_key_id,
            controller_id: &binding.controller_id,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            authorize_public_key_digest: &public_key_digest,
            authorize_signing_key_binding_digest: &binding_digest,
            verify_seal_signature: &verify_pcr_seal,
            verify_lifecycle_reducer: &verify_lifecycle,
        },
    )
    .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let transparency_verified = if let Some(transparency) = transparency {
        verify_external_trust(NativeAgentHistoricalTrustRequest::Transparency(
            transparency,
        ))?;
        true
    } else {
        false
    };
    let verdict = arkret_signatures::agent_evidence::validate_current_agent_signer_evidence(
        Some(agent_signer_evidence),
        &arkret_signatures::agent_evidence::CurrentAgentSignerEvidenceValidationContext {
            common: arkret_signatures::agent_evidence::AgentEvidenceCommonContext {
                signer_id,
                agent_key_id: &binding.agent_key_id,
                controller_id: &binding.controller_id,
                verification_method,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &public_key_digest,
                authorize_signing_key_binding_digest: &binding_digest,
                expected_authority_service_id: &core.authority_service_id,
                expected_authority_verification_method: &snapshot.lease.verification_method,
                expected_account_authority_service_id: &gate.authority_service_id,
                expected_account_authority_verification_method: &gate.verification_method,
                controller_public_key: &controller_public_key,
                authority_public_key: &authority_public_key,
                account_authority_public_key: &account_authority_public_key,
                verified_state: &verified_state,
                require_transparency: transparency.is_some(),
                transparency_verified,
                now: source.source_proof.created_at,
            },
            operation_id: &current_observation.operation_id,
            request_digest: &current_observation.request_digest,
            verifier_id: &current_observation.verifier_id,
            audience: &current_observation.audience,
            challenge: &current_observation.challenge,
        },
    );
    match verdict {
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Verified(key) => {
            Ok(PublicKeyMaterial::Ed25519Raw {
                bytes: key.key().to_vec(),
            })
        }
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Unresolved(reason) => {
            Err(WireError::Protocol(reason.as_str().to_owned()))
        }
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Rejected(reason) => {
            Err(WireError::Protocol(reason.as_str().to_owned()))
        }
    }
}

fn verify_event_proofs_default<VerifyNativeAgentHistoryKey>(
    event: &Event,
    event_digest_suite: arkret_canonical::DigestSuite,
    dependencies: &[GovernanceDependency],
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<(), WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    match event.proofs.as_slice() {
        [EventProof::Producer(producer)] => {
            let digest = producer
                .signer_resolution_evidence_digest
                .as_ref()
                .ok_or_else(|| {
                    WireError::Protocol("direct Event omits signer evidence".to_owned())
                })?;
            let evidence = evidence_by_digest(dependencies, digest)?;
            if producer.signer_resolution_evidence_ref.as_ref() != Some(&evidence.evidence_ref()?)
                || evidence.verification_method() != &producer.verification_method
                || evidence.signer_id() != event.executed_by.as_ref().unwrap_or(&event.actor_id)
            {
                return Err(WireError::Protocol(
                    "direct Event signer evidence binding mismatch".to_owned(),
                ));
            }
            let key = match evidence {
                AuthenticatedSignerResolutionEvidence::NativeAgent { .. } => {
                    verify_native_agent_history_key(
                        event,
                        event_digest_suite,
                        evidence,
                        dependencies,
                    )?
                }
                _ => authenticated_document_key(evidence, dependencies, producer.created_at)?,
            };
            arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                producer,
                &envelope_bytes,
                &event.actor_id,
                &key,
                event_digest_suite,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))
        }
        [
            EventProof::Producer(producer),
            EventProof::PrincipalServerAdmission(admission),
        ] => {
            admission.validate_binding(
                &producer.event_digest,
                producer,
                &event.principal_server_id,
            )?;
            let multibase = admission
                .producer_signing_key
                .as_str()
                .strip_prefix("did:key:")
                .ok_or_else(|| {
                    WireError::Protocol("invalid admitted producer did:key".to_owned())
                })?;
            let producer_key = PublicKeyMaterial::Ed25519Raw {
                bytes: arkret_canonical::decode_ed25519_multibase(multibase)?.to_vec(),
            };
            arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                producer,
                &envelope_bytes,
                &event.actor_id,
                &producer_key,
                event_digest_suite,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            let evidence =
                evidence_by_digest(dependencies, &admission.signer_resolution_evidence_digest)?;
            let AuthenticatedSignerResolutionEvidence::Service {
                signer_id,
                authenticated_resolution,
                ..
            } = evidence
            else {
                return Err(WireError::Protocol(
                    "Principal Server admission signer evidence must be service-kind".to_owned(),
                ));
            };
            if signer_id != &event.principal_server_id
                || evidence.verification_method() != &admission.verification_method
                || evidence.evidence_ref()? != admission.signer_resolution_evidence_ref
            {
                return Err(WireError::Protocol(
                    "Principal Server admission signer evidence binding mismatch".to_owned(),
                ));
            }
            let historical_document = arkret_identity::authenticated_service_document_at(
                authenticated_resolution,
                signer_id,
                admission.accepted_at,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            arkret_identity::verify_jws_with_document(
                &admission.canonical_binding_bytes()?,
                &admission.jws,
                &admission.verification_method,
                &historical_document.id,
                &historical_document,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))
        }
        _ => Err(WireError::Protocol(
            "replayed Event has an unsupported proof regime".to_owned(),
        )),
    }
}

pub fn verify_seal_availability_dependencies_default(
    seal: &Seal,
    events: &BTreeMap<Hash, Event>,
    replay_context: &SealDependencyReplayContext,
    dependencies: &[GovernanceDependency],
) -> Result<(), WireError> {
    let SealAvailabilityReplayAuthority::Predecessor {
        policy: availability_policy,
        eligible_holder_ids,
    } = &replay_context.availability_authority
    else {
        return verify_genesis_availability_commitment(
            &seal.availability_receipt_digests,
            dependencies,
        );
    };
    availability_policy.validate()?;
    let seal_include_required = availability_policy
        .applies_to
        .contains(&AvailabilityEvidenceScope::SealInclude);
    let required = seal
        .availability_receipt_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if required.len() != seal.availability_receipt_digests.len() {
        return Err(WireError::Protocol(
            "Seal availability receipt digest list is not unique".to_owned(),
        ));
    }
    if !seal_include_required {
        if !required.is_empty() {
            return Err(WireError::Protocol(
                "Seal commits availability receipts while seal_include policy is disabled"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    let mut receipts = Vec::new();
    for dependency in dependencies {
        let GovernanceDependency::AvailabilityReceipt {
            selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
            availability_receipt,
        } = dependency
        else {
            continue;
        };
        if !required.contains(content_digest) {
            continue;
        }
        availability_receipt.validate_structural()?;
        if availability_receipt.realm_id != seal.realm_id {
            return Err(WireError::Protocol(
                "availability receipt is cross-Realm".to_owned(),
            ));
        }
        let event = events
            .values()
            .find(|event| event.event_id == availability_receipt.event_id)
            .ok_or_else(|| {
                WireError::Protocol("availability receipt Event is unresolved".to_owned())
            })?;
        let event_digest = signed_event_digest_claim(event)?;
        if !seal.delta.contains(&event_digest) {
            return Err(WireError::Protocol(
                "availability receipt does not cover this Seal delta".to_owned(),
            ));
        }
        let event_digest_suite = replay_context
            .event_digest_suites
            .get(&event_digest)
            .copied()
            .ok_or_else(|| {
                WireError::Protocol(
                    "availability receipt Event has no verified historical digest suite".to_owned(),
                )
            })?;
        let digest = |bytes: &[u8]| {
            Hash::new(arkret_canonical::digest(event_digest_suite, bytes)).map_err(Into::into)
        };
        if availability_receipt.full_receipt_digest(digest)? != *content_digest {
            return Err(WireError::Protocol(
                "availability receipt dependency selector digest mismatch".to_owned(),
            ));
        }
        availability_receipt.validate_signature_payload_digest(digest)?;
        availability_receipt.validate_event_bytes_digest(event, digest)?;
        let evidence = evidence_by_digest(
            dependencies,
            &availability_receipt.holder_signer_evidence_digest,
        )?;
        if evidence.signer_id() != &availability_receipt.holder_id
            || evidence.verification_method() != &availability_receipt.signature.verification_method
            || evidence.evidence_ref()? != availability_receipt.holder_signer_evidence_ref
        {
            return Err(WireError::Protocol(
                "availability receipt holder signer evidence binding mismatch".to_owned(),
            ));
        }
        let key = authenticated_document_key(
            evidence,
            dependencies,
            availability_receipt.signature.created_at,
        )?;
        arkret_signatures::verify_ed25519_detached_jws_payload_proof(
            &availability_receipt.signature,
            &availability_receipt.canonical_signature_binding_bytes()?,
            &key,
        )
        .map_err(|error| WireError::Protocol(error.to_string()))?;
        receipts.push((content_digest.clone(), availability_receipt.clone()));
    }
    let supplied = receipts
        .iter()
        .map(|(digest, _)| digest.clone())
        .collect::<BTreeSet<_>>();
    if supplied != required || supplied.len() != receipts.len() {
        return Err(WireError::Protocol(
            "availability receipt dependencies are not every-and-only the Seal commitment"
                .to_owned(),
        ));
    }
    let minimum_retention_ms = availability_policy
        .minimum_retention_ms
        .unwrap_or(86_400_000);
    let mut holders_by_event = BTreeMap::<_, BTreeSet<_>>::new();
    for (_, receipt) in &receipts {
        let holder_id = &receipt.holder_id;
        if !eligible_holder_ids.contains(holder_id) {
            return Err(WireError::Protocol(
                "availability receipt holder has no accepted predecessor role".to_owned(),
            ));
        }
        let retained_for_ms = receipt
            .retention_expires_at
            .signed_duration_since(seal.sealed_at)
            .num_milliseconds();
        if retained_for_ms < 0
            || u64::try_from(retained_for_ms).unwrap_or_default() < minimum_retention_ms
        {
            return Err(WireError::Protocol(
                "availability receipt retention is below the predecessor policy minimum".to_owned(),
            ));
        }
        if !holders_by_event
            .entry(receipt.event_id.clone())
            .or_default()
            .insert(holder_id.clone())
        {
            return Err(WireError::Protocol(
                "availability receipt holder is duplicated for one Event".to_owned(),
            ));
        }
    }
    for digest in &seal.delta {
        let event = events.get(digest).ok_or_else(|| {
            WireError::Protocol("Seal delta Event is unresolved for availability policy".to_owned())
        })?;
        let holder_count = holders_by_event
            .get(&event.event_id)
            .map_or(0, BTreeSet::len);
        if holder_count < usize::from(availability_policy.min_holders) {
            return Err(WireError::Protocol(
                "Seal delta Event does not meet the predecessor availability holder quorum"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_genesis_availability_commitment(
    availability_receipt_digests: &[Hash],
    _dependencies: &[GovernanceDependency],
) -> Result<(), WireError> {
    // `dependencies` is the checkpoint-wide closure shared while replaying
    // every Seal in the path. Successor receipts can therefore be present
    // while the genesis Seal is being checked; they are not supplied *by*
    // genesis unless its own signed commitment names them.
    if !availability_receipt_digests.is_empty() {
        return Err(WireError::Protocol(
            "genesis Seal must not commit availability receipts".to_owned(),
        ));
    }
    Ok(())
}

/// Verify a complete crash-safe governance checkpoint by isolated replay.
/// Retained Events may use either the sole-Producer direct-history regime or
/// the Producer + PrincipalServerAdmission federation regime. The SDK owns
/// frozen-notary selection, dependency verification, availability policy,
/// reducer projection, recovery, and final state-root/basis checks.
pub fn verify_mls_governance_checkpoint<VerifyNativeAgentHistoryKey>(
    candidate: &MlsGovernanceVerificationCheckpoint,
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = candidate
        .accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&candidate.accepted_events);
    arkret_state::mls_governance_proof::verify_mls_governance_checkpoint_with_registry(
        candidate,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_native_agent_history_key,
            )
        },
        |seal, _, replay_context, dependencies| {
            verify_seal_availability_dependencies_default(
                seal,
                &event_map,
                replay_context,
                dependencies,
            )
        },
        |event, digest_suite| {
            project_governance_cell_writes(event, digest_suite, &authority_audits)
        },
    )
}

/// Verify raw complete governance material and derive both the target live
/// digest suite and every accepted Event's historical suite by isolated
/// replay. This is the bootstrap entry point for callers that do not yet have
/// a durable verified checkpoint.
#[allow(clippy::too_many_arguments)]
pub fn verify_mls_governance_closure<VerifyNativeAgentHistoryKey>(
    realm_id: &RealmId,
    basis: &SealBasis,
    seals: &[Seal],
    events: &[Event],
    dependencies: &[GovernanceDependency],
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<VerifiedMlsGovernanceClosure, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let authority_audits = arkret_schema::CapabilityAuthorityAuditIndex::from_events(events);
    let (checkpoint, event_digest_suites) =
        arkret_state::mls_governance_proof::verify_mls_governance_closure_with_registry(
            realm_id,
            basis,
            seals,
            events,
            dependencies,
            &registry,
            arkret_signatures::verify_frozen_notary_signature,
            |event, digest_suite, dependencies| {
                verify_event_proofs_default(
                    event,
                    digest_suite,
                    dependencies,
                    verify_native_agent_history_key,
                )
            },
            |seal, _, replay_context, dependencies| {
                verify_seal_availability_dependencies_default(
                    seal,
                    &event_map,
                    replay_context,
                    dependencies,
                )
            },
            |event, digest_suite| {
                project_governance_cell_writes(event, digest_suite, &authority_audits)
            },
        )?;
    Ok(VerifiedMlsGovernanceClosure {
        checkpoint,
        event_digest_suites,
    })
}

/// Derive and re-verify the exact checkpoint pinned to an ancestor basis of a
/// complete verified checkpoint. Seal and Event closure selection, recursive
/// signer-evidence discovery, and reducer replay remain SDK-owned; callers do
/// not trim the checkpoint themselves.
pub fn derive_verified_mls_governance_checkpoint_at_basis<VerifyNativeAgentHistoryKey>(
    existing_checkpoint: &MlsGovernanceVerificationCheckpoint,
    requested_basis: &SealBasis,
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    requested_basis.validate_protocol_bounds()?;
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = existing_checkpoint
        .accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let authority_audits = arkret_schema::CapabilityAuthorityAuditIndex::from_events(
        &existing_checkpoint.accepted_events,
    );
    let (verified, requested_live_digest_suite, verified_event_digest_suites) =
        arkret_state::mls_governance_proof::verified_live_digest_suite_at_basis_with_registry(
            existing_checkpoint,
            requested_basis,
            &registry,
            arkret_signatures::verify_frozen_notary_signature,
            |event, digest_suite, dependencies| {
                verify_event_proofs_default(
                    event,
                    digest_suite,
                    dependencies,
                    verify_native_agent_history_key,
                )
            },
            |seal, _, replay_context, dependencies| {
                verify_seal_availability_dependencies_default(
                    seal,
                    &event_map,
                    replay_context,
                    dependencies,
                )
            },
            |event, digest_suite| {
                project_governance_cell_writes(event, digest_suite, &authority_audits)
            },
        )?;
    let seals_by_id = verified
        .accepted_seals
        .iter()
        .map(|seal| (seal.id.clone(), seal))
        .collect::<BTreeMap<_, _>>();
    let mut selected_ids = BTreeSet::new();
    let mut pending = requested_basis.leaves.to_vec();
    while let Some(seal_id) = pending.pop() {
        if !selected_ids.insert(seal_id.clone()) {
            continue;
        }
        let seal = seals_by_id.get(&seal_id).ok_or_else(|| {
            WireError::Protocol(
                "requested checkpoint basis is outside the verified Seal closure".to_owned(),
            )
        })?;
        pending.extend(seal.predecessor_refs.iter().cloned());
    }
    let selected_seals = selected_ids
        .iter()
        .map(|seal_id| {
            seals_by_id
                .get(seal_id)
                .map(|seal| (*seal).clone())
                .expect("selected Seal id was resolved during closure traversal")
        })
        .collect::<Vec<_>>();
    let selected_event_digests = selected_seals
        .iter()
        .flat_map(|seal| seal.delta.iter().cloned())
        .collect::<BTreeSet<_>>();
    let events_by_digest = verified
        .accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event)))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let selected_events = selected_event_digests
        .iter()
        .map(|digest| {
            events_by_digest
                .get(digest)
                .map(|event| (*event).clone())
                .ok_or_else(|| {
                    WireError::Protocol(
                        "derived checkpoint is missing a selected Seal delta Event".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let selected_dependencies = replay_dependency_closure(
        &selected_seals,
        &selected_events,
        &verified_event_digest_suites,
        &verified.governance_dependencies,
    )?;
    verify_mls_governance_checkpoint(
        &MlsGovernanceVerificationCheckpoint {
            realm_id: verified.realm_id,
            basis: requested_basis.clone(),
            live_digest_suite: requested_live_digest_suite,
            accepted_seals: selected_seals,
            accepted_events: selected_events,
            governance_dependencies: selected_dependencies,
        },
        verify_native_agent_history_key,
    )
}

fn replay_dependency_closure(
    seals: &[Seal],
    events: &[Event],
    event_digest_suites: &BTreeMap<Hash, arkret_canonical::DigestSuite>,
    available: &[GovernanceDependency],
) -> Result<Vec<GovernanceDependency>, WireError> {
    let mut available_by_selector = BTreeMap::new();
    for item in available {
        let key = arkret_canonical::canonical_json_bytes(item.selector())?;
        if let Some(previous) = available_by_selector.insert(key, item)
            && previous != item
        {
            return Err(WireError::Protocol(
                "verified checkpoint contains conflicting dependency values".to_owned(),
            ));
        }
    }
    let ordered_event_digest_suites = events
        .iter()
        .map(|event| {
            let digest = signed_event_digest_claim(event)?;
            event_digest_suites.get(&digest).copied().ok_or_else(|| {
                WireError::Protocol(
                    "verified replay omitted an Event digest-suite assignment".to_owned(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut pending = VecDeque::from(governance_runtime_dependency_selectors_for_replay(
        seals,
        events,
        &ordered_event_digest_suites,
    )?);
    let mut selected = BTreeMap::<Vec<u8>, GovernanceDependency>::new();
    while let Some(selector) = pending.pop_front() {
        let key = arkret_canonical::canonical_json_bytes(&selector)?;
        if selected.contains_key(&key) {
            continue;
        }
        let item = available_by_selector.get(&key).ok_or_else(|| {
            WireError::Protocol(
                "verified checkpoint lacks a dependency required by the requested basis".to_owned(),
            )
        })?;
        if let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence,
            ..
        } = item
        {
            pending.extend(governance_attester_evidence_selectors(std::iter::once(
                authenticated_signer_resolution_evidence.as_ref(),
            ))?);
        }
        selected.insert(key, (*item).clone());
    }
    Ok(selected.into_values().collect())
}

/// Verify an exact retained `(base, target]` cut without fetching material
/// before the caller's frozen base checkpoint. The SDK first re-verifies the
/// complete base checkpoint, then replays every-and-only cut Seal and Event
/// objects against that state. A caller that has only a `SealBasis` cannot use
/// this entry point.
pub fn verify_mls_governance_cut<VerifyNativeAgentHistoryKey>(
    base_checkpoint: &MlsGovernanceVerificationCheckpoint,
    target_basis: &SealBasis,
    cut_seals: &[Seal],
    cut_events: &[Event],
    cut_dependencies: &[GovernanceDependency],
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let verified_base =
        verify_mls_governance_checkpoint(base_checkpoint, verify_native_agent_history_key)?;
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = verified_base
        .accepted_events
        .iter()
        .chain(cut_events)
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let authority_audits = arkret_schema::CapabilityAuthorityAuditIndex::from_events(
        verified_base.accepted_events.iter().chain(cut_events),
    );
    arkret_state::mls_governance_proof::verify_mls_governance_cut_with_registry(
        &verified_base,
        target_basis,
        cut_seals,
        cut_events,
        cut_dependencies,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_native_agent_history_key,
            )
        },
        |seal, _, replay_context, dependencies| {
            verify_seal_availability_dependencies_default(
                seal,
                &event_map,
                replay_context,
                dependencies,
            )
        },
        |event, digest_suite| {
            project_governance_cell_writes(event, digest_suite, &authority_audits)
        },
    )
}

/// Verify a near-current MLS governance proof with the SDK's unique generated
/// registry, reducer projector, frozen-notary cryptography, Event proof
/// transcripts, and dependency verification. Applications supply only Native
/// Agent historical-authority verification. AvailabilityReceipt policy,
/// holder roles, retention, and quorum are derived from each Seal's verified
/// predecessor state and checked entirely inside the SDK.
#[allow(clippy::too_many_arguments)]
pub fn verify_mls_governance_frontier<VerifyNativeAgentHistoryKey>(
    request: &MlsGovernanceProofRequestBody,
    bundle: &MlsGovernanceProofBundle,
    base_checkpoint: &MlsGovernanceVerificationCheckpoint,
    resolved_seals: &[Seal],
    resolved_delta_events: &[Event],
    resolved_provenance_events: &[Event],
    resolved_dependencies: &[GovernanceDependency],
    group_genesis_binding: &MlsGroupGenesisBinding,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<VerifiedMlsGovernanceFrontier, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = base_checkpoint
        .accepted_events
        .iter()
        .chain(resolved_delta_events)
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let authority_audits = arkret_schema::CapabilityAuthorityAuditIndex::from_events(
        base_checkpoint
            .accepted_events
            .iter()
            .chain(resolved_delta_events)
            .chain(resolved_provenance_events),
    );
    arkret_state::mls_governance_proof::verify_mls_governance_frontier_with_registry(
        request,
        bundle,
        base_checkpoint,
        resolved_seals,
        resolved_delta_events,
        resolved_provenance_events,
        resolved_dependencies,
        group_genesis_binding,
        local_mls_leaves,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_native_agent_history_key,
            )
        },
        |seal, _, replay_context, dependencies| {
            verify_seal_availability_dependencies_default(
                seal,
                &event_map,
                replay_context,
                dependencies,
            )
        },
        |event, digest_suite| {
            project_governance_cell_writes(event, digest_suite, &authority_audits)
        },
    )
}

/// Build the exact bounded near-current proof page from a complete candidate
/// target checkpoint. The SDK first verifies the whole checkpoint, then
/// materializes per-target-Seal branches from isolated reducer stores.
#[allow(clippy::too_many_arguments)]
pub fn materialize_mls_governance_frontier<VerifyNativeAgentHistoryKey>(
    request: &MlsGovernanceProofRequestBody,
    target_checkpoint: &MlsGovernanceVerificationCheckpoint,
    group_genesis_binding: &MlsGroupGenesisBinding,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<MlsGovernanceProofBundle, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let verified =
        verify_mls_governance_checkpoint(target_checkpoint, verify_native_agent_history_key)?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&verified.accepted_events);
    arkret_state::mls_governance_proof::materialize_mls_governance_frontier_from_verified_checkpoint(
        request,
        &verified,
        group_genesis_binding,
        local_mls_leaves,
        &registry,
        |event, digest_suite| {
            project_governance_cell_writes(event, digest_suite, &authority_audits)
        },
    )
}

/// Verify and materialize the first crash-safe checkpoint for an event-derived
/// Realm. The candidate genesis Seal must cover the content-derived Realm
/// create Event and the complete anchor unit; all ordinary reducer and frozen
/// notary checks are then replayed before the checkpoint is returned.
#[allow(clippy::too_many_arguments)]
pub fn verify_event_derived_genesis_checkpoint<VerifyNativeAgentHistoryKey>(
    realm_id: &RealmId,
    genesis_seal: &Seal,
    accepted_events: &[Event],
    governance_dependencies: &[GovernanceDependency],
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyNativeAgentHistoryKey: Fn(
            &Event,
            arkret_canonical::DigestSuite,
            &AuthenticatedSignerResolutionEvidence,
            &[GovernanceDependency],
        ) -> Result<PublicKeyMaterial, WireError>
        + Copy,
{
    let create = accepted_events
        .iter()
        .find(|event| event.kind.as_str() == arkret_wire::event_kind_str::REALM_CREATE)
        .ok_or_else(|| {
            WireError::Protocol("genesis checkpoint has no Realm create Event".to_owned())
        })?;
    arkret_state::mls_governance_proof::admit_event_derived_genesis_anchor::<WireError, _>(
        realm_id,
        create,
        genesis_seal,
        |_, _| Ok(()),
    )?;
    let candidate = MlsGovernanceVerificationCheckpoint {
        realm_id: realm_id.clone(),
        basis: genesis_seal.seal_basis(),
        live_digest_suite: declared_genesis_live_digest_suite(create)?,
        accepted_seals: vec![genesis_seal.clone()],
        accepted_events: accepted_events.to_vec(),
        governance_dependencies: governance_dependencies.to_vec(),
    };
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(accepted_events);
    arkret_state::mls_governance_proof::verify_mls_governance_checkpoint_with_registry(
        &candidate,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_native_agent_history_key,
            )
        },
        |seal, _, replay_context, dependencies| {
            verify_seal_availability_dependencies_default(
                seal,
                &event_map,
                replay_context,
                dependencies,
            )
        },
        |event, digest_suite| {
            project_governance_cell_writes(event, digest_suite, &authority_audits)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_availability_gate_is_absent_and_commitment_is_empty() {
        verify_genesis_availability_commitment(&[], &[]).unwrap();

        let committed = Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let error = verify_genesis_availability_commitment(&[committed], &[]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("genesis Seal must not commit availability receipts")
        );
    }
}
