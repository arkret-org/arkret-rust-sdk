use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;

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
) -> Result<Vec<arkret_wire::cbs::ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes_with_authority_resolver(
        event,
        digest_suite,
        &|grant_id| authority_audits.resolve(grant_id),
    )
    .map_err(|error| error.to_string())
}

/// Derive the exact current membership incarnation from a fully verified
/// reducer checkpoint for use in an MLS Add proposal.
pub async fn current_authorization_incarnation_from_verified_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    target: &arkret_wire::ActorId,
    circle_id: Option<&CircleId>,
) -> Result<AuthorizationIncarnation, WireError> {
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS authorization-incarnation registry construction failed: {error}"
        ))
    })?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&checkpoint.accepted_events);
    let realm_cell = realm_membership_cell(target)?;
    let realm_membership_incarnation_ref =
        arkret_state::mls_governance_proof::winning_membership_join_event_from_verified_checkpoint(
            checkpoint,
            &realm_cell,
            &registry,
            |event, digest_suite| {
                project_governance_cell_writes(event, digest_suite, &authority_audits)
            },
        )
        .await?;
    let Some(circle_id) = circle_id else {
        return Ok(AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        });
    };
    let circle_subject = arkret_wire::cell::composite_subject(&[
        serde_json::Value::String(circle_id.as_str().to_owned()),
        serde_json::Value::String(target.canonical_key()?),
    ])?;
    let circle_cell = CellRef::new(arkret_wire::cell::subject_cell(
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
        &circle_subject,
    ))?;
    Ok(AuthorizationIncarnation::Circle {
        realm_membership_incarnation_ref,
        circle_membership_incarnation_ref:
            arkret_state::mls_governance_proof::winning_membership_join_event_from_verified_checkpoint(
                checkpoint,
                &circle_cell,
                &registry,
                |event, digest_suite| {
                    project_governance_cell_writes(event, digest_suite, &authority_audits)
                },
            )
            .await?,
    })
}

fn realm_membership_cell(target: &arkret_wire::ActorId) -> Result<CellRef, WireError> {
    let subject = arkret_wire::cell::composite_subject(&[serde_json::Value::String(
        target.canonical_key()?,
    )])?;
    Ok(CellRef::new(arkret_wire::cell::subject_cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        &subject,
    ))?)
}

/// The only Agent historical-evidence checks that cannot be derived
/// from the retained evidence/dependency closure itself.
pub enum AgentHistoricalTrustRequest<'a> {
    /// Verify this embedded PCR Seal against independently pinned historical
    /// notary authority.
    PcrSeal(&'a Seal),
    /// Verify the accepted lifecycle Event/provenance against the PCR reducer.
    LifecycleWitness(&'a AgentLifecycleWitness),
    /// Verify the optional transparency statement against an independently
    /// pinned transparency log/witness policy.
    Transparency(&'a AgentEvidenceTransparency),
}

#[cfg(not(target_arch = "wasm32"))]
pub type AgentHistoricalTrustFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), WireError>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type AgentHistoricalTrustFuture<'a> = Pin<Box<dyn Future<Output = Result<(), WireError>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub type VerifyAgentHistoryKeyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PublicKeyMaterial, WireError>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type VerifyAgentHistoryKeyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PublicKeyMaterial, WireError>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub trait VerifyAgentHistoryKeySend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> VerifyAgentHistoryKeySend for T {}
#[cfg(target_arch = "wasm32")]
pub trait VerifyAgentHistoryKeySend {}
#[cfg(target_arch = "wasm32")]
impl<T> VerifyAgentHistoryKeySend for T {}

/// Return the single Event digest claim carried by its proof set. This is a
/// content-addressing coordinate only; it does not authenticate the Event or
/// choose a digest suite.
pub fn signed_event_digest_claim(event: &Event) -> Result<Hash, WireError> {
    let mut digest = None;
    for proof in &event.proofs {
        let current = match proof {
            EventProof::Producer(proof) => &proof.event_digest,
            EventProof::StationAdmission(proof) => &proof.event_digest,
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

pub fn authenticated_document_key(
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    at: chrono::DateTime<chrono::Utc>,
) -> Result<PublicKeyMaterial, WireError> {
    authenticated_document_method_key(evidence, dependencies, evidence.verification_method(), at)
}

pub fn authenticated_document_method_key(
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<PublicKeyMaterial, WireError> {
    let did = method.as_str().split('#').next().unwrap_or_default();
    if arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did.to_owned())?)?
        != *evidence.signer_id()
    {
        return Err(WireError::Protocol(
            "historical method belongs to a different signer".to_owned(),
        ));
    }
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
            attester_signer_evidence_ref,
            ..
        } => {
            let attester = evidence_by_digest(
                dependencies,
                &attester_signer_evidence_ref.content_digest()?,
            )?;
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
            if public_resolution.account_id.station_id != *attester_id
                || public_resolution.account_id.principal_id != *signer_id
                || public_resolution.resolution_projection.did != normalized_did_document.id
                || public_resolution
                    .method_history_evidence
                    .evidence()
                    .document_digest
                    != arkret_models_identity::normalized_did_document_digest(
                        normalized_did_document,
                    )?
            {
                return Err(WireError::Protocol(
                    "principal signer evidence projection does not bind its normalized document"
                        .to_owned(),
                ));
            }
            let projection_at = public_resolution
                .projection_attestation
                .attestation
                .issued_at;
            arkret_identity::verify_public_principal_resolution_history(
                public_resolution,
                authenticated_resolution,
                normalized_did_document,
                projection_at,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            match &public_resolution.method_history_evidence {
                arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
                    log_entries,
                    ..
                } => {
                    let point = arkret_signatures::webvh::validate_webvh_history_at(
                        &normalized_did_document.id,
                        log_entries,
                        at,
                    )
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                    serde_json::from_value(point.document)?
                }
                arkret_models_identity::ResolutionMethodHistoryEvidence::DidKeyExpansion {
                    ..
                } => normalized_did_document.clone(),
                arkret_models_identity::ResolutionMethodHistoryEvidence::DidWebDocument {
                    ..
                } => {
                    return Err(WireError::Protocol(
                        "mutable did:web cannot authenticate historical Principal methods"
                            .to_owned(),
                    ));
                }
            }
        }
        AuthenticatedSignerResolutionEvidence::AccountDevice { .. } => {
            return Err(WireError::Protocol("account device history evidence cannot authorize a document or Control Event signature".to_owned()));
        }
        AuthenticatedSignerResolutionEvidence::Agent { .. } => {
            return Err(WireError::Protocol(
                "Agent signer evidence requires the explicit historical-authority verifier"
                    .to_owned(),
            ));
        }
    };
    arkret_identity::validate_verification_method_relationship(
        &document,
        method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    arkret_identity::public_key_material_from_document(&document, method)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

pub(crate) fn bound_evidence_by_ref<'a>(
    dependencies: &'a [GovernanceDependency],
    evidence_ref: &arkret_wire::SignerEvidenceRef,
    signer_id: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
) -> Result<&'a AuthenticatedSignerResolutionEvidence, WireError> {
    let evidence = evidence_by_digest(dependencies, &evidence_ref.content_digest()?)?;
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

fn validate_agent_controller_account(
    evidence: &AuthenticatedSignerResolutionEvidence,
    controller_principal_id: &arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
) -> Result<(), WireError> {
    let AuthenticatedSignerResolutionEvidence::Principal {
        public_resolution, ..
    } = evidence
    else {
        return Err(WireError::Protocol(
            "Agent controller source must authenticate a Principal account".to_owned(),
        ));
    };
    if public_resolution.account_id.principal_id != *controller_principal_id
        || public_resolution.account_id.station_id != *station_id
    {
        return Err(WireError::Protocol(
            "Agent controller source belongs to a different AccountId".to_owned(),
        ));
    }
    Ok(())
}

/// Construct one canonical Agent root; current authority has no receiver
/// dependency, while historical acceptance retains the exact accepting key.
pub fn build_agent_signer_resolution_evidence(
    agent_signer_evidence: AgentSignerEvidence,
    authority_evidence: &AuthenticatedSignerResolutionEvidence,
    controller_evidence: &AuthenticatedSignerResolutionEvidence,
    account_authority_evidence: &AuthenticatedSignerResolutionEvidence,
    receiver_evidence: Option<&AuthenticatedSignerResolutionEvidence>,
) -> Result<AuthenticatedSignerResolutionEvidence, WireError> {
    let admission = match &agent_signer_evidence {
        AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        }
        | AgentSignerEvidence::HistoricalEvent {
            admission_evidence, ..
        } => admission_evidence,
    };
    let snapshot = &admission.agent_authority_state_evidence;
    let binding = &snapshot.state.signing_key_binding;
    let gate = &admission.controller_account_gate_attestation;
    for evidence in [
        authority_evidence,
        controller_evidence,
        account_authority_evidence,
    ]
    .into_iter()
    .chain(receiver_evidence)
    {
        evidence.validate_attester_binding()?;
    }
    validate_agent_controller_account(
        controller_evidence,
        &binding.controller_principal_id,
        &snapshot.state.authority_id,
    )?;
    if gate.authority_id != snapshot.state.authority_id
        || authority_evidence.signer_id() != &snapshot.state.authority_id
        || authority_evidence.verification_method() != &snapshot.lease.verification_method
        || controller_evidence.signer_id() != &binding.controller_principal_id
        || controller_evidence.verification_method()
            != &binding.controller_proof.verification_method
        || account_authority_evidence.signer_id() != &gate.authority_id
        || account_authority_evidence.verification_method() != &gate.verification_method
        || !matches!(
            authority_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
        || !matches!(
            account_authority_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
    {
        return Err(WireError::Protocol(
            "Agent evidence authority dependencies mismatch".to_owned(),
        ));
    }
    match (&agent_signer_evidence, receiver_evidence) {
        (AgentSignerEvidence::CurrentAdmission { .. }, None) => {}
        (
            AgentSignerEvidence::HistoricalEvent {
                event_admission, ..
            },
            Some(receiver),
        ) => {
            let method =
                arkret_signatures::agent_evidence::historical_admission_verification_method(
                    event_admission,
                )
                .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
            if receiver.signer_id() != &event_admission.receiver_id()?
                || receiver.verification_method() != &method
                || !matches!(
                    receiver,
                    AuthenticatedSignerResolutionEvidence::Service { .. }
                )
            {
                return Err(WireError::Protocol(
                    "Agent historical acceptance dependency mismatch".to_owned(),
                ));
            }
        }
        _ => {
            return Err(WireError::Protocol(
                "Agent current evidence forbids receiver; historical evidence requires it"
                    .to_owned(),
            ));
        }
    }
    let result = AuthenticatedSignerResolutionEvidence::Agent {
        signer_id: binding.agent_id.clone(),
        verification_method: binding.verification_method.clone(),
        agent_signer_evidence: Box::new(agent_signer_evidence),
        attester_signer_evidence_ref: authority_evidence.evidence_ref()?,
        controller_signer_evidence_ref: controller_evidence.evidence_ref()?,
        account_authority_signer_evidence_ref: account_authority_evidence.evidence_ref()?,
        receiver_signer_evidence_ref: receiver_evidence
            .map(AuthenticatedSignerResolutionEvidence::evidence_ref)
            .transpose()?,
    };
    result.validate_attester_binding()?;
    Ok(result)
}

/// Authenticate the PCR proof keys from the portable closure itself. No
/// current DID resolution is performed for historical signatures.
pub fn verify_agent_portable_trust(
    request: AgentHistoricalTrustRequest<'_>,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
) -> Result<(), WireError> {
    let AuthenticatedSignerResolutionEvidence::Agent {
        agent_signer_evidence,
        ..
    } = root
    else {
        return Err(WireError::Protocol(
            "portable Agent trust requires Agent root".to_owned(),
        ));
    };
    let state = &agent_signer_evidence
        .admission_evidence()
        .agent_authority_state_evidence
        .state;
    match request {
        AgentHistoricalTrustRequest::PcrSeal(seal) => {
            let canonical = seal.canonical_bytes_for_id()?;
            let expected_digest = Hash::new(arkret_canonical::sha256_digest(&canonical))?;
            let signatures = match &seal.notary_signature {
                arkret_wire::NotarySig::Single(signature) => vec![signature],
                arkret_wire::NotarySig::Multi(signatures) => signatures.signatures.iter().collect(),
            };
            if signatures.is_empty() {
                return Err(WireError::Protocol(
                    "Agent PCR Seal has no signature".to_owned(),
                ));
            }
            for signature in signatures {
                let did = signature
                    .verification_method
                    .as_str()
                    .split('#')
                    .next()
                    .unwrap_or_default();
                let signer =
                    arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did.to_owned())?)?;
                if signer != state.authority_id
                    && signer != state.signing_key_binding.controller_principal_id
                    || signature.payload_digest != expected_digest
                {
                    return Err(WireError::Protocol(
                        "Agent PCR Seal signer or digest mismatch".to_owned(),
                    ));
                }
                let key = authenticated_method_key(
                    dependencies,
                    &signature.verification_method,
                    seal.sealed_at,
                )?;
                arkret_signatures::Ed25519DetachedJwsVerifier::new()
                    .verify_detached_jws(&signature.jws, &canonical, &key)
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
            }
            Ok(())
        }
        AgentHistoricalTrustRequest::LifecycleWitness(witness) => {
            let proof = witness
                .accepted_status_event
                .proofs
                .iter()
                .find_map(EventProof::as_station_admission)
                .ok_or_else(|| {
                    WireError::Protocol(
                        "Agent lifecycle Event omitted Station admission".to_owned(),
                    )
                })?;
            let evidence = evidence_by_digest(
                dependencies,
                &proof.signer_resolution_evidence_ref.content_digest()?,
            )?;
            if evidence.verification_method() != &proof.verification_method {
                return Err(WireError::Protocol(
                    "Agent lifecycle Station method mismatch".to_owned(),
                ));
            }
            let key = authenticated_document_key(evidence, dependencies, proof.accepted_at)?;
            arkret_signatures::agent_evidence::verify_agent_lifecycle_event_signature(
                witness,
                &|method| (method == &proof.verification_method).then(|| key.clone()),
            )
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))
        }
        AgentHistoricalTrustRequest::Transparency(_) => Err(WireError::Protocol(
            "transparency needs its independently configured log trust".to_owned(),
        )),
    }
}

pub fn authenticated_method_key(
    dependencies: &[GovernanceDependency],
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<PublicKeyMaterial, WireError> {
    let mut resolved = None;
    for dependency in dependencies {
        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence: evidence,
            ..
        } = dependency
        else {
            continue;
        };
        if let Ok(key) = authenticated_document_method_key(evidence, dependencies, method, at) {
            if resolved.as_ref().is_some_and(|previous| previous != &key) {
                return Err(WireError::Protocol(
                    "historical method has conflicting authenticated keys".to_owned(),
                ));
            }
            resolved = Some(key);
        }
    }
    resolved.ok_or_else(|| {
        WireError::Protocol("historical method dependency is missing or invalid".to_owned())
    })
}

/// Verify the complete Agent historical-event evidence state machine
/// and return the exact Ed25519 Event key. Historical controller, Agent
/// Authority, Account Authority, and receiver keys are resolved only from the
/// typed signer-evidence dependency closure. The caller supplies one narrow
/// callback for PCR notary/lifecycle/transparency trust anchors that the
/// portable evidence does not self-authenticate.
pub async fn verify_agent_historical_event_key<VerifyExternalTrust>(
    event: &Event,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    verify_external_trust: VerifyExternalTrust,
) -> Result<PublicKeyMaterial, WireError>
where
    VerifyExternalTrust:
        for<'a> Fn(AgentHistoricalTrustRequest<'a>) -> AgentHistoricalTrustFuture<'a> + Clone,
{
    event.validate_station_admission_binding(event.event_id.event_digest().digest_suite()?)?;
    evidence.validate_attester_binding()?;
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        attester_signer_evidence_ref,
        controller_signer_evidence_ref,
        account_authority_signer_evidence_ref,
        receiver_signer_evidence_ref,
    } = evidence
    else {
        return Err(WireError::Protocol(
            "Agent historical key verifier received non-agent evidence".to_owned(),
        ));
    };
    let AgentSignerEvidence::HistoricalEvent {
        admission_evidence,
        event_admission,
        transparency,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        return Err(WireError::Protocol(
            "Agent signer evidence is not historical_event".to_owned(),
        ));
    };
    let authority_evidence_state = &admission_evidence.agent_authority_state_evidence;
    let core = &authority_evidence_state.state;
    let binding = &core.signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;

    let authority_evidence = bound_evidence_by_ref(
        dependencies,
        attester_signer_evidence_ref,
        &core.authority_id,
        &authority_evidence_state.lease.verification_method,
    )?;
    let controller_evidence = bound_evidence_by_ref(
        dependencies,
        controller_signer_evidence_ref,
        &binding.controller_principal_id,
        &binding.controller_proof.verification_method,
    )?;
    validate_agent_controller_account(
        controller_evidence,
        &binding.controller_principal_id,
        event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .route_service_id(),
    )?;
    let controller_public_key =
        authenticated_document_key(controller_evidence, dependencies, binding.issued_at)?;
    let authority_public_key = authenticated_document_key(
        authority_evidence,
        dependencies,
        authority_evidence_state.lease.issued_at,
    )?;
    let account_authority_evidence = bound_evidence_by_ref(
        dependencies,
        account_authority_signer_evidence_ref,
        &gate.authority_id,
        &gate.verification_method,
    )?;
    let account_authority_public_key =
        authenticated_document_key(account_authority_evidence, dependencies, gate.issued_at)?;
    let receipt_method =
        arkret_signatures::agent_evidence::historical_admission_verification_method(
            event_admission,
        )
        .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let receiver_evidence = bound_evidence_by_ref(
        dependencies,
        receiver_signer_evidence_ref.as_ref().ok_or_else(|| {
            WireError::Protocol("historical Agent receiver evidence missing".to_owned())
        })?,
        &event_admission.receiver_id()?,
        &receipt_method,
    )?;
    let receiver_public_key = authenticated_document_key(
        receiver_evidence,
        dependencies,
        event_admission.receiver_accepted_at()?,
    )?;

    let public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    for seal in &core.seal_lineages {
        verify_external_trust(AgentHistoricalTrustRequest::PcrSeal(seal)).await?;
    }
    verify_external_trust(AgentHistoricalTrustRequest::LifecycleWitness(
        &core.agent_lifecycle_witness,
    ))
    .await?;
    let verify_pcr_seal = |_seal: &Seal| Ok(());
    let verify_lifecycle = |_witness: &AgentLifecycleWitness| Ok(());
    let verified_state = arkret_signatures::agent_evidence::verify_agent_evidence_state(
        admission_evidence,
        &arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
            signer_id,
            signer_actor_id: event.executed_by.as_ref().unwrap_or(&event.actor_id),
            agent_key_id: &binding.agent_key_id,
            controller_principal_id: &binding.controller_principal_id,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            authorize_public_key_digest: &public_key_digest,
            authorize_signing_key_binding_digest: &binding_digest,
            verify_seal_signature: &verify_pcr_seal,
            verify_lifecycle_reducer: &verify_lifecycle,
        },
    )
    .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let transparency_verified = if let Some(transparency) = transparency {
        verify_external_trust(AgentHistoricalTrustRequest::Transparency(transparency)).await?;
        true
    } else {
        false
    };
    let origin_admission = event
        .proofs
        .iter()
        .find_map(|proof| match proof {
            EventProof::StationAdmission(value) => Some(value),
            EventProof::Producer(_) => None,
        })
        .ok_or_else(|| WireError::Protocol("Agent Event omitted origin admission".to_owned()))?;
    if let arkret_models_identity::AgentEventAdmission::ReceiverReceipt { receipt } =
        event_admission
    {
        let did = origin_admission
            .verification_method
            .as_str()
            .split('#')
            .next()
            .unwrap_or_default();
        let origin = arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did.to_owned())?)?;
        if receipt.receiver_id == origin && receipt.accepted_at == origin_admission.accepted_at {
            return Err(WireError::Protocol(
                "same-Station original acceptance must reuse its Station proof".to_owned(),
            ));
        }
    }
    let producer_evidence_ref = origin_admission
        .producer_signer_resolution_evidence_ref
        .as_ref()
        .ok_or_else(|| {
            WireError::Protocol("Agent Event omitted producer evidence ref".to_owned())
        })?;
    let frozen = build_agent_signer_resolution_evidence(
        AgentSignerEvidence::CurrentAdmission {
            schema: arkret_wire::NonEmptyString::new(
                arkret_wire::SchemaId::AGENT_SIGNER_EVIDENCE_V1,
            )
            .map_err(|error| WireError::Protocol(error.to_owned()))?,
            admission_evidence: admission_evidence.clone(),
            transparency: transparency.clone(),
        },
        authority_evidence,
        controller_evidence,
        account_authority_evidence,
        None,
    )?;
    if frozen.evidence_ref()? != *producer_evidence_ref {
        return Err(WireError::Protocol(
            "historical Agent authority is not the original frozen admission root".to_owned(),
        ));
    }
    if let arkret_models_identity::AgentEventAdmission::StationAdmission { accepted_event } =
        event_admission
    {
        if accepted_event.digest_payload()? != event.digest_payload()?
            || accepted_event
                .proofs
                .iter()
                .find_map(EventProof::as_station_admission)
                != event
                    .proofs
                    .iter()
                    .find_map(EventProof::as_station_admission)
        {
            return Err(WireError::Protocol(
                "historical Agent acceptance Event mismatch".to_owned(),
            ));
        }
    }
    let receiver_accepted_at = event_admission.receiver_accepted_at()?;
    let resolve_receiver = |method: &arkret_wire::DidUrl, at| {
        (method == &receipt_method && at == receiver_accepted_at)
            .then(|| receiver_public_key.clone())
    };
    let verdict = arkret_signatures::agent_evidence::validate_historical_agent_signer_evidence(
        Some(agent_signer_evidence),
        &arkret_signatures::agent_evidence::HistoricalAgentSignerEvidenceValidationContext {
            common: arkret_signatures::agent_evidence::AgentEvidenceCommonContext {
                signer_id,
                agent_key_id: &binding.agent_key_id,
                controller_principal_id: &binding.controller_principal_id,
                verification_method,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &public_key_digest,
                authorize_signing_key_binding_digest: &binding_digest,
                expected_authority_id: &core.authority_id,
                expected_authority_verification_method: &authority_evidence_state
                    .lease
                    .verification_method,
                expected_account_authority_id: &gate.authority_id,
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
            receiver_id: &event_admission.receiver_id()?,
            producer_station_id: &arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(
                origin_admission
                    .verification_method
                    .as_str()
                    .split('#')
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
            )?)?,
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

/// Verify reusable Agent authority entirely from its content-addressed
/// dependency closure. The result has no public constructor and retains the
/// original expiry across messages, connections, and local cache operations.
pub async fn verify_agent_history_source_key<VerifyExternalTrust>(
    source: &HistoryKeyResponseSendRequest,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    verify_external_trust: VerifyExternalTrust,
) -> Result<PublicKeyMaterial, WireError>
where
    VerifyExternalTrust:
        for<'a> Fn(AgentHistoricalTrustRequest<'a>) -> AgentHistoricalTrustFuture<'a> + Clone,
{
    source.validate()?;
    let key = verify_agent_current_signer_key(
        &source.source_actor_id,
        &source.source_proof.verification_method,
        evidence,
        dependencies,
        source.source_proof.created_at,
        verify_external_trust,
    )
    .await?;
    Ok(PublicKeyMaterial::Ed25519Raw {
        bytes: key.key().to_vec(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentCurrentContext {
    key: arkret_signatures::agent_evidence::VerifiedAgentSigningKey,
    document_keys: BTreeMap<Hash, VerifiedAgentDocumentKey>,
    transparency_digest: Option<Hash>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedAgentDocumentKey {
    key: PublicKeyMaterial,
    valid_from: chrono::DateTime<chrono::Utc>,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
}
impl VerifiedAgentCurrentContext {
    pub fn key(&self) -> &arkret_signatures::agent_evidence::VerifiedAgentSigningKey {
        &self.key
    }
}

fn agent_document_key(
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    at: chrono::DateTime<chrono::Utc>,
    cache: &mut BTreeMap<Hash, VerifiedAgentDocumentKey>,
) -> Result<PublicKeyMaterial, WireError> {
    let digest = evidence.canonical_sha256_digest()?;
    if let Some(cached) = cache.get(&digest).filter(|cached| {
        at >= cached.valid_from && cached.valid_until.is_none_or(|until| at < until)
    }) {
        return Ok(cached.key.clone());
    }
    let key = authenticated_document_key(evidence, dependencies, at)?;
    let (valid_from, valid_until) = match evidence {
        AuthenticatedSignerResolutionEvidence::Service {
            authenticated_resolution,
            ..
        } => match &authenticated_resolution.method_history_evidence {
            arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
                log_entries,
                ..
            } => {
                let times = log_entries
                    .iter()
                    .map(|entry| {
                        entry
                            .get("versionTime")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                WireError::Protocol(
                                    "verified WebVH history omitted version time".to_owned(),
                                )
                            })?
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .map_err(|error| WireError::Protocol(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (
                    times
                        .iter()
                        .copied()
                        .filter(|time| *time <= at)
                        .max()
                        .ok_or_else(|| {
                            WireError::Protocol(
                                "verified WebVH history has no effective version".to_owned(),
                            )
                        })?,
                    times.into_iter().filter(|time| *time > at).min(),
                )
            }
            arkret_models_identity::ResolutionMethodHistoryEvidence::DidKeyExpansion { .. } => {
                (chrono::DateTime::<chrono::Utc>::MIN_UTC, None)
            }
            _ => (at, at.checked_add_signed(chrono::Duration::nanoseconds(1))),
        },
        _ => (at, at.checked_add_signed(chrono::Duration::nanoseconds(1))),
    };
    cache.insert(
        digest,
        VerifiedAgentDocumentKey {
            key: key.clone(),
            valid_from,
            valid_until,
        },
    );
    Ok(key)
}

pub async fn verify_agent_current_signer_key<VerifyExternalTrust>(
    actor: &arkret_wire::ActorId,
    verification_method: &arkret_wire::DidUrl,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    now: chrono::DateTime<chrono::Utc>,
    verify_external_trust: VerifyExternalTrust,
) -> Result<arkret_signatures::agent_evidence::VerifiedAgentSigningKey, WireError>
where
    VerifyExternalTrust:
        for<'a> Fn(AgentHistoricalTrustRequest<'a>) -> AgentHistoricalTrustFuture<'a> + Clone,
{
    Ok(verify_agent_current_context(
        actor,
        verification_method,
        evidence,
        dependencies,
        now,
        None,
        verify_external_trust,
    )
    .await?
    .key)
}

pub async fn verify_agent_current_context<VerifyExternalTrust>(
    actor: &arkret_wire::ActorId,
    verification_method: &arkret_wire::DidUrl,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    now: chrono::DateTime<chrono::Utc>,
    previous: Option<&VerifiedAgentCurrentContext>,
    verify_external_trust: VerifyExternalTrust,
) -> Result<VerifiedAgentCurrentContext, WireError>
where
    VerifyExternalTrust:
        for<'a> Fn(AgentHistoricalTrustRequest<'a>) -> AgentHistoricalTrustFuture<'a> + Clone,
{
    evidence.validate_attester_binding()?;
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method: root_method,
        agent_signer_evidence,
        attester_signer_evidence_ref,
        controller_signer_evidence_ref,
        account_authority_signer_evidence_ref,
        receiver_signer_evidence_ref: _,
    } = evidence
    else {
        return Err(WireError::Protocol(
            "Agent history source verifier received non-agent evidence".to_owned(),
        ));
    };
    let AgentSignerEvidence::CurrentAdmission {
        admission_evidence,
        transparency,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        return Err(WireError::Protocol(
            "Agent history source evidence is not current_admission".to_owned(),
        ));
    };
    if signer_id != actor.signing_principal_id() || root_method != verification_method {
        return Err(WireError::Protocol(
            "Agent current signer identity mismatch".to_owned(),
        ));
    }
    let authority_evidence_state = &admission_evidence.agent_authority_state_evidence;
    let core = &authority_evidence_state.state;
    let binding = &core.signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;
    let authority_evidence = bound_evidence_by_ref(
        dependencies,
        attester_signer_evidence_ref,
        &core.authority_id,
        &authority_evidence_state.lease.verification_method,
    )?;
    let controller_evidence = bound_evidence_by_ref(
        dependencies,
        controller_signer_evidence_ref,
        &binding.controller_principal_id,
        &binding.controller_proof.verification_method,
    )?;
    let account_authority_evidence = bound_evidence_by_ref(
        dependencies,
        account_authority_signer_evidence_ref,
        &gate.authority_id,
        &gate.verification_method,
    )?;
    validate_agent_controller_account(
        controller_evidence,
        &binding.controller_principal_id,
        actor.route_service_id(),
    )?;
    let mut document_keys = previous
        .map(|context| context.document_keys.clone())
        .unwrap_or_default();
    let controller_public_key = agent_document_key(
        controller_evidence,
        dependencies,
        binding.issued_at,
        &mut document_keys,
    )?;
    let authority_public_key = agent_document_key(
        authority_evidence,
        dependencies,
        authority_evidence_state.lease.issued_at,
        &mut document_keys,
    )?;
    let account_authority_public_key = agent_document_key(
        account_authority_evidence,
        dependencies,
        gate.issued_at,
        &mut document_keys,
    )?;
    let public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let unchanged_state = previous.filter(|previous| {
        previous.key.state_digest() == &authority_evidence_state.state_digest
            && previous.key.signer_actor_id() == actor
            && previous.key.verification_method() == verification_method
    });
    let verified_state = if let Some(previous) = unchanged_state {
        previous.key.verified_state().clone()
    } else {
        for seal in &core.seal_lineages {
            verify_external_trust(AgentHistoricalTrustRequest::PcrSeal(seal)).await?;
        }
        verify_external_trust(AgentHistoricalTrustRequest::LifecycleWitness(
            &core.agent_lifecycle_witness,
        ))
        .await?;
        let verify_pcr_seal = |_seal: &Seal| Ok(());
        let verify_lifecycle = |_witness: &AgentLifecycleWitness| Ok(());
        arkret_signatures::agent_evidence::verify_agent_evidence_state(
            admission_evidence,
            &arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
                signer_id,
                signer_actor_id: actor,
                agent_key_id: &binding.agent_key_id,
                controller_principal_id: &binding.controller_principal_id,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &public_key_digest,
                authorize_signing_key_binding_digest: &binding_digest,
                verify_seal_signature: &verify_pcr_seal,
                verify_lifecycle_reducer: &verify_lifecycle,
            },
        )
        .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?
    };
    let transparency_digest = transparency
        .as_ref()
        .map(|value| {
            arkret_canonical::canonical_sha256(value)
                .map_err(WireError::from)
                .and_then(|digest| Hash::new(digest).map_err(Into::into))
        })
        .transpose()?;
    let transparency_verified = if let Some(transparency) = transparency {
        if previous.is_none_or(|previous| previous.transparency_digest != transparency_digest) {
            verify_external_trust(AgentHistoricalTrustRequest::Transparency(transparency)).await?;
        }
        true
    } else {
        false
    };
    let verdict = arkret_signatures::agent_evidence::refresh_current_agent_signer_evidence(
        Some(agent_signer_evidence),
        &arkret_signatures::agent_evidence::CurrentAgentSignerEvidenceValidationContext {
            common: arkret_signatures::agent_evidence::AgentEvidenceCommonContext {
                signer_id,
                agent_key_id: &binding.agent_key_id,
                controller_principal_id: &binding.controller_principal_id,
                verification_method,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &public_key_digest,
                authorize_signing_key_binding_digest: &binding_digest,
                expected_authority_id: &core.authority_id,
                expected_authority_verification_method: &authority_evidence_state
                    .lease
                    .verification_method,
                expected_account_authority_id: &gate.authority_id,
                expected_account_authority_verification_method: &gate.verification_method,
                controller_public_key: &controller_public_key,
                authority_public_key: &authority_public_key,
                account_authority_public_key: &account_authority_public_key,
                verified_state: &verified_state,
                require_transparency: transparency.is_some(),
                transparency_verified,
                now,
            },
        },
        previous.map(|previous| &previous.key),
    );
    let retained_key_digests = [
        attester_signer_evidence_ref.content_digest()?,
        controller_signer_evidence_ref.content_digest()?,
        account_authority_signer_evidence_ref.content_digest()?,
    ];
    document_keys.retain(|digest, _| retained_key_digests.contains(digest));
    match verdict {
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Verified(key) => {
            Ok(VerifiedAgentCurrentContext {
                key,
                document_keys,
                transparency_digest,
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

async fn verify_event_proofs_default<VerifyAgentHistoryKey>(
    event: &Event,
    event_digest_suite: arkret_canonical::DigestSuite,
    dependencies: &[GovernanceDependency],
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<(), WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
{
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    match event.proofs.as_slice() {
        [EventProof::Producer(producer)] => {
            let evidence_ref = producer
                .signer_resolution_evidence_ref
                .as_ref()
                .ok_or_else(|| {
                    WireError::Protocol("direct Event omits signer evidence".to_owned())
                })?;
            let evidence = evidence_by_digest(dependencies, &evidence_ref.content_digest()?)?;
            if evidence_ref != &evidence.evidence_ref()?
                || evidence.verification_method() != &producer.verification_method
                || evidence.signer_id()
                    != event
                        .executed_by
                        .as_ref()
                        .unwrap_or(&event.actor_id)
                        .signing_principal_id()
            {
                return Err(WireError::Protocol(
                    "direct Event signer evidence binding mismatch".to_owned(),
                ));
            }
            let key = match evidence {
                AuthenticatedSignerResolutionEvidence::Agent { .. } => {
                    verify_agent_history_key(event, event_digest_suite, evidence, dependencies)
                        .await?
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
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            arkret_models_collaboration::governance_dependencies::validate_fork_resolution_collision_dependencies(
                event,
                dependencies,
                event_digest_suite,
                |record, binding_bytes| {
                    if record.proof.verification_method != producer.verification_method {
                        return Err(WireError::Protocol(
                            "direct collision record proof must use the verified resolution signer method"
                                .to_owned(),
                        ));
                    }
                    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
                        &record.proof,
                        binding_bytes,
                        &key,
                    )
                    .map_err(|error| WireError::Protocol(error.to_string()))
                },
            )
        }
        [
            EventProof::Producer(producer),
            EventProof::StationAdmission(admission),
        ] => {
            admission.validate_binding(
                &producer.event_digest,
                producer,
                event
                    .executed_by
                    .as_ref()
                    .unwrap_or(&event.actor_id)
                    .route_service_id(),
            )?;
            let multibase = admission
                .producer_signing_key_did
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
            let evidence = evidence_by_digest(
                dependencies,
                &admission.signer_resolution_evidence_ref.content_digest()?,
            )?;
            let AuthenticatedSignerResolutionEvidence::Service {
                signer_id,
                authenticated_resolution,
                ..
            } = evidence
            else {
                return Err(WireError::Protocol(
                    "Station admission signer evidence must be service-kind".to_owned(),
                ));
            };
            if signer_id
                != event
                    .executed_by
                    .as_ref()
                    .unwrap_or(&event.actor_id)
                    .route_service_id()
                || evidence.verification_method() != &admission.verification_method
                || evidence.evidence_ref()? != admission.signer_resolution_evidence_ref
            {
                return Err(WireError::Protocol(
                    "Station admission signer evidence binding mismatch".to_owned(),
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
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            arkret_models_collaboration::governance_dependencies::validate_fork_resolution_collision_dependencies(
                event,
                dependencies,
                event_digest_suite,
                |record, binding_bytes| {
                    arkret_identity::verify_jws_with_document(
                        binding_bytes,
                        &record.proof.jws,
                        &record.proof.verification_method,
                        &historical_document.id,
                        &historical_document,
                    )
                    .map_err(|error| WireError::Protocol(error.to_string()))
                },
            )
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
        eligible_holder_service_ids,
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
            &availability_receipt
                .holder_signer_evidence_ref
                .content_digest()?,
        )?;
        if evidence.signer_id() != &availability_receipt.holder_service_id
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
        let holder_service_id = &receipt.holder_service_id;
        if !eligible_holder_service_ids.contains(holder_service_id) {
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
            .insert(holder_service_id.clone())
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
/// the Producer + StationAdmission federation regime. The SDK owns
/// frozen-notary selection, dependency verification, availability policy,
/// reducer projection, recovery, and final state-root/basis checks.
pub async fn verify_mls_governance_checkpoint<VerifyAgentHistoryKey>(
    candidate: &MlsGovernanceVerificationCheckpoint,
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
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
            Box::pin(verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_agent_history_key.clone(),
            ))
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
    .await
}

/// Verify raw complete governance material and derive both the target live
/// digest suite and every accepted Event's historical suite by isolated
/// replay. This is the bootstrap entry point for callers that do not yet have
/// a durable verified checkpoint.
#[allow(clippy::too_many_arguments)]
pub async fn verify_mls_governance_closure<VerifyAgentHistoryKey>(
    realm_id: &RealmId,
    basis: &SealBasis,
    seals: &[Seal],
    events: &[Event],
    dependencies: &[GovernanceDependency],
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<VerifiedMlsGovernanceClosure, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
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
                Box::pin(verify_event_proofs_default(
                    event,
                    digest_suite,
                    dependencies,
                    verify_agent_history_key.clone(),
                ))
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
        .await?;
    Ok(VerifiedMlsGovernanceClosure {
        checkpoint,
        event_digest_suites,
    })
}

/// Derive and re-verify the exact checkpoint pinned to an ancestor basis of a
/// complete verified checkpoint. Seal and Event closure selection, recursive
/// signer-evidence discovery, and reducer replay remain SDK-owned; callers do
/// not trim the checkpoint themselves.
pub async fn derive_verified_mls_governance_checkpoint_at_basis<VerifyAgentHistoryKey>(
    existing_checkpoint: &MlsGovernanceVerificationCheckpoint,
    requested_basis: &SealBasis,
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
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
                Box::pin(verify_event_proofs_default(
                    event,
                    digest_suite,
                    dependencies,
                    verify_agent_history_key.clone(),
                ))
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
        .await?;
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
        verify_agent_history_key,
    )
    .await
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
    let mut selected = selected
        .into_values()
        .map(|item| Ok((item.selector().canonical_sort_key()?, item)))
        .collect::<Result<Vec<_>, WireError>>()?;
    selected.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(selected.into_iter().map(|(_, item)| item).collect())
}

/// Verify an exact retained `(base, target]` cut without fetching material
/// before the caller's frozen base checkpoint. The SDK first re-verifies the
/// complete base checkpoint, then replays every-and-only cut Seal and Event
/// objects against that state. A caller that has only a `SealBasis` cannot use
/// this entry point.
pub async fn verify_mls_governance_cut<VerifyAgentHistoryKey>(
    base_checkpoint: &MlsGovernanceVerificationCheckpoint,
    target_basis: &SealBasis,
    cut_seals: &[Seal],
    cut_events: &[Event],
    cut_dependencies: &[GovernanceDependency],
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
{
    let verified_base =
        verify_mls_governance_checkpoint(base_checkpoint, verify_agent_history_key.clone()).await?;
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
            Box::pin(verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_agent_history_key.clone(),
            ))
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
    .await
}

/// Verify a near-current MLS governance proof with the SDK's unique generated
/// registry, reducer projector, frozen-notary cryptography, Event proof
/// transcripts, and dependency verification. Applications supply only Native
/// Agent historical-authority verification. AvailabilityReceipt policy,
/// holder roles, retention, and quorum are derived from each Seal's verified
/// predecessor state and checked entirely inside the SDK.
#[allow(clippy::too_many_arguments)]
pub async fn verify_mls_governance_frontier<VerifyAgentHistoryKey>(
    request: &MlsGovernanceProofRequestBody,
    bundle: &MlsGovernanceProofBundle,
    base_checkpoint: &MlsGovernanceVerificationCheckpoint,
    resolved_seals: &[Seal],
    resolved_delta_events: &[Event],
    resolved_provenance_events: &[Event],
    resolved_dependencies: &[GovernanceDependency],
    group_genesis_binding: &MlsGroupGenesisBinding,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<VerifiedMlsGovernanceFrontier, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
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
            Box::pin(verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_agent_history_key.clone(),
            ))
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
    .await
}

/// Build the exact bounded near-current proof page from a complete candidate
/// target checkpoint. The SDK first verifies the whole checkpoint, then
/// materializes per-target-Seal branches from isolated reducer stores.
#[allow(clippy::too_many_arguments)]
pub async fn materialize_mls_governance_frontier<VerifyAgentHistoryKey>(
    request: &MlsGovernanceProofRequestBody,
    target_checkpoint: &MlsGovernanceVerificationCheckpoint,
    group_genesis_binding: &MlsGroupGenesisBinding,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<MlsGovernanceProofBundle, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
{
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let verified =
        verify_mls_governance_checkpoint(target_checkpoint, verify_agent_history_key).await?;
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
    .await
}

/// Verify and materialize the first crash-safe checkpoint for an event-derived
/// Realm. The candidate genesis Seal must cover the content-derived Realm
/// create Event and the complete anchor unit; all ordinary reducer and frozen
/// notary checks are then replayed before the checkpoint is returned.
#[allow(clippy::too_many_arguments)]
pub async fn verify_event_derived_genesis_checkpoint<VerifyAgentHistoryKey>(
    realm_id: &RealmId,
    genesis_seal: &Seal,
    accepted_events: &[Event],
    governance_dependencies: &[GovernanceDependency],
    verify_agent_history_key: VerifyAgentHistoryKey,
) -> Result<MlsGovernanceVerificationCheckpoint, WireError>
where
    VerifyAgentHistoryKey: for<'a> Fn(
            &'a Event,
            arkret_canonical::DigestSuite,
            &'a AuthenticatedSignerResolutionEvidence,
            &'a [GovernanceDependency],
        ) -> VerifyAgentHistoryKeyFuture<'a>
        + Clone
        + VerifyAgentHistoryKeySend
        + 'static,
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
            Box::pin(verify_event_proofs_default(
                event,
                digest_suite,
                dependencies,
                verify_agent_history_key.clone(),
            ))
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
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_local_verification<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("portable verification unexpectedly performed I/O"),
        }
    }

    fn verify_public_agent_fixture(
        actor: &arkret_wire::ActorId,
        method: &arkret_wire::DidUrl,
        root: &AuthenticatedSignerResolutionEvidence,
        dependencies: &[GovernanceDependency],
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<VerifiedAgentCurrentContext, WireError> {
        let trust_root = std::sync::Arc::new(root.clone());
        let trust_dependencies = std::sync::Arc::new(dependencies.to_vec());
        complete_local_verification(verify_agent_current_context(
            actor,
            method,
            root,
            dependencies,
            at,
            None,
            move |request| {
                let root = trust_root.clone();
                let dependencies = trust_dependencies.clone();
                Box::pin(async move { verify_agent_portable_trust(request, &root, &dependencies) })
            },
        ))
    }

    #[test]
    fn portable_agent_context_reuses_verified_state_and_binds_full_controller_account() {
        #[derive(serde::Deserialize)]
        struct PublicFixture {
            actor: arkret_wire::ActorId,
            verification_method: arkret_wire::DidUrl,
            root: AuthenticatedSignerResolutionEvidence,
            dependencies: Vec<AuthenticatedSignerResolutionEvidence>,
        }
        let fixture: PublicFixture = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/agent-current-context.json"),
            )
            .expect("public Agent context fixture"),
        )
        .unwrap();
        let dependencies = fixture
            .dependencies
            .iter()
            .map(
                |evidence| GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                    selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest: evidence.canonical_sha256_digest().unwrap(),
                    },
                    authenticated_signer_resolution_evidence: Box::new(evidence.clone()),
                },
            )
            .collect::<Vec<_>>();
        let AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            controller_signer_evidence_ref,
            ..
        } = &fixture.root
        else {
            panic!("Agent fixture expected")
        };
        let admission = agent_signer_evidence.admission_evidence();
        let at = admission.valid_from();
        let first = verify_public_agent_fixture(
            &fixture.actor,
            &fixture.verification_method,
            &fixture.root,
            &dependencies,
            at,
        )
        .unwrap();
        assert!(
            first
                .key()
                .permits(&fixture.actor, &fixture.verification_method, at)
        );
        let reused = complete_local_verification(verify_agent_current_context(
            &fixture.actor,
            &fixture.verification_method,
            &fixture.root,
            &dependencies,
            at,
            Some(&first),
            |_request| panic!("unchanged stable state was reverified"),
        ))
        .unwrap();
        assert_eq!(first, reused);
        assert!(!reused.key().permits(
            &fixture.actor,
            &fixture.verification_method,
            admission.expires_at()
        ));

        let state = &admission.agent_authority_state_evidence.state;
        let state_digest = &admission.agent_authority_state_evidence.state_digest;
        let compact = arkret_models_collaboration::current_signer_evidence::CompactAgentSignerResolutionEvidence::from_full(&fixture.root, std::slice::from_ref(state_digest)).unwrap();
        assert!(compact.hydrate(&BTreeMap::new()).is_err());
        let hydrated = compact
            .hydrate(&BTreeMap::from([(state_digest.clone(), state.clone())]))
            .unwrap();
        assert_eq!(
            hydrated.evidence_ref().unwrap(),
            fixture.root.evidence_ref().unwrap()
        );

        let other_station =
            arkret_wire::DidCoreId::new("ak:did_core:web:unrelated-station.example").unwrap();
        let substituted_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            fixture.actor.signing_principal_id().clone(),
            other_station.clone(),
        ));
        assert!(
            verify_public_agent_fixture(
                &substituted_actor,
                &fixture.verification_method,
                &fixture.root,
                &dependencies,
                at
            )
            .is_err()
        );

        let old_ref = controller_signer_evidence_ref.clone();
        let mut substituted_dependencies = dependencies.clone();
        let mut new_ref = None;
        for dependency in &mut substituted_dependencies {
            if let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector,
                authenticated_signer_resolution_evidence,
            } = dependency
                && authenticated_signer_resolution_evidence
                    .evidence_ref()
                    .unwrap()
                    == old_ref
            {
                let AuthenticatedSignerResolutionEvidence::Principal {
                    public_resolution, ..
                } = authenticated_signer_resolution_evidence.as_mut()
                else {
                    panic!("Principal controller fixture expected")
                };
                public_resolution.account_id.station_id = other_station.clone();
                let reference = authenticated_signer_resolution_evidence
                    .evidence_ref()
                    .unwrap();
                *selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: reference.content_digest().unwrap(),
                };
                new_ref = Some(reference);
            }
        }
        let mut substituted_root = fixture.root.clone();
        let AuthenticatedSignerResolutionEvidence::Agent {
            controller_signer_evidence_ref,
            ..
        } = &mut substituted_root
        else {
            unreachable!()
        };
        *controller_signer_evidence_ref = new_ref.expect("controller dependency");
        let error = verify_public_agent_fixture(
            &fixture.actor,
            &fixture.verification_method,
            &substituted_root,
            &substituted_dependencies,
            at,
        )
        .unwrap_err();
        assert!(error.to_string().contains("different AccountId"));
    }

    #[test]
    fn realm_membership_lookup_uses_registered_composite_subject() {
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let subject = arkret_wire::cell::composite_subject(&[serde_json::Value::String(
            actor.canonical_key().unwrap(),
        )])
        .unwrap();
        let expected = CellRef::new(arkret_wire::cell::subject_cell(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            &subject,
        ))
        .unwrap();

        assert_eq!(realm_membership_cell(&actor).unwrap(), expected);
    }

    #[test]
    fn collision_variant_record_proof_context_kat_verifies() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../arkret-spec/spec/v1/artifacts/fixtures/proof-context-transcript-fixture.json",
        );
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("proof-context fixture"))
                .expect("proof-context JSON");
        let vector = fixture["cases"]
            .as_array()
            .expect("proof-context cases")
            .iter()
            .find(|case| {
                case["vector_id"]
                    == "ak.vector.proof_context.transcript.collision_variant_record.v1"
            })
            .expect("collision record vector");
        let key = PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(
                fixture["test_key"]["public_key"].as_str().unwrap(),
            )
            .unwrap(),
        };

        // 1. The registered transcript itself: the four-member binding object the vector publishes
        //    must be exactly the canonical bytes the vector signs, and its detached JWS must verify
        //    against them.
        let vector_binding = arkret_canonical::canonical_json_bytes(&vector["binding_object"])
            .expect("binding object is canonicalizable");
        assert_eq!(
            std::str::from_utf8(&vector_binding).unwrap(),
            vector["binding_jcs"].as_str().unwrap()
        );
        let vector_proof = arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                vector["binding_object"]["verification_method"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
            payload_digest: Hash::new(vector["unsigned_digest"].as_str().unwrap().to_owned())
                .unwrap(),
            created_at: arkret_canonical::parse_timestamp_canonical(
                vector["binding_object"]["created_at"].as_str().unwrap(),
            )
            .unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: vector["detached_jws"].as_str().unwrap().to_owned(),
        };
        arkret_signatures::verify_ed25519_detached_jws_payload_proof(
            &vector_proof,
            &vector_binding,
            &key,
        )
        .expect("registered collision record proof transcript verifies");

        // 2. The SDK carrier produces that same transcript shape, and it takes `payload_digest`
        //    from its own recomputed unsigned projection, not from whatever the carrier reports. A
        //    record whose proof claims a foreign digest therefore produces a transcript that cannot
        //    verify.
        let record: arkret_models_collaboration::events_payloads::state::CollisionVariantRecord =
            serde_json::from_value(serde_json::json!({
                "schema": "ak.schema.collision_variant_record.v1",
                "collision_variant_record_id": "ak:collision_variant_record:01964140-0000-7000-8000-000000000000",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
                "collision_event_id": "ak:event:AR8bu-n-kOOB3nRUvYuIEglCX5B-JpFaNTex9gxs_cWY",
                "canonical_event_bytes_b64u": "e30",
                "canonical_event_size_bytes": 2,
                "recorded_at": "2026-05-01T00:00:00.000Z",
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": vector["binding_object"]["verification_method"],
                    "payload_digest": vector["unsigned_digest"],
                    "created_at": vector["binding_object"]["created_at"],
                    "jws": vector["detached_jws"]
                }
            }))
            .expect("collision record proof carrier");
        let binding: serde_json::Value =
            serde_json::from_slice(&record.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(
            binding
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "context".to_owned(),
                "created_at".to_owned(),
                "payload_digest".to_owned(),
                "verification_method".to_owned(),
            ]
        );
        assert_eq!(
            binding["context"],
            serde_json::json!("ak.collision_variant_record_proof.v1")
        );
        assert_eq!(
            binding["created_at"],
            vector["binding_object"]["created_at"]
        );
        assert_eq!(
            binding["verification_method"],
            vector["binding_object"]["verification_method"]
        );
        assert_ne!(
            binding["payload_digest"], vector["unsigned_digest"],
            "the transcript digest is recomputed, never copied from the carrier"
        );

        // 3. A different registered context over the same values is a different transcript and must
        //    not verify.
        let wrong_binding = arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": "ak.account_binding_receipt_proof.v1",
            "payload_digest": vector["unsigned_digest"],
            "verification_method": vector["binding_object"]["verification_method"],
            "created_at": vector["binding_object"]["created_at"],
        }))
        .unwrap();
        assert!(
            arkret_signatures::verify_ed25519_detached_jws_payload_proof(
                &vector_proof,
                &wrong_binding,
                &key,
            )
            .is_err()
        );
    }

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
