use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector, governance_attester_evidence_selectors,
    governance_runtime_dependency_selectors_for_replay,
};
use arkret_models_collaboration::history_key::{
    AuthorizationIncarnation, HistoryKeyResponseSendRequestBody,
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
use arkret_wire::{CircleId, Event, Hash, RealmId, Seal, SealBasis, WireError};

/// Result of verifying raw complete governance material without trusting a
/// caller-supplied target digest suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceClosure {
    pub checkpoint: MlsGovernanceVerificationCheckpoint,
    pub event_digest_suites: BTreeMap<Hash, arkret_canonical::DigestSuite>,
}

/// Derive the exact current membership incarnation from a fully verified
/// reducer checkpoint for use in an MLS Add proposal.
pub async fn current_authorization_incarnation_from_verified_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    target: &arkret_wire::ActorId,
    circle_id: Option<&CircleId>,
) -> Result<AuthorizationIncarnation, WireError> {
    let scope = match circle_id {
        Some(circle_id) => arkret_wire::HistoryEffectiveScope::Circle {
            realm_id: checkpoint.realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        None => arkret_wire::HistoryEffectiveScope::Realm {
            realm_id: checkpoint.realm_id.clone(),
        },
    };
    Ok(
        verified_membership_from_checkpoint(checkpoint, &scope, target)
            .await?
            .incarnation()
            .clone(),
    )
}

/// Resolve membership independently of MLS admission, from the registered cells.
pub async fn verified_membership_from_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    scope: &arkret_wire::HistoryEffectiveScope,
    target: &arkret_wire::ActorId,
) -> Result<arkret_state::history_authorization::VerifiedMembership, WireError> {
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS authorization-incarnation registry construction failed: {error}"
        ))
    })?;
    arkret_state::mls_governance_proof::membership_from_verified_checkpoint(
        checkpoint,
        scope,
        target,
        &registry,
        crate::project_control_writes_at_state,
    )
    .await
}

/// Require the exact requested membership and return its independently derived
/// MLS stage. A missing lineage is pending, never an epoch-zero fallback.
pub async fn history_join_epoch_from_verified_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    scope: &arkret_wire::HistoryEffectiveScope,
    actor: &arkret_wire::ActorId,
    incarnation: &AuthorizationIncarnation,
) -> Result<Option<u64>, WireError> {
    let (membership, epoch) =
        verified_member_history_from_checkpoint(checkpoint, scope, actor).await?;
    if membership.incarnation() != incarnation {
        return Err(WireError::Protocol(
            "history request authorization incarnation is not current at its verified cut"
                .to_owned(),
        ));
    }
    Ok(epoch)
}

/// Query membership and its MLS floor with one shared replay, including the
/// exact Genesis-time membership when this actor is the initial principal.
pub async fn verified_member_history_from_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    scope: &arkret_wire::HistoryEffectiveScope,
    actor: &arkret_wire::ActorId,
) -> Result<
    (
        arkret_state::history_authorization::VerifiedMembership,
        Option<u64>,
    ),
    WireError,
> {
    let registry = arkret_lattice_registry::try_build_sdk_state_registry()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    arkret_state::mls_governance_proof::member_history_from_verified_checkpoint(
        checkpoint,
        scope,
        actor,
        &registry,
        crate::project_control_writes_at_state,
    )
    .await
}

/// The only Agent historical-evidence checks that cannot be derived
/// from the retained evidence/dependency closure itself.
pub enum AgentHistoricalTrustRequest<'a> {
    /// Verify this embedded PCR Seal against independently pinned historical
    /// notary authority.
    PcrSeal(&'a Seal),
    /// Verify the accepted lifecycle Event/provenance against the PCR reducer.
    LifecycleWitness(&'a AgentLifecycleWitness),
    /// Verify one applicable confirmed authorization closure.
    AuthorizationClosure(&'a arkret_wire::SealId),
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
    let [proof] = event.proofs.as_slice() else {
        return Err(WireError::Protocol(
            "Event must carry exactly one producer proof".to_owned(),
        ));
    };
    Ok(proof.event_digest.clone())
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
        AuthenticatedSignerResolutionEvidence::AccountDevice { .. }
        | AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. } => {
            return Err(WireError::Protocol("account device history evidence cannot authorize a document or Control Event signature".to_owned()));
        }
        AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. } => {
            return Err(WireError::Protocol(
                "account-device Control evidence requires the complete PCR verifier".to_owned(),
            ));
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
        return Err(WireError::Protocol(format!(
            "historical signer evidence does not match its bound identity and method: expected ref {evidence_ref:?}, signer {signer_id}, method {verification_method}; resolved ref {:?}, signer {}, method {}",
            evidence.evidence_ref()?,
            evidence.signer_id(),
            evidence.verification_method(),
        )));
    }
    Ok(evidence)
}

fn validate_agent_control_accounts(
    state: &arkret_models_identity::AgentAuthorityState,
    actor: &arkret_wire::ActorId,
) -> Result<(), WireError> {
    let controller = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        state.authorized_key()?.controller_principal_id,
        actor.route_service_id().clone(),
    ));
    for event in [
        &state.pcr_genesis_event,
        &state.key_authorization_event,
        &state.agent_lifecycle_witness.accepted_status_event,
    ] {
        if event.actor_id != *actor
            || event.executed_by.as_ref() != Some(&controller)
            || event.realm_id != state.principal_control_realm_id
            || event.authorization_ref != state.pcr_genesis_event.authorization_ref
        {
            return Err(WireError::Protocol(
                "Agent control Event belongs to a different AccountId or delegation".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verified_agent_control_event_key(
    event: &Event,
    dependencies: &[GovernanceDependency],
) -> Result<PublicKeyMaterial, WireError> {
    let [proof] = event.proofs.as_slice() else {
        return Err(WireError::Protocol(
            "Agent control Event must carry one producer proof".to_owned(),
        ));
    };
    let controller = event.executed_by.as_ref().ok_or_else(|| {
        WireError::Protocol("Agent control Event omitted controller execution".to_owned())
    })?;
    let evidence = bound_evidence_by_ref(
        dependencies,
        proof
            .signer_resolution_evidence_ref
            .as_ref()
            .ok_or_else(|| {
                WireError::Protocol("portable Agent control Event omits signer evidence".to_owned())
            })?,
        controller.signing_principal_id(),
        &proof.verification_method,
    )?;
    let key = authenticated_document_key(evidence, dependencies, proof.created_at)?;
    arkret_signatures::agent_evidence::verify_agent_accepted_event_signature(event, &|method| {
        (method == &proof.verification_method).then(|| key.clone())
    })
    .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    Ok(key)
}

/// Construct one canonical Agent signer-evidence root.
pub fn build_agent_signer_evidence(
    agent_signer_evidence: AgentSignerEvidence,
    authority_evidence: &AuthenticatedSignerResolutionEvidence,
    account_authority_evidence: &AuthenticatedSignerResolutionEvidence,
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
    let binding = snapshot.state.authorized_key()?;
    let gate = &admission.controller_account_gate_attestation;
    for evidence in [authority_evidence, account_authority_evidence] {
        evidence.validate_attester_binding()?;
    }
    validate_agent_control_accounts(
        &snapshot.state,
        &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            binding.agent_id.clone(),
            snapshot.state.authority_id.clone(),
        )),
    )?;
    if gate.authority_id != snapshot.state.authority_id
        || authority_evidence.signer_id() != &snapshot.state.authority_id
        || authority_evidence.verification_method() != &snapshot.attestation.verification_method
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
    let result = AuthenticatedSignerResolutionEvidence::Agent {
        signer_id: binding.agent_id.clone(),
        verification_method: binding.verification_method.clone(),
        agent_signer_evidence: Box::new(agent_signer_evidence),
        attester_signer_evidence_ref: authority_evidence.evidence_ref()?,
        account_authority_signer_evidence_ref: account_authority_evidence.evidence_ref()?,
    };
    result.validate_attester_binding()?;
    Ok(result)
}

/// Derive the canonical content address used by producer proofs and retained
/// runtime state for one fully authenticated signer-evidence object.
pub fn signer_evidence_ref(
    evidence: &AuthenticatedSignerResolutionEvidence,
) -> Result<arkret_wire::SignerEvidenceRef, WireError> {
    evidence.validate_attester_binding()?;
    evidence.evidence_ref()
}

/// Verify PCR proof components inside the complete Agent verification flow.
/// No current DID or device resolution is performed for historical signatures.
///
/// A successful component result does not authorize the Agent. Delegated
/// notary descriptors acquire provenance only when the main current or
/// historical verifier also authenticates the state-covering authority attestation.
/// Use this function as that verifier's trust callback; never treat its result
/// alone as an authenticated admission or a reusable verified context.
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
            verified_agent_control_event_key(&state.pcr_genesis_event, dependencies)?;
            let authority = arkret_bootstrap::AgentPcrGenesisAuthority::from_accepted_create(
                &state.pcr_genesis_event,
                &|event| {
                    arkret_schema::project_registered_cell_writes(
                        event,
                        event
                            .event_id
                            .event_digest()
                            .digest_suite()
                            .map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())
                },
            )?;
            if authority.realm_id() != &state.principal_control_realm_id
                || authority.agent_id() != &state.pcr_genesis_event.actor_id
                || seal.realm_id != state.principal_control_realm_id
            {
                return Err(WireError::Protocol(
                    "Agent PCR founding authority mismatch".to_owned(),
                ));
            }
            let delegated = validated_delegated_notary_signers(state, &authority)?;
            let digest_suite = seal.state_root.digest_suite()?;
            seal.validate_id(digest_suite)?;
            let canonical = seal.commit_transcript_bytes(digest_suite)?;
            let signature = &seal.notary_signature;
            let descriptor = delegated
                .get(&signature.verification_method)
                .copied()
                .or_else(|| {
                    authority
                        .notary()
                        .signer_descriptor(&signature.verification_method)
                })
                .ok_or_else(|| {
                    WireError::Protocol(
                        "Agent PCR Seal signer has no accepted key source".to_owned(),
                    )
                })?;
            arkret_signatures::verify_frozen_notary_signature(
                signature,
                descriptor,
                &canonical,
                digest_suite,
            )?;
            Ok(())
        }
        AgentHistoricalTrustRequest::LifecycleWitness(_) => {
            for event in [
                &state.pcr_genesis_event,
                &state.key_authorization_event,
                &state.agent_lifecycle_witness.accepted_status_event,
            ] {
                verified_agent_control_event_key(event, dependencies)?;
            }
            Ok(())
        }
        AgentHistoricalTrustRequest::AuthorizationClosure(_) => Err(WireError::Protocol(
            "authorization closure needs independently retained Seal trust".to_owned(),
        )),
        AgentHistoricalTrustRequest::Transparency(_) => Err(WireError::Protocol(
            "transparency needs its independently configured log trust".to_owned(),
        )),
    }
}

fn validated_delegated_notary_signers<'a>(
    state: &'a arkret_models_identity::AgentAuthorityState,
    authority: &arkret_bootstrap::AgentPcrGenesisAuthority,
) -> Result<BTreeMap<arkret_wire::DidUrl, &'a arkret_wire::NotarySignerDescriptor>, WireError> {
    let used = state
        .seal_lineages
        .iter()
        .map(|seal| &seal.notary_signature)
        .filter(|signature| {
            authority
                .notary()
                .signer_descriptor(&signature.verification_method)
                .is_none()
        })
        .map(|signature| signature.verification_method.clone())
        .collect::<BTreeSet<_>>();
    let mut previous = None;
    let mut mapped = BTreeMap::new();
    for descriptor in &state.accepted_delegated_notary_signers {
        descriptor.validate()?;
        let method = &descriptor.verification_method;
        if descriptor.actor_id != *authority.controller_actor_id()
            || descriptor.actor_id.as_account_id().is_none()
            || previous.is_some_and(|old: &arkret_wire::DidUrl| old >= method)
            || !used.contains(method)
        {
            return Err(WireError::Protocol("Agent delegated notary mapping is unordered, unrelated, or belongs to a different controller Account".to_owned()));
        }
        previous = Some(method);
        mapped.insert(method.clone(), descriptor);
    }
    if mapped.len() != used.len() {
        return Err(WireError::Protocol(
            "Agent delegated notary admitted key source is missing".to_owned(),
        ));
    }
    Ok(mapped)
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
    let signer =
        verify_agent_historical_event_signer(event, evidence, dependencies, verify_external_trust)
            .await?;
    Ok(PublicKeyMaterial::Ed25519Raw {
        bytes: signer.key().to_vec(),
    })
}

/// Preserve the exact authenticated Agent, controller Account, authorization
/// and publication window after verifying the same complete historical evidence
/// closure used by the Event-key API. No caller can construct this identity from
/// a bare key or a controller relationship alone.
pub async fn verify_agent_historical_event_signer<VerifyExternalTrust>(
    event: &Event,
    evidence: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
    verify_external_trust: VerifyExternalTrust,
) -> Result<arkret_signatures::agent_evidence::VerifiedAgentSigningKey, WireError>
where
    VerifyExternalTrust:
        for<'a> Fn(AgentHistoricalTrustRequest<'a>) -> AgentHistoricalTrustFuture<'a> + Clone,
{
    event.validate_for_direct_history_structural()?;
    evidence.validate_attester_binding()?;
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        attester_signer_evidence_ref,
        account_authority_signer_evidence_ref,
    } = evidence
    else {
        return Err(WireError::Protocol(
            "Agent historical key verifier received non-agent evidence".to_owned(),
        ));
    };
    let AgentSignerEvidence::HistoricalEvent {
        admission_evidence,
        authorization_closure_refs,
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
    let binding = core.authorized_key()?;
    let gate = &admission_evidence.controller_account_gate_attestation;

    let authority_evidence = bound_evidence_by_ref(
        dependencies,
        attester_signer_evidence_ref,
        &core.authority_id,
        &authority_evidence_state.attestation.verification_method,
    )?;
    validate_agent_control_accounts(core, event.executed_by.as_ref().unwrap_or(&event.actor_id))?;
    let controller_public_key =
        verified_agent_control_event_key(&core.key_authorization_event, dependencies)?;
    let authority_public_key = authenticated_document_key(
        authority_evidence,
        dependencies,
        authority_evidence_state.attestation.issued_at,
    )?;
    let account_authority_evidence = bound_evidence_by_ref(
        dependencies,
        account_authority_signer_evidence_ref,
        &gate.authority_id,
        &gate.verification_method,
    )?;
    let account_authority_public_key =
        authenticated_document_key(account_authority_evidence, dependencies, gate.issued_at)?;

    let public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
            .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    for seal in &core.seal_lineages {
        verify_external_trust(AgentHistoricalTrustRequest::PcrSeal(seal)).await?;
    }
    verify_external_trust(AgentHistoricalTrustRequest::LifecycleWitness(
        &core.agent_lifecycle_witness,
    ))
    .await?;
    for closure_ref in authorization_closure_refs {
        verify_external_trust(AgentHistoricalTrustRequest::AuthorizationClosure(
            closure_ref,
        ))
        .await?;
    }
    let verify_pcr_seal = |_seal: &Seal| Ok(());
    let verify_control_event = |_event: &Event| Ok(());
    let verified_state = arkret_signatures::agent_evidence::verify_agent_evidence_state(
        admission_evidence,
        &arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
            signer_id,
            signer_actor_id: event.executed_by.as_ref().unwrap_or(&event.actor_id),
            agent_key_id: &binding.agent_key_id,
            controller_principal_id: &binding.controller_principal_id,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            authorize_public_key_digest: &public_key_digest,
            verify_seal_signature: &verify_pcr_seal,
            verify_control_event_signature: &verify_control_event,
        },
    )
    .map_err(|reason| WireError::Protocol(reason.as_str().to_owned()))?;
    let transparency_verified = if let Some(transparency) = transparency {
        verify_external_trust(AgentHistoricalTrustRequest::Transparency(transparency)).await?;
        true
    } else {
        false
    };
    let producer = event
        .proofs
        .first()
        .ok_or_else(|| WireError::Protocol("Agent Event omitted producer proof".to_owned()))?;
    let expected_evidence_ref = evidence.evidence_ref()?;
    if &producer.verification_method != verification_method
        || producer.signer_resolution_evidence_ref.as_ref() != Some(&expected_evidence_ref)
    {
        return Err(WireError::Protocol(
            "Agent Event producer evidence binding mismatch".to_owned(),
        ));
    }
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
                expected_authority_id: &core.authority_id,
                expected_authority_verification_method: &authority_evidence_state
                    .attestation
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
            observed_at: producer.created_at,
        },
    );
    match verdict {
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Verified(key) => Ok(key),
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
    source: &HistoryKeyResponseSendRequestBody,
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
    controller_public_key: PublicKeyMaterial,
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
        account_authority_signer_evidence_ref,
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
    let binding = core.authorized_key()?;
    let gate = &admission_evidence.controller_account_gate_attestation;
    let authority_evidence = bound_evidence_by_ref(
        dependencies,
        attester_signer_evidence_ref,
        &core.authority_id,
        &authority_evidence_state.attestation.verification_method,
    )?;
    let account_authority_evidence = bound_evidence_by_ref(
        dependencies,
        account_authority_signer_evidence_ref,
        &gate.authority_id,
        &gate.verification_method,
    )?;
    validate_agent_control_accounts(core, actor)?;
    let mut document_keys = previous
        .map(|context| context.document_keys.clone())
        .unwrap_or_default();
    let controller_public_key = if let Some(previous) = previous.filter(|previous| {
        previous.key.state_digest() == &authority_evidence_state.state_digest
            && previous.key.signer_actor_id() == actor
            && previous.key.verification_method() == verification_method
    }) {
        previous.controller_public_key.clone()
    } else {
        verified_agent_control_event_key(&core.key_authorization_event, dependencies)?
    };
    let authority_public_key = agent_document_key(
        authority_evidence,
        dependencies,
        authority_evidence_state.attestation.issued_at,
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
        let verify_control_event = |_event: &Event| Ok(());
        arkret_signatures::agent_evidence::verify_agent_evidence_state(
            admission_evidence,
            &arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
                signer_id,
                signer_actor_id: actor,
                agent_key_id: &binding.agent_key_id,
                controller_principal_id: &binding.controller_principal_id,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
                authorize_public_key_digest: &public_key_digest,

                verify_seal_signature: &verify_pcr_seal,
                verify_control_event_signature: &verify_control_event,
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

                expected_authority_id: &core.authority_id,
                expected_authority_verification_method: &authority_evidence_state
                    .attestation
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
        account_authority_signer_evidence_ref.content_digest()?,
    ];
    document_keys.retain(|digest, _| retained_key_digests.contains(digest));
    match verdict {
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Verified(key) => {
            Ok(VerifiedAgentCurrentContext {
                key,
                document_keys,
                transparency_digest,
                controller_public_key,
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

/// Verify one retained governance Event against its exact persisted signer dependencies.
/// This is a server/auditor operation; clients consume their own Station result.
pub async fn verify_retained_governance_event_proofs<VerifyAgentHistoryKey>(
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
    if event.kind == arkret_wire::EventKind::AgentSelectorClaim {
        let claim: arkret_models_identity::AgentSelectorClaim =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        claim.validate()?;
        if event.actor_id.signing_principal_id() != &claim.controller_subject_id {
            return Err(WireError::Protocol(
                "selector Event actor must be its controller".into(),
            ));
        }
        let producer = event
            .proofs
            .first()
            .ok_or_else(|| WireError::Protocol("selector producer proof missing".into()))?;
        let evidence_ref = producer
            .signer_resolution_evidence_ref
            .as_ref()
            .ok_or_else(|| {
                WireError::Protocol("portable selector Event omits signer evidence".into())
            })?;
        let evidence = evidence_by_digest(dependencies, &evidence_ref.content_digest()?)?;
        if evidence.signer_id() != &claim.controller_subject_id {
            return Err(WireError::Protocol(
                "selector evidence names another controller".into(),
            ));
        }
        for proof in &claim.proofs {
            let key = authenticated_document_method_key(
                evidence,
                dependencies,
                &proof.verification_method,
                proof.created_at,
            )?;
            arkret_signatures::verify_ed25519_detached_jws_payload_proof(
                proof,
                &claim.canonical_proof_binding_bytes(proof)?,
                &key,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        }
    }
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    match event.proofs.as_slice() {
        [producer] => {
            let evidence_ref = producer
                .signer_resolution_evidence_ref
                .as_ref()
                .ok_or_else(|| {
                    WireError::Protocol("portable Event omits signer evidence".into())
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
        _ => Err(WireError::Protocol(
            "replayed Event must carry exactly one producer proof".to_owned(),
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
/// Retained Events use the sole producer proof regime. The SDK owns
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = candidate
        .accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    arkret_state::mls_governance_proof::verify_mls_governance_checkpoint_with_registry(
        candidate,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            Box::pin(verify_retained_governance_event_proofs(
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
        crate::project_control_writes_at_state,
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
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
                Box::pin(verify_retained_governance_event_proofs(
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
            crate::project_control_writes_at_state,
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = existing_checkpoint
        .accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    let (verified, requested_live_digest_suite, verified_event_digest_suites) =
        arkret_state::mls_governance_proof::verified_live_digest_suite_at_basis_with_registry(
            existing_checkpoint,
            requested_basis,
            &registry,
            arkret_signatures::verify_frozen_notary_signature,
            |event, digest_suite, dependencies| {
                Box::pin(verify_retained_governance_event_proofs(
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
            crate::project_control_writes_at_state,
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
        pending.extend(seal.predecessor_ref.iter().cloned());
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
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
    arkret_state::mls_governance_proof::verify_mls_governance_cut_with_registry(
        &verified_base,
        target_basis,
        cut_seals,
        cut_events,
        cut_dependencies,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            Box::pin(verify_retained_governance_event_proofs(
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
        crate::project_control_writes_at_state,
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
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
            Box::pin(verify_retained_governance_event_proofs(
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
        crate::project_control_writes_at_state,
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let verified =
        verify_mls_governance_checkpoint(target_checkpoint, verify_agent_history_key).await?;
    arkret_state::mls_governance_proof::materialize_mls_governance_frontier_from_verified_checkpoint(
        request,
        &verified,
        group_genesis_binding,
        local_mls_leaves,
        &registry,
        crate::project_control_writes_at_state,
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
    let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(|error| {
        WireError::Protocol(format!(
            "MLS governance registry construction failed: {error}"
        ))
    })?;
    let event_map = accepted_events
        .iter()
        .map(|event| Ok((signed_event_digest_claim(event)?, event.clone())))
        .collect::<Result<BTreeMap<_, _>, WireError>>()?;
    arkret_state::mls_governance_proof::verify_mls_governance_checkpoint_with_registry(
        &candidate,
        &registry,
        arkret_signatures::verify_frozen_notary_signature,
        |event, digest_suite, dependencies| {
            Box::pin(verify_retained_governance_event_proofs(
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
        crate::project_control_writes_at_state,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

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
