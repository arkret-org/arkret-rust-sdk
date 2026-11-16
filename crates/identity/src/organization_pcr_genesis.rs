//! Organization PCR genesis authority from original native history and Event approvals.
//! This proof grants no producer, hosting, transport or governance authority by itself.

use std::collections::BTreeSet;

use arkret_models_identity::{OrganizationGovernance, ResolutionCommitment};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{
    AccountId, ActorId, ApprovalContext, ApprovalSignature, CapabilityActionId, DidUrl, ErrorCode,
    EventAdmissionSubmission, GenesisGovernance, ServiceOperationId, WireError,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{DidDocument, IdentityError, Result};

/// Process-local verified authority, never a caller-selected or serialized flag.
#[derive(Clone, Debug)]
pub struct VerifiedOrganizationPcrGenesis {
    holder: AccountId,
    methods: Vec<(ApprovalSignature, [u8; 32])>,
    delegated_service: Option<arkret_wire::DidCoreId>,
}

impl VerifiedOrganizationPcrGenesis {
    pub fn holder(&self) -> &AccountId {
        &self.holder
    }
    pub fn methods(&self) -> &[(ApprovalSignature, [u8; 32])] {
        &self.methods
    }
    pub fn delegated_service(&self) -> Option<&arkret_wire::DidCoreId> {
        self.delegated_service.as_ref()
    }
}

fn invalid(code: ErrorCode, detail: impl std::fmt::Display) -> IdentityError {
    WireError::ProtocolCode {
        code,
        message: format!("Organization PCR genesis: {detail}"),
    }
    .into()
}
fn signature(detail: impl std::fmt::Display) -> IdentityError {
    invalid(ErrorCode::SignatureInvalid, detail)
}

/// Select a controller/governance key from the exact method-native state.
/// The existing native-key adapter handles cold roots. Operational control
/// uses original DID relationships and the normalized, declared controller.
fn control_key(
    point: &arkret_signatures::webvh::ValidatedWebvhHistoryPoint,
    holder: &AccountId,
    method: &DidUrl,
) -> Result<PublicKeyMaterial> {
    let document: DidDocument = serde_json::from_value(point.document.clone())?;
    if arkret_wire::project_did_to_core_id(&document.id)? != holder.principal_id {
        return Err(signature("control state names another organization"));
    }
    if let Ok(native) =
        crate::principal_control::native_identity_control_key_from_verified_selection(
            &document.id,
            &holder.principal_id,
            std::slice::from_ref(&point.active_update_key_multibase),
            method,
            crate::principal_control::DirectIdentityControlPurpose::ApprovalSignature,
        )
    {
        return Ok(PublicKeyMaterial::Ed25519Raw {
            bytes: native.public_key().to_vec(),
        });
    }
    let normalized = arkret_models_identity::normalized_did_document(&document)?;
    let related = [
        "authentication",
        "assertion_methods",
        "capability_invocations",
    ]
    .into_iter()
    .any(|name| {
        normalized[name]
            .as_array()
            .into_iter()
            .flatten()
            .any(|row| row["verification_method"].as_str() == Some(method.as_str()))
    });
    let controlled = normalized["verification_methods"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|row| {
            row["verification_method"].as_str() == Some(method.as_str())
                && row["controller_did"].as_str() == Some(document.id.as_str())
        });
    if !related || !controlled {
        return Err(signature("method lacks original organization control"));
    }
    crate::public_key_material_from_document(&document, method).map_err(signature)
}

/// Verify either finite exact-Event root authorization or the existing
/// unique Service bootstrap delegation. Full native history and witness
/// originals are consumed again by durable-source readers without networking.
/// Producer/Service or Device evidence and the native PG unit remain separate.
pub fn verify_organization_pcr_genesis_authority(
    submission: &EventAdmissionSubmission,
    log_entries: &[Value],
    witness_records: &[Value],
    accepted_at: DateTime<Utc>,
) -> Result<VerifiedOrganizationPcrGenesis> {
    submission.validate()?;
    arkret_event_draft::validate_event_for_submit(&submission.event)
        .map_err(|error| invalid(ErrorCode::SchemaViolation, error))?;
    let event = &submission.event;
    let holder = match GenesisGovernance::from_genesis(event).map_err(signature)? {
        GenesisGovernance::Organization => {
            event.actor_id.as_account_id().cloned().ok_or_else(|| {
                invalid(
                    ErrorCode::SchemaViolation,
                    "organization requires its full Account",
                )
            })?
        }
        _ => {
            return Err(invalid(
                ErrorCode::SchemaViolation,
                "not an organization create",
            ));
        }
    };
    if event
        .payload
        .get("object")
        .and_then(|v| v.get("founding_device_descriptor"))
        .is_some()
    {
        return Err(invalid(
            ErrorCode::SchemaViolation,
            "Human founding Device is forbidden",
        ));
    }
    let resolution: ResolutionCommitment = serde_json::from_value(
        event
            .payload
            .get("object")
            .and_then(|v| v.get("initial_resolution"))
            .cloned()
            .ok_or_else(|| signature("missing original initial resolution"))?,
    )?;
    if resolution.did.method() != "webvh"
        || arkret_wire::project_did_to_core_id(&resolution.did)? != holder.principal_id
        || log_entries.is_empty()
    {
        return Err(signature("organization native identity differs"));
    }
    let mut bytes = Vec::new();
    for entry in log_entries {
        bytes.extend(arkret_canonical::canonical_json_bytes(entry)?);
        bytes.push(b'\n');
    }
    let witnesses = arkret_canonical::canonical_json_bytes(witness_records)?;
    let verified = crate::verify_did_webvh_v1_chain_and_witness_bytes(
        &resolution.did,
        &bytes,
        Some(&witnesses),
    )
    .map_err(signature)?;
    if verified
        .log
        .entries
        .last()
        .is_none_or(|entry| entry.version_created_at > accepted_at)
    {
        return Err(signature("native history is future-dated"));
    }
    let point = arkret_signatures::webvh::validate_webvh_history_at(
        &resolution.did,
        log_entries,
        event.created_at,
    )
    .map_err(signature)?;
    // First admission uses the accepting cut's governance, while signatures
    // remain bound to their original historical methods. Cold verification
    // supplies the original committed_at, never today's authorization.
    let accepting_point = arkret_signatures::webvh::validate_webvh_history_at(
        &resolution.did,
        log_entries,
        accepted_at,
    )
    .map_err(signature)?;
    let selected = log_entries
        .iter()
        .find(|entry| {
            entry.get("versionId").and_then(Value::as_str) == Some(point.version_id.as_str())
        })
        .ok_or_else(|| signature("original selected entry is missing"))?;
    if point.version_id != resolution.version_id
        || arkret_canonical::canonical_sha256(selected)? != resolution.method_history_head
    {
        return Err(signature(
            "initial resolution does not bind Event-time native history",
        ));
    }
    let document: DidDocument = serde_json::from_value(point.document.clone())?;
    let governance = OrganizationGovernance::from_document(&document)?;
    let authorization_ref = DidUrl::new(
        event
            .authorization_ref
            .as_ref()
            .ok_or_else(|| signature("authority source reference is missing"))?
            .as_str(),
    )
    .map_err(signature)?;
    let accepting_document: DidDocument = serde_json::from_value(accepting_point.document.clone())?;
    let accepting_governance = OrganizationGovernance::from_document(&accepting_document)?;
    let threshold = accepting_governance
        .as_ref()
        .and_then(|g| g.threshold.as_ref());
    let (methods, eligible) = finite_votes(
        submission,
        &holder,
        &resolution.did,
        log_entries,
        accepting_governance.as_ref(),
        CapabilityActionId::RealmCreate,
        accepted_at,
    )?;
    let finite_root_approval = methods
        .iter()
        .any(|(approval, _)| approval.proof.verification_method == authorization_ref);
    let required = threshold.map_or(0, |threshold| threshold.min_signature_count);
    if u64::try_from(eligible.len()).map_err(signature)? < required {
        return Err(invalid(
            ErrorCode::CapabilityDenied,
            "organization governance quorum is not met",
        ));
    }
    let delegated_service = if finite_root_approval {
        None
    } else {
        let ActorId::Service { service_id } = event.actual_signer() else {
            return Err(invalid(
                ErrorCode::CapabilityDenied,
                "Device executor requires finite root approval",
            ));
        };
        // The reference names the original authority source; the ongoing
        // delegation must also remain valid at the actual accepting cut.
        control_key(&point, &holder, &authorization_ref)?;
        require_bootstrap_delegation(governance.as_ref(), service_id, event.created_at)?;
        require_bootstrap_delegation(accepting_governance.as_ref(), service_id, accepted_at)?;
        Some(service_id.clone())
    };
    Ok(VerifiedOrganizationPcrGenesis {
        holder,
        methods,
        delegated_service,
    })
}

fn require_bootstrap_delegation(
    governance: Option<&OrganizationGovernance>,
    service_id: &arkret_wire::DidCoreId,
    at: DateTime<Utc>,
) -> Result<()> {
    let delegation = governance
        .and_then(|g| g.delegations.as_ref())
        .into_iter()
        .flatten()
        .find(|row| &row.service_id == service_id)
        .ok_or_else(|| {
            invalid(
                ErrorCode::CapabilityDenied,
                "finite approval or current exact Service delegation is missing",
            )
        })?;
    if !delegation
        .purposes
        .iter()
        .any(|purpose| purpose == "principal_control_realm_bootstrap")
        || at < delegation.not_before
        || delegation.expires_at.is_some_and(|end| at >= end)
    {
        return Err(invalid(
            ErrorCode::CapabilityDenied,
            "bootstrap delegation purpose or time differs at its applicable cut",
        ));
    }
    Ok(())
}

/// Authenticate a real Service executor independently of the organization root,
/// source hosting Station and accepting governor. The retained service carrier
/// is existing SDK data, and all original native history is consumed again.
pub fn verify_organization_pcr_service_producer(
    event: &arkret_wire::Event,
    resolution: &arkret_models_identity::AuthenticatedServiceResolution,
    accepted_at: DateTime<Utc>,
) -> Result<()> {
    let ActorId::Service { service_id } = event.actual_signer() else {
        return Err(invalid(
            ErrorCode::SchemaViolation,
            "Service executor required",
        ));
    };
    crate::verify_authenticated_service_resolution_history(resolution, service_id, accepted_at)?;
    let document =
        crate::authenticated_service_document_at(resolution, service_id, event.created_at)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| signature("Service producer proof missing"))?;
    crate::validate_verification_method_relationship(
        &document,
        &proof.verification_method,
        &document.id,
        crate::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(signature)?;
    let key = crate::public_key_material_from_document(&document, &proof.verification_method)
        .map_err(signature)?;
    // Producer first-admission authority differs from a finite historical
    // approval. Its actual Service method/key must still be current at C.
    let current = crate::authenticated_service_document_at(resolution, service_id, accepted_at)?;
    resolution.projection().map_err(signature)?;
    if crate::document_canonical_digest(&current).map_err(signature)?
        != crate::document_canonical_digest(&resolution.normalized_did_document)
            .map_err(signature)?
    {
        return Err(signature(
            "Service source is not the accepting method-native head",
        ));
    }
    crate::validate_verification_method_relationship(
        &current,
        &proof.verification_method,
        &current.id,
        crate::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(signature)?;
    let current_key =
        crate::public_key_material_from_document(&current, &proof.verification_method)
            .map_err(signature)?;
    if current_key.ed25519_bytes().map_err(signature)? != key.ed25519_bytes().map_err(signature)? {
        return Err(signature(
            "historical Service producer key is no longer current",
        ));
    }
    let suite = event.event_id.digest_suite_code().digest_suite();
    event.verify_event_id_matches_content_with_digest_suite(suite)?;
    event.verify_producer_proof_self_consistency(suite)?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(signature)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(signature)?;
    Ok(())
}

/// Independently establish original Org intent before the selected G is trusted.
/// Every input is frozen at the original acceptance cut; no resolver or clock is used.
pub fn verify_organization_genesis_signer_fact(
    full: &arkret_wire::CommittedEventFullView,
    fact: &arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact,
) -> Result<VerifiedOrganizationPcrGenesis> {
    use arkret_models_identity::ResolutionMethodHistoryEvidence;
    let suite = full.event.event_id.digest_suite_code().digest_suite();
    fact.validate_commit_binding(full, suite)
        .map_err(signature)?;
    let ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries,
        witness_records,
        ..
    } = &fact.method_history_evidence
    else {
        return Err(signature("Org source has no complete native history"));
    };
    let terminal: DidDocument = serde_json::from_value(
        log_entries
            .last()
            .and_then(|entry| entry.get("state"))
            .cloned()
            .ok_or_else(|| signature("Org source terminal method state is absent"))?,
    )?;
    let expected = crate::build_webvh_method_history_evidence(
        &terminal,
        log_entries.clone(),
        witness_records.clone(),
    )?;
    if expected != fact.method_history_evidence {
        return Err(signature(
            "Org source boundary or method receipt differs from its originals",
        ));
    }
    // Finite root approvals establish G independently; delegation establishes S.
    // Neither branch may use G's own Commit to invent Org intent or an S key.
    let submission = EventAdmissionSubmission {
        event: full.event.clone(),
        approval_signatures: fact.approval_signatures.clone(),
    };
    let original = verify_organization_pcr_genesis_authority(
        &submission,
        log_entries,
        witness_records,
        full.commit.committed_at,
    )?;
    if let Some(resolution) = &fact.producer_resolution {
        verify_organization_pcr_service_producer(
            &full.event,
            resolution,
            full.commit.committed_at,
        )?;
    } else {
        // Only an exact finite root authorization permits the Device branch.
        if original.delegated_service.is_some() {
            return Err(signature(
                "bootstrap Service delegation cannot authorize a Device",
            ));
        }
        verify_organization_genesis_event_signature(&full.event, fact, suite)?;
    }
    Ok(original)
}

/// Verify only the original Event signature, not Org authorization or G selection.
/// The complete accepted-cut check requires the covering original Commit above.
pub fn verify_organization_genesis_event_signature(
    event: &arkret_wire::Event,
    fact: &arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact,
    suite: arkret_canonical::DigestSuite,
) -> Result<()> {
    fact.validate_event_binding(event, suite)
        .map_err(signature)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| signature("Org Event producer proof is absent"))?;
    let key = if let Some(resolution) = &fact.producer_resolution {
        let ActorId::Service { service_id } = event.actual_signer() else {
            return Err(signature("Org source does not bind a Service producer"));
        };
        let document =
            crate::authenticated_service_document_at(resolution, service_id, event.created_at)?;
        crate::validate_verification_method_relationship(
            &document,
            &proof.verification_method,
            &document.id,
            crate::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(signature)?;
        crate::public_key_material_from_document(&document, &proof.verification_method)
            .map_err(signature)?
    } else {
        let value = fact
            .public_key_base64url
            .as_ref()
            .ok_or_else(|| signature("finite Org Device key is absent"))?;
        PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(value.as_str()).map_err(signature)?,
        }
    };
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(signature)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(signature)?;
    Ok(())
}

/// Verify the one original native admission source and project its public fact.
/// HTTP calls this only after all real history I/O; PG reuses the exact inputs
/// at the proposed committed_at under its native/current/Account cut.
pub fn verify_organization_pcr_genesis_source(
    request: &arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody,
    source: &arkret_wire::DidCoreId,
    entries: &[Value],
    witnesses: &[Value],
    producer_resolution: Option<&arkret_models_identity::AuthenticatedServiceResolution>,
    accepted_at: DateTime<Utc>,
) -> Result<(
    VerifiedOrganizationPcrGenesis,
    arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact,
)> {
    request.validate()?;
    if !request.is_organization_pcr_genesis_candidate() {
        return Err(signature("original source is not an Org Genesis candidate"));
    }
    let event = &request.event_submission.event;
    let holder = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| signature("original Org source lacks its full Account"))?;
    if &holder.station_id != source {
        return Err(signature(
            "authenticated hosting Source differs from the Org Account",
        ));
    }
    let genesis: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    let governor = &genesis.object.governance_station_id;
    let authority = verify_organization_pcr_genesis_authority(
        &request.event_submission,
        entries,
        witnesses,
        accepted_at,
    )?;
    let (producer_resolution, public_key_base64url) =
        match (event.account_device_producer()?, producer_resolution) {
            (Some(_), None) => {
                let evidence = request
                    .producer_device_evidence
                    .as_ref()
                    .ok_or_else(|| signature("original Org executor Device evidence is absent"))?;
                let original =
                crate::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
                    evidence,
                    event,
                    source,
                    governor,
                    &arkret_models_collaboration::authority_commit::authority_forward_body_digest(
                        request,
                    )?,
                    event.event_id.digest_suite_code().digest_suite(),
                    accepted_at,
                )?;
                (None, Some(original.into_fact().key.public_key_base64url))
            }
            (None, Some(resolution)) => {
                verify_organization_pcr_service_producer(event, resolution, accepted_at)?;
                (Some(resolution.clone()), None)
            }
            _ => {
                return Err(signature(
                    "original Org producer source is missing or mixed",
                ));
            }
        };
    let terminal: DidDocument = serde_json::from_value(
        entries
            .last()
            .and_then(|entry| entry.get("state"))
            .cloned()
            .ok_or_else(|| signature("original Org method head is absent"))?,
    )?;
    let fact = arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact {
        event_id: event.event_id.clone(),
        method_history_evidence: crate::build_webvh_method_history_evidence(
            &terminal,
            entries.to_vec(),
            witnesses.to_vec(),
        )?,
        approval_signatures: request.event_submission.approval_signatures.clone(),
        producer_resolution,
        public_key_base64url,
    };
    fact.validate_event_binding(event, event.event_id.digest_suite_code().digest_suite())?;
    Ok((authority, fact))
}

/// Verify each finite vote at its own historical method, then count only
/// contributions allowed by the policy at the original accepting cut.
fn finite_votes(
    submission: &EventAdmissionSubmission,
    holder: &AccountId,
    did: &arkret_wire::Did,
    entries: &[Value],
    policy: Option<&OrganizationGovernance>,
    action: CapabilityActionId,
    accepted_at: DateTime<Utc>,
) -> Result<(Vec<(ApprovalSignature, [u8; 32])>, BTreeSet<DidUrl>)> {
    let event = &submission.event;
    let threshold = policy.and_then(|policy| policy.threshold.as_ref());
    let mut methods = Vec::new();
    let mut eligible = BTreeSet::new();
    for approval in submission.approval_signatures.iter().flatten() {
        approval.validate()?;
        if !matches!(
            approval.input.approval_context,
            ApprovalContext::RealmGovernance {}
        ) || arkret_wire::project_did_to_core_id(&approval.input.approver_did)?
            != holder.principal_id
        {
            return Err(signature("approval has no organization authority basis"));
        }
        let signing_point = arkret_signatures::webvh::validate_webvh_history_at(
            did,
            entries,
            approval.input.approved_at,
        )
        .map_err(signature)?;
        let key = control_key(&signing_point, holder, &approval.proof.verification_method)?;
        arkret_signatures::approval_signature::verify_event_approval_signature_with_verified_controller(
            approval, event, ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            action, accepted_at, &key, Some(&holder.principal_id),
        ).map_err(signature)?;
        if threshold.is_none_or(|threshold| {
            threshold
                .allowed_kids
                .contains(&approval.proof.verification_method)
        }) {
            eligible.insert(approval.proof.verification_method.clone());
        }
        methods.push((approval.clone(), key.ed25519_bytes().map_err(signature)?));
    }
    Ok((methods, eligible))
}

/// Finite Organization control proof for the registered planned handoff Event.
/// The caller independently loads the accepted native inception source and
/// checks current authority/root/head. Returned original qualified methods
/// never grant a transport, hosting or producer identity.
pub fn verify_organization_pcr_governance_change_authority(
    inception: &VerifiedOrganizationPcrGenesis,
    submission: &EventAdmissionSubmission,
    entries: &[Value],
    witnesses: &[Value],
    accepted_at: DateTime<Utc>,
) -> Result<Vec<(ApprovalSignature, [u8; 32])>> {
    submission.validate()?;
    arkret_event_draft::validate_event_for_submit(&submission.event)
        .map_err(|error| invalid(ErrorCode::SchemaViolation, error))?;
    let event = &submission.event;
    if event.kind != arkret_wire::EventKind::RealmGovernanceStationChange
        || event.actor_id.as_account_id() != Some(inception.holder())
        || event.executed_by.is_none()
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || event.applet_id.is_some()
        || event.authorization_ref.is_none()
    {
        return Err(invalid(
            ErrorCode::SchemaViolation,
            "finite change differs from its actual Org holder/root carrier",
        ));
    }
    let did = arkret_wire::Did::new(
        entries
            .last()
            .and_then(|row| row.pointer("/state/id"))
            .and_then(Value::as_str)
            .ok_or_else(|| signature("current Org method head is absent"))?,
    )?;
    if did.method() != "webvh"
        || arkret_wire::project_did_to_core_id(&did)? != inception.holder().principal_id
    {
        return Err(signature(
            "current control history belongs to another Org principal",
        ));
    }
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(arkret_canonical::canonical_json_bytes(entry)?);
        bytes.push(b'\n');
    }
    let witness_bytes = arkret_canonical::canonical_json_bytes(witnesses)?;
    let verified =
        crate::verify_did_webvh_v1_chain_and_witness_bytes(&did, &bytes, Some(&witness_bytes))
            .map_err(signature)?;
    if verified
        .log
        .entries
        .last()
        .is_none_or(|row| row.version_created_at > accepted_at)
    {
        return Err(signature("finite change control history is future-dated"));
    }
    let current = arkret_signatures::webvh::validate_webvh_history_at(&did, entries, accepted_at)
        .map_err(signature)?;
    let document: DidDocument = serde_json::from_value(current.document)?;
    let policy = OrganizationGovernance::from_document(&document)?;
    let (methods, eligible) = finite_votes(
        submission,
        inception.holder(),
        &did,
        entries,
        policy.as_ref(),
        CapabilityActionId::RealmGovernanceStationChange,
        accepted_at,
    )?;
    let required = policy
        .as_ref()
        .and_then(|policy| policy.threshold.as_ref())
        .map_or(1, |threshold| threshold.min_signature_count);
    if u64::try_from(eligible.len()).map_err(signature)? < required {
        return Err(invalid(
            ErrorCode::CapabilityDenied,
            "finite organization change quorum is not met",
        ));
    }
    // Bootstrap delegation is intentionally never consulted for a change.
    Ok(methods)
}
