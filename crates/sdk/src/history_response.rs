//! High-level verification for receipt-bound history response records.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

use arkret_models_collaboration::events_payloads::mls::MlsGenesisPayload;
use arkret_models_collaboration::governance_dependencies::GovernanceDependency;
use arkret_models_collaboration::history_key::{
    AuthorProfile, EpochRange, HistoryGovernanceTraversalIntent, HistoryKeyRequestCreateOutcome,
    HistoryKeyResponseContent, HistoryKeyResponseLostRecord, HistoryKeyResponseRecord,
    HistoryKeyResponseSendRequestBody, HistoryManifestAdmission, HistoryResponseChunkDescriptor,
    HistoryResponseId, HistoryResponseManifest, HistorySecretChunkSealContext,
    HistorySecretChunkSealPurpose, HistorySourceSignerKind, HistorySourceSignerOutcome,
    MinimalMetadataMlsLeafSignerEvidence, SealedHistoryChunk,
};
use arkret_models_crypto::mls_payloads::MlsCommitPayload;
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_signatures::proof::PublicKeyMaterial;
use arkret_state::mls_governance_proof::MlsGovernanceVerificationCheckpoint;
use arkret_wire::{
    ActorId, ContentScheme, EventId, Hash, HistoryEffectiveScope, ScopeRef, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistorySourceProofExternalVerificationRequest<'a> {
    Agent {
        source_record: &'a HistoryKeyResponseSendRequestBody,
        signer_evidence: &'a AuthenticatedSignerResolutionEvidence,
        dependencies: &'a [GovernanceDependency],
    },
    MinimalMetadata {
        source_record: &'a HistoryKeyResponseSendRequestBody,
        signer_evidence: &'a MinimalMetadataMlsLeafSignerEvidence,
        verified_checkpoint: &'a MlsGovernanceVerificationCheckpoint,
    },
}

#[cfg(not(target_arch = "wasm32"))]
pub type HistorySourceProofVerificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PublicKeyMaterial, WireError>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type HistorySourceProofVerificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PublicKeyMaterial, WireError>> + 'a>>;

/// Verify the Principal-signed IdentityLink embedded byte-exactly in a
/// minimal-metadata signer-evidence object.
///
/// The evidence object is only a carrier. Authority comes from the referenced
/// Principal signer evidence and its recursively verified attester closure.
pub fn verify_minimal_metadata_identity_link_signature(
    signer_evidence: &MinimalMetadataMlsLeafSignerEvidence,
    dependencies: &[GovernanceDependency],
) -> Result<arkret_models_collaboration::objects::profiles::IdentityLink, WireError> {
    signer_evidence.validate()?;
    let identity_link = signer_evidence.validate_identity_link_binding()?;
    let identity_link_signer = super::mls_governance::bound_evidence_by_ref(
        dependencies,
        &signer_evidence.identity_link_signer_evidence_ref,
        &identity_link.principal_id,
        &identity_link.proof.verification_method,
    )?;
    if !matches!(
        identity_link_signer,
        AuthenticatedSignerResolutionEvidence::Principal { .. }
    ) {
        return invalid("minimal-metadata IdentityLink signer evidence is non-Principal");
    }
    let identity_link_key = super::mls_governance::authenticated_document_key(
        identity_link_signer,
        dependencies,
        identity_link.effective_at,
    )?;
    if identity_link.proof.signature_algorithm != "Ed25519" {
        return invalid("minimal-metadata IdentityLink proof algorithm is unsupported");
    }
    arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
        &identity_link.canonical_proof_input()?,
        &identity_link.proof.signature,
        &identity_link_key,
    )
    .map_err(|error| {
        WireError::Protocol(format!(
            "minimal-metadata IdentityLink proof is invalid: {error}"
        ))
    })?;
    Ok(identity_link)
}

/// Verify the receiver-local half of a minimal-metadata history source key.
///
/// The IdentityLink bytes must come from the receiver's encrypted MLS receive
/// cache and the group view must come from its independently verified winning
/// MLS state. The signer evidence is not an authority for either input.
pub fn verify_minimal_metadata_history_source_local_state(
    source: &HistoryKeyResponseSendRequestBody,
    signer_evidence: &MinimalMetadataMlsLeafSignerEvidence,
    accepted_transition: &arkret_models_crypto::MlsEpochHead,
    received_identity_link: &arkret_models_collaboration::objects::profiles::IdentityLink,
    received_identity_link_canonical_bytes: &[u8],
    winning_group_state: &arkret_policy::minimal_metadata_author::AuthorGroupStateView,
) -> Result<PublicKeyMaterial, WireError> {
    source.validate()?;
    signer_evidence.validate()?;
    accepted_transition.validate()?;
    received_identity_link.validate_minimal()?;
    let canonical_received = arkret_canonical::canonical_json_bytes(received_identity_link)?;
    let expected_identity_link = arkret_wire::base64url::base64url_decode(
        signer_evidence
            .identity_link_canonical_bytes_b64u
            .as_str()
            .as_bytes(),
    )?;
    if canonical_received != received_identity_link_canonical_bytes
        || received_identity_link_canonical_bytes != expected_identity_link
        || received_identity_link != &signer_evidence.validate_identity_link_binding()?
        || source.source_actor_id != signer_evidence.source_actor_id
        || source.source_proof.verification_method != signer_evidence.verification_method
        || source.effective_scope != signer_evidence.effective_scope
        || winning_group_state.group_id != signer_evidence.mls_group_id
        || winning_group_state.epoch != signer_evidence.epoch
        || winning_group_state.group_state_ref
            != signer_evidence.winning_group_state_transition_ref.as_str()
    {
        return invalid(
            "minimal-metadata source does not match the locally received IdentityLink and winning MLS state",
        );
    }
    if signer_evidence
        .winning_group_state_transition_ref
        .identity_key()
        .event_digest()
        != signer_evidence.winning_group_state_event_digest
    {
        return invalid("minimal-metadata winning transition Event digest mismatch");
    }
    if accepted_transition.transition_ref != signer_evidence.winning_group_state_transition_ref
        || accepted_transition.transition_event_digest
            != signer_evidence.winning_group_state_event_digest
        || accepted_transition.mls_transition_digest
            != signer_evidence.winning_mls_transition_digest
        || accepted_transition.mls_group_id.as_str() != signer_evidence.mls_group_id
        || accepted_transition.next_epoch != signer_evidence.epoch
        || !scope_matches(
            &signer_evidence.effective_scope,
            &accepted_transition.effective_scope,
        )
    {
        return invalid("minimal-metadata source does not bind the accepted MLS transition");
    }
    let leaf_index = u32::try_from(signer_evidence.leaf_index).map_err(|_| {
        WireError::Protocol("minimal-metadata leaf index exceeds RFC 9420 bounds".to_owned())
    })?;
    let mut matching = winning_group_state.active_leaves.iter().filter(|leaf| {
        leaf.leaf_index == leaf_index
            && matches!(
                &leaf.credential,
                arkret_policy::minimal_metadata_author::AuthorLeafCredential::Basic { identity }
                    if identity.as_slice() == signer_evidence.pairwise_actor_id.as_str().as_bytes()
            )
    });
    let leaf = matching.next().ok_or_else(|| {
        WireError::Protocol("minimal-metadata source has no exact active local LeafNode".to_owned())
    })?;
    if matching.next().is_some()
        || leaf.leaf_node_canonical_bytes.is_empty()
        || leaf.leaf_node_canonical_bytes
            != arkret_wire::base64url::base64url_decode(
                signer_evidence
                    .leaf_node_canonical_bytes_b64u
                    .as_str()
                    .as_bytes(),
            )?
    {
        return invalid("minimal-metadata source local LeafNode is ambiguous or mismatched");
    }
    let key = arkret_wire::base64url::base64url_decode(
        signer_evidence
            .response_signing_public_key_b64u
            .as_str()
            .as_bytes(),
    )?;
    Ok(PublicKeyMaterial::Ed25519Raw { bytes: key })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedHistoryManifest {
    pub response_id: HistoryResponseId,
    pub source_actor_id: ActorId,
    pub source_sender_domain: String,
    pub manifest_digest: Hash,
    pub manifest_admission_digest: Hash,
    pub chunks: Vec<HistoryResponseChunkDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedHistoryChunk {
    pub response_id: HistoryResponseId,
    pub source_actor_id: ActorId,
    pub source_sender_domain: String,
    pub covered_epoch_range: EpochRange,
    pub sealed_chunk: SealedHistoryChunk,
    pub seal_context: HistorySecretChunkSealContext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedHistoryResponseRecord {
    Manifest {
        sequence: u64,
        cursor: String,
        record_digest: Hash,
        manifest: VerifiedHistoryManifest,
    },
    Chunk {
        sequence: u64,
        cursor: String,
        record_digest: Hash,
        chunk: Box<VerifiedHistoryChunk>,
    },
}

impl VerifiedHistoryResponseRecord {
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Manifest { sequence, .. } | Self::Chunk { sequence, .. } => *sequence,
        }
    }
}

/// Verify source signatures and end-to-end bindings using the Account Station result.
/// The caller must obtain the record and signer result from the accepted
/// request account's trusted Station and bind that transport to its current
/// account session. This API does not independently verify Station governance
/// or release-service signer authority. The callback checks only receiver-local
/// minimal-metadata MLS state.
#[allow(clippy::too_many_arguments)]
pub async fn verify_history_response_record<VerifyExternalSourceKey>(
    accepted: &HistoryKeyRequestCreateOutcome,
    record: &HistoryKeyResponseRecord,
    signer_result: &HistorySourceSignerOutcome,
    verified_manifest: Option<&VerifiedHistoryManifest>,
    now: DateTime<Utc>,
    verify_external_source_key: VerifyExternalSourceKey,
) -> Result<VerifiedHistoryResponseRecord, WireError>
where
    VerifyExternalSourceKey: for<'a> Fn(
            &'a HistoryKeyResponseSendRequestBody,
            &'a MinimalMetadataMlsLeafSignerEvidence,
        ) -> HistorySourceProofVerificationFuture<'a>
        + Clone,
{
    accepted.validate()?;
    record.validate()?;
    signer_result.validate_for_source(&record.source_record)?;
    if now >= accepted.request.expires_at
        || record.sent_at > accepted.request.expires_at
        || record.source_record.expires_at != accepted.request.expires_at
    {
        return invalid("history response record is outside the accepted request lifetime");
    }

    let request_digest = accepted.request.request_digest()?;
    let receipt_digest = accepted.request_receipt.request_receipt_digest()?;
    let source = &record.source_record;
    if source.effective_scope != accepted.request.effective_scope
        || source.request_digest != request_digest
        || source.request_receipt_digest != receipt_digest
    {
        return invalid("history source record does not bind the accepted request");
    }

    if source.source_proof.created_at > record.sent_at
        || source.source_proof.created_at > source.expires_at
    {
        return invalid("history source proof timestamp is outside its signed record lifetime");
    }
    let source_key = match signer_result {
        HistorySourceSignerOutcome::Authenticated {
            public_key_b64u, ..
        } => PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_wire::base64url::base64url_decode(public_key_b64u.as_str().as_bytes())?,
        },
        HistorySourceSignerOutcome::ReceiverMls {
            signer_evidence,
            identity_link_public_key_b64u,
            ..
        } => {
            let link = signer_evidence.validate_identity_link_binding()?;
            let key = PublicKeyMaterial::Ed25519Raw {
                bytes: arkret_wire::base64url::base64url_decode(
                    identity_link_public_key_b64u.as_str().as_bytes(),
                )?,
            };
            if link.proof.signature_algorithm != "Ed25519" {
                return invalid("minimal-metadata IdentityLink proof algorithm is unsupported");
            }
            arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                &link.canonical_proof_input()?,
                &link.proof.signature,
                &key,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            let verified = verify_external_source_key(source, signer_evidence).await?;
            let expected = arkret_wire::base64url::base64url_decode(
                signer_evidence
                    .response_signing_public_key_b64u
                    .as_str()
                    .as_bytes(),
            )?;
            if verified != (PublicKeyMaterial::Ed25519Raw { bytes: expected }) {
                return invalid("receiver-local MLS check returned an unrelated source key");
            }
            verified
        }
    };
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &source.source_proof,
        &source.proof_binding_bytes()?,
        &source_key,
    )
    .map_err(|error| WireError::Protocol(format!("history source proof is invalid: {error}")))?;

    let intent = member_history_intent(accepted)?;
    match (
        &source.content,
        &record.manifest_admission,
        &record.release_attestation,
    ) {
        (HistoryKeyResponseContent::Manifest(manifest), Some(admission), None) => {
            verify_manifest(accepted, source, manifest, admission, intent)?;
            Ok(VerifiedHistoryResponseRecord::Manifest {
                sequence: record.sequence,
                cursor: record.cursor.clone(),
                record_digest: record.record_digest.clone(),
                manifest: VerifiedHistoryManifest {
                    response_id: source.response_id.clone(),
                    source_actor_id: source.source_actor_id.clone(),
                    source_sender_domain: source.source_sender_domain.clone(),
                    manifest_digest: source.manifest_digest()?,
                    manifest_admission_digest: admission.manifest_admission_digest.clone(),
                    chunks: manifest.chunks.clone(),
                },
            })
        }
        (HistoryKeyResponseContent::Chunk(chunk), None, Some(attestation)) => {
            let manifest = verified_manifest.ok_or_else(|| {
                WireError::Protocol("history chunk arrived before its verified manifest".to_owned())
            })?;
            let descriptor = manifest
                .chunks
                .iter()
                .find(|descriptor| descriptor.chunk_response_id == source.response_id)
                .ok_or_else(|| {
                    WireError::Protocol(
                        "history chunk response id is absent from the verified manifest".to_owned(),
                    )
                })?;
            if descriptor.chunk_index != chunk.chunk_index
                || manifest.manifest_digest != chunk.manifest_digest
                || manifest.manifest_admission_digest != chunk.manifest_admission_digest
            {
                return invalid("history chunk does not match its verified manifest descriptor");
            }
            verify_release_attestation(
                accepted,
                source,
                chunk,
                descriptor,
                attestation,
                manifest,
                signer_result,
            )?;
            let seal_context = HistorySecretChunkSealContext {
                purpose: HistorySecretChunkSealPurpose::Value,
                manifest_admission_digest: chunk.manifest_admission_digest.clone(),
                chunk_response_id: source.response_id.clone(),
                chunk_index: chunk.chunk_index,
                source_actor_id: source.source_actor_id.clone(),
                source_sender_domain: source.source_sender_domain.clone(),
            };
            seal_context.validate()?;
            Ok(VerifiedHistoryResponseRecord::Chunk {
                sequence: record.sequence,
                cursor: record.cursor.clone(),
                record_digest: record.record_digest.clone(),
                chunk: Box::new(VerifiedHistoryChunk {
                    response_id: source.response_id.clone(),
                    source_actor_id: source.source_actor_id.clone(),
                    source_sender_domain: source.source_sender_domain.clone(),
                    covered_epoch_range: descriptor.covered_epoch_range,
                    sealed_chunk: chunk.clone(),
                    seal_context,
                }),
            })
        }
        _ => invalid("history response record branch is inconsistent"),
    }
}

/// Verify a source-authored manifest/chunk before release-service admission.
///
/// `source_signer_dependencies` must be the exact root evidence plus its
/// recursively referenced attester closure. Missing, duplicate, ambiguous, or
/// surplus signer evidence fails closed so a service can atomically pin the
/// same verified bytes it used for admission.
pub async fn verify_history_source_proof<VerifyExternalSourceKey>(
    source: &HistoryKeyResponseSendRequestBody,
    verified_checkpoint: &MlsGovernanceVerificationCheckpoint,
    source_signer_dependencies: &[GovernanceDependency],
    verify_external_source_key: VerifyExternalSourceKey,
) -> Result<HistorySourceSignerOutcome, WireError>
where
    VerifyExternalSourceKey: for<'a> Fn(
            HistorySourceProofExternalVerificationRequest<'a>,
        ) -> HistorySourceProofVerificationFuture<'a>
        + Clone,
{
    source.validate()?;
    verified_checkpoint.validate_checkpoint()?;
    arkret_models_collaboration::governance_dependencies::validate_history_source_signer_dependency_closure(
        source,
        source_signer_dependencies,
    )?;
    let source_key = resolve_source_proof_key(
        source,
        verified_checkpoint,
        source_signer_dependencies,
        verify_external_source_key,
    )
    .await?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &source.source_proof,
        &source.proof_binding_bytes()?,
        &source_key,
    )
    .map_err(|error| WireError::Protocol(format!("history source proof is invalid: {error}")))?;
    let root_digest = source.source_signer_evidence_ref.content_digest()?;
    let root = source_signer_dependencies.iter().find(|item| match item {
        GovernanceDependency::AuthenticatedSignerResolutionEvidence { selector:
            arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest }, .. }
        | GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence { selector:
            arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence { content_digest }, .. } => content_digest == &root_digest,
        _ => false,
    }).ok_or_else(|| WireError::Protocol("history source root is absent".to_owned()))?;
    let result = match root {
        GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence: evidence,
            ..
        } => {
            let signer_kind = match evidence.as_ref() {
                AuthenticatedSignerResolutionEvidence::AccountDevice { .. } => {
                    HistorySourceSignerKind::AccountDevice
                }
                AuthenticatedSignerResolutionEvidence::Principal { .. } => {
                    HistorySourceSignerKind::Principal
                }
                AuthenticatedSignerResolutionEvidence::Agent { .. } => {
                    HistorySourceSignerKind::Agent
                }
                _ => return invalid("service evidence cannot authorize a history source"),
            };
            HistorySourceSignerOutcome::Authenticated {
                source_signer_evidence_ref: source.source_signer_evidence_ref.clone(),
                signer_kind,
                signer_id: evidence.signer_id().clone(),
                verification_method: evidence.verification_method().clone(),
                public_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_wire::base64url::base64url_encode(
                        source_key
                            .ed25519_bytes()
                            .map_err(|error| WireError::Protocol(error.to_string()))?,
                    ),
                )
                .map_err(|error| WireError::Protocol(error.to_owned()))?,
            }
        }
        GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
            minimal_metadata_mls_leaf_signer_evidence: evidence,
            ..
        } => {
            let link = evidence.validate_identity_link_binding()?;
            let principal = super::mls_governance::bound_evidence_by_ref(
                source_signer_dependencies,
                &evidence.identity_link_signer_evidence_ref,
                &link.principal_id,
                &link.proof.verification_method,
            )?;
            let key = super::mls_governance::authenticated_document_key(
                principal,
                source_signer_dependencies,
                link.effective_at,
            )?;
            HistorySourceSignerOutcome::ReceiverMls {
                source_signer_evidence_ref: source.source_signer_evidence_ref.clone(),
                signer_evidence: Box::new(evidence.clone()),
                identity_link_public_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_wire::base64url::base64url_encode(
                        key.ed25519_bytes()
                            .map_err(|error| WireError::Protocol(error.to_string()))?,
                    ),
                )
                .map_err(|error| WireError::Protocol(error.to_owned()))?,
            }
        }
        _ => return invalid("history source root is not signer evidence"),
    };
    result.validate_for_source(source)?;
    Ok(result)
}

async fn resolve_source_proof_key<VerifyExternalSourceKey>(
    source: &HistoryKeyResponseSendRequestBody,
    verified_checkpoint: &MlsGovernanceVerificationCheckpoint,
    dependencies: &[GovernanceDependency],
    verify_external_source_key: VerifyExternalSourceKey,
) -> Result<PublicKeyMaterial, WireError>
where
    VerifyExternalSourceKey: for<'a> Fn(
            HistorySourceProofExternalVerificationRequest<'a>,
        ) -> HistorySourceProofVerificationFuture<'a>
        + Clone,
{
    let source_signer_evidence_digest = source.source_signer_evidence_ref.content_digest()?;
    let expected_selector =
        arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: source_signer_evidence_digest.clone(),
        };
    let expected_minimal_selector =
        arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
            content_digest: source_signer_evidence_digest,
        };
    let mut authenticated = None;
    let mut minimal = None;
    for dependency in dependencies {
        match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector,
                authenticated_signer_resolution_evidence,
            } if selector == &expected_selector => {
                if authenticated
                    .replace(authenticated_signer_resolution_evidence)
                    .is_some()
                {
                    return invalid("duplicate source signer-resolution evidence dependency");
                }
            }
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                selector,
                minimal_metadata_mls_leaf_signer_evidence,
            } if selector == &expected_minimal_selector
                && minimal
                    .replace(minimal_metadata_mls_leaf_signer_evidence)
                    .is_some() =>
            {
                return invalid("duplicate minimal-metadata source signer evidence dependency");
            }
            _ => {}
        }
    }
    match (authenticated, minimal) {
        (Some(_), Some(_)) => invalid("source signer evidence digest is ambiguous across kinds"),
        (None, None) => invalid("source signer evidence dependency is missing"),
        (Some(evidence), None) => {
            if evidence.evidence_ref()? != source.source_signer_evidence_ref
                || evidence.signer_id() != source.source_actor_id.signing_principal_id()
                || evidence.verification_method() != &source.source_proof.verification_method
            {
                return invalid("source signer evidence does not bind its actor and method");
            }
            match evidence.as_ref() {
                AuthenticatedSignerResolutionEvidence::Agent { .. } => {
                    let verified = verify_external_source_key(
                        HistorySourceProofExternalVerificationRequest::Agent {
                            source_record: source,
                            signer_evidence: evidence.as_ref(),
                            dependencies,
                        },
                    )
                    .await?;
                    let AuthenticatedSignerResolutionEvidence::Agent {
                        agent_signer_evidence,
                        ..
                    } = evidence.as_ref()
                    else {
                        unreachable!("matched Agent evidence above")
                    };
                    let binding = match agent_signer_evidence.as_ref() {
                        arkret_models_identity::AgentSignerEvidence::CurrentAdmission {
                            admission_evidence,
                            ..
                        }
                        | arkret_models_identity::AgentSignerEvidence::HistoricalEvent {
                            admission_evidence,
                            ..
                        } => {
                            &admission_evidence
                                .agent_authority_state_evidence
                                .state
                                .signing_key_binding
                        }
                    };
                    let expected = arkret_wire::base64url::base64url_decode(
                        binding.public_key.key.as_str().as_bytes(),
                    )?;
                    if verified != (PublicKeyMaterial::Ed25519Raw { bytes: expected }) {
                        return invalid(
                            "Agent source verifier returned a key outside its signed evidence",
                        );
                    }
                    Ok(verified)
                }
                AuthenticatedSignerResolutionEvidence::AccountDevice {
                    device_projection_attestation,
                    attester_signer_evidence_ref,
                    ..
                } => {
                    let core = &device_projection_attestation.attestation;
                    let at = source.source_proof.created_at;
                    if source.source_actor_id.as_account_id() != Some(&core.account_id)
                        || source.source_sender_domain != core.device_id.as_str()
                        || at < core.attested_at
                        || at >= core.expires_at
                    {
                        return invalid(
                            "device history source does not bind the exact account, device and signed validity interval",
                        );
                    }
                    let attester = super::mls_governance::bound_evidence_by_ref(
                        dependencies,
                        attester_signer_evidence_ref,
                        &core.account_id.station_id,
                        &device_projection_attestation.proof.verification_method,
                    )?;
                    if !matches!(
                        attester,
                        AuthenticatedSignerResolutionEvidence::Service { .. }
                    ) {
                        return invalid("device history attester must be its origin Station");
                    }
                    let material = super::mls_governance::authenticated_document_key(
                        attester,
                        dependencies,
                        at,
                    )?;
                    arkret_signatures::device_projection::verify_device_projection_with_key_material(
                        device_projection_attestation, &material, at,
                    )?;
                    let value = core
                        .device_signing_key_did
                        .as_str()
                        .strip_prefix("did:key:")
                        .ok_or_else(|| {
                            WireError::Protocol("device signing key must be did:key".to_owned())
                        })?
                        .to_owned();
                    let key = PublicKeyMaterial::Ed25519Multibase { value };
                    key.ed25519_bytes()
                        .map_err(|error| WireError::Protocol(error.to_string()))?;
                    Ok(key)
                }
                _ => super::mls_governance::authenticated_document_key(
                    evidence,
                    dependencies,
                    source.source_proof.created_at,
                ),
            }
        }
        (None, Some(evidence)) => {
            evidence.validate()?;
            verify_minimal_metadata_identity_link_signature(evidence, dependencies)?;
            if evidence.evidence_ref()? != source.source_signer_evidence_ref
                || evidence.source_actor_id != source.source_actor_id
                || evidence.verification_method != source.source_proof.verification_method
                || evidence.effective_scope != source.effective_scope
                || evidence.mls_group_id != source.effective_scope.canonical_mls_group_id()?
                || evidence.target_basis != verified_checkpoint.basis
            {
                return invalid("minimal-metadata signer evidence does not bind the source record");
            }
            let verified = verify_external_source_key(
                HistorySourceProofExternalVerificationRequest::MinimalMetadata {
                    source_record: source,
                    signer_evidence: evidence,
                    verified_checkpoint,
                },
            )
            .await?;
            let expected = arkret_wire::base64url::base64url_decode(
                evidence
                    .response_signing_public_key_b64u
                    .as_str()
                    .as_bytes(),
            )?;
            if verified != (PublicKeyMaterial::Ed25519Raw { bytes: expected }) {
                return invalid(
                    "minimal-metadata source verifier returned a key outside its signed evidence",
                );
            }
            Ok(verified)
        }
    }
}

/// Verify a signed lost-record descriptor against the request's frozen release
/// service resolution and the exact successor chain effective at `lost_at`.
pub fn verify_history_response_lost_record(
    accepted: &HistoryKeyRequestCreateOutcome,
    lost_record: &HistoryKeyResponseLostRecord,
    signer_dependencies: &[GovernanceDependency],
) -> Result<(), WireError> {
    accepted.validate()?;
    lost_record.validate()?;
    if lost_record.lost_at > accepted.request.expires_at {
        return invalid("history lost record is outside the accepted request lifetime");
    }
    verify_release_service_proof(
        accepted,
        &lost_record.service_proof,
        &lost_record.proof_binding_bytes()?,
        lost_record.lost_at,
        &lost_record.release_service_signer_evidence_ref,
        signer_dependencies,
    )
}

fn verify_release_service_proof(
    accepted: &HistoryKeyRequestCreateOutcome,
    proof: &arkret_wire::PayloadProof,
    binding_bytes: &[u8],
    signed_at: DateTime<Utc>,
    evidence_ref: &arkret_wire::SignerEvidenceRef,
    dependencies: &[GovernanceDependency],
) -> Result<(), WireError> {
    let receipt = &accepted.request_receipt;
    if proof.created_at > signed_at {
        return invalid("history release service proof method or timestamp mismatch");
    }
    let evidence = super::mls_governance::bound_evidence_by_ref(
        dependencies,
        evidence_ref,
        &receipt.release_id,
        &proof.verification_method,
    )?;
    if !matches!(
        evidence,
        AuthenticatedSignerResolutionEvidence::Service { .. }
    ) {
        return invalid("history release-service signer evidence is not service-kind");
    }
    let key = super::mls_governance::authenticated_document_key(
        evidence,
        dependencies,
        proof.created_at,
    )?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(proof, binding_bytes, &key)
        .map_err(|error| {
            WireError::Protocol(format!("history release service proof is invalid: {error}"))
        })
}

fn member_history_intent(
    accepted: &HistoryKeyRequestCreateOutcome,
) -> Result<&HistoryGovernanceTraversalIntent, WireError> {
    let retention = &accepted.request_receipt.history_traversal_retention;
    retention.validate_digest()?;
    let intent = &retention.traversal_intent;
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        effective_scope,
        mls_group_id,
        request_digest,
        requested_ranges,
        authorization_incarnation,
        retention: intent_retention,
        ..
    } = intent
    else {
        return invalid("history response request used a non-member traversal intent");
    };
    let request = &accepted.request;
    if effective_scope != &request.effective_scope
        || mls_group_id != &request.effective_scope.canonical_mls_group_id()?
        || request_digest != &request.request_digest()?
        || requested_ranges != &request.requested_ranges
        || authorization_incarnation != &request.requester_authorization_incarnation
        || intent_retention.expires_at != request.expires_at
    {
        return invalid("history traversal intent does not bind the accepted request");
    }
    Ok(intent)
}

fn verify_manifest(
    accepted: &HistoryKeyRequestCreateOutcome,
    source: &HistoryKeyResponseSendRequestBody,
    manifest: &HistoryResponseManifest,
    admission: &HistoryManifestAdmission,
    intent: &HistoryGovernanceTraversalIntent,
) -> Result<(), WireError> {
    let digest = source.manifest_digest()?;
    if admission.manifest_digest != digest
        || admission.request_digest != source.request_digest
        || admission.request_receipt_digest != source.request_receipt_digest
        || admission.traversal_intent_digest != intent.canonical_digest()?
        || admission.authorized_ranges != accepted.request.requested_ranges
    {
        return invalid("history manifest admission does not bind the request and traversal");
    }
    let mut response_ids = BTreeSet::new();
    for descriptor in &manifest.chunks {
        if !response_ids.insert(descriptor.chunk_response_id.clone())
            || !range_is_authorized(
                &descriptor.covered_epoch_range,
                &accepted.request.requested_ranges,
            )
        {
            return invalid("history manifest descriptors are duplicate or unauthorized");
        }
    }
    Ok(())
}

fn verify_release_attestation(
    accepted: &HistoryKeyRequestCreateOutcome,
    source: &HistoryKeyResponseSendRequestBody,
    chunk: &SealedHistoryChunk,
    descriptor: &HistoryResponseChunkDescriptor,
    attestation: &arkret_models_collaboration::history_key::HistoryReleaseAttestation,
    manifest: &VerifiedHistoryManifest,
    signer_result: &HistorySourceSignerOutcome,
) -> Result<(), WireError> {
    let source_digest = source.source_record_digest()?;
    let request = &accepted.request;
    let receipt = &accepted.request_receipt;
    if attestation.source_record_digest != source_digest
        || attestation.response_id != source.response_id
        || attestation.request_digest != source.request_digest
        || attestation.request_receipt_digest != source.request_receipt_digest
        || attestation.effective_scope != source.effective_scope
        || attestation.manifest_admission_digest != chunk.manifest_admission_digest
        || attestation.released_range != descriptor.covered_epoch_range
        || attestation.recipient_actor_id != request.requester_actor_id
        || attestation.recipient_sender_domain != request.requester_sender_domain
        || attestation.recipient_authorization_incarnation
            != request.requester_authorization_incarnation
        || attestation.recipient_author_profile != request.requester_author_profile
        || attestation.source_actor_id != source.source_actor_id
        || attestation.source_sender_domain != source.source_sender_domain
        || attestation.expires_at != source.expires_at
        || attestation.accepted_at > attestation.expires_at
        || manifest.source_actor_id != source.source_actor_id
        || manifest.source_sender_domain != source.source_sender_domain
        || manifest.manifest_digest != chunk.manifest_digest
        || receipt.expires_at != attestation.expires_at
    {
        return invalid("history release attestation does not bind the exact request and chunk");
    }
    let evidence_kind = match signer_result {
        HistorySourceSignerOutcome::Authenticated { signer_kind, .. } => match signer_kind {
            HistorySourceSignerKind::Principal => SourceEvidenceKind::Principal,
            HistorySourceSignerKind::AccountDevice => SourceEvidenceKind::AccountDevice,
            HistorySourceSignerKind::Agent => SourceEvidenceKind::Agent,
        },
        HistorySourceSignerOutcome::ReceiverMls { .. } => SourceEvidenceKind::MinimalMetadata,
    };
    let profile_matches = matches!(
        (attestation.source_author_profile, evidence_kind),
        (
            Some(AuthorProfile::OrdinaryHuman),
            SourceEvidenceKind::Principal
        ) | (
            Some(AuthorProfile::OrdinaryHuman),
            SourceEvidenceKind::AccountDevice
        ) | (Some(AuthorProfile::Agent), SourceEvidenceKind::Agent)
            | (
                Some(AuthorProfile::MinimalMetadata),
                SourceEvidenceKind::MinimalMetadata
            )
            | (None, SourceEvidenceKind::Principal)
    );
    if !profile_matches {
        return invalid("history release source profile does not match signer evidence kind");
    }
    if evidence_kind == SourceEvidenceKind::MinimalMetadata {
        let minimal = match signer_result {
            HistorySourceSignerOutcome::ReceiverMls {
                signer_evidence, ..
            } => Some(signer_evidence),
            _ => None,
        };
        if attestation.source_authorization_incarnation
            != minimal.map(|evidence| evidence.authorization_incarnation.clone())
        {
            return invalid(
                "history release source authorization incarnation does not match minimal-metadata evidence",
            );
        }
    }
    let scope_realm_id = match &source.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    if &attestation
        .accepted_authority_views
        .scope_realm
        .authority_realm_id
        != scope_realm_id
        || attestation.accepted_authority_views.source_relay.expires_at != attestation.expires_at
        || attestation
            .accepted_authority_views
            .source_relay
            .observed_at
            > attestation.accepted_authority_views.source_relay.expires_at
    {
        return invalid("history release authority-view vector is inconsistent");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceEvidenceKind {
    Principal,
    AccountDevice,
    Agent,
    MinimalMetadata,
}

fn range_is_authorized(candidate: &EpochRange, authorized: &[EpochRange]) -> bool {
    authorized.iter().any(|range| {
        range.from_epoch <= candidate.from_epoch && candidate.to_epoch <= range.to_epoch
    })
}

/// Read the effective scope's own winning history policy from verified replay.
/// A Circle never inherits its parent Realm's history policy.
pub async fn history_access_from_verified_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    scope: &HistoryEffectiveScope,
) -> Result<arkret_wire::HistoryAccess, WireError> {
    checkpoint.validate_checkpoint()?;
    let (realm_id, cell) = match scope {
        HistoryEffectiveScope::Realm { realm_id } => (
            realm_id,
            arkret_wire::cell::null_subject_cell(
                arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1,
            ),
        ),
        HistoryEffectiveScope::Circle {
            realm_id,
            circle_id,
        } => (
            realm_id,
            arkret_wire::subject_cell(
                arkret_wire::CellFamilyId::CIRCLE_HISTORY_ACCESS_V1,
                circle_id.as_str(),
            ),
        ),
    };
    if &checkpoint.realm_id != realm_id {
        return invalid("history policy checkpoint belongs to another Realm");
    }
    let cell = arkret_wire::CellRef::new(cell)?;
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&checkpoint.accepted_events);
    let value = arkret_state::mls_governance_proof::materialize_registered_cell_value_from_verified_checkpoint(
        checkpoint, &cell, &registry,
        |event, digest_suite| arkret_schema::project_registered_cell_writes_with_authority_resolver(
            event, digest_suite, &|grant_id| audits.resolve(grant_id),
        ).map_err(|error| error.to_string()),
    ).await?;
    serde_json::from_value(value)
        .map_err(|error| WireError::Protocol(format!("winning history policy is invalid: {error}")))
}

/// Resolve the pinned suite after checking the complete winning lineage.
pub async fn winning_history_cipher_suite_from_verified_checkpoint(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    effective_scope: &HistoryEffectiveScope,
    mls_group_id: &str,
    requested_ranges: &[EpochRange],
) -> Result<String, WireError> {
    checkpoint.validate_checkpoint()?;
    arkret_models_collaboration::history_key::validate_canonical_ranges(requested_ranges, 64)?;
    if effective_scope.canonical_mls_group_id()? != mls_group_id {
        return invalid("history suite query group id is not canonical for its scope");
    }
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry().map_err(|error| {
        WireError::Protocol(format!("MLS history registry construction failed: {error}"))
    })?;
    let cell = arkret_state::mls_cells::mls_epoch_cell_id(
        &ScopeRef::from(effective_scope.clone()),
        mls_group_id,
    )?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&checkpoint.accepted_events);
    let target = arkret_state::mls_governance_proof::materialize_registered_cell_value_from_verified_checkpoint(
        checkpoint,
        &cell,
        &registry,
        |event, digest_suite| {
            arkret_schema::project_registered_cell_writes_with_authority_resolver(
                event,
                digest_suite,
                &|grant_id| authority_audits.resolve(grant_id),
            )
            .map_err(|error| error.to_string())
        },
    )
    .await?;
    let target_ref = target
        .get("transition_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            WireError::Protocol("winning MLS epoch cell lacks transition_ref".to_owned())
        })?;
    if target
        .get("mls_group_id")
        .and_then(serde_json::Value::as_str)
        != Some(mls_group_id)
        || target
            .get("content_scheme")
            .and_then(serde_json::Value::as_str)
            != Some("mls_exporter_aead_v1")
    {
        return invalid("winning MLS epoch cell does not bind the history group and scheme");
    }
    let mut events = checkpoint
        .accepted_events
        .iter()
        .map(|event| (event.event_id.clone(), event))
        .collect::<BTreeMap<_, _>>();
    if events.len() != checkpoint.accepted_events.len() {
        return invalid("verified checkpoint repeats an Event id");
    }
    let mut winning_commits = BTreeMap::<u64, MlsCommitPayload>::new();
    let mut winning_ids = BTreeSet::new();
    let mut current = EventId::new(target_ref.to_owned())?;
    let genesis = loop {
        if !winning_ids.insert(current.clone()) {
            return invalid("winning MLS transition lineage contains a cycle");
        }
        let event = events.remove(&current).ok_or_else(|| {
            WireError::Protocol(
                "winning MLS transition is absent from the verified closure".to_owned(),
            )
        })?;
        match event.kind.as_str() {
            arkret_wire::event_kind_str::MLS_COMMIT => {
                let payload: MlsCommitPayload = serde_json::from_value(
                    serde_json::to_value(&event.payload)
                        .map_err(|error| WireError::Protocol(error.to_string()))?,
                )
                .map_err(|error| {
                    WireError::Protocol(format!("invalid winning MLS Commit: {error}"))
                })?;
                if payload.mls_group_id() != mls_group_id
                    || !scope_matches(
                        effective_scope,
                        payload.governance_binding().effective_scope(),
                    )
                    || payload.governance_binding().content_scheme()
                        != ContentScheme::MlsExporterAeadV1
                {
                    return invalid("winning MLS Commit crosses group, scope, or content scheme");
                }
                let next_epoch = payload.next_epoch();
                current = EventId::new(payload.base_epoch_ref().to_owned())?;
                if winning_commits.insert(next_epoch, payload).is_some() {
                    return invalid("winning MLS transition lineage repeats an epoch");
                }
            }
            arkret_wire::event_kind_str::MLS_GENESIS => {
                let payload: MlsGenesisPayload = serde_json::from_value(
                    serde_json::to_value(&event.payload)
                        .map_err(|error| WireError::Protocol(error.to_string()))?,
                )
                .map_err(|error| {
                    WireError::Protocol(format!("invalid winning MLS Genesis: {error}"))
                })?;
                payload.validate()?;
                if payload.mls_group_id.as_str() != mls_group_id
                    || !scope_matches(effective_scope, &payload.effective_scope)
                {
                    return invalid("winning MLS Genesis crosses group or scope");
                }
                break payload;
            }
            _ => return invalid("winning MLS transition_ref names a non-transition Event"),
        }
    };
    if genesis.governance_binding.content_scheme() != ContentScheme::MlsExporterAeadV1 {
        return invalid("history secret ranges require mls_exporter_aead_v1");
    }
    let cipher_suite = genesis.cipher_suite.as_str().to_owned();
    registered_mls_ciphersuite_kdf_nh(&cipher_suite)?;
    let maximum_epoch = requested_ranges
        .last()
        .expect("canonical non-empty ranges validated above")
        .to_epoch;
    for epoch in 1..=maximum_epoch {
        let commit = winning_commits.get(&epoch).ok_or_else(|| {
            WireError::Protocol(format!(
                "verified MLS history has no winning transition for epoch {epoch}"
            ))
        })?;
        if commit.base_epoch() + 1 != epoch {
            return invalid("verified MLS winning transition chain is discontinuous");
        }
    }
    Ok(cipher_suite)
}

/// Resolve `KDF.Nh` for one exact MLS ciphersuite identifier registered by the
/// embedded v1 protocol artifacts.
///
/// Callers must still obtain `cipher_suite` from a verified winning transition;
/// this helper only maps that authoritative suite to its RFC 9420 hash width.
/// Unknown identifiers and registered rows without a supported mapping fail
/// closed rather than defaulting to SHA-256.
pub fn registered_mls_ciphersuite_kdf_nh(cipher_suite: &str) -> Result<u16, WireError> {
    if !arkret_wire::MLS_CIPHERSUITES
        .iter()
        .any(|row| row.canonical_id == cipher_suite)
    {
        return invalid("MLS history cipher suite is not registered");
    }
    match cipher_suite {
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        | "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
        | "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519" => Ok(32),
        "MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44" => Ok(48),
        _ => invalid("registered MLS cipher suite has no history KDF.Nh mapping"),
    }
}

fn scope_matches(history: &HistoryEffectiveScope, scope: &ScopeRef) -> bool {
    match (history, scope) {
        (HistoryEffectiveScope::Realm { realm_id: left }, ScopeRef::Realm { realm_id: right }) => {
            left == right
        }
        (
            HistoryEffectiveScope::Circle {
                realm_id: left_realm,
                circle_id: left_circle,
            },
            ScopeRef::Circle {
                realm_id: right_realm,
                circle_id: right_circle,
            },
        ) => left_realm == right_realm && left_circle == right_circle,
        _ => false,
    }
}

fn invalid<T>(message: &str) -> Result<T, WireError> {
    Err(WireError::Protocol(message.to_owned()))
}

#[cfg(test)]
mod mls_ciphersuite_kdf_nh_tests {
    use super::registered_mls_ciphersuite_kdf_nh;

    #[test]
    fn every_registered_suite_has_its_exact_hash_width() {
        let expected = [
            ("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", 32_u16),
            ("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519", 32),
            ("MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519", 32),
            ("MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44", 48),
        ];
        assert_eq!(arkret_wire::MLS_CIPHERSUITES.len(), expected.len());
        for (suite, kdf_nh) in expected {
            assert!(
                arkret_wire::MLS_CIPHERSUITES
                    .iter()
                    .any(|row| row.canonical_id == suite)
            );
            assert_eq!(registered_mls_ciphersuite_kdf_nh(suite).unwrap(), kdf_nh);
        }
        assert!(registered_mls_ciphersuite_kdf_nh("MLS_000_UNKNOWN").is_err());
    }
}
