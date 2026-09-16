//! Complete method-native verification for retained service signer evidence.

use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument,
    PublicPrincipalResolution, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionDidBindingMethodProofKind, ResolutionDidBindingWitness,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence, ServiceMethodState,
    ServiceResolutionProjection,
};
use arkret_wire::{Did, DidCoreId, Hash, WireError, project_did_to_core_id};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    DidKeyResolver, DidResolver as _, IdentityError, Result, parse_did_webvh_witness_policy,
    verify_did_webvh_v1_chain_and_witness_bytes,
};

/// Build and verify the complete retained WebVH resolution closure served by
/// the open service-resolution operation.
pub fn build_authenticated_webvh_service_resolution(
    service_id: DidCoreId,
    service_kind: String,
    normalized_did_document: DidDocument,
    log_entries: Vec<Value>,
    witness_records: Vec<Value>,
    now: DateTime<Utc>,
) -> Result<AuthenticatedServiceResolution> {
    if normalized_did_document.id.method() != "webvh" {
        return Err(IdentityError::Protocol(
            "WebVH service resolution builder received a different DID method or document"
                .to_owned(),
        ));
    }
    let first_version = version_id(log_entries.first().ok_or_else(|| {
        IdentityError::Protocol("WebVH signer evidence has no log entries".to_owned())
    })?)?;
    let last_version = version_id(
        log_entries
            .last()
            .expect("non-empty WebVH log checked above"),
    )?;
    let first_history_head = history_head(
        log_entries
            .first()
            .expect("non-empty WebVH log checked above"),
    )?;
    let last_history_head = history_head(
        log_entries
            .last()
            .expect("non-empty WebVH log checked above"),
    )?;
    let witnesses = terminal_witnesses(&log_entries)?;
    let witness_proofs_digest = Hash::new(arkret_canonical::canonical_sha256(&witness_records)?)
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let document_digest = crate::document_canonical_digest(&normalized_did_document)
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let resolution = AuthenticatedServiceResolution {
        service_id,
        service_kind,
        method_history_evidence: ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: first_history_head,
                from_version_id: first_version,
                to_method_history_head: last_history_head.clone(),
                to_version_id: last_version,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: last_history_head,
                    witnesses,
                    witness_proofs_digest,
                }],
            },
            log_entries,
            witness_records,
        },
        normalized_did_document,
    };
    let expected_service_id = resolution.service_id.clone();
    verify_authenticated_service_resolution_history(&resolution, &expected_service_id, now)?;
    Ok(resolution)
}

/// Build current no-history evidence from a DID document independently verified by the adapter.
pub fn build_authenticated_did_web_service_resolution(
    service_id: DidCoreId,
    service_kind: String,
    normalized_did_document: DidDocument,
    now: DateTime<Utc>,
) -> Result<AuthenticatedServiceResolution> {
    if normalized_did_document.id.method() != "web" {
        return Err(IdentityError::Protocol(
            "did:web service resolution requires a did:web document".to_owned(),
        ));
    }
    let digest = arkret_models_identity::normalized_did_document_digest(&normalized_did_document)
        .map_err(wire)?;
    let version = format!(
        "synthetic-jcs-sha256:{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let resolution = AuthenticatedServiceResolution {
        service_id,
        service_kind,
        method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: digest.to_string(),
                from_version_id: version.clone(),
                to_method_history_head: digest.to_string(),
                to_version_id: version,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".to_owned(),
                document_digest: digest,
                method_proofs: Vec::new(),
            },
        },
        normalized_did_document,
    };
    resolution
        .validate_shape(&resolution.service_id, now)
        .map_err(wire)?;
    Ok(resolution)
}

/// Verify a retained service resolution without consulting a current DID
/// resolver. WebVH consumes the complete retained log and witness records;
/// did:key is reconstructed from the identifier; mutable did:web is rejected.
pub fn verify_authenticated_service_resolution_history(
    resolution: &AuthenticatedServiceResolution,
    expected_service_id: &DidCoreId,
    now: DateTime<Utc>,
) -> Result<()> {
    resolution
        .validate_shape(expected_service_id, now)
        .map_err(wire)?;
    let did = &resolution.normalized_did_document.id;
    let coordinates = resolution.method_history_evidence.boundary();
    match &resolution.method_history_evidence {
        ResolutionMethodHistoryEvidence::WebvhLog {
            boundary,
            evidence,
            log_entries,
            witness_records,
            ..
        } => verify_webvh_history(
            did,
            &resolution.normalized_did_document,
            boundary,
            evidence,
            log_entries,
            witness_records,
            &coordinates.to_method_history_head,
            &coordinates.to_version_id,
        )?,
        ResolutionMethodHistoryEvidence::DidKeyExpansion { boundary, .. } => {
            let expected_head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
            let expected_version = format!(
                "synthetic-did-sha256:{}",
                expected_head.trim_start_matches("sha256:")
            );
            if did.method() != "key"
                || boundary.from_method_history_head != boundary.to_method_history_head
                || boundary.from_version_id != boundary.to_version_id
                || boundary.to_method_history_head != expected_head
                || boundary.to_version_id != expected_version
            {
                return Err(IdentityError::Protocol(
                    "did:key service resolution boundary mismatch".to_owned(),
                ));
            }
            let expected = DidKeyResolver::new().resolve_did(did)?.document;
            require_same_document(&expected, &resolution.normalized_did_document)?;
        }
        ResolutionMethodHistoryEvidence::DidWebDocument { .. } => {
            return Err(IdentityError::Protocol(
                "mutable did:web cannot be retained as historical service signer evidence"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

/// Verify the complete public principal-resolution closure and return the
/// accepted projection.
///
/// The Station resolution authenticates the projection attester. The
/// separately resolved principal document and the response's method-history
/// evidence authenticate the projected DID and its exact method head.
/// Callers must not persist `resolution_projection` before this function
/// succeeds.
pub fn verify_public_principal_resolution_history(
    resolution: &PublicPrincipalResolution,
    station_resolution: &AuthenticatedServiceResolution,
    principal_document: &DidDocument,
    now: DateTime<Utc>,
) -> Result<arkret_models_identity::PrincipalResolutionProjection> {
    verify_authenticated_service_resolution_history(
        station_resolution,
        &resolution.account_id.station_id,
        now,
    )?;
    let station_document = authenticated_service_document_at(
        station_resolution,
        &resolution.account_id.station_id,
        resolution.projection_attestation.attestation.issued_at,
    )?;
    arkret_signatures::service_resolution::verify_public_principal_resolution(
        resolution,
        &station_document,
        now,
    )
    .map_err(wire)?;

    let projection = &resolution.resolution_projection;
    if project_did_to_core_id(&projection.did)
        .map_err(|error| WireError::Protocol(error.to_string()))?
        != resolution.account_id.principal_id
        || principal_document.id != projection.did
        || projection.updated_at > resolution.projection_attestation.attestation.issued_at
    {
        return Err(WireError::Protocol(
            "principal resolution projection does not bind its identity document".to_owned(),
        )
        .into());
    }
    let evidence = &resolution.method_history_evidence;
    evidence.validate_shape().map_err(wire)?;
    let boundary = evidence.boundary();
    if boundary.from_method_history_head != projection.method_history_head
        || boundary.to_method_history_head != projection.method_history_head
        || boundary.from_version_id != projection.version_id
        || boundary.to_version_id != projection.version_id
    {
        return Err(WireError::Protocol(
            "principal resolution method-history boundary differs from the projection".to_owned(),
        )
        .into());
    }
    let document_digest = crate::document_canonical_digest(principal_document)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    if evidence.evidence().document_digest != document_digest {
        return Err(WireError::Protocol(
            "principal resolution evidence binds a different DID document".to_owned(),
        )
        .into());
    }

    match evidence {
        ResolutionMethodHistoryEvidence::WebvhLog {
            evidence,
            log_entries,
            witness_records,
            ..
        } => {
            let first = log_entries.first().ok_or_else(|| {
                WireError::Protocol("principal WebVH resolution has no log entries".to_owned())
            })?;
            let complete_boundary = ResolutionMethodEvidenceBoundary {
                from_method_history_head: history_head(first)?,
                from_version_id: version_id(first)?,
                to_method_history_head: projection.method_history_head.clone(),
                to_version_id: projection.version_id.clone(),
            };
            verify_webvh_history(
                &projection.did,
                principal_document,
                &complete_boundary,
                evidence,
                log_entries,
                witness_records,
                &projection.method_history_head,
                &projection.version_id,
            )?;
        }
        ResolutionMethodHistoryEvidence::DidKeyExpansion { .. } => {
            if projection.did.method() != "key" {
                return Err(WireError::Protocol(
                    "did:key evidence was supplied for another DID method".to_owned(),
                )
                .into());
            }
            let expected = DidKeyResolver::new().resolve_did(&projection.did)?.document;
            require_same_document(&expected, principal_document)?;
            verify_synthetic_projection_coordinates(
                projection,
                &Hash::new(arkret_canonical::sha256_digest(
                    projection.did.as_str().as_bytes(),
                ))
                .map_err(|error| WireError::Protocol(error.to_string()))?,
                "synthetic-did-sha256:",
            )?;
        }
        ResolutionMethodHistoryEvidence::DidWebDocument { .. } => {
            if projection.did.method() != "web" {
                return Err(WireError::Protocol(
                    "did:web evidence was supplied for another DID method".to_owned(),
                )
                .into());
            }
            verify_synthetic_projection_coordinates(
                projection,
                &document_digest,
                "synthetic-jcs-sha256:",
            )?;
        }
    }
    Ok(projection.clone())
}

/// Verify a public principal resolution whose method evidence is sufficient to
/// reconstruct the current document without another network lookup.
///
/// `did:webvh` carries its complete log and `did:key` is self-certifying.
/// Mutable `did:web` deliberately requires the caller to obtain the current
/// document independently and use [`verify_public_principal_resolution_history`].
pub fn verify_embedded_public_principal_resolution_history(
    resolution: &PublicPrincipalResolution,
    station_resolution: &AuthenticatedServiceResolution,
    now: DateTime<Utc>,
) -> Result<(
    arkret_models_identity::PrincipalResolutionProjection,
    DidDocument,
)> {
    let projection = &resolution.resolution_projection;
    let document = match &resolution.method_history_evidence {
        ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries,
            witness_records,
            ..
        } => {
            let log_bytes = json_lines(log_entries)?;
            let witness_bytes = arkret_canonical::canonical_json_bytes(witness_records)
                .map_err(|error| WireError::Protocol(error.to_string()))?;
            let verified = verify_did_webvh_v1_chain_and_witness_bytes(
                &projection.did,
                &log_bytes,
                (!witness_records.is_empty()).then_some(witness_bytes.as_slice()),
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            serde_json::from_value(verified.log.head_state).map_err(|error| {
                WireError::Protocol(format!("invalid principal WebVH head document: {error}"))
            })?
        }
        ResolutionMethodHistoryEvidence::DidKeyExpansion { .. } => {
            DidKeyResolver::new().resolve_did(&projection.did)?.document
        }
        ResolutionMethodHistoryEvidence::DidWebDocument { .. } => {
            return Err(WireError::Protocol(
                "did:web public resolution requires an independently fetched current document"
                    .to_owned(),
            )
            .into());
        }
    };
    let projection =
        verify_public_principal_resolution_history(resolution, station_resolution, &document, now)?;
    Ok((projection, document))
}

fn verify_synthetic_projection_coordinates(
    projection: &arkret_models_identity::PrincipalResolutionProjection,
    digest: &Hash,
    version_prefix: &str,
) -> Result<()> {
    let digest_hex = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        WireError::Protocol("principal resolution digest omits its suite prefix".to_owned())
    })?;
    if projection.method_history_head != digest.as_str()
        || projection.version_id != format!("{version_prefix}{digest_hex}")
    {
        return Err(WireError::Protocol(
            "principal resolution synthetic coordinates do not match the DID method evidence"
                .to_owned(),
        )
        .into());
    }
    Ok(())
}

/// Verify the retained carrier and return the DID document that was effective
/// at `at`. WebVH selection is performed from the complete retained log; it
/// never falls back to the carrier's current head document.
pub fn authenticated_service_document_at(
    resolution: &AuthenticatedServiceResolution,
    expected_service_id: &DidCoreId,
    at: DateTime<Utc>,
) -> Result<DidDocument> {
    verify_authenticated_service_resolution_history(resolution, expected_service_id, at)?;
    let did = &resolution.normalized_did_document.id;
    match &resolution.method_history_evidence {
        ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } => {
            let point = arkret_signatures::webvh::validate_webvh_history_at(did, log_entries, at)
                .map_err(|error| IdentityError::Protocol(error.to_string()))?;
            serde_json::from_value(point.document).map_err(|error| {
                IdentityError::Protocol(format!("invalid historical WebVH document: {error}"))
            })
        }
        ResolutionMethodHistoryEvidence::DidKeyExpansion { .. } => {
            Ok(resolution.normalized_did_document.clone())
        }
        ResolutionMethodHistoryEvidence::DidWebDocument { .. } => Err(IdentityError::Protocol(
            "mutable did:web cannot be used for historical service key selection".to_owned(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_webvh_history(
    did: &Did,
    document: &DidDocument,
    boundary: &ResolutionMethodEvidenceBoundary,
    evidence: &ResolutionDidBindingEvidenceReceipt,
    log_entries: &[Value],
    witness_records: &[Value],
    expected_history_head: &str,
    expected_version_id: &str,
) -> Result<()> {
    if did.method() != "webvh"
        || log_entries.is_empty()
        || log_entries.len() > 4_096
        || witness_records.len() > 4_096
    {
        return Err(IdentityError::Protocol(
            "WebVH signer evidence omits a complete history".to_owned(),
        ));
    }
    let log_bytes = json_lines(log_entries)?;
    let witness_bytes = arkret_canonical::canonical_json_bytes(&witness_records)
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let verified = verify_did_webvh_v1_chain_and_witness_bytes(
        did,
        &log_bytes,
        (!witness_records.is_empty()).then_some(witness_bytes.as_slice()),
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let mut supplied_witness_versions = witness_records
        .iter()
        .map(version_id)
        .collect::<Result<Vec<_>>>()?;
    supplied_witness_versions.sort();
    if supplied_witness_versions
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(IdentityError::Protocol(
            "WebVH signer evidence repeats a witness record version".to_owned(),
        ));
    }
    let mut required_witness_versions = verified
        .witness_sets
        .iter()
        .map(|set| set.version_id.clone())
        .collect::<Vec<_>>();
    required_witness_versions.sort();
    if supplied_witness_versions != required_witness_versions {
        return Err(IdentityError::Protocol(
            "WebVH signer evidence has missing or surplus witness records".to_owned(),
        ));
    }
    let first_version = version_id(&log_entries[0])?;
    let first_history_head = history_head(&log_entries[0])?;
    let last_version = verified.log.head_version_id.as_str();
    let last_history_head = history_head(
        log_entries
            .last()
            .expect("non-empty WebVH log checked above"),
    )?;
    let method_proof = evidence.method_proofs.first().ok_or_else(|| {
        IdentityError::Protocol("WebVH signer evidence omits its method proof".to_owned())
    })?;
    let expected_witnesses = terminal_witnesses(log_entries)?;
    let witness_digest = Hash::new(arkret_canonical::canonical_sha256(&witness_records)?)
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    if boundary.from_method_history_head != first_history_head
        || boundary.from_version_id != first_version
        || boundary.to_method_history_head != last_history_head
        || boundary.to_version_id != last_version
        || expected_history_head != last_history_head
        || expected_version_id != last_version
        || evidence.method != "webvh"
        || method_proof.kind != ResolutionDidBindingMethodProofKind::WebvhLog
        || method_proof.history_head != last_history_head
        || method_proof.witnesses != expected_witnesses
        || method_proof.witness_proofs_digest != witness_digest
    {
        return Err(IdentityError::Protocol(
            "WebVH signer evidence boundary or head mismatch".to_owned(),
        ));
    }
    let head_document: DidDocument =
        serde_json::from_value(verified.log.head_state).map_err(|error| {
            IdentityError::Protocol(format!("invalid WebVH head document: {error}"))
        })?;
    require_same_document(&head_document, document)
}

fn terminal_witnesses(log_entries: &[Value]) -> Result<Vec<ResolutionDidBindingWitness>> {
    let mut policy = None;
    for entry in log_entries {
        let parameters = entry.get("parameters").ok_or_else(|| {
            IdentityError::Protocol("WebVH log entry omits parameters".to_owned())
        })?;
        if let Some(next) = parse_did_webvh_witness_policy(parameters)
            .map_err(|error| IdentityError::Protocol(error.to_string()))?
        {
            policy = Some(next);
        }
    }
    let mut witnesses = policy
        .map(|policy| policy.witnesses)
        .unwrap_or_default()
        .into_iter()
        .map(|id| {
            let witness_did =
                Did::new(id).map_err(|error| IdentityError::Protocol(error.to_string()))?;
            Ok(ResolutionDidBindingWitness {
                controlling_organization_did: witness_did.clone(),
                witness_did,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    witnesses.sort_by(|left, right| left.witness_did.as_str().cmp(right.witness_did.as_str()));
    Ok(witnesses)
}

fn json_lines(entries: &[Value]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(
            arkret_canonical::canonical_json_bytes(entry)
                .map_err(|error| IdentityError::Protocol(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn version_id(entry: &Value) -> Result<String> {
    entry
        .get("versionId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| IdentityError::Protocol("WebVH log entry omits versionId".to_owned()))
}

fn history_head(entry: &Value) -> Result<String> {
    Hash::new(arkret_canonical::canonical_sha256(entry)?)
        .map(|digest| digest.as_ref().to_owned())
        .map_err(|error| IdentityError::Protocol(error.to_string()))
}

fn require_same_document(expected: &DidDocument, actual: &DidDocument) -> Result<()> {
    let expected = arkret_canonical::canonical_json_bytes(
        &arkret_models_identity::normalized_did_document(expected).map_err(wire)?,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let actual = arkret_canonical::canonical_json_bytes(
        &arkret_models_identity::normalized_did_document(actual).map_err(wire)?,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    if expected != actual {
        return Err(IdentityError::Protocol(
            "retained normalized DID document does not match method-native history".to_owned(),
        ));
    }
    Ok(())
}

fn wire(error: WireError) -> IdentityError {
    IdentityError::Protocol(error.to_string())
}

/// Verify route authority against an independently fetched current method state.
/// The caller must apply its method adapter trust policy to `current`.
pub fn verify_current_service_resolution(
    resolution: &AuthenticatedServiceResolution,
    expected_service_id: &DidCoreId,
    expected_kind: &str,
    current: &crate::ResolvedDid,
    now: DateTime<Utc>,
) -> Result<ServiceResolutionProjection> {
    resolution
        .validate_shape(expected_service_id, now)
        .map_err(wire)?;
    if resolution.service_kind != expected_kind {
        return Err(IdentityError::Protocol("service kind mismatch".to_owned()));
    }
    let current_document = &current.document;
    require_same_document(current_document, &resolution.normalized_did_document)?;
    if current_document.id.method() == "web" {
        if !matches!(
            resolution.method_history_evidence,
            ResolutionMethodHistoryEvidence::DidWebDocument { .. }
        ) {
            return Err(IdentityError::Protocol(
                "did:web requires current document evidence".to_owned(),
            ));
        }
    } else {
        let boundary = resolution.method_history_evidence.boundary();
        if current_document.id.method() != "webvh"
            || current.method_evidence.version_id.as_deref()
                != Some(boundary.to_version_id.as_str())
            || current.method_evidence.history_head.as_deref()
                != Some(boundary.to_version_id.as_str())
            || current.method_evidence.proofs.len() != 1
            || !current
                .method_evidence
                .proofs
                .iter()
                .all(|proof| match proof {
                    crate::MethodEvidenceProof::WebvhLog(proof) => {
                        proof.history_head == boundary.to_version_id
                    }
                })
        {
            return Err(IdentityError::Protocol(
                "service native history is not the independently resolved current state".to_owned(),
            ));
        }
        verify_authenticated_service_resolution_history(resolution, expected_service_id, now)?;
    }
    resolution.projection().map_err(wire)
}
/// Require an accepted native state to occur in the fully verified incoming history.
pub fn verify_service_resolution_floor(
    resolution: &AuthenticatedServiceResolution,
    floor: &ServiceMethodState,
) -> Result<()> {
    if resolution.service_id != floor.service_id || resolution.service_kind != floor.service_kind {
        return Err(IdentityError::Protocol(
            "service method state identity mismatch".to_owned(),
        ));
    }
    match &resolution.method_history_evidence {
        ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } => {
            verify_authenticated_service_resolution_history(
                resolution,
                &floor.service_id,
                floor.verified_at,
            )?;
            for entry in log_entries {
                if version_id(entry)? == floor.version_id
                    && history_head(entry)? == floor.method_history_head
                    && entry
                        .get("state")
                        .and_then(|state| state.get("id"))
                        .and_then(Value::as_str)
                        == Some(floor.did.as_str())
                {
                    return Ok(());
                }
            }
            Err(IdentityError::Protocol(
                "service method state rollback or fork".to_owned(),
            ))
        }
        ResolutionMethodHistoryEvidence::DidWebDocument { .. }
            if resolution.normalized_did_document.id == floor.did =>
        {
            Ok(())
        }
        _ => Err(IdentityError::Protocol(
            "unsupported service method state transition".to_owned(),
        )),
    }
}

/// Discover the terminal DID from an old hosting location's native log.
/// This is only a discovery hint: the destination must be independently queried
/// and its current document, complete method evidence and witnesses verified.
pub fn discover_webvh_current_did(expected_core: &DidCoreId, raw_log_bytes: &[u8]) -> Result<Did> {
    if raw_log_bytes.len() > crate::DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32) {
        return Err(IdentityError::Protocol(
            "DID history exceeds the native log size limit".to_owned(),
        ));
    }
    let mut last = None;
    let mut count = 0;
    for entry in serde_json::Deserializer::from_slice(raw_log_bytes).into_iter::<Value>() {
        count += 1;
        if count > 4096 {
            return Err(IdentityError::Protocol(
                "service DID history exceeds 4096 entries".to_owned(),
            ));
        }
        last = Some(entry.map_err(|error| IdentityError::Protocol(error.to_string()))?);
    }
    let did = last
        .as_ref()
        .and_then(|entry| entry.pointer("/state/id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            IdentityError::Protocol("service DID history omits terminal DID".to_owned())
        })?;
    let did = Did::new(did).map_err(|error| IdentityError::Protocol(error.to_string()))?;
    if project_did_to_core_id(&did)? != *expected_core {
        return Err(IdentityError::Protocol(
            "service DID history changed its stable identity".to_owned(),
        ));
    }
    crate::verify_did_webvh_v1_chain_bytes(&did, raw_log_bytes)?;
    Ok(did)
}
