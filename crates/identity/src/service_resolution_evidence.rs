//! Complete method-native verification for retained service signer evidence.

use arkret_models_identity::{
    AuthenticatedServiceResolution, AuthenticatedSignerResolutionEvidence, DidDocument,
    ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
    ResolutionDidBindingMethodProof, ResolutionDidBindingMethodProofKind,
    ResolutionDidBindingWitness, ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    ServiceResolutionRecord,
};
use arkret_wire::{DidCoreId, DidFullId, Error as WireError, Hash};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    DidKeyResolver, DidResolver as _, Error, Result, parse_did_webvh_witness_policy,
    verify_did_webvh_v1_chain_and_witness_bytes,
};

/// Build and verify the complete retained WebVH resolution closure served by
/// the open service-resolution operation.
pub fn build_authenticated_webvh_service_resolution(
    service_resolution_record: ServiceResolutionRecord,
    normalized_did_document: DidDocument,
    log_entries: Vec<Value>,
    witness_records: Vec<Value>,
    now: DateTime<Utc>,
) -> Result<AuthenticatedServiceResolution> {
    let record = &service_resolution_record.record;
    if record.full_id.method() != "webvh" || normalized_did_document.id != record.full_id {
        return Err(Error::Protocol(
            "WebVH service resolution builder received a different DID method or document"
                .to_owned(),
        ));
    }
    let first_version =
        version_id(log_entries.first().ok_or_else(|| {
            Error::Protocol("WebVH signer evidence has no log entries".to_owned())
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
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let document_digest = Hash::new(arkret_canonical::canonical_sha256(
        &normalized_did_document,
    )?)
    .map_err(|error| Error::Protocol(error.to_string()))?;
    let resolution = AuthenticatedServiceResolution {
        service_resolution_record,
        method_history_evidence: ResolutionMethodHistoryEvidence::WebvhLog {
            adapter_version: "did:webvh:1.0".to_owned(),
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: first_history_head,
                from_version_id: first_version,
                to_method_history_head: last_history_head.clone(),
                to_version_id: last_version.clone(),
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
    let expected_service_id = resolution
        .service_resolution_record
        .record
        .service_id
        .clone();
    verify_authenticated_service_resolution_history(&resolution, &expected_service_id, now)?;
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
    let record = &resolution.service_resolution_record.record;
    match &resolution.method_history_evidence {
        ResolutionMethodHistoryEvidence::WebvhLog {
            boundary,
            evidence,
            log_entries,
            witness_records,
            ..
        } => verify_webvh_history(
            &record.full_id,
            &resolution.normalized_did_document,
            boundary,
            evidence,
            log_entries,
            witness_records,
            &record.method_history_head,
            &record.version_id,
        )?,
        ResolutionMethodHistoryEvidence::DidKeyExpansion { boundary, .. } => {
            if record.full_id.method() != "key"
                || boundary.from_method_history_head != boundary.to_method_history_head
                || boundary.from_version_id != boundary.to_version_id
                || boundary.to_method_history_head != record.method_history_head
                || boundary.to_version_id != record.version_id
            {
                return Err(Error::Protocol(
                    "did:key service resolution boundary mismatch".to_owned(),
                ));
            }
            let expected = DidKeyResolver::new().resolve_did(&record.full_id)?.document;
            require_same_document(&expected, &resolution.normalized_did_document)?;
        }
        ResolutionMethodHistoryEvidence::DidWebDocument { .. } => {
            return Err(Error::Protocol(
                "mutable did:web cannot be retained as historical service signer evidence"
                    .to_owned(),
            ));
        }
    }
    arkret_signatures::service_resolution::verify_authenticated_service_resolution(
        resolution,
        expected_service_id,
        now,
    )
    .map(|_| ())
    .map_err(wire)
}

/// Verify a complete current resolution and retain the exact assertion method
/// that signed its record as a content-addressed service signer-evidence leaf.
pub fn service_signer_evidence_from_authenticated_resolution(
    resolution: AuthenticatedServiceResolution,
    expected_service_id: &DidCoreId,
    now: DateTime<Utc>,
) -> Result<AuthenticatedSignerResolutionEvidence> {
    verify_authenticated_service_resolution_history(&resolution, expected_service_id, now)?;
    let evidence = AuthenticatedSignerResolutionEvidence::Service {
        signer_id: expected_service_id.clone(),
        verification_method: resolution
            .service_resolution_record
            .proof
            .verification_method
            .clone(),
        authenticated_resolution: resolution,
    };
    evidence.validate_attester_binding().map_err(wire)?;
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn verify_webvh_history(
    full_id: &DidFullId,
    document: &DidDocument,
    boundary: &ResolutionMethodEvidenceBoundary,
    evidence: &ResolutionDidBindingEvidenceReceipt,
    log_entries: &[Value],
    witness_records: &[Value],
    record_history_head: &str,
    record_version_id: &str,
) -> Result<()> {
    if full_id.method() != "webvh"
        || log_entries.is_empty()
        || log_entries.len() > 4_096
        || witness_records.len() > 4_096
    {
        return Err(Error::Protocol(
            "WebVH signer evidence omits a complete history".to_owned(),
        ));
    }
    let log_bytes = json_lines(log_entries)?;
    let witness_bytes = arkret_canonical::canonical_json_bytes(&witness_records)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let verified = verify_did_webvh_v1_chain_and_witness_bytes(
        full_id,
        &log_bytes,
        (!witness_records.is_empty()).then_some(witness_bytes.as_slice()),
    )
    .map_err(|error| Error::Protocol(error.to_string()))?;
    let mut supplied_witness_versions = witness_records
        .iter()
        .map(version_id)
        .collect::<Result<Vec<_>>>()?;
    supplied_witness_versions.sort();
    if supplied_witness_versions
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(Error::Protocol(
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
        return Err(Error::Protocol(
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
        Error::Protocol("WebVH signer evidence omits its method proof".to_owned())
    })?;
    let expected_witnesses = terminal_witnesses(log_entries)?;
    let witness_digest = Hash::new(arkret_canonical::canonical_sha256(&witness_records)?)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if boundary.from_method_history_head != first_history_head
        || boundary.from_version_id != first_version
        || boundary.to_method_history_head != last_history_head
        || boundary.to_version_id != last_version
        || record_history_head != last_history_head
        || record_version_id != last_version
        || evidence.method != "webvh"
        || method_proof.kind != ResolutionDidBindingMethodProofKind::WebvhLog
        || method_proof.history_head != last_history_head
        || method_proof.witnesses != expected_witnesses
        || method_proof.witness_proofs_digest != witness_digest
    {
        return Err(Error::Protocol(
            "WebVH signer evidence boundary or head mismatch".to_owned(),
        ));
    }
    let head_document: DidDocument = serde_json::from_value(verified.log.head_state)
        .map_err(|error| Error::Protocol(format!("invalid WebVH head document: {error}")))?;
    require_same_document(&head_document, document)
}

fn terminal_witnesses(log_entries: &[Value]) -> Result<Vec<ResolutionDidBindingWitness>> {
    let mut policy = None;
    for entry in log_entries {
        let parameters = entry
            .get("parameters")
            .ok_or_else(|| Error::Protocol("WebVH log entry omits parameters".to_owned()))?;
        if let Some(next) = parse_did_webvh_witness_policy(parameters)
            .map_err(|error| Error::Protocol(error.to_string()))?
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
                DidFullId::new(id).map_err(|error| Error::Protocol(error.to_string()))?;
            Ok(ResolutionDidBindingWitness {
                controlling_organization: witness_did.clone(),
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
                .map_err(|error| Error::Protocol(error.to_string()))?,
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
        .ok_or_else(|| Error::Protocol("WebVH log entry omits versionId".to_owned()))
}

fn history_head(entry: &Value) -> Result<String> {
    Hash::new(arkret_canonical::canonical_sha256(entry)?)
        .map(|digest| digest.as_ref().to_owned())
        .map_err(|error| Error::Protocol(error.to_string()))
}

fn require_same_document(expected: &DidDocument, actual: &DidDocument) -> Result<()> {
    let expected = arkret_canonical::canonical_json_bytes(expected)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let actual = arkret_canonical::canonical_json_bytes(actual)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if expected != actual {
        return Err(Error::Protocol(
            "retained normalized DID document does not match method-native history".to_owned(),
        ));
    }
    Ok(())
}

fn wire(error: WireError) -> Error {
    Error::Protocol(error.to_string())
}
