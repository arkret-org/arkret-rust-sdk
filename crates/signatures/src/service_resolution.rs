//! Signed `ServiceResolutionRecord` builder and verifier.

use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, PrincipalResolutionProjectionAttestation,
    PrincipalResolutionProjectionAttestationCore, PublicPrincipalResolution,
    ServiceResolutionPublishAck, ServiceResolutionPublishAckCore, ServiceResolutionRecord,
    ServiceResolutionRecordCore, ServiceRouteHandoverNotice, ServiceRouteHandoverNoticeCore,
};
use arkret_wire::{Base64UrlString, DidCoreId, DidFullId, DidUrl, ProtocolSignature};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

pub fn sign_service_resolution_record(
    core: ServiceResolutionRecordCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<ServiceResolutionRecord> {
    let created_at = core.issued_at;
    let mut record = ServiceResolutionRecord {
        record: core,
        proof: ProtocolSignature {
            verification_method,
            created_at,
            jws: base64_value("AA".to_owned())?,
        },
    };
    let bytes = record.proof_signing_bytes()?;
    record.proof.jws = base64_value(arkret_canonical::base64url_encode(
        signing_key.sign(&bytes).to_bytes(),
    ))?;
    Ok(record)
}

pub fn sign_service_route_handover_notice(
    core: ServiceRouteHandoverNoticeCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<ServiceRouteHandoverNotice> {
    core.validate_shape()?;
    let mut notice = ServiceRouteHandoverNotice {
        proof: placeholder_proof(verification_method, core.issued_at)?,
        notice: core,
    };
    notice.proof.jws = signature_value(signing_key, &notice.proof_signing_bytes()?)?;
    Ok(notice)
}

pub fn sign_service_resolution_publish_ack(
    core: ServiceResolutionPublishAckCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<ServiceResolutionPublishAck> {
    let mut ack = ServiceResolutionPublishAck {
        proof: placeholder_proof(verification_method, core.accepted_at)?,
        ack: core,
    };
    ack.proof.jws = signature_value(signing_key, &ack.proof_signing_bytes()?)?;
    Ok(ack)
}

/// Sign the Principal Server projection attestation that makes the public
/// resolution surface verifiable without disclosing any PCR material.
pub fn sign_principal_resolution_projection_attestation(
    core: PrincipalResolutionProjectionAttestationCore,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::Result<PrincipalResolutionProjectionAttestation> {
    if core.issued_at >= core.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "projection attestation is not a positive validity window".to_owned(),
        ));
    }
    let mut attestation = PrincipalResolutionProjectionAttestation {
        proof: placeholder_proof(verification_method, core.issued_at)?,
        attestation: core,
    };
    attestation.proof.jws = signature_value(signing_key, &attestation.proof_signing_bytes()?)?;
    Ok(attestation)
}

/// Verify a public principal resolution end to end.
///
/// The response halves are cross-bound first, then the attestation is checked
/// against the serving Principal Server's own DID Document: an attestation that
/// verifies under some other key is not evidence about this account.
pub fn verify_public_principal_resolution(
    resolution: &PublicPrincipalResolution,
    principal_server_document: &DidDocument,
    now: DateTime<Utc>,
) -> arkret_wire::Result<VerifyingKey> {
    resolution.validate_attestation_binding()?;
    verify_full_to_core_binding(
        &principal_server_document.id,
        &resolution.principal_server_id,
    )?;
    let attestation = &resolution.projection_attestation;
    if attestation.proof.created_at != attestation.attestation.issued_at {
        return Err(arkret_wire::WireError::Protocol(
            "projection attestation proof timestamp mismatch".to_owned(),
        ));
    }
    if now >= attestation.attestation.expires_at {
        return Err(arkret_wire::WireError::Protocol(
            "projection attestation is expired".to_owned(),
        ));
    }
    let evidence_digest = arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
        &resolution.method_history_evidence,
    )?)?;
    if attestation.attestation.method_history_evidence_digest != evidence_digest {
        return Err(arkret_wire::WireError::Protocol(
            "projection attestation does not bind the supplied method history evidence".to_owned(),
        ));
    }
    verify_document_signature(
        principal_server_document,
        &attestation.proof,
        &attestation.proof_signing_bytes()?,
        "invalid principal resolution projection attestation proof",
    )
}

pub fn verify_service_route_handover_notice(
    notice: &ServiceRouteHandoverNotice,
    target_document: &DidDocument,
    expected_service_id: &DidCoreId,
    now: DateTime<Utc>,
) -> arkret_wire::Result<VerifyingKey> {
    notice.notice.validate_shape()?;
    verify_full_to_core_binding(&target_document.id, expected_service_id)?;
    if notice.notice.service_id != *expected_service_id
        || notice.proof.created_at != notice.notice.issued_at
        || now >= notice.notice.expires_at
    {
        return Err(arkret_wire::WireError::Protocol(
            "handover notice target or freshness mismatch".to_owned(),
        ));
    }
    verify_document_signature(
        target_document,
        &notice.proof,
        &notice.proof_signing_bytes()?,
        "invalid service route handover proof",
    )
}

pub fn verify_service_resolution_publish_ack(
    ack: &ServiceResolutionPublishAck,
    receiver_document: &DidDocument,
) -> arkret_wire::Result<VerifyingKey> {
    verify_full_to_core_binding(&receiver_document.id, &ack.ack.receiver_service_id)?;
    if ack.proof.created_at != ack.ack.accepted_at {
        return Err(arkret_wire::WireError::Protocol(
            "publish ack proof timestamp mismatch".to_owned(),
        ));
    }
    verify_document_signature(
        receiver_document,
        &ack.proof,
        &ack.proof_signing_bytes()?,
        "invalid service resolution publish ack proof",
    )
}

pub fn verify_full_to_core_binding(
    full_id: &DidFullId,
    expected_service_id: &DidCoreId,
) -> arkret_wire::Result<()> {
    let projected = arkret_wire::project_full_id_to_core_id(full_id)?;
    if &projected != expected_service_id {
        return Err(arkret_wire::WireError::Protocol(
            "full_id does not project to expected service core id".to_owned(),
        ));
    }
    Ok(())
}

pub fn verify_record_successor(
    previous: &ServiceResolutionRecord,
    successor: &ServiceResolutionRecord,
    now: DateTime<Utc>,
) -> arkret_wire::Result<()> {
    let previous_digest = arkret_wire::Hash::new(arkret_canonical::canonical_sha256(previous)?)?;
    if successor.record.service_id != previous.record.service_id
        || successor.record.service_kind != previous.record.service_kind
        || successor.record.record_sequence != previous.record.record_sequence + 1
        || successor.record.previous_record_digest.as_ref() != Some(&previous_digest)
        || successor.record.issued_at > successor.record.refresh_after
        || successor.record.refresh_after >= successor.record.expires_at
        || now >= successor.record.expires_at
    {
        return Err(arkret_wire::WireError::Protocol(
            "service resolution successor has a gap, fork, or expired validity".to_owned(),
        ));
    }
    verify_full_to_core_binding(&successor.record.full_id, &successor.record.service_id)
}

fn placeholder_proof(
    verification_method: DidUrl,
    created_at: DateTime<Utc>,
) -> arkret_wire::Result<ProtocolSignature> {
    Ok(ProtocolSignature {
        verification_method,
        created_at,
        jws: base64_value("AA".to_owned())?,
    })
}

fn signature_value(signing_key: &SigningKey, bytes: &[u8]) -> arkret_wire::Result<Base64UrlString> {
    base64_value(arkret_canonical::base64url_encode(
        signing_key.sign(bytes).to_bytes(),
    ))
}

fn base64_value(value: String) -> arkret_wire::Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(|error| arkret_wire::WireError::Protocol(error.to_owned()))
}

pub fn verify_authenticated_service_resolution(
    resolution: &AuthenticatedServiceResolution,
    expected_service_id: &DidCoreId,
    now: DateTime<Utc>,
) -> arkret_wire::Result<VerifyingKey> {
    resolution.validate_shape(expected_service_id, now)?;
    let record = &resolution.service_resolution_record;
    verify_document_signature(
        &resolution.normalized_did_document,
        &record.proof,
        &record.proof_signing_bytes()?,
        "invalid service resolution proof",
    )
}

fn verify_document_signature(
    document: &DidDocument,
    proof: &ProtocolSignature,
    signing_bytes: &[u8],
    invalid_message: &str,
) -> arkret_wire::Result<VerifyingKey> {
    require_assertion_method(document, &proof.verification_method)?;
    let material = lookup_key_material(document, &proof.verification_method)?;
    let bytes = crate::proof::PublicKeyMaterial::Ed25519Multibase { value: material }
        .ed25519_bytes()
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let signature_bytes = arkret_canonical::base64url_decode(proof.jws.as_str())
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    key.verify(signing_bytes, &signature)
        .map_err(|_| arkret_wire::WireError::Protocol(invalid_message.to_owned()))?;
    Ok(key)
}

fn lookup_key_material(document: &DidDocument, method: &DidUrl) -> arkret_wire::Result<String> {
    let full = method.as_str();
    let fragment = full
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"));
    document
        .verification_methods
        .get(full)
        .or_else(|| {
            fragment
                .as_ref()
                .and_then(|key| document.verification_methods.get(key))
        })
        .or_else(|| {
            fragment.as_deref().and_then(|key| {
                document
                    .verification_methods
                    .get(key.trim_start_matches('#'))
            })
        })
        .cloned()
        .ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "service resolution proof key is absent from DID document".to_owned(),
            )
        })
}

fn require_assertion_method(document: &DidDocument, method: &DidUrl) -> arkret_wire::Result<()> {
    let Some(methods) = document
        .raw_properties
        .get("assertionMethod")
        .and_then(serde_json::Value::as_array)
    else {
        return Err(arkret_wire::WireError::Protocol(
            "service DID document has no assertionMethod relationship".to_owned(),
        ));
    };
    let full = method.as_str();
    let relative = full
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"));
    if !methods
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|item| item == full || relative.as_deref().is_some_and(|relative| item == relative))
    {
        return Err(arkret_wire::WireError::Protocol(
            "service resolution proof key is not an assertionMethod".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_identity::{
        ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
        ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    };
    use arkret_wire::{DidCoreId, Hash};
    use chrono::TimeZone as _;

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn fixture() -> (AuthenticatedServiceResolution, DidCoreId) {
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let full_id = DidFullId::new("did:web:agent-authority.example").unwrap();
        let service_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
        let method = DidUrl::new(format!("{full_id}#signing-1")).unwrap();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let document = DidDocument {
            id: full_id.clone(),
            verification_methods: BTreeMap::from([(method.to_string(), multibase)]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::from([(
                "assertionMethod".to_owned(),
                serde_json::json!([method]),
            )]),
        };
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap();
        let record = sign_service_resolution_record(
            ServiceResolutionRecordCore {
                service_id: service_id.clone(),
                service_kind: "principal_server".to_owned(),
                full_id,
                method_history_head: "did-web-document-sha256:fixture".to_owned(),
                version_id: "did-web-document-sha256:fixture".to_owned(),
                resolution_event_ref: format!("did-web-document-sha256:{}", "1".repeat(64)),
                record_sequence: 0,
                previous_record_digest: None,
                current_record_url: format!(
                    "https://agent-authority.example/_arkret/open/services/{service_id}/resolution"
                ),
                base_url: "https://agent-authority.example/".to_owned(),
                describe_digest: hash('2'),
                issued_at,
                refresh_after: issued_at + chrono::Duration::minutes(5),
                expires_at: issued_at + chrono::Duration::minutes(10),
            },
            method,
            &signing_key,
        )
        .unwrap();
        let document_digest =
            Hash::new(arkret_canonical::canonical_sha256(&document).unwrap()).unwrap();
        let evidence = ResolutionMethodHistoryEvidence::DidWebDocument {
            adapter_version: "did:web:1".to_owned(),
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: record.record.method_history_head.clone(),
                from_version_id: record.record.version_id.clone(),
                to_method_history_head: record.record.method_history_head.clone(),
                to_version_id: record.record.version_id.clone(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".to_owned(),
                document_digest,
                method_proofs: Vec::new(),
            },
        };
        (
            AuthenticatedServiceResolution {
                service_resolution_record: record,
                method_history_evidence: evidence,
                normalized_did_document: document,
            },
            service_id,
        )
    }

    #[test]
    fn signed_resolution_round_trips_and_rejects_tampering() {
        let (mut resolution, service_id) = fixture();
        let now = resolution.service_resolution_record.record.issued_at;
        assert!(verify_authenticated_service_resolution(&resolution, &service_id, now).is_ok());
        resolution.service_resolution_record.record.base_url =
            "https://attacker.example/".to_owned();
        assert!(verify_authenticated_service_resolution(&resolution, &service_id, now).is_err());
    }

    #[test]
    fn same_core_successor_accepts_exact_chain_and_rejects_fork() {
        let (resolution, _) = fixture();
        let previous = resolution.service_resolution_record;
        let mut successor = previous.clone();
        successor.record.record_sequence = previous.record.record_sequence + 1;
        successor.record.previous_record_digest =
            Some(Hash::new(arkret_canonical::canonical_sha256(&previous).unwrap()).unwrap());
        successor.record.full_id = DidFullId::new("did:web:agent-authority.example").unwrap();
        assert!(verify_record_successor(&previous, &successor, successor.record.issued_at).is_ok());

        successor.record.record_sequence = previous.record.record_sequence;
        assert!(
            verify_record_successor(&previous, &successor, successor.record.issued_at).is_err()
        );
    }
}
