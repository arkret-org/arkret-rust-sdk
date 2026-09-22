//! Principal projection attestation signing and verification.

use arkret_models_identity::{
    DidDocument, PrincipalResolutionProjectionAttestation,
    PrincipalResolutionProjectionAttestationCore, PublicPrincipalResolution,
};
use arkret_wire::{Did, DidCoreId, DidUrl, ProtocolSignature};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_ed25519_detached_jws};

/// Sign the Station projection attestation that makes the public
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
    attestation.proof.jws =
        sign_ed25519_detached_jws(signing_key, &attestation.proof_signing_bytes()?)
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ok(attestation)
}

/// Verify a public principal resolution end to end.
///
/// The response halves are cross-bound first, then the attestation is checked
/// against the serving Station's own DID Document: an attestation that
/// verifies under some other key is not evidence about this account.
pub fn verify_public_principal_resolution(
    resolution: &PublicPrincipalResolution,
    station_document: &DidDocument,
    now: DateTime<Utc>,
) -> arkret_wire::Result<VerifyingKey> {
    resolution.validate_attestation_binding()?;
    verify_full_to_core_binding(&station_document.id, &resolution.account_id.station_id)?;
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
        station_document,
        &attestation.proof,
        &attestation.proof_signing_bytes()?,
        "invalid principal resolution projection attestation proof",
    )
}

pub fn verify_full_to_core_binding(
    did: &Did,
    expected_service_id: &DidCoreId,
) -> arkret_wire::Result<()> {
    let projected = arkret_wire::project_did_to_core_id(did)?;
    if &projected != expected_service_id {
        return Err(arkret_wire::WireError::Protocol(
            "did does not project to expected service core id".to_owned(),
        ));
    }
    Ok(())
}

fn placeholder_proof(
    verification_method: DidUrl,
    created_at: DateTime<Utc>,
) -> arkret_wire::Result<ProtocolSignature> {
    Ok(ProtocolSignature {
        verification_method,
        created_at,
        jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
    })
}

fn verify_document_signature(
    document: &DidDocument,
    proof: &ProtocolSignature,
    signing_bytes: &[u8],
    invalid_message: &str,
) -> arkret_wire::Result<VerifyingKey> {
    require_assertion_method(document, &proof.verification_method)?;
    let material = lookup_key_material(document, &proof.verification_method)?;
    let bytes = PublicKeyMaterial::Ed25519Multibase { value: material }
        .ed25519_bytes()
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &proof.jws,
            signing_bytes,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_bytes().to_vec(),
            },
        )
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
    let methods = document
        .raw_properties
        .get("assertionMethod")
        .and_then(serde_json::Value::as_array)
        .or_else(|| {
            document
                .raw_properties
                .get("assertion_methods")
                .and_then(serde_json::Value::as_array)
        });
    let Some(methods) = methods else {
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
        .filter_map(|item| {
            item.as_str().or_else(|| {
                item.get("verification_method")
                    .and_then(serde_json::Value::as_str)
            })
        })
        .any(|item| item == full || relative.as_deref().is_some_and(|relative| item == relative))
    {
        return Err(arkret_wire::WireError::Protocol(
            "service resolution proof key is not an assertionMethod".to_owned(),
        ));
    }
    Ok(())
}
