//! Pure original-signature checks for the existing recovery cleanup carriers.
//! Native episode, scope, inventory and monotonic-fence admission remain with
//! the owning Stations; successful cryptography never substitutes those facts.

use arkret_models_collaboration::content_history::ContentRecoveryScopeCleanupSource;
use arkret_models_crypto::{
    ContentRecoveryScopeCleanupResponseBody, ContentRecoveryScopeCleanupSelfResponseBody,
    ContentScopeRetirementDeliverySigningKey, ContentScopeRetirementProof,
    ContentScopeRetirementSigningKey, KeyOperationSignature,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{DidCoreId, DidUrl, Hash};
use chrono::{DateTime, Utc};

use crate::{IdentityError, Result, VerifiedRealmAuthority};

fn invalid(detail: impl std::fmt::Display) -> IdentityError {
    arkret_wire::WireError::ProtocolCode {
        code: arkret_wire::ErrorCode::SignatureInvalid,
        message: format!("scope cleanup {detail}"),
    }
    .into()
}

pub(crate) fn verify_signature(
    resolution: &AuthenticatedServiceResolution,
    owner: &DidCoreId,
    at: DateTime<Utc>,
    method: &DidUrl,
    signature: &KeyOperationSignature,
    input: &[u8],
) -> Result<[u8; 32]> {
    if resolution.service_kind != "station"
        || &resolution.service_id != owner
        || signature.kid.as_str() != method.as_str()
    {
        return Err(invalid("original Station or method differs"));
    }
    let document =
        crate::authenticated_service_document_at(resolution, owner, at).map_err(invalid)?;
    let service: arkret_models_identity::service_identity::ServiceDidDocument =
        serde_json::from_value(serde_json::to_value(&document).map_err(invalid)?)
            .map_err(invalid)?;
    service
        .validate_service_kind(&arkret_wire::ServiceKind::Station)
        .map_err(invalid)?;
    crate::validate_verification_method_relationship(
        &document,
        method,
        &document.id,
        crate::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let key = crate::public_key_material_from_document(&document, method)
        .map_err(invalid)?
        .ed25519_bytes()
        .map_err(invalid)?;
    if !arkret_signatures::proof::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        },
        input,
        signature.signature.as_str(),
    ) {
        return Err(invalid("original Ed25519 signature differs"));
    }
    Ok(key)
}

/// Check original H history/signature and the actual authenticated transport
/// roles. The caller repeats the source window after native lock waits.
pub fn verify_content_recovery_scope_cleanup_source(
    source: &ContentRecoveryScopeCleanupSource,
    authenticated_source: &DidCoreId,
    destination: &DidCoreId,
    now: DateTime<Utc>,
) -> Result<()> {
    source.validate_shape().map_err(invalid)?;
    let attestation = &source.attestation;
    let account = attestation
        .replacement
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("source has no full Account"))?;
    if &account.station_id != authenticated_source
        || &attestation.destination_service_id != destination
        || attestation.attested_at > now
        || now >= attestation.expires_at
    {
        return Err(invalid(
            "transport role, destination or source window differs",
        ));
    }
    verify_signature(
        &source.origin_resolution,
        authenticated_source,
        attestation.attested_at,
        &attestation.verification_method,
        &attestation.signature,
        &attestation.signing_bytes().map_err(invalid)?,
    )?;
    Ok(())
}

/// Verify the original historical proof separately from the current delivery.
/// Current governance must come from the caller's independently verified fresh
/// authority bundle. This proves signatures, not actual native import/erasure.
pub fn verify_content_scope_cleanup_delivery(
    response: &ContentRecoveryScopeCleanupResponseBody,
    source: &ContentRecoveryScopeCleanupSource,
    original_resolution: Option<&AuthenticatedServiceResolution>,
    delivery_resolution: Option<&AuthenticatedServiceResolution>,
    authority: &VerifiedRealmAuthority,
    now: DateTime<Utc>,
) -> Result<ContentRecoveryScopeCleanupSelfResponseBody> {
    let account = source
        .attestation
        .replacement
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("source has no full Account"))?;
    verify_content_recovery_scope_cleanup_source(
        source,
        &account.station_id,
        authority.current_service_id(),
        now,
    )?;
    response
        .validate_for_source(&source.attestation)
        .map_err(invalid)?;
    if source
        .attestation
        .inventory_entry
        .effective_scope
        .realm_id()
        != authority.realm_id()
        || authority
            .current_assertion_expires_at()
            .is_none_or(|expires| expires <= now)
    {
        return Err(invalid("delivery has no fresh exact Realm authority"));
    }
    let ContentRecoveryScopeCleanupResponseBody::Retired(result) = response else {
        return Ok(ContentRecoveryScopeCleanupSelfResponseBody {
            delivery: response.clone(),
            attestor_signing_key: None,
            delivery_signing_key: None,
        });
    };
    let proof = &result.cleanup.retirement_proof;
    let (ContentScopeRetirementProof::Removed {
        governance_station_id,
        governance_generation,
        attested_at,
        verification_method,
        ..
    }
    | ContentScopeRetirementProof::Terminated {
        governance_station_id,
        governance_generation,
        attested_at,
        verification_method,
        ..
    }) = proof;
    if authority.authority_service_at(*governance_generation) != Some(governance_station_id)
        || !authority.authorizes_generation_issuer_at(
            governance_station_id,
            *governance_generation,
            *attested_at,
        )
        || *attested_at > now
    {
        return Err(invalid(
            "original proof is outside its historical governing tenure",
        ));
    }
    let (ContentScopeRetirementProof::Removed { signature, .. }
    | ContentScopeRetirementProof::Terminated { signature, .. }) = proof;
    let original_key = verify_signature(
        original_resolution.ok_or_else(|| invalid("original proof Service history is absent"))?,
        governance_station_id,
        *attested_at,
        verification_method,
        signature,
        &proof.signing_bytes().map_err(invalid)?,
    )?;
    let delivery = &result.delivery_attestation;
    if &delivery.governance_station_id != authority.current_service_id()
        || delivery.governance_generation != authority.current_generation()
        || !authority.authorizes_generation_issuer_at(
            &delivery.governance_station_id,
            delivery.governance_generation,
            delivery.attested_at,
        )
        || delivery.attested_at > now
        || now >= delivery.expires_at
    {
        return Err(invalid("delivery is not live current governance"));
    }
    let delivery_key = verify_signature(
        delivery_resolution.ok_or_else(|| invalid("current delivery Service history is absent"))?,
        &delivery.governance_station_id,
        delivery.attested_at,
        &delivery.verification_method,
        &delivery.signature,
        &delivery.signing_bytes().map_err(invalid)?,
    )?;
    Ok(ContentRecoveryScopeCleanupSelfResponseBody {
        delivery: response.clone(),
        attestor_signing_key: Some(ContentScopeRetirementSigningKey {
            proof_digest: Hash::new(arkret_canonical::canonical_sha256(proof)?)?,
            verification_method: verification_method.clone(),
            public_key_base64url: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(original_key),
            )
            .map_err(invalid)?,
        }),
        delivery_signing_key: Some(ContentScopeRetirementDeliverySigningKey {
            delivery_digest: Hash::new(arkret_canonical::canonical_sha256(delivery)?)?,
            verification_method: delivery.verification_method.clone(),
            public_key_base64url: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(delivery_key),
            )
            .map_err(invalid)?,
        }),
    })
}

#[cfg(test)]
#[path = "content_scope_cleanup/source_tests.rs"]
mod source_tests;

#[cfg(test)]
pub(crate) fn original_cleanup_source_for_delivery_test(
    at: DateTime<Utc>,
) -> ContentRecoveryScopeCleanupSource {
    source_tests::original_source_at(Some(at))
}
