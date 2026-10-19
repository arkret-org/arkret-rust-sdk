use arkret_models_crypto::{
    KeyPackageConsumeReceipt, PeerKeyPackageClaimReceipt,
    peer_keypackage_claim_receipt_signing_bytes,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::WireError;

/// Verify a destination Station's KeyPackage claim receipt against
/// the exact service key that was effective when the receipt was issued.
///
/// The authenticated resolution, rather than a key asserted by the receipt or
/// by service describe, is the authority for historical key selection.
pub fn verify_peer_keypackage_claim_receipt_signature(
    receipt: &PeerKeyPackageClaimReceipt,
    authenticated_resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    let document = arkret_identity::authenticated_service_document_at(
        authenticated_resolution,
        &receipt.destination_id,
        receipt.claimed_at,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let verification_method = arkret_wire::DidUrl::new(receipt.signature.kid.as_str().to_owned())
        .map_err(|error| WireError::Protocol(error.to_owned()))?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let public_key =
        arkret_identity::public_key_material_from_document(&document, &verification_method)
            .map_err(|error| WireError::Protocol(error.to_string()))?
            .ed25519_bytes()
            .map_err(|error| WireError::Protocol(error.to_string()))?;
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(receipt)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public_key,
        verification_method.as_str(),
        &signing_bytes,
        &receipt.signature,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))
}

/// Verify the exact terminal receipt under the Station key effective at its
/// original consumption coordinate. Callers additionally bind the request
/// digest and the complete nested durable receipt to their frozen command.
pub fn verify_peer_keypackage_consume_receipt_signature(
    receipt: &KeyPackageConsumeReceipt,
    authenticated_resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    if authenticated_resolution.service_kind != "station" {
        return Err(WireError::Protocol(
            "consume receipt signer is not a Station".into(),
        ));
    }
    receipt
        .validate_shape()
        .map_err(|error| WireError::Protocol(error.into()))?;
    let document = arkret_identity::authenticated_service_document_at(
        authenticated_resolution,
        &receipt.recipient_durable_receipt.recipient_id,
        receipt.consumed_at,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let method = arkret_wire::DidUrl::new(receipt.signature.kid.as_str().to_owned())
        .map_err(|error| WireError::Protocol(error.to_owned()))?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let key = arkret_identity::public_key_material_from_document(&document, &method)
        .map_err(|error| WireError::Protocol(error.to_string()))?
        .ed25519_bytes()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &key,
        method.as_str(),
        &receipt.canonical_signing_bytes()?,
        &receipt.signature,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))
}
