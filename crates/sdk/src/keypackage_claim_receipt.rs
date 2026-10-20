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
/// For a Realm recipient, `expected_issuer` comes from the verified accepting
/// governance tenure. The nested recipient_id remains the original claim
/// issuer and is not the consume signer after a governance handoff.
pub fn verify_peer_keypackage_consume_receipt_signature(
    receipt: &KeyPackageConsumeReceipt,
    expected_issuer: &arkret_wire::DidCoreId,
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
    if !matches!(
        &receipt.recipient_durable_receipt.recipient,
        arkret_models_crypto::RecipientMlsDurableSigner::RealmDevice { .. }
    ) && expected_issuer != &receipt.recipient_durable_receipt.recipient_id
    {
        return Err(WireError::Protocol(
            "ordinary recipient consume signer differs from its fixed Station".into(),
        ));
    }
    let document = arkret_identity::authenticated_service_document_at(
        authenticated_resolution,
        expected_issuer,
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
