use arkret_models_crypto::{
    PeerKeyPackageClaimReceipt, peer_keypackage_claim_receipt_signing_bytes,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::WireError;

/// Verify a destination Principal Server's KeyPackage claim receipt against
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
