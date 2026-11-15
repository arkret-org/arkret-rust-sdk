//! Independent successor signatures over the finite owner-transfer intent.

use arkret_models_crypto::realm_owner_transfer::RealmOwnerTransferAcceptanceIntent;
use arkret_wire::{DetachedObjectSignature, DetachedSignatureContext, DidUrl};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;

use crate::{Error, PublicKeyMaterial, Result};

pub fn sign_realm_owner_transfer_acceptance(
    intent: &RealmOwnerTransferAcceptanceIntent,
    verification_method: DidUrl,
    created_at: DateTime<Utc>,
    signing_key: &SigningKey,
) -> Result<DetachedObjectSignature> {
    intent
        .validate()
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let signature = crate::detached_object::sign_detached_object(
        intent,
        DetachedSignatureContext::RealmOwnerTransferAcceptance,
        verification_method,
        created_at,
        signing_key,
    )?;
    intent
        .validate_acceptance(&signature)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(signature)
}

/// Mathematical signature verification only; current Device identity and
/// limited key-purpose eligibility still come from the native C source.
pub fn verify_realm_owner_transfer_acceptance(
    intent: &RealmOwnerTransferAcceptanceIntent,
    signature: &DetachedObjectSignature,
    public_key: &PublicKeyMaterial,
) -> Result<()> {
    intent
        .validate_acceptance(signature)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    crate::detached_object::verify_detached_object_signature(
        signature,
        intent,
        DetachedSignatureContext::RealmOwnerTransferAcceptance,
        public_key,
    )
}

#[cfg(test)]
mod tests;
