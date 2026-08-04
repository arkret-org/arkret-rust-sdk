//! Canonical KeyPackage write signatures.

use arkret_models_crypto::{
    KeyOperationSignature, KeyPackageUploadEntry, KeyPackagesConsumeUnsignedRequest,
    KeyPackagesRevokeUnsignedRequest, KeyPackagesUploadUnsignedRequest,
    keypackage_upload_entry_signing_input, keypackages_consume_signing_input,
    keypackages_revoke_signing_input, keypackages_upload_signing_input,
};
use arkret_wire::{Base64UrlString, DeviceId, Did, NonEmptyString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

#[derive(Debug, thiserror::Error)]
pub enum KeyPackageSignatureError {
    #[error("invalid verification method: {0}")]
    InvalidVerificationMethod(String),
    #[error("canonical KeyPackage signing input failed: {0}")]
    Canonical(#[from] arkret_canonical::CanonicalError),
    #[error("invalid KeyPackage signature encoding")]
    InvalidSignatureEncoding,
    #[error("KeyPackage signature verification method mismatch")]
    VerificationMethodMismatch,
    #[error("unsupported KeyPackage signature algorithm")]
    UnsupportedAlgorithm,
    #[error("KeyPackage signature verification failed")]
    VerificationFailed,
}

pub type KeyPackageSignatureResult<T> = Result<T, KeyPackageSignatureError>;

pub fn keypackage_signature_from_bytes(
    verification_method: &str,
    signature: &[u8],
) -> KeyPackageSignatureResult<KeyOperationSignature> {
    let kid = NonEmptyString::new(verification_method.to_owned())
        .map_err(|error| KeyPackageSignatureError::InvalidVerificationMethod(error.to_owned()))?;
    Signature::from_slice(signature)
        .map_err(|_| KeyPackageSignatureError::InvalidSignatureEncoding)?;
    Ok(KeyOperationSignature {
        kid,
        signature_algorithm: Some(
            NonEmptyString::new("Ed25519").expect("static algorithm is non-empty"),
        ),
        sig: Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
            .expect("Ed25519 signature base64url is valid"),
    })
}

pub fn sign_keypackage_signing_input(
    signing_seed: &[u8; 32],
    verification_method: &str,
    signing_input: &[u8],
) -> KeyPackageSignatureResult<KeyOperationSignature> {
    let signing_key = SigningKey::from_bytes(signing_seed);
    let signature = signing_key.sign(signing_input);
    keypackage_signature_from_bytes(verification_method, &signature.to_bytes())
}

pub fn verify_keypackage_signing_input(
    public_key: &[u8; 32],
    expected_verification_method: &str,
    signing_input: &[u8],
    signature: &KeyOperationSignature,
) -> KeyPackageSignatureResult<()> {
    if signature.kid.as_str() != expected_verification_method {
        return Err(KeyPackageSignatureError::VerificationMethodMismatch);
    }
    if !signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() == "Ed25519")
    {
        return Err(KeyPackageSignatureError::UnsupportedAlgorithm);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature.sig.as_str())
        .map_err(|_| KeyPackageSignatureError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| KeyPackageSignatureError::InvalidSignatureEncoding)?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| KeyPackageSignatureError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(signing_input, &signature)
        .map_err(|_| KeyPackageSignatureError::VerificationFailed)
}

pub fn sign_keypackages_upload_request(
    unsigned: &KeyPackagesUploadUnsignedRequest,
    verification_method: &str,
    signing_seed: &[u8; 32],
) -> KeyPackageSignatureResult<KeyOperationSignature> {
    sign_keypackage_signing_input(
        signing_seed,
        verification_method,
        &keypackages_upload_signing_input(unsigned)?,
    )
}

pub fn sign_keypackage_upload_entry(
    principal_id: &Did,
    device_id: &DeviceId,
    entry: &KeyPackageUploadEntry,
    verification_method: &str,
    signing_seed: &[u8; 32],
) -> KeyPackageSignatureResult<KeyOperationSignature> {
    sign_keypackage_signing_input(
        signing_seed,
        verification_method,
        &keypackage_upload_entry_signing_input(principal_id, device_id, entry)?,
    )
}

pub fn sign_keypackages_consume_request(
    unsigned: &KeyPackagesConsumeUnsignedRequest,
    verification_method: &str,
    signing_seed: &[u8; 32],
) -> KeyPackageSignatureResult<KeyOperationSignature> {
    sign_keypackage_signing_input(
        signing_seed,
        verification_method,
        &keypackages_consume_signing_input(unsigned)?,
    )
}

pub fn sign_keypackages_revoke_request(
    unsigned: &KeyPackagesRevokeUnsignedRequest,
    verification_method: &str,
    signing_seed: &[u8; 32],
) -> KeyPackageSignatureResult<KeyOperationSignature> {
    sign_keypackage_signing_input(
        signing_seed,
        verification_method,
        &keypackages_revoke_signing_input(unsigned)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_signature_verifies_and_rejects_wrong_domain() {
        let seed = std::array::from_fn(|index| index as u8);
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let input = concat!(
            "ak.self.keys.keypackages.command.revoke\n",
            "{\"device_id\":\"ak:device:01964137-0000-7000-8000-00000000000d\",",
            "\"key_package_refs\":[\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"],",
            "\"reason\":\"authorization_superseded\"}"
        )
        .as_bytes();
        let signature = sign_keypackage_signing_input(
            &seed,
            "did:webvh:z6mkfixture:agent.example#runtime-1",
            input,
        )
        .unwrap();
        assert_eq!(
            signature.sig.as_str(),
            "ppUSC9bLl-DUCa9Wdtq4Lzjjk3oZVcS8RcdcpiYfpLThhyrXWx3IGn3hcqdd5AaONUAbzOYtR5lWCdW9Jo3pCA"
        );
        verify_keypackage_signing_input(
            &public_key,
            "did:webvh:z6mkfixture:agent.example#runtime-1",
            input,
            &signature,
        )
        .unwrap();
        assert!(
            verify_keypackage_signing_input(
                &public_key,
                "did:webvh:z6mkfixture:agent.example#runtime-1",
                b"ak.keypackage-revoke-v1\n{\"device_id\":\"fixture\"}",
                &signature,
            )
            .is_err()
        );
    }
}
