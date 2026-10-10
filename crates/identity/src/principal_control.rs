//! Historical native identity control for direct approval and Invite subject proofs.
//! Callers must authenticate the complete WebVH history and select the exact
//! non-deactivated state at the protocol timestamp before using this helper.
use arkret_wire::{Did, DidCoreId, DidUrl};

use crate::{IdentityError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectIdentityControlPurpose {
    ApprovalSignature,
    InviteClaimSubject,
}

#[derive(Clone, Debug)]
pub struct NativeIdentityControlKey {
    principal: DidCoreId,
    method: DidUrl,
    public_key: [u8; 32],
}
impl NativeIdentityControlKey {
    pub fn principal(&self) -> &DidCoreId {
        &self.principal
    }
    pub fn method(&self) -> &DidUrl {
        &self.method
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

/// A native update key controls the selected WebVH identity; its did:key DID
/// is a key identity and must never be substituted for the principal identity.
pub fn native_identity_control_key_from_verified_selection(
    selected_identity: &Did,
    expected_principal: &DidCoreId,
    selected_update_keys: &[String],
    verification_method: &DidUrl,
    _purpose: DirectIdentityControlPurpose,
) -> Result<NativeIdentityControlKey> {
    let fail = || {
        IdentityError::Protocol(
            "historical native identity control does not bind this principal".to_owned(),
        )
    };
    if selected_identity.method() != "webvh"
        || arkret_wire::project_did_to_core_id(selected_identity)? != *expected_principal
    {
        return Err(fail());
    }
    let (key_did, fragment) = verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(fail)?;
    let multibase = key_did.strip_prefix("did:key:").ok_or_else(fail)?;
    if fragment != multibase
        || !selected_update_keys
            .iter()
            .any(|key| key.strip_prefix("did:key:").unwrap_or(key) == multibase)
    {
        return Err(fail());
    }
    let public_key = arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    Ok(NativeIdentityControlKey {
        principal: expected_principal.clone(),
        method: verification_method.clone(),
        public_key,
    })
}

/// Verify one approval after the native history adapter resolved its signer.
pub fn verify_native_control_event_approval(
    control: &NativeIdentityControlKey,
    signature: &arkret_wire::ApprovalSignature,
    event: &arkret_wire::Event,
    operation: &str,
    action: arkret_wire::CapabilityActionId,
    at: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<(), arkret_signatures::approval_signature::ApprovalEventVerificationError>
{
    use arkret_signatures::approval_signature::ApprovalEventVerificationError as Error;
    if control.method() != &signature.proof.verification_method {
        return Err(Error::Binding);
    }
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: control.public_key().to_vec(),
    };
    arkret_signatures::approval_signature::verify_event_approval_signature_with_verified_controller(
        signature,
        event,
        operation,
        action,
        at,
        &key,
        Some(control.principal()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_control_requires_exact_historical_key_and_principal() {
        let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([71; 32], "fixture");
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signer.verifying_key().as_bytes(),
        );
        let identity =
            Did::new("did:webvh:QmPa2Sq5krCJFV3c8hmoCxbV4C7XS3zzXV6EBYREriEkm9:principal.example")
                .unwrap();
        let principal = arkret_wire::project_did_to_core_id(&identity).unwrap();
        let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
        let purpose = DirectIdentityControlPurpose::InviteClaimSubject;
        let selected = native_identity_control_key_from_verified_selection(
            &identity,
            &principal,
            std::slice::from_ref(&multibase),
            &method,
            purpose,
        )
        .unwrap();
        assert_eq!(selected.principal(), &principal);
        assert_eq!(selected.public_key(), &signer.verifying_key().to_bytes());
        assert!(
            native_identity_control_key_from_verified_selection(
                &identity,
                &principal,
                &[],
                &method,
                purpose
            )
            .is_err()
        );
        let wrong_fragment = DidUrl::new(format!("did:key:{multibase}#root")).unwrap();
        assert!(
            native_identity_control_key_from_verified_selection(
                &identity,
                &principal,
                std::slice::from_ref(&multibase),
                &wrong_fragment,
                purpose
            )
            .is_err()
        );
        let other =
            Did::new("did:webvh:QmYtphrt7JWauh1egU6yaa43n1aLhrnFQi7S2UeiNU1HRE:other.example")
                .unwrap();
        assert!(
            native_identity_control_key_from_verified_selection(
                &other,
                &principal,
                &[multibase],
                &method,
                purpose
            )
            .is_err()
        );
    }
}
