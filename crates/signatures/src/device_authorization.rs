use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;

use crate::proof::PublicKeyMaterial;
use crate::{Error, Result, verify_detached_ed25519_signature};

/// Verify the Ed25519 proof of possession over the SDK-owned device
/// authorization transcript.
pub fn verify_device_authorize_possession(
    payload: &DeviceAuthorizePayload,
    subject_account_id: &arkret_wire::AccountId,
) -> Result<()> {
    payload
        .validate_wire_constraints()
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
    let signature = device_authorize_signature_value(&payload.device_signature)?;
    let public_key = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::Protocol("device_authorize_device_public_key_invalid".to_owned()))?;
    let key = PublicKeyMaterial::Ed25519Multibase {
        value: public_key.to_owned(),
    };
    let transcript = payload.device_possession_signature_input(subject_account_id)?;
    if !verify_detached_ed25519_signature(&key, &transcript, signature) {
        return Err(Error::Protocol(
            "device_authorize_device_signature_invalid".to_owned(),
        ));
    }
    Ok(())
}

fn device_authorize_signature_value(
    value: &arkret_models_collaboration::events_payloads::SignatureMaterial,
) -> Result<&str> {
    match value {
        arkret_models_collaboration::events_payloads::SignatureMaterial::NonEmptyString(value) => {
            Some(value.as_str())
        }
        arkret_models_collaboration::events_payloads::SignatureMaterial::Variant1(value) => {
            value.get("signature").and_then(serde_json::Value::as_str)
        }
    }
    .ok_or_else(|| Error::Protocol("device_authorize_device_signature_invalid".to_owned()))
}
