use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_wire::{
    DeviceId, DidKey, DidUrl, EventId, PrincipalAuthorityKey, project_full_id_to_core_id,
};

use crate::proof::PublicKeyMaterial;
use crate::{Error, Result, verify_detached_ed25519_signature};

/// Host-local result of validating a principal device against the current PCR
/// state. This token is intentionally not serializable and is never accepted as
/// federation evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPrincipalDevice {
    authority: PrincipalAuthorityKey,
    device_id: DeviceId,
    verification_method: DidUrl,
    signing_key: DidKey,
    authorize_event_id: EventId,
    device_generation: u64,
}

impl VerifiedPrincipalDevice {
    pub fn from_local_pcr_state(
        authority: PrincipalAuthorityKey,
        device_id: DeviceId,
        verification_method: DidUrl,
        signing_key: DidKey,
        authorize_event_id: EventId,
        device_generation: u64,
    ) -> Result<Self> {
        let (controller, fragment) =
            verification_method
                .as_str()
                .split_once('#')
                .ok_or_else(|| {
                    Error::Protocol("device verification method has no fragment".to_owned())
                })?;
        let controller = arkret_wire::DidFullId::new(controller.to_owned())?;
        if fragment != device_id.as_str()
            || project_full_id_to_core_id(&controller)? != authority.principal_id
        {
            return Err(Error::Protocol(
                "local principal device does not bind its authority and device id".to_owned(),
            ));
        }
        Ok(Self {
            authority,
            device_id,
            verification_method,
            signing_key,
            authorize_event_id,
            device_generation,
        })
    }

    pub fn authority(&self) -> &PrincipalAuthorityKey {
        &self.authority
    }

    pub fn principal_id(&self) -> &arkret_wire::DidCoreId {
        &self.authority.principal_id
    }

    pub fn principal_server_id(&self) -> &arkret_wire::DidCoreId {
        &self.authority.principal_server_id
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn verification_method(&self) -> &DidUrl {
        &self.verification_method
    }

    pub fn signing_key(&self) -> &DidKey {
        &self.signing_key
    }

    pub fn authorize_event_id(&self) -> &EventId {
        &self.authorize_event_id
    }

    pub fn device_generation(&self) -> u64 {
        self.device_generation
    }
}

/// Verify the Ed25519 proof of possession over the SDK-owned device
/// authorization transcript.
pub fn verify_device_authorize_possession(payload: &DeviceAuthorizePayload) -> Result<()> {
    payload
        .validate_wire_constraints()
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
    let signature = device_authorize_signature_value(&payload.device_signature)?;
    let public_key = payload
        .device_public_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::Protocol("device_authorize_device_public_key_invalid".to_owned()))?;
    let key = PublicKeyMaterial::Ed25519Multibase {
        value: public_key.to_owned(),
    };
    let transcript = payload.device_possession_signature_input()?;
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
