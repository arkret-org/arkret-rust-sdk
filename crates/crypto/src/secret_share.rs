//! Device-to-device secret sharing over the Arkret RFC 9180 HPKE profile.
//!
//! This module owns the stable cryptographic boundary shared by clients. It
//! deliberately does not encode a synchronization or history state machine;
//! callers bind the ciphertext to a concrete device-message envelope and use
//! committed protocol events for authorization and progress.

use arkret_models_crypto::{SecretShareRequestContent, SecretShareSendContent};
pub use arkret_models_crypto::{
    SecretShareRequestContent as RequestContent, SecretShareSendContent as SendContent,
};
use arkret_wire::{DeviceId, HPKE_SUITE_X25519_CHACHA20POLY1305_V1};

use crate::{Error, Result};

/// Wire `kind` for a secret request.
pub const SECRET_REQUEST_KIND: &str = arkret_wire::SECRET_REQUEST_KIND;
/// Wire `kind` for a sealed secret response.
pub const SECRET_SEND_KIND: &str = arkret_wire::SECRET_SEND_KIND;

/// Canonical HPKE AAD for an `ak.secret.send` device message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretShareSendAad<'a> {
    pub device_message_id: &'a arkret_wire::DeviceMessageId,
    pub sender_principal_id: &'a arkret_wire::DidCoreId,
    pub sender_device_id: &'a DeviceId,
    pub recipient_principal_id: &'a arkret_wire::DidCoreId,
    pub recipient_device_id: &'a DeviceId,
    pub request_id: &'a str,
    pub secret_id: &'a str,
    pub expires_at: &'a str,
}

impl SecretShareSendAad<'_> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        arkret_canonical::validate_timestamp_canonical(self.expires_at).map_err(|error| {
            Error::Protocol(format!(
                "invalid secret-share expires_at {:?}: {error}",
                self.expires_at
            ))
        })?;
        if self.request_id.trim().is_empty() || self.secret_id.trim().is_empty() {
            return Err(Error::Protocol(
                "secret-share AAD requires non-empty request_id and secret_id".to_owned(),
            ));
        }
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "device_message_id": self.device_message_id.as_str(),
            "kind": SECRET_SEND_KIND,
            "sender_principal_id": self.sender_principal_id.as_str(),
            "sender_device_id": self.sender_device_id.as_str(),
            "recipient_principal_id": self.recipient_principal_id.as_str(),
            "recipient_device_id": self.recipient_device_id.as_str(),
            "request_id": self.request_id,
            "secret_id": self.secret_id,
            "expires_at": self.expires_at,
        }))
        .map_err(|error| Error::Protocol(format!("canonicalize secret-share AAD: {error}")))
    }
}

/// Seal bytes to a raw X25519 public key using the registered base-mode suite.
pub fn seal_base_mode_to_x25519_pubkey(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<String> {
    crate::hpke::seal_x25519_chacha20poly1305(recipient_public_key, plaintext, info, aad)
}

/// Open a value produced by [`seal_base_mode_to_x25519_pubkey`].
pub fn open_base_mode_with_x25519_privkey(
    recipient_private_key: &[u8],
    sealed: &str,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    crate::hpke::open_x25519_chacha20poly1305(recipient_private_key, sealed, info, aad)
}

/// Assemble typed response content from a framed HPKE value.
pub fn send_content_from_sealed(
    request: &SecretShareRequestContent,
    from_device_id: DeviceId,
    sealed: &str,
) -> Result<SecretShareSendContent> {
    request.validate()?;
    let framed = arkret_canonical::base64url::base64url_decode(sealed.as_bytes())?;
    if framed.len() <= 32 {
        return Err(Error::Protocol(
            "HPKE value is too short to contain an encapsulated key and ciphertext".to_owned(),
        ));
    }
    let content = SecretShareSendContent {
        request_id: request.request_id.clone(),
        secret_id: request.secret_id.clone(),
        from_device_id,
        scheme: HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned(),
        enc: arkret_canonical::base64url::base64url_encode(&framed[..32]),
        ciphertext: arkret_canonical::base64url::base64url_encode(&framed[32..]),
    };
    content.validate()?;
    Ok(content)
}

/// Reassemble the HPKE frame carried by typed response content.
pub fn sealed_from_send_content(content: &SecretShareSendContent) -> Result<String> {
    content.validate()?;
    let enc = arkret_canonical::base64url::base64url_decode(content.enc.as_bytes())?;
    if enc.len() != 32 {
        return Err(Error::Protocol(
            "secret-share HPKE enc must decode to exactly 32 bytes".to_owned(),
        ));
    }
    let ciphertext = arkret_canonical::base64url::base64url_decode(content.ciphertext.as_bytes())?;
    if ciphertext.is_empty() {
        return Err(Error::Protocol(
            "secret-share HPKE ciphertext must not be empty".to_owned(),
        ));
    }
    let mut framed = Vec::with_capacity(enc.len() + ciphertext.len());
    framed.extend_from_slice(&enc);
    framed.extend_from_slice(&ciphertext);
    Ok(arkret_canonical::base64url::base64url_encode(framed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_aad_identifiers_before_crypto() {
        let message = arkret_wire::DeviceMessageId::new(
            "ak:device_message:01904100-0000-7000-8000-0000000000d1".to_owned(),
        )
        .unwrap();
        let principal =
            arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap();
        let device =
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000a".to_owned()).unwrap();
        let error = SecretShareSendAad {
            device_message_id: &message,
            sender_principal_id: &principal,
            sender_device_id: &device,
            recipient_principal_id: &principal,
            recipient_device_id: &device,
            request_id: "",
            secret_id: "account-secret",
            expires_at: "2026-09-16T00:00:00.000Z",
        }
        .canonical_bytes()
        .unwrap_err();
        assert!(error.to_string().contains("request_id"));
    }
}
