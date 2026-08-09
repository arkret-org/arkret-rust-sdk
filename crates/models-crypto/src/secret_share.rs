//! Typed content carried by the standard `ak.secret.*` device messages.

use arkret_wire::{DeviceId, Error, HPKE_SUITE_X25519_CHACHA20POLY1305_V1, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretShareRequestContent {
    pub request_id: String,
    pub secret_id: String,
    pub from_device: DeviceId,
    pub recipient_hpke_public_key: String,
}

impl SecretShareRequestContent {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.request.request_id must not be empty".to_owned(),
            ));
        }
        if self.secret_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.request.secret_id must not be empty".to_owned(),
            ));
        }
        if self.recipient_hpke_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.request.recipient_hpke_public_key must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretShareSendContent {
    pub request_id: String,
    pub secret_id: String,
    pub from_device: DeviceId,
    pub scheme: String,
    pub enc: String,
    pub ciphertext: String,
}

impl SecretShareSendContent {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.send.request_id must not be empty".to_owned(),
            ));
        }
        if self.secret_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.send.secret_id must not be empty".to_owned(),
            ));
        }
        if self.scheme != HPKE_SUITE_X25519_CHACHA20POLY1305_V1 {
            return Err(Error::Protocol(format!(
                "ak.secret.send.scheme must be {HPKE_SUITE_X25519_CHACHA20POLY1305_V1}, got {}",
                self.scheme
            )));
        }
        if self.enc.trim().is_empty() || self.ciphertext.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.send.enc and ciphertext must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}
