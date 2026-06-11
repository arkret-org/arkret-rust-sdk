//! Typed to-device secret-share content per `crypto-media/device-lifecycle.md` §10.7.
//!
//! Two `ck.secret.*` to-device kinds let a newly authorized device pull an
//! account-scope secret (e.g. the MLS account secret) from an existing
//! authorized device over HPKE, after the two devices completed SAS
//! verification (§10.3). This module provides the strongly-typed `content`
//! bodies that ride inside the `DeviceMessageEnvelope.content` field, mirroring
//! `artifacts/schemas/device-message.schema.json#/$defs/secret_request_content`
//! and `secret_send_content`.
//!
//! These structs carry **only** the wire-visible content. The sealed plaintext
//! (`{account_secret, secret_version, request_id, secret_id}`) is produced and
//! opened by the client crypto layer (HPKE RFC 9180); it never appears on the
//! wire in cleartext.

use serde::{Deserialize, Serialize};

use crate::{DeviceId, Error, Result};

/// Wire `kind` for the secret request (`ck.secret.request`).
pub const SECRET_REQUEST_KIND: &str = "ck.secret.request";
/// Wire `kind` for the sealed secret response (`ck.secret.send`).
pub const SECRET_SEND_KIND: &str = "ck.secret.send";

/// HPKE scheme label required on `ck.secret.send` content. Matches the
/// canonical device HPKE algorithm in `device-lifecycle.md` §4 / the
/// `ck.hpke_x25519_aead_xchacha20poly1305.v1` label used by
/// file-transfer.schema.json.
pub const HPKE_SECRET_SHARE_SCHEME: &str = "ck.hpke_x25519_aead_xchacha20poly1305.v1";

/// `secret_id` for the yougen MLS account secret — the only secret class the
/// D2D direct-share path ships in v1. Kept here so client and conformance code
/// agree on the exact opaque token.
pub const SECRET_ID_MLS_ACCOUNT: &str = "yougen_mls_account_secret";

/// `ck.secret.request.content` — a newly authorized device asks an existing
/// authorized device for `secret_id`, advertising the HPKE public key the
/// responder should seal to. Carries no secret material itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretShareRequestContent {
    /// Caller-generated random correlation id; MUST NOT be reused after the
    /// request is answered or cancelled.
    pub request_id: String,
    /// Opaque identifier of the requested secret, e.g.
    /// [`SECRET_ID_MLS_ACCOUNT`].
    pub secret_id: String,
    /// Requesting (new) device; MUST equal the envelope `sender_device_id`.
    pub from_device: DeviceId,
    /// base64url X25519 HPKE public key the requesting device controls and the
    /// responder seals to.
    pub recipient_hpke_public_key: String,
}

impl SecretShareRequestContent {
    /// Reject empty load-bearing fields before the content is shipped.
    pub fn validate(&self) -> Result<()> {
        if self.request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.secret.request.request_id must not be empty".to_owned(),
            ));
        }
        if self.secret_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.secret.request.secret_id must not be empty".to_owned(),
            ));
        }
        if self.recipient_hpke_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.secret.request.recipient_hpke_public_key must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// `ck.secret.send.content` — the existing authorized device returns the
/// requested secret HPKE-sealed to the requester's
/// `recipient_hpke_public_key`. The plaintext is never visible to the queue
/// service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretShareSendContent {
    /// Correlates to the pending [`SecretShareRequestContent::request_id`];
    /// MUST equal the `request_id` authenticated inside the sealed plaintext.
    pub request_id: String,
    /// Secret identifier, matching the request.
    pub secret_id: String,
    /// Authorizing (existing) device; MUST equal the envelope
    /// `sender_device_id` and MUST be a non-revoked device of the recipient
    /// principal.
    pub from_device: DeviceId,
    /// HPKE scheme label; MUST equal [`HPKE_SECRET_SHARE_SCHEME`].
    pub scheme: String,
    /// base64url HPKE (RFC 9180) encapsulated key (KEM output).
    pub enc: String,
    /// base64url HPKE AEAD ciphertext over the secret plaintext. The HPKE AAD
    /// MUST cover the envelope binding fields per `device-lifecycle.md` §7.
    pub ciphertext: String,
}

impl SecretShareSendContent {
    /// Reject a mis-labelled scheme or empty crypto material before the content
    /// is shipped or after it is received.
    pub fn validate(&self) -> Result<()> {
        if self.request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.secret.send.request_id must not be empty".to_owned(),
            ));
        }
        if self.secret_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.secret.send.secret_id must not be empty".to_owned(),
            ));
        }
        if self.scheme != HPKE_SECRET_SHARE_SCHEME {
            return Err(Error::Protocol(format!(
                "ck.secret.send.scheme must be {HPKE_SECRET_SHARE_SCHEME}, got {}",
                self.scheme
            )));
        }
        if self.enc.trim().is_empty() || self.ciphertext.trim().is_empty() {
            return Err(Error::Protocol(
                "ck.secret.send.enc and ciphertext must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn device() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000a").unwrap()
    }

    #[test]
    fn request_content_round_trips_and_validates() {
        let content = SecretShareRequestContent {
            request_id: "req-1".to_owned(),
            secret_id: SECRET_ID_MLS_ACCOUNT.to_owned(),
            from_device: device(),
            recipient_hpke_public_key: "cHVia2V5".to_owned(),
        };
        content.validate().unwrap();
        let value = serde_json::to_value(&content).unwrap();
        assert_eq!(value["secret_id"], json!(SECRET_ID_MLS_ACCOUNT));
        let parsed: SecretShareRequestContent = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, content);
    }

    #[test]
    fn send_content_round_trips_and_rejects_bad_scheme() {
        let content = SecretShareSendContent {
            request_id: "req-1".to_owned(),
            secret_id: SECRET_ID_MLS_ACCOUNT.to_owned(),
            from_device: device(),
            scheme: HPKE_SECRET_SHARE_SCHEME.to_owned(),
            enc: "ZW5j".to_owned(),
            ciphertext: "Y2lwaGVy".to_owned(),
        };
        content.validate().unwrap();
        let parsed: SecretShareSendContent =
            serde_json::from_value(serde_json::to_value(&content).unwrap()).unwrap();
        assert_eq!(parsed, content);

        let mut bad = content;
        bad.scheme = "mls-rfc9420".to_owned();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn request_content_rejects_empty_fields() {
        let content = SecretShareRequestContent {
            request_id: "  ".to_owned(),
            secret_id: SECRET_ID_MLS_ACCOUNT.to_owned(),
            from_device: device(),
            recipient_hpke_public_key: "cHVia2V5".to_owned(),
        };
        assert!(content.validate().is_err());
    }
}
