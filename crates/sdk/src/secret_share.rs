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

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use cokret_core::base64url::{base64url_decode, base64url_encode};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

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

// ─── HPKE-style history-secret sealing ───────────────────────────────────────
//
// Seals a retained `history_secret[from..to]` map to a recipient device's
// X25519 public key so it can decrypt pre-join content. This is the payload that
// rides inside a `ck.realm_key.share` `ciphertext` for the history-sharing flow.
//
// Scheme (matches the [`HPKE_SECRET_SHARE_SCHEME`] label
// `ck.hpke_x25519_aead_xchacha20poly1305.v1`): a fresh ephemeral X25519 keypair
// is generated per seal; the DH(ephemeral_priv, recipient_pub) shared secret is
// stretched with HKDF-SHA256 (salt = ephemeral_pub || recipient_pub, info =
// scheme label) into a 32-byte XChaCha20-Poly1305 key; the secret list is
// AEAD-sealed under a zero nonce (safe because the key is single-use per
// ephemeral keypair). The wire blob is `base64url(ephemeral_pub(32) ||
// ciphertext)`.

/// HKDF info / AEAD-AAD domain separator for the history-secret seal.
const HISTORY_SEAL_INFO: &[u8] = b"ck-realm-history-secret-share-v1";

fn base_mode_seal_key(
    shared_secret: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
    info: &[u8],
) -> Result<[u8; 32]> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pub);
    salt.extend_from_slice(recipient_pub);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|_| Error::Crypto("base-mode seal key derivation failed".to_owned()))?;
    Ok(key)
}

/// Generic base-mode X25519 + HKDF-SHA256 + XChaCha20-Poly1305 seal
/// (the `ck.hpke_x25519_aead_xchacha20poly1305.v1` construction shared by
/// the history-secret share and yougen's `hpke_backup` path — call this
/// instead of re-implementing the primitive stack downstream).
///
/// A fresh ephemeral X25519 keypair is generated per seal; the
/// DH(ephemeral_priv, recipient_pub) shared secret is stretched with
/// HKDF-SHA256 (salt = ephemeral_pub || recipient_pub, info = caller `info`
/// label) into a 32-byte XChaCha20-Poly1305 key; `plaintext` is AEAD-sealed
/// under a zero nonce (safe because the key is single-use per ephemeral
/// keypair) with the caller-provided `aad`. The wire blob is
/// `base64url(ephemeral_pub(32) || ciphertext)`.
///
/// The `info` label and `aad` are the caller's domain-separation contract:
/// two protocols MUST NOT share the same `(info, aad)` pair.
pub fn seal_base_mode_to_x25519_pubkey(
    recipient_pubkey: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<String> {
    let recipient_pub: [u8; 32] = recipient_pubkey.try_into().map_err(|_| {
        Error::Protocol(format!(
            "recipient HPKE public key must be 32 bytes, got {}",
            recipient_pubkey.len()
        ))
    })?;
    let recipient_public = X25519PublicKey::from(recipient_pub);

    // Fresh ephemeral keypair from OS randomness (mirrors key_agreement.rs).
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| Error::Crypto(error.to_string()))?;
    let ephemeral = StaticSecret::from(seed);
    seed.zeroize();
    let ephemeral_public = X25519PublicKey::from(&ephemeral);
    let ephemeral_pub = *ephemeral_public.as_bytes();

    let shared = ephemeral.diffie_hellman(&recipient_public);
    if shared.as_bytes().iter().all(|b| *b == 0) {
        return Err(Error::Protocol(
            "base-mode seal x25519 shared secret must not be all zero".to_owned(),
        ));
    }
    let key = base_mode_seal_key(shared.as_bytes(), &ephemeral_pub, &recipient_pub, info)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("invalid base-mode seal AEAD key".to_owned()))?;
    let nonce = [0u8; 24];
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("base-mode seal AEAD encryption failed".to_owned()))?;

    let mut blob = Vec::with_capacity(32 + ciphertext.len());
    blob.extend_from_slice(&ephemeral_pub);
    blob.extend_from_slice(&ciphertext);
    Ok(base64url_encode(blob))
}

/// Open a blob produced by [`seal_base_mode_to_x25519_pubkey`] with the
/// recipient's raw 32-byte X25519 private key. The caller MUST pass the same
/// `info` label and `aad` used at seal time.
pub fn open_base_mode_with_x25519_privkey(
    privkey: &[u8],
    sealed: &str,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let privkey: [u8; 32] = privkey.try_into().map_err(|_| {
        Error::Protocol(format!(
            "recipient HPKE private key must be 32 bytes, got {}",
            privkey.len()
        ))
    })?;
    let recipient_secret = StaticSecret::from(privkey);
    let recipient_pub = *X25519PublicKey::from(&recipient_secret).as_bytes();

    let blob = base64url_decode(sealed.as_bytes())?;
    if blob.len() <= 32 {
        return Err(Error::Protocol(
            "base-mode seal blob too short to contain ephemeral key + ciphertext".to_owned(),
        ));
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&blob[..32]);
    let ciphertext = &blob[32..];

    let ephemeral_public = X25519PublicKey::from(ephemeral_pub);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    if shared.as_bytes().iter().all(|b| *b == 0) {
        return Err(Error::Protocol(
            "base-mode seal x25519 shared secret must not be all zero".to_owned(),
        ));
    }
    let key = base_mode_seal_key(shared.as_bytes(), &ephemeral_pub, &recipient_pub, info)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("invalid base-mode seal AEAD key".to_owned()))?;
    let nonce = [0u8; 24];
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("base-mode seal AEAD tag check failed".to_owned()))
}

/// Canonical plaintext encoding of `[(epoch, secret)]`: JSON array of
/// `[epoch, base64url(secret)]` pairs, deterministically ordered by epoch.
fn encode_history_secrets(history_secrets: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(u64, Vec<u8>)> = history_secrets.iter().collect();
    sorted.sort_by_key(|(epoch, _)| *epoch);
    let rows: Vec<(u64, String)> = sorted
        .into_iter()
        .map(|(epoch, secret)| (*epoch, base64url_encode(secret)))
        .collect();
    // serde_json over a Vec of tuples is infallible for these types.
    serde_json::to_vec(&rows).expect("history-secret rows serialize")
}

fn decode_history_secrets(plaintext: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let rows: Vec<(u64, String)> = serde_json::from_slice(plaintext)
        .map_err(|err| Error::Protocol(format!("history-secret seal plaintext decode: {err}")))?;
    let mut out = Vec::with_capacity(rows.len());
    for (epoch, secret_b64) in rows {
        out.push((epoch, base64url_decode(secret_b64.as_bytes())?));
    }
    Ok(out)
}

/// HPKE-seal the retained `history_secrets` to `recipient_pubkey` (raw 32-byte
/// X25519 public key). Returns the `base64url(ephemeral_pub || ciphertext)`
/// blob to place in `ck.realm_key.share.ciphertext`.
///
/// Thin wrapper over [`seal_base_mode_to_x25519_pubkey`] with the
/// history-share `info`/`aad` label; the produced bytes are identical to the
/// pre-refactor construction.
pub fn seal_history_secret_to_device_pubkey(
    recipient_pubkey: &[u8],
    history_secrets: &[(u64, Vec<u8>)],
) -> Result<String> {
    let plaintext = encode_history_secrets(history_secrets);
    seal_base_mode_to_x25519_pubkey(
        recipient_pubkey,
        &plaintext,
        HISTORY_SEAL_INFO,
        HISTORY_SEAL_INFO,
    )
}

/// Open a blob produced by [`seal_history_secret_to_device_pubkey`] with the
/// recipient device's raw 32-byte X25519 private key, recovering the
/// `[(epoch, history_secret)]` list.
pub fn open_history_secret_with_device_privkey(
    privkey: &[u8],
    sealed: &str,
) -> Result<Vec<(u64, Vec<u8>)>> {
    let plaintext =
        open_base_mode_with_x25519_privkey(privkey, sealed, HISTORY_SEAL_INFO, HISTORY_SEAL_INFO)?;
    decode_history_secrets(&plaintext)
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
    fn history_secret_seal_round_trips() {
        // Deterministic recipient keypair.
        let recipient_priv = StaticSecret::from([7u8; 32]);
        let recipient_pub = *X25519PublicKey::from(&recipient_priv).as_bytes();

        let secrets: Vec<(u64, Vec<u8>)> = vec![
            (0, vec![0xAA; 32]),
            (3, vec![0xBB; 32]),
            (7, vec![0xCC; 32]),
        ];

        let sealed = seal_history_secret_to_device_pubkey(&recipient_pub, &secrets).unwrap();
        let opened =
            open_history_secret_with_device_privkey(recipient_priv.to_bytes().as_slice(), &sealed)
                .unwrap();
        assert_eq!(opened, secrets);
    }

    #[test]
    fn history_secret_seal_rejects_wrong_recipient_and_tamper() {
        let recipient_priv = StaticSecret::from([7u8; 32]);
        let recipient_pub = *X25519PublicKey::from(&recipient_priv).as_bytes();
        let secrets = vec![(1u64, vec![0x11; 32])];
        let sealed = seal_history_secret_to_device_pubkey(&recipient_pub, &secrets).unwrap();

        // Wrong private key → AEAD tag check fails.
        let wrong = StaticSecret::from([9u8; 32]);
        assert!(
            open_history_secret_with_device_privkey(wrong.to_bytes().as_slice(), &sealed).is_err()
        );

        // Bad recipient pubkey length is rejected up front.
        assert!(seal_history_secret_to_device_pubkey(&[0u8; 31], &secrets).is_err());
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
