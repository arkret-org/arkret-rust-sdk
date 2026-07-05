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
//! opened by the client crypto layer using **standard RFC 9180 HPKE base mode**
//! (SetupBaseS / SetupBaseR) with DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 +
//! ChaCha20-Poly1305 (96-bit nonce). The AEAD nonce is the key-schedule-derived
//! `base_nonce` (single-shot seq=0), never carried on the wire; the plaintext
//! never appears on the wire in cleartext. See hpke-suite-registry.json for the
//! suite vocabulary.

use chacha20poly1305::ChaCha20Poly1305;
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
/// v1 default-MUST device HPKE suite in `device-lifecycle.md` §4 / the
/// `ck.hpke_x25519_aead_chacha20poly1305.v1` label used by
/// file-transfer.schema.json (RFC 9180 base mode).
pub const HPKE_SECRET_SHARE_SCHEME: &str = "ck.hpke_x25519_aead_chacha20poly1305.v1";

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
    /// base64url ephemeral X25519 public key (the RFC 9180 DHKEM encapsulation
    /// `enc`).
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

// ─── RFC 9180 HPKE base-mode sealing ─────────────────────────────────────────
//
// Standard RFC 9180 HPKE, base mode, single-shot seal. Suite:
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305 (the v1
// default-MUST `ck.hpke_x25519_aead_chacha20poly1305.v1`). Used both by the
// history-secret share below and by yougen's `hpke_backup` path — call these
// helpers instead of re-implementing the primitive stack downstream.
//
// The wire blob is `base64url(enc(32) || ciphertext)` where `enc` is the DHKEM
// encapsulated key (the ephemeral X25519 public key). The AEAD nonce is the
// key-schedule-derived `base_nonce` (single-shot seq=0), NOT carried on the
// wire; each seal mints a fresh ephemeral so base_nonce is unique per envelope.

/// HKDF info / AEAD-AAD domain separator for the history-secret seal.
const HISTORY_SEAL_INFO: &[u8] = b"ck-realm-history-secret-share-v1";

// RFC 9180 algorithm ids for the v1 default-MUST suite.
const HPKE_KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const HPKE_KDF_ID: u16 = 0x0001; // HKDF-SHA256
const HPKE_AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305
const HPKE_NK: usize = 32; // ChaCha20Poly1305 key length
const HPKE_NN: usize = 12; // ChaCha20Poly1305 nonce length

fn kem_suite_id() -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
    v
}

fn hpke_suite_id() -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
    v.extend_from_slice(&HPKE_KDF_ID.to_be_bytes());
    v.extend_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    v
}

/// RFC 9180 §4 `LabeledExtract(salt, label, ikm)` → 32-byte PRK.
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    // An empty salt maps to HKDF-Extract's HashLen-zero salt (None), which is
    // byte-identical to RFC 9180's `salt = ""` case.
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, &labeled_ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// RFC 9180 §4 `LabeledExpand(prk, label, info, L)`.
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let mut labeled_info = Vec::with_capacity(9 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| Error::Crypto("hpke labeled-expand prk length".to_owned()))?;
    let mut out = vec![0u8; length];
    hkdf.expand(&labeled_info, &mut out)
        .map_err(|_| Error::Crypto("hpke labeled-expand failed".to_owned()))?;
    Ok(out)
}

/// RFC 9180 §4.1 `DHKEM(X25519,…).ExtractAndExpand`: derive the DHKEM shared
/// secret from the raw X25519 DH output and `kem_context = enc || pkRm`.
fn dhkem_shared_secret(dh: &[u8; 32], enc: &[u8; 32], pk_r: &[u8; 32]) -> Result<[u8; 32]> {
    let kem_id = kem_suite_id();
    let eae_prk = labeled_extract(&kem_id, b"", b"eae_prk", dh);
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(pk_r);
    let ss = labeled_expand(&kem_id, &eae_prk, b"shared_secret", &kem_context, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&ss);
    Ok(out)
}

/// RFC 9180 §5.1 `KeySchedule` (mode_base, psk = psk_id = ""): derive the AEAD
/// `key` and `base_nonce` from the DHKEM shared secret and the HPKE `info`.
fn key_schedule_base(shared_secret: &[u8; 32], info: &[u8]) -> Result<([u8; 32], [u8; HPKE_NN])> {
    let suite = hpke_suite_id();
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + 32 + 32);
    ks_context.push(0x00); // mode_base
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);
    let secret = labeled_extract(&suite, shared_secret, b"secret", b"");
    let key = labeled_expand(&suite, &secret, b"key", &ks_context, HPKE_NK)?;
    let base_nonce = labeled_expand(&suite, &secret, b"base_nonce", &ks_context, HPKE_NN)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(&key);
    let mut n = [0u8; HPKE_NN];
    n.copy_from_slice(&base_nonce);
    Ok((k, n))
}

/// Shared context derivation for seal (`enc = ephemeral pub`, `dh = DH(skE, pkR)`)
/// and open (`enc` from wire, `dh = DH(skR, pkE)`): both feed the same DHKEM
/// shared secret and base-mode key schedule.
fn hpke_context(
    dh: &[u8; 32],
    enc: &[u8; 32],
    recipient_pub: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], [u8; HPKE_NN])> {
    if dh.iter().all(|b| *b == 0) {
        return Err(Error::Protocol(
            "hpke x25519 shared secret must not be all zero".to_owned(),
        ));
    }
    let shared = dhkem_shared_secret(dh, enc, recipient_pub)?;
    key_schedule_base(&shared, info)
}

/// RFC 9180 base-mode single-shot seal to a recipient X25519 public key.
/// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305: a fresh
/// ephemeral keypair is generated per seal, the DHKEM shared secret and base
/// key schedule derive the AEAD key and `base_nonce`, and `plaintext` is sealed
/// under `base_nonce` (seq=0) with the caller-provided `aad`. The wire blob is
/// `base64url(enc(32) || ciphertext)`.
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
    // `enc` is the DHKEM encapsulated key = serialized ephemeral public key.
    let enc = *X25519PublicKey::from(&ephemeral).as_bytes();
    let dh = ephemeral.diffie_hellman(&recipient_public);

    let (key, nonce) = hpke_context(dh.as_bytes(), &enc, &recipient_pub, info)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("invalid hpke AEAD key".to_owned()))?;
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("hpke seal AEAD encryption failed".to_owned()))?;

    let mut blob = Vec::with_capacity(32 + ciphertext.len());
    blob.extend_from_slice(&enc);
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
            "hpke seal blob too short to contain enc + ciphertext".to_owned(),
        ));
    }
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&blob[..32]);
    let ciphertext = &blob[32..];

    let ephemeral_public = X25519PublicKey::from(enc);
    let dh = recipient_secret.diffie_hellman(&ephemeral_public);

    let (key, nonce) = hpke_context(dh.as_bytes(), &enc, &recipient_pub, info)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("invalid hpke AEAD key".to_owned()))?;
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("hpke open AEAD tag check failed".to_owned()))
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn unhex32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// RFC 9180 base-mode known-answer test for
    /// `ck.hpke_x25519_aead_chacha20poly1305.v1`, byte-for-byte against the
    /// official CFRG vectors mirrored in
    /// `cokret-spec/.../fixtures/hpke-suite-fixture.json`
    /// (`ck.vector.hpke.x25519_chacha20poly1305_base.v1`). Proves the SetupBase
    /// / DHKEM / key-schedule / seal path is RFC 9180 conformant.
    #[test]
    fn rfc9180_chacha20poly1305_base_kat() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let sk_em = unhex32("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        let pk_em = unhex32("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let sk_rm = unhex32("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let pk_rm = unhex32("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let want_shared =
            unhex32("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
        let want_key = unhex32("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91");
        let want_base_nonce = unhex("5c4d98150661b848853b547f");
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let aad0 = unhex("436f756e742d30");
        let want_ct0 = unhex(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        );

        // DeriveKeyPair fidelity: our X25519 public key from the vector's skEm
        // matches the vector's pkEm, and the recipient likewise.
        let eph = StaticSecret::from(sk_em);
        assert_eq!(*X25519PublicKey::from(&eph).as_bytes(), pk_em, "pkEm");
        let recipient = StaticSecret::from(sk_rm);
        assert_eq!(*X25519PublicKey::from(&recipient).as_bytes(), pk_rm, "pkRm");

        // DHKEM.Encap(pkR) with the fixed ephemeral → shared secret.
        let dh = eph.diffie_hellman(&X25519PublicKey::from(pk_rm));
        let shared = dhkem_shared_secret(dh.as_bytes(), &pk_em, &pk_rm).unwrap();
        assert_eq!(shared, want_shared, "DHKEM shared_secret");

        // Base-mode key schedule → key + base_nonce.
        let (key, base_nonce) = key_schedule_base(&shared, &info).unwrap();
        assert_eq!(key, want_key, "key");
        assert_eq!(base_nonce.to_vec(), want_base_nonce, "base_nonce");

        // Seal seq=0 (nonce = base_nonce) reproduces the KAT ciphertext.
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ct = cipher
            .encrypt(&base_nonce.into(), Payload { msg: &pt, aad: &aad0 })
            .unwrap();
        assert_eq!(ct, want_ct0, "seal ciphertext");

        // DHKEM.Decap(enc, skR) on the recipient side yields the same context.
        let dh_r = recipient.diffie_hellman(&X25519PublicKey::from(pk_em));
        let shared_r = dhkem_shared_secret(dh_r.as_bytes(), &pk_em, &pk_rm).unwrap();
        assert_eq!(shared_r, want_shared, "decap shared_secret");
    }

    #[test]
    fn hpke_seal_open_roundtrips_and_rejects_tamper() {
        let recipient_priv = StaticSecret::from([13u8; 32]);
        let recipient_pub = *X25519PublicKey::from(&recipient_priv).as_bytes();
        let pt = b"account-secret-bytes";
        let info = b"ck-test-info-v1";
        let aad = b"ck-test-aad-v1";

        let sealed = seal_base_mode_to_x25519_pubkey(&recipient_pub, pt, info, aad).unwrap();
        let opened = open_base_mode_with_x25519_privkey(
            recipient_priv.to_bytes().as_slice(),
            &sealed,
            info,
            aad,
        )
        .unwrap();
        assert_eq!(opened, pt);

        // Wrong aad fails the AEAD tag.
        assert!(
            open_base_mode_with_x25519_privkey(
                recipient_priv.to_bytes().as_slice(),
                &sealed,
                info,
                b"wrong-aad"
            )
            .is_err()
        );
        // Wrong recipient key fails.
        let wrong = StaticSecret::from([14u8; 32]);
        assert!(
            open_base_mode_with_x25519_privkey(wrong.to_bytes().as_slice(), &sealed, info, aad)
                .is_err()
        );
    }
}
