//! Typed to-device secret-share content per `crypto-media/device-lifecycle.md` §10.7.
//!
//! Two `ak.secret.*` to-device kinds let a newly authorized device pull an
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
//! ChaCha20-Poly1305 (96-bit nonce), via the audited `hpke` crate
//! (rozbb/rust-hpke). The AEAD nonce is the key-schedule-derived `base_nonce`
//! (single-shot seq=0), never carried on the wire; the plaintext never appears
//! on the wire unencrypted. See hpke-suite-registry.json for the suite
//! vocabulary.

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_wire::DeviceId;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, single_shot_open, single_shot_seal};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Wire `kind` for the secret request (`ak.secret.request`).
pub const SECRET_REQUEST_KIND: &str = "ak.secret.request";
/// Wire `kind` for the sealed secret response (`ak.secret.send`).
pub const SECRET_SEND_KIND: &str = "ak.secret.send";

/// HPKE scheme label required on `ak.secret.send` content. Matches the
/// v1 default-MUST device HPKE suite in `device-lifecycle.md` §4 / the
/// `ak.hpke_x25519_aead_chacha20poly1305.v1` label used by
/// file-transfer.schema.json (RFC 9180 base mode).
pub const HPKE_SECRET_SHARE_SCHEME: &str = "ak.hpke_x25519_aead_chacha20poly1305.v1";

/// `secret_id` for the inkson MLS account secret — the only secret class the
/// D2D direct-share path ships in v1. Kept here so client and conformance code
/// agree on the exact opaque token.
pub const SECRET_ID_MLS_ACCOUNT: &str = "inkson_mls_account_secret";

/// `ak.secret.request.content` — a newly authorized device asks an existing
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

/// `ak.secret.send.content` — the existing authorized device returns the
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
                "ak.secret.send.request_id must not be empty".to_owned(),
            ));
        }
        if self.secret_id.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.secret.send.secret_id must not be empty".to_owned(),
            ));
        }
        if self.scheme != HPKE_SECRET_SHARE_SCHEME {
            return Err(Error::Protocol(format!(
                "ak.secret.send.scheme must be {HPKE_SECRET_SHARE_SCHEME}, got {}",
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

// ─── RFC 9180 HPKE base-mode sealing (via the `hpke` crate) ──────────────────
//
// Standard RFC 9180 HPKE base mode, single-shot seal. Suite:
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305 (the v1
// default-MUST `ak.hpke_x25519_aead_chacha20poly1305.v1`). The crypto is the
// audited rozbb/rust-hpke crate; this module owns only the wire framing and the
// caller (info, aad) domain-separation contract. Used by the history-secret
// share below and by inkson's `hpke_backup` path.
//
// The wire blob is `base64url(enc(Npk=32) || ciphertext)` where `enc` is the
// DHKEM encapsulated key. The AEAD nonce is the key-schedule-derived
// `base_nonce` (single-shot seq=0), NOT carried on the wire.

/// HKDF info / AEAD-AAD domain separator for the history-secret seal.
const HISTORY_SEAL_INFO: &[u8] = b"ak.realm-history-secret-share-v1";

// The v1 default-MUST HPKE suite as `hpke`-crate trait types.
type HpkeKem = X25519HkdfSha256;
type HpkeAead = ChaCha20Poly1305;
type HpkeKdf = HkdfSha256;

/// DHKEM(X25519) encapsulated-key length (RFC 9180 `Npk`); fixed at 32 bytes.
const HPKE_ENC_LEN: usize = 32;

/// Minimal CSPRNG adapter over `getrandom` for the `hpke` crate's rand_core 0.9
/// RNG interface. Only used to mint the per-seal ephemeral DHKEM keypair.
struct OsCsRng;

impl rand_core_09::RngCore for OsCsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::fill(dst).expect("OS CSPRNG must not fail");
    }
}

impl rand_core_09::CryptoRng for OsCsRng {}

/// RFC 9180 base-mode single-shot seal to a recipient X25519 public key
/// (`ak.hpke_x25519_aead_chacha20poly1305.v1`), via the `hpke` crate. A fresh
/// ephemeral keypair is generated per seal. The wire blob is
/// `base64url(enc || ciphertext)`.
///
/// The `info` label and `aad` are the caller's domain-separation contract:
/// two protocols MUST NOT share the same `(info, aad)` pair.
pub fn seal_base_mode_to_x25519_pubkey(
    recipient_pubkey: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<String> {
    let recipient_pub =
        <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient_pubkey).map_err(|_| {
            Error::Protocol(format!(
                "recipient HPKE public key must be a valid 32-byte X25519 key, got {} bytes",
                recipient_pubkey.len()
            ))
        })?;

    // Probe the OS CSPRNG up front so an unavailable entropy source (early
    // boot, seccomp-restricted `getrandom`) surfaces as a propagated
    // `Error::Crypto` instead of panicking inside `OsCsRng::fill_bytes`
    // (the rand_core trait offers no fallible variant, so the seal path
    // cannot otherwise recover).
    let mut rng_probe = [0u8; 1];
    getrandom::fill(&mut rng_probe)
        .map_err(|err| Error::Crypto(format!("OS CSPRNG unavailable for HPKE seal: {err}")))?;

    let (encapped, ciphertext) = single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &recipient_pub,
        info,
        plaintext,
        aad,
        &mut OsCsRng,
    )
    .map_err(|_| Error::Crypto("hpke seal failed".to_owned()))?;

    let enc = encapped.to_bytes();
    let mut blob = Vec::with_capacity(enc.len() + ciphertext.len());
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
    let recipient_secret =
        <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(privkey).map_err(|_| {
            Error::Protocol(format!(
                "recipient HPKE private key must be a valid 32-byte X25519 key, got {} bytes",
                privkey.len()
            ))
        })?;

    let blob = base64url_decode(sealed.as_bytes())?;
    if blob.len() <= HPKE_ENC_LEN {
        return Err(Error::Protocol(
            "hpke seal blob too short to contain enc + ciphertext".to_owned(),
        ));
    }
    let (enc_bytes, ciphertext) = blob.split_at(HPKE_ENC_LEN);
    let encapped = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|_| Error::Protocol("hpke enc (encapsulated key) invalid".to_owned()))?;

    single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeR::Base,
        &recipient_secret,
        &encapped,
        info,
        ciphertext,
        aad,
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
/// blob to place in `ak.realm_key.share.ciphertext`.
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
        DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000a").unwrap()
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

    /// Fresh X25519 recovery/device keypair `(priv, pub)` as raw bytes, minted
    /// via the `hpke` crate so the tests do not re-derive X25519 by hand.
    fn hpke_keypair() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = <HpkeKem as hpke::Kem>::gen_keypair(&mut OsCsRng);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }

    #[test]
    fn history_secret_seal_round_trips() {
        let (recipient_priv, recipient_pub) = hpke_keypair();

        let secrets: Vec<(u64, Vec<u8>)> = vec![
            (0, vec![0xAA; 32]),
            (3, vec![0xBB; 32]),
            (7, vec![0xCC; 32]),
        ];

        let sealed = seal_history_secret_to_device_pubkey(&recipient_pub, &secrets).unwrap();
        let opened = open_history_secret_with_device_privkey(&recipient_priv, &sealed).unwrap();
        assert_eq!(opened, secrets);
    }

    #[test]
    fn history_secret_seal_rejects_wrong_recipient_and_tamper() {
        let (_recipient_priv, recipient_pub) = hpke_keypair();
        let secrets = vec![(1u64, vec![0x11; 32])];
        let sealed = seal_history_secret_to_device_pubkey(&recipient_pub, &secrets).unwrap();

        // Wrong private key → AEAD tag check fails.
        let (wrong_priv, _) = hpke_keypair();
        assert!(open_history_secret_with_device_privkey(&wrong_priv, &sealed).is_err());

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

    /// RFC 9180 base-mode known-answer test for
    /// `ak.hpke_x25519_aead_chacha20poly1305.v1`, against the official CFRG
    /// vector mirrored in `arkret-spec/.../fixtures/hpke-suite-fixture.json`
    /// (`ak.vector.hpke.x25519_chacha20poly1305_base.v1`). We reconstruct the
    /// on-wire blob `base64url(enc || ciphertext)` from the vector's `enc`
    /// (= pkEm) and first ciphertext, then drive our [`open_base_mode_with_x25519_privkey`]
    /// (→ the `hpke` crate's SetupBaseR) with the vector's skR, info and aad and
    /// assert it recovers the exact plaintext — proving suite selection + wire
    /// framing are RFC 9180 conformant end-to-end.
    #[test]
    fn rfc9180_chacha20poly1305_base_kat() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let sk_rm = unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        // enc == pkEm for DHKEM(X25519).
        let enc = unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let aad0 = unhex("436f756e742d30");
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let ct0 = unhex(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        );

        let mut blob = enc;
        blob.extend_from_slice(&ct0);
        let sealed = base64url_encode(blob);

        let opened = open_base_mode_with_x25519_privkey(&sk_rm, &sealed, &info, &aad0).unwrap();
        assert_eq!(opened, pt, "RFC 9180 KAT plaintext");

        // Same blob under the wrong aad MUST fail the AEAD tag.
        assert!(open_base_mode_with_x25519_privkey(&sk_rm, &sealed, &info, b"wrong-aad").is_err());
    }

    #[test]
    fn hpke_seal_open_roundtrips_and_rejects_tamper() {
        let (recipient_priv, recipient_pub) = hpke_keypair();
        let pt = b"account-secret-bytes";
        let info = b"ak.test-info-v1";
        let aad = b"ak.test-aad-v1";

        let sealed = seal_base_mode_to_x25519_pubkey(&recipient_pub, pt, info, aad).unwrap();
        let opened =
            open_base_mode_with_x25519_privkey(&recipient_priv, &sealed, info, aad).unwrap();
        assert_eq!(opened, pt);

        // Wrong aad fails the AEAD tag.
        assert!(
            open_base_mode_with_x25519_privkey(&recipient_priv, &sealed, info, b"wrong-aad")
                .is_err()
        );
        // Wrong recipient key fails.
        let (wrong_priv, _) = hpke_keypair();
        assert!(open_base_mode_with_x25519_privkey(&wrong_priv, &sealed, info, aad).is_err());
    }
}
