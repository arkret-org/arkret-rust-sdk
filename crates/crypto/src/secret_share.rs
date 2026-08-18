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
pub use arkret_models_crypto::{SecretShareRequestContent, SecretShareSendContent};
#[cfg(test)]
use arkret_wire::{DeviceId, HPKE_SUITE_X25519_CHACHA20POLY1305_V1};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, single_shot_open, single_shot_seal};

use crate::{Error, Result};

/// Wire `kind` for the secret request (`ak.secret.request`).
pub const SECRET_REQUEST_KIND: &str = arkret_wire::SECRET_REQUEST_KIND;
/// Wire `kind` for the sealed secret response (`ak.secret.send`).
pub const SECRET_SEND_KIND: &str = arkret_wire::SECRET_SEND_KIND;

/// `secret_id` for the inkson MLS account secret — the only secret class the
/// D2D direct-share path ships in v1. Kept here so client and conformance code
/// agree on the exact opaque token.
pub const SECRET_ID_MLS_ACCOUNT: &str = "inkson_mls_account_secret";

/// Canonical HPKE AAD for an `ak.secret.send` to-device envelope.
///
/// `crypto-media/device-lifecycle.md` §10.7 fixes the AAD as the RFC 8785
/// canonical JSON of exactly nine members: the envelope's `device_message_id`,
/// `kind`, `sender_principal_id`, `sender_device_id`, `recipient_principal_id`,
/// `recipient_device_id` and `expires_at`, plus the content's `request_id` and
/// `secret_id`.
///
/// This is the single construction point. Callers pass the typed members and
/// receive canonical bytes; they MUST NOT hand-assemble a JSON value, because a
/// short AAD lets different messages / requests / secrets share one binding and
/// leaves isolation to in-ciphertext claims alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretShareSendAad<'a> {
    /// Envelope `device_message_id`; MUST be allocated before sealing so the
    /// ciphertext, the envelope and the durable queue row all carry one value.
    pub device_message_id: &'a arkret_wire::DeviceMessageId,
    pub sender_principal_id: &'a arkret_wire::DidCoreId,
    pub sender_device_id: &'a arkret_wire::DeviceId,
    pub recipient_principal_id: &'a arkret_wire::DidCoreId,
    pub recipient_device_id: &'a arkret_wire::DeviceId,
    /// Content `request_id`, verbatim.
    pub request_id: &'a str,
    /// Content `secret_id`, verbatim.
    pub secret_id: &'a str,
    /// Envelope `expires_at`, already validated as the canonical `.sssZ` form.
    /// It enters the AAD as that same string; no `*_unix` derivation exists.
    pub expires_at: &'a str,
}

impl SecretShareSendAad<'_> {
    /// Canonical AAD bytes. `kind` is pinned to [`SECRET_SEND_KIND`] and is not
    /// a caller input, so an envelope of another kind cannot reuse this binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        arkret_canonical::validate_timestamp_canonical(self.expires_at).map_err(|err| {
            Error::Protocol(format!(
                "invalid secret-share expires_at {:?}: {err}",
                self.expires_at
            ))
        })?;
        if self.request_id.is_empty() || self.secret_id.is_empty() {
            return Err(Error::Protocol(
                "secret-share AAD requires non-empty request_id and secret_id".to_owned(),
            ));
        }
        let aad = serde_json::json!({
            "device_message_id": self.device_message_id.as_str(),
            "kind": SECRET_SEND_KIND,
            "sender_principal_id": self.sender_principal_id.as_str(),
            "sender_device_id": self.sender_device_id.as_str(),
            "recipient_principal_id": self.recipient_principal_id.as_str(),
            "recipient_device_id": self.recipient_device_id.as_str(),
            "request_id": self.request_id,
            "secret_id": self.secret_id,
            "expires_at": self.expires_at,
        });
        arkret_canonical::canonical_json_bytes(&aad)
            .map_err(|err| Error::Protocol(format!("canonicalize secret-share AAD: {err}")))
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
const HISTORY_SEAL_INFO: &[u8] =
    arkret_wire::DomainSeparationId::REALM_HISTORY_SECRET_SHARE_V1.as_bytes();

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
mod secret_share_send_aad_tests {
    use super::*;

    const MESSAGE_ID: &str = "ak:device_message:01904100-0000-7000-8000-0000000000d1";
    const SENDER: &str = "ak:did_core:webvh:z6mkfixturesender";
    const SENDER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000a";
    const RECIPIENT: &str = "ak:did_core:webvh:z6mkfixturerecipient";
    const RECIPIENT_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000b";
    const REQUEST_ID: &str = "req-01904100";
    const EXPIRES: &str = "2026-06-10T00:30:00.000Z";

    struct Members {
        device_message_id: arkret_wire::DeviceMessageId,
        sender_principal_id: arkret_wire::DidCoreId,
        sender_device_id: arkret_wire::DeviceId,
        recipient_principal_id: arkret_wire::DidCoreId,
        recipient_device_id: arkret_wire::DeviceId,
        request_id: String,
        secret_id: String,
        expires_at: String,
    }

    impl Members {
        fn golden() -> Self {
            Self {
                device_message_id: arkret_wire::DeviceMessageId::new(MESSAGE_ID.to_owned())
                    .unwrap(),
                sender_principal_id: arkret_wire::DidCoreId::new(SENDER.to_owned()).unwrap(),
                sender_device_id: arkret_wire::DeviceId::new(SENDER_DEVICE.to_owned()).unwrap(),
                recipient_principal_id: arkret_wire::DidCoreId::new(RECIPIENT.to_owned()).unwrap(),
                recipient_device_id: arkret_wire::DeviceId::new(RECIPIENT_DEVICE.to_owned())
                    .unwrap(),
                request_id: REQUEST_ID.to_owned(),
                secret_id: SECRET_ID_MLS_ACCOUNT.to_owned(),
                expires_at: EXPIRES.to_owned(),
            }
        }

        fn bytes(&self) -> Vec<u8> {
            SecretShareSendAad {
                device_message_id: &self.device_message_id,
                sender_principal_id: &self.sender_principal_id,
                sender_device_id: &self.sender_device_id,
                recipient_principal_id: &self.recipient_principal_id,
                recipient_device_id: &self.recipient_device_id,
                request_id: &self.request_id,
                secret_id: &self.secret_id,
                expires_at: &self.expires_at,
            }
            .canonical_bytes()
            .unwrap()
        }
    }

    /// Byte-level KAT: the AAD is the RFC 8785 canonical JSON of exactly the
    /// nine members `device-lifecycle.md` §10.7 lists, keys in JCS order.
    #[test]
    fn send_aad_is_the_nine_member_canonical_json() {
        let expected = concat!(
            r#"{"device_message_id":"ak:device_message:01904100-0000-7000-8000-0000000000d1","#,
            r#""expires_at":"2026-06-10T00:30:00.000Z","#,
            r#""kind":"ak.secret.send","#,
            r#""recipient_device_id":"ak:device:01904100-0000-7000-8000-00000000000b","#,
            r#""recipient_principal_id":"ak:did_core:webvh:z6mkfixturerecipient","#,
            r#""request_id":"req-01904100","#,
            r#""secret_id":"inkson_mls_account_secret","#,
            r#""sender_device_id":"ak:device:01904100-0000-7000-8000-00000000000a","#,
            r#""sender_principal_id":"ak:did_core:webvh:z6mkfixturesender"}"#,
        );
        assert_eq!(
            String::from_utf8(Members::golden().bytes()).unwrap(),
            expected
        );
    }

    /// Every member is load-bearing: mutating any one of the eight caller-supplied
    /// members changes the AAD, so a different message / request / secret cannot
    /// reuse another one's binding. `kind` is pinned, not a caller input.
    #[test]
    fn every_member_changes_the_send_aad() {
        let golden = Members::golden().bytes();

        let mut mutated = Members::golden();
        mutated.device_message_id = arkret_wire::DeviceMessageId::new(
            "ak:device_message:01904100-0000-7000-8000-0000000000d2".to_owned(),
        )
        .unwrap();
        assert_ne!(mutated.bytes(), golden, "device_message_id");

        let mut mutated = Members::golden();
        mutated.sender_principal_id =
            arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixtureother".to_owned()).unwrap();
        assert_ne!(mutated.bytes(), golden, "sender_principal_id");

        let mut mutated = Members::golden();
        mutated.sender_device_id =
            arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000c".to_owned())
                .unwrap();
        assert_ne!(mutated.bytes(), golden, "sender_device_id");

        let mut mutated = Members::golden();
        mutated.recipient_principal_id =
            arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixtureother".to_owned()).unwrap();
        assert_ne!(mutated.bytes(), golden, "recipient_principal_id");

        let mut mutated = Members::golden();
        mutated.recipient_device_id =
            arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000c".to_owned())
                .unwrap();
        assert_ne!(mutated.bytes(), golden, "recipient_device_id");

        let mut mutated = Members::golden();
        mutated.request_id = "req-other".to_owned();
        assert_ne!(mutated.bytes(), golden, "request_id");

        let mut mutated = Members::golden();
        mutated.secret_id = "other_secret".to_owned();
        assert_ne!(mutated.bytes(), golden, "secret_id");

        let mut mutated = Members::golden();
        mutated.expires_at = "2026-06-10T00:30:01.000Z".to_owned();
        assert_ne!(mutated.bytes(), golden, "expires_at");
    }

    /// A non-canonical `expires_at` is rejected before any AAD is produced;
    /// receivers must never see a leniently-parsed spelling.
    #[test]
    fn send_aad_rejects_non_canonical_expires_at_and_empty_ids() {
        let mut bad = Members::golden();
        bad.expires_at = "2026-06-10T00:30:00Z".to_owned();
        assert!(
            SecretShareSendAad {
                device_message_id: &bad.device_message_id,
                sender_principal_id: &bad.sender_principal_id,
                sender_device_id: &bad.sender_device_id,
                recipient_principal_id: &bad.recipient_principal_id,
                recipient_device_id: &bad.recipient_device_id,
                request_id: &bad.request_id,
                secret_id: &bad.secret_id,
                expires_at: &bad.expires_at,
            }
            .canonical_bytes()
            .is_err()
        );

        let mut bad = Members::golden();
        bad.request_id = String::new();
        assert!(
            SecretShareSendAad {
                device_message_id: &bad.device_message_id,
                sender_principal_id: &bad.sender_principal_id,
                sender_device_id: &bad.sender_device_id,
                recipient_principal_id: &bad.recipient_principal_id,
                recipient_device_id: &bad.recipient_device_id,
                request_id: &bad.request_id,
                secret_id: &bad.secret_id,
                expires_at: &bad.expires_at,
            }
            .canonical_bytes()
            .is_err()
        );
    }
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
            scheme: HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned(),
            enc: "ZW5j".to_owned(),
            ciphertext: "Y2lwaGVy".to_owned(),
        };
        content.validate().unwrap();
        let parsed: SecretShareSendContent =
            serde_json::from_value(serde_json::to_value(&content).unwrap()).unwrap();
        assert_eq!(parsed, content);

        let mut bad = content;
        bad.scheme = "mls_rfc9420".to_owned();
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
