//! RFC 9180 HPKE base-mode helpers for the Arkret X25519 profile.
//!
//! This module owns only the cryptographic framing shared by current backup
//! protocols. Callers provide protocol-specific `info` and AAD bytes and must
//! keep those domains distinct.

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, single_shot_open, single_shot_seal};

use crate::{Error, Result};

type HpkeKem = X25519HkdfSha256;
type HpkeAead = ChaCha20Poly1305;
type HpkeKdf = HkdfSha256;

const HPKE_ENCAPSULATED_KEY_LEN: usize = 32;

/// Encrypt one plaintext with RFC 9180 base mode using
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305.
///
/// The returned value is unpadded base64url of `enc || ciphertext`. A fresh
/// ephemeral keypair is generated for every call.
pub fn seal_x25519_chacha20poly1305(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<String> {
    let recipient_public_key = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| {
            Error::Protocol(format!(
                "recipient HPKE public key must be a valid 32-byte X25519 key, got {} bytes",
                recipient_public_key.len()
            ))
        })?;

    let mut entropy_probe = [0_u8; 1];
    getrandom::fill(&mut entropy_probe)
        .map_err(|error| Error::Crypto(format!("OS CSPRNG unavailable for HPKE seal: {error}")))?;

    let (encapsulated_key, ciphertext) = single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        &recipient_public_key,
        info,
        plaintext,
        aad,
    )
    .map_err(|_| Error::Crypto("HPKE seal failed".to_owned()))?;

    let encapsulated_key = encapsulated_key.to_bytes();
    let mut framed = Vec::with_capacity(encapsulated_key.len() + ciphertext.len());
    framed.extend_from_slice(&encapsulated_key);
    framed.extend_from_slice(&ciphertext);
    Ok(base64url_encode(framed))
}

/// Open a value produced by [`seal_x25519_chacha20poly1305`].
///
/// `info` and `aad` must exactly match the values supplied by the sealing
/// protocol.
pub fn open_x25519_chacha20poly1305(
    recipient_private_key: &[u8],
    sealed: &str,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let recipient_private_key =
        <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(recipient_private_key).map_err(|_| {
            Error::Protocol(format!(
                "recipient HPKE private key must be a valid 32-byte X25519 key, got {} bytes",
                recipient_private_key.len()
            ))
        })?;

    let framed = base64url_decode(sealed.as_bytes())?;
    if framed.len() <= HPKE_ENCAPSULATED_KEY_LEN {
        return Err(Error::Protocol(
            "HPKE value is too short to contain an encapsulated key and ciphertext".to_owned(),
        ));
    }
    let (encapsulated_key, ciphertext) = framed.split_at(HPKE_ENCAPSULATED_KEY_LEN);
    let encapsulated_key = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(encapsulated_key)
        .map_err(|_| Error::Protocol("HPKE encapsulated key is invalid".to_owned()))?;

    single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeR::Base,
        &recipient_private_key,
        &encapsulated_key,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| Error::Crypto("HPKE open authentication failed".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (private_key, public_key) = <HpkeKem as hpke::Kem>::gen_keypair();
        (
            private_key.to_bytes().to_vec(),
            public_key.to_bytes().to_vec(),
        )
    }

    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn opens_rfc9180_base_mode_known_answer() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let private_key = unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let mut framed = unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let aad = unhex("436f756e742d30");
        let plaintext = unhex("4265617574792069732074727574682c20747275746820626561757479");
        framed.extend_from_slice(&unhex(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        ));
        let sealed = base64url_encode(framed);

        assert_eq!(
            open_x25519_chacha20poly1305(&private_key, &sealed, &info, &aad).unwrap(),
            plaintext
        );
        assert!(open_x25519_chacha20poly1305(&private_key, &sealed, &info, b"wrong-aad").is_err());
    }

    #[test]
    fn round_trip_rejects_wrong_context_and_recipient() {
        let (private_key, public_key) = keypair();
        let sealed = seal_x25519_chacha20poly1305(
            &public_key,
            b"backup-key-material",
            b"ak.backup.test.info.v1",
            b"ak.backup.test.aad.v1",
        )
        .unwrap();

        assert_eq!(
            open_x25519_chacha20poly1305(
                &private_key,
                &sealed,
                b"ak.backup.test.info.v1",
                b"ak.backup.test.aad.v1",
            )
            .unwrap(),
            b"backup-key-material"
        );
        assert!(
            open_x25519_chacha20poly1305(
                &private_key,
                &sealed,
                b"ak.backup.test.info.v1",
                b"wrong-aad",
            )
            .is_err()
        );
        let (wrong_private_key, _) = keypair();
        assert!(
            open_x25519_chacha20poly1305(
                &wrong_private_key,
                &sealed,
                b"ak.backup.test.info.v1",
                b"ak.backup.test.aad.v1",
            )
            .is_err()
        );
    }
}
