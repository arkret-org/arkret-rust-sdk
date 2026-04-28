//! Shared authenticated encryption helpers.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const AEAD_ALGORITHM: &str = "xchacha20poly1305-sha256-key-v1";
const NONCE_LEN: usize = 24;

pub fn seal(plaintext: &[u8], key_material: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = Sha256::digest(key_material);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| Error::Crypto(error.to_string()))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("AEAD encryption failed".to_owned()))?;
    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn open(envelope: &[u8], key_material: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < NONCE_LEN {
        return Err(Error::Crypto("AEAD envelope is shorter than nonce".to_owned()));
    }
    let (nonce, ciphertext) = envelope.split_at(NONCE_LEN);
    let key = Sha256::digest(key_material);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Crypto("AEAD decryption failed".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_seal_open_roundtrips_and_authenticates_aad() {
        let sealed = seal(b"secret", b"passphrase", b"context").unwrap();
        assert_ne!(sealed, b"secret");
        assert_eq!(open(&sealed, b"passphrase", b"context").unwrap(), b"secret");
        assert!(open(&sealed, b"passphrase", b"wrong-context").is_err());
    }
}
