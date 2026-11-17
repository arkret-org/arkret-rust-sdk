//! Device-to-device secret sharing over the Arkret RFC 9180 HPKE profile.
//!
//! This module owns the stable cryptographic boundary shared by clients. It
//! deliberately does not encode a synchronization or history state machine;
//! callers bind the ciphertext to a concrete device-message envelope and use
//! committed protocol events for authorization and progress.

pub use arkret_models_crypto::{
    SecretShareRequestContent as RequestContent, SecretShareSendContent as SendContent,
};

use crate::Result;

/// Wire `kind` for a secret request.
pub const SECRET_REQUEST_KIND: &str = arkret_wire::SECRET_REQUEST_KIND;
/// Wire `kind` for a sealed secret response.
pub const SECRET_SEND_KIND: &str = arkret_wire::SECRET_SEND_KIND;

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
