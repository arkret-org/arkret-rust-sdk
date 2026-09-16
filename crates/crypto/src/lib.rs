//! Protocol crypto machine contracts.
//!
//! ## Feature flags
//!
//! * `backup` — pulls in the [`backup`] module, which provides client-side Argon2id KDF,
//!   XChaCha20-Poly1305 AEAD, and a recovery-key codec. Envelope assembly and authorization remain
//!   with the calling protocol layer.

#[cfg(feature = "account-data")]
pub mod account_data_crypto;
#[cfg(feature = "aead")]
pub mod aead_nonce;
#[cfg(feature = "backup")]
pub mod backup;
#[cfg(feature = "blob-aead")]
pub mod blob_aead;
#[cfg(feature = "blob-aead")]
pub mod file_transfer_aead;
#[cfg(feature = "hpke")]
pub mod hpke;
#[cfg(feature = "identity-root")]
pub mod identity_root;
#[cfg(feature = "aead")]
pub mod mls_exporter;
#[cfg(feature = "sframe")]
pub mod sframe;

mod errors;

// Crate-root re-export preserved from the original module layout.
#[cfg(feature = "aead")]
pub use aead_nonce::*;
pub use errors::*;
#[cfg(feature = "aead")]
pub use mls_exporter::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error;

    #[test]
    fn crypto_error_converts_to_core_protocol_error() {
        // Every CryptoError renders to Error::Protocol.
        let core_err: Error = CryptoError::ReplayDetected.into();
        assert!(matches!(core_err, Error::Protocol(_)));

        let core_err: Error = CryptoError::BoundsExceeded {
            field: "field".to_owned(),
            limit: 10,
        }
        .into();
        if let Error::Protocol(message) = core_err {
            assert!(message.contains("field"));
            assert!(message.contains("10"));
        } else {
            panic!("expected Error::Protocol");
        }
    }
}
