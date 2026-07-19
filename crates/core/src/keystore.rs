//! Transitional re-export of the [`KeyStore`] contract.
//!
//! The pure storage contract — the [`KeyStore`] trait, the typed
//! [`KeyStoreError`], the zeroizing [`InMemoryKeyStore`], and the id /
//! service-name helpers — is owned by `arkret-keystore` (registry decision
//! G1/R1: the trait lives with its backends). This module keeps the historic
//! `arkret_core::keystore::*` import paths compiling until the core facade
//! retires (phase 5).

pub use arkret_keystore::{
    InMemoryKeyStore, KeyBytes, KeyStore, KeyStoreError, service_name, validate_id,
};
