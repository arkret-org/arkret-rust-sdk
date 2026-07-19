//! Client-side encryption for principal-private Account Data values.
//!
//! The implementation now lives in [`arkret_crypto::account_data_crypto`]; this
//! module re-exports it so the historical `arkret::account_data_crypto::*` /
//! `arkret_sdk::account_data_crypto::*` paths stay stable.

pub use arkret_crypto::account_data_crypto::*;
