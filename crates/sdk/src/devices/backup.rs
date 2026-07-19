//! Key-backup subdomain KDF, commitment and AAD helpers (`key-management.md`
//! §7). The implementation now lives in [`arkret_crypto::backup`]; this module
//! re-exports it so the historical `arkret_sdk::devices::key_backup_*` paths
//! stay stable.

pub use arkret_crypto::backup::{key_backup_aad, key_backup_commitment, key_backup_subdomain_key};
