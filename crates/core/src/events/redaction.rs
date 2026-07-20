//! Shim: per-message redaction tombstone helpers migrated to
//! `arkret-models-collaboration` (`events_payloads::redaction`). Re-exported
//! here to preserve the `arkret_core::` path.

pub use arkret_models_collaboration::events_payloads::redaction::*;
