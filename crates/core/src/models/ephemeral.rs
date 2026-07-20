//! Shim: the broadcast ephemeral envelope and the typed `ak.call.signal`
//! payload helpers / per-key sequence bookkeeping migrated to
//! `arkret-models-collaboration` (`events_payloads::ephemeral`). Re-exported
//! here to preserve the `arkret_core::` path.

pub use arkret_models_collaboration::events_payloads::ephemeral::*;
