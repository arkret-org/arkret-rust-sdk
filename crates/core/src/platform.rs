//! Shim: runtime platform wire shapes migrated to `arkret-wire`
//! (`platform`). Re-exported here to preserve the `arkret_core::` path (the
//! FFI crate is the sole consumer).

pub use arkret_wire::platform::*;
