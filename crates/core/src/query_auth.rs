//! Query-parameter auth-material detection, re-exported from `arkret-wire`.
//!
//! The canonical constant set and detection helpers moved to
//! `arkret_wire::query_auth` (they are a wire-layer protocol vocabulary). This
//! shim keeps the `arkret_core::query_auth::*` and `arkret_core::is_query_auth_parameter`
//! paths stable until the facade retires.

pub use arkret_wire::query_auth::*;
