//! Cursor surface relocated to `arkret-wire`.
//!
//! The issuing-service `ak:cursor:` mint/validate surface is a wire-protocol
//! token, so it now lives in `arkret-wire` alongside the other cross-domain
//! wire shapes. This module re-exports it verbatim so the historical
//! `arkret_hlc::cursor::*` path stays stable.

pub use arkret_wire::cursor::*;
