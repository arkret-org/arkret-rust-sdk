//! SDK MLS-commit-Move shim.
//!
//! The MLS commit Move builders (`mls_epoch` / `key_schedule` /
//! `covered_seals` cell-id, precondition, and effect construction) plus the
//! `covered_seals` or-set join resolver now live in `arkret-state`, beside
//! the lattice runtime whose or-set semantics they exercise. This module
//! keeps the historical `arkret::mls_move::*` / `arkret_sdk::mls_move::*`
//! paths stable.

pub use arkret_state::mls_move::*;
