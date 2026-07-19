//! SDK consent shim.
//!
//! The holder-private consent or-set builders (`grant`/`revoke` effect
//! construction and effective-consent evaluation) now live in
//! `arkret-state`: the evaluator reads a reducer-runtime `CellState`, so the
//! module belongs beside the lattice runtime rather than in the umbrella.
//! This module keeps the historical `arkret::consent::*` /
//! `arkret_sdk::consent::*` paths stable.

pub use arkret_state::consent::*;
