//! Contrix v1 Move/Anchor/Lattice state resolution.
//!
//! This crate hosts the SDK-side runtime for the Move/Anchor/Lattice model
//! introduced in spec 2026-05-08. It provides:
//!
//! - [`store`] — `MoveStore` / `AnchorStore` / `CellStore` / `CellRegistry`
//!   trait contracts, with [`store::memory`] in-memory backends used by
//!   tests and the SDK harness.
//! - [`verify`] — the four-step Move verifier pipeline (structural →
//!   signature → capability → preconditions → effect-shape).
//! - [`anchor`] — `apply_anchor` and `effective_anchor_view` per spec
//!   §4.3 / §4.1.
//! - [`state_root`] — canonical Merkle compute per spec §4.2 normative.
//!
//! Architecture rationale + design tradeoffs live in
//! `contrix-rust-sdk/docs/move-anchor-runtime.md`. Wire / protocol rules
//! live in `contrix-spec/spec/v1/zh/authz/event-auth-state-resolution.md`
//! §3-§5.
//!
//! The legacy `StateReducer` / `state_hash` / `is_state_event` /
//! `subject_for_event` / `candidate_wins` / `StateAuthority` API has been
//! removed (v1 unreleased; no backward-compat shim).

pub mod anchor;
pub mod state_root;
pub mod store;
pub mod verify;

pub use anchor::{
    AnchorEffect, AnchorReject, apply_anchor, deterministic_order, effective_anchor_view,
    union_predecessor_frontiers,
};
pub use state_root::{compute_state_root, leaf_hash};
pub use store::{
    AnchorStore, AnchoredMoveRecord, BottomMode, CellLatticeBinding, CellRegistry, CellStore,
    MoveStore, StoreError, StoreResult,
    memory::{MemoryAnchorStore, MemoryCellRegistry, MemoryCellStore, MemoryMoveStore},
};
pub use verify::{MoveReject, verify_move};
