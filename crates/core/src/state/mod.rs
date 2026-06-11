//! Cokret v1 Move/Seal/Lattice state resolution.
//!
//! This module hosts the SDK-side runtime for the Move/Seal/Lattice model
//! introduced in spec 2026-05-08. It provides:
//!
//! - [`store`] — `MoveStore` / `SealStore` / `CellStore` / `CellRegistry` trait contracts, with
//!   [`store::memory`] in-memory backends used by tests and the SDK harness.
//! - [`verify`] — the four-step Move verifier pipeline (structural → signature → capability →
//!   preconditions → effect-shape).
//! - [`seal`] — `apply_seal` and `effective_seal_view` per spec §4.3 / §4.1.
//! - [`state_root`] — canonical Merkle compute per spec §4.2 normative.
//!
//! Architecture rationale + design tradeoffs live in
//! `cokret-rust-sdk/docs/move-seal-runtime.md`. Wire / protocol rules
//! live in `cokret-spec/spec/v1/zh/authz/event-auth-state-resolution.md`
//! §3-§5.
pub mod compaction;
pub mod seal;
pub mod state_root;
pub mod store;
pub mod verify;

pub use compaction::{CompactionPolicy, PruneCandidate, PruneEligibility};
pub use seal::{
    SealEffect, SealReject, apply_seal, control_event_set_root, deterministic_order,
    effective_seal_view, union_predecessor_covered_events, view_hash,
};
pub use state_root::{EMPTY_STATE_ROOT, compute_state_root, leaf_hash};
pub use store::memory::{MemoryCellRegistry, MemoryCellStore, MemoryMoveStore, MemorySealStore};
pub use store::{
    BottomMode, CellLatticeBinding, CellRegistry, CellStore, MoveStore, SealStore,
    SealedMoveRecord, StoreError, StoreResult,
};
pub use verify::{MoveReject, MoveRejectMap, reject_to_error_code, verify_move};
