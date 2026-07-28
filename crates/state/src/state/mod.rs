//! Arkret v1 control-plane Event / Seal / Lattice state resolution.
//!
//! This module hosts the SDK-side runtime for the CBA control plane. It
//! provides:
//!
//! - [`store`] — `ControlEventStore` / `SealStore` / `CellStore` / `CellRegistry` trait contracts,
//!   with [`store::memory`] in-memory backends used by tests and the SDK harness.
//! - [`verify`] — the Control Move verifier pipeline (structural → proofs → critical refs →
//!   preconditions → receiver-derived writes).
//! - [`seal`] — `apply_seal`, `verify_seal_basis` and `effective_seal_view` per spec §6.3 / §5.1.
//! - [`state_root`] — canonical Merkle compute per spec §6.2.1 normative.
//!
//! Architecture rationale + design tradeoffs live in
//! `arkret-rust-sdk/docs/move-anchor-runtime.md`. Wire / protocol rules
//! live in `arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md`
//! §5-§6.
pub mod compaction;
pub mod seal;
pub mod state_root;
pub mod store;
pub mod verify;

pub use compaction::{CompactionPolicy, PruneCandidate, PruneEligibility};
pub use seal::{
    EffectiveSealView, SealEffect, SealLeafUnionProof, SealReject, apply_seal,
    control_event_completeness_root, control_event_set_root, deterministic_order,
    effective_seal_view, effective_state_at, join_cell, leaf_union_proof, predecessor_seal_closure,
    union_predecessor_covered_events, verify_seal_basis, view_hash,
};
pub use state_root::{
    EMPTY_STATE_ROOT, StateInclusionProof, compute_state_root, leaf_hash, state_inclusion_proof,
    state_value_leaf_digest, verify_state_inclusion_proof,
};
pub use store::memory::{
    MemoryCellRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
};
pub use store::{
    BottomMode, CellLatticeBinding, CellRegistry, CellStore, ControlEventStore, SealStore,
    SealedControlEventRecord, StoreError, StoreResult, control_event_digest,
};
pub use verify::{
    ControlMoveReject, ControlMoveRejectMap, reject_to_error_code, verify_control_move,
};
