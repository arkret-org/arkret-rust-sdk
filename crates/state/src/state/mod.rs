//! Arkret v1 control-plane Event / Seal / Lattice state resolution.
//!
//! This module hosts the SDK-side runtime for the CBA control plane. It
//! provides:
//!
//! - [`store`] — `ControlEventStore` / `SealStore` / `CellStore` / `CellRegistry` trait contracts,
//!   with [`store::memory`] in-memory backends used by tests and the SDK harness.
//! - [`verify`] — the Control Move verifier pipeline (structural → proofs → critical refs →
//!   preconditions → receiver-derived writes).
//! - [`seal`] — `apply_seal_in_context`, `verify_seal_basis` and `effective_seal_view` per spec
//!   §6.3 / §5.1.
//! - [`state_root`] — canonical Merkle compute per spec §6.2.1 normative.
//!
//! Architecture rationale + design tradeoffs live in
//! `arkret-rust-sdk/docs/move-anchor-runtime.md`. Wire / protocol rules
//! live in `arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md`
//! §5-§6.
pub mod seal;
pub mod state_root;
pub mod store;
pub mod verify;

pub use seal::{
    EffectiveSealView, EventDigestSetInclusionProof, JoinedView, ListedControlEvent,
    PreparedSealEffect, SealBasisVerificationContext, SealDigestSuites, SealEffect,
    SealLeafUnionProof, SealReject, apply_accepted_seal_in_context, apply_replayed_seal_in_context,
    apply_seal_in_context, cas_heads_for_batches, causal_heads_for_batches,
    control_event_completeness_root, is_causal_register,
    control_event_completeness_root_from_listed, control_event_set_root, deterministic_order,
    effective_cas_heads_at, effective_cas_heads_with_new_ops, effective_joined_view_at,
    effective_seal_view, effective_state_at, event_digest_set_inclusion_proof,
    event_digest_set_root, join_cell, join_cell_seal_batches, leaf_union_proof,
    live_digest_suite_from_state, predecessor_seal_closure, prepare_seal_in_context,
    union_predecessor_covered_events, verify_event_digest_set_inclusion_proof,
    verify_recovery_witness, verify_seal_basis, view_hash,
};
pub use state_root::{
    CasHeadsByCell, EMPTY_STATE_ROOT, GovernanceView, StateInclusionProof, cas_leaf_hash,
    compute_state_root, leaf_hash, state_inclusion_proof, state_value_leaf_digest,
    value_frontier_digest, verify_state_inclusion_proof,
};
pub use store::memory::{
    MemoryCellRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
};
pub use store::{
    AcklessSelfPrincipalIngress, BottomMode, CellLatticeBinding, CellRegistry, CellStore,
    ControlEventStore, ControlProposalIngress, ControlProposalIngressClass,
    ControlProposalSnapshot, ControlSealAttemptCompletion, ControlSealAttemptOutcome,
    ControlSealScheduleClaim, ControlSealScheduleRepairStats, ControlSealScheduleStats,
    PendingControlEventRecord, SealStore, SealedControlEventRecord, StoreError, StoreResult,
    control_event_digest,
};
pub use verify::{
    ControlMoveReject, ControlMoveVerificationContext, reject_to_error_code,
    resolve_projected_write, verify_accepted_control_move_in_context, verify_control_move,
    verify_control_move_in_context,
};
