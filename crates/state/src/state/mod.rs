//! Arkret v1 security Event, Seal, and sequenced-state resolution.
//!
//! This module hosts the SDK-side runtime for the CBS control plane. It
//! provides:
//!
//! - [`store`] — security Event, Seal, and cell-state storage contracts, with [`store::memory`]
//!   in-memory backends used by tests and the SDK harness.
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
    EffectiveSealView, EventDigestSetInclusionProof, JoinedView, PreparedSealEffect,
    SealBasisVerificationContext, SealDigestSuites, SealEffect, SealLeafUnionProof, SealReject,
    apply_accepted_seal_in_context, apply_replayed_seal_in_context, apply_seal_in_context,
    causal_heads_for_batches, control_event_set_root, deterministic_order,
    effective_joined_view_at, effective_seal_view, effective_state_at,
    event_digest_set_inclusion_proof, event_digest_set_root, join_cell, join_cell_seal_batches,
    leaf_union_proof, live_digest_suite_from_state, predecessor_seal_closure,
    prepare_seal_in_context, union_predecessor_covered_events,
    verify_event_digest_set_inclusion_proof, verify_seal_basis, view_hash,
};
pub use state_root::{
    CausalHeadsByCell, EMPTY_STATE_ROOT, GovernanceView, StateInclusionProof, compute_state_root,
    leaf_hash, sequenced_state_leaf_digest, state_inclusion_proof, state_leaf_canonical_preimage,
    state_leaf_hash_from_state_object, value_frontier_digest, verify_state_inclusion_proof,
};
pub use store::memory::{
    MemoryCellStateRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
};
pub use store::{
    AcklessSelfPrincipalIngress, CellStateModelBinding, CellStateRegistry, CellStore,
    ControlEventStore, ControlProposalIngress, ControlProposalIngressClass,
    ControlProposalSnapshot, ControlSealAttemptCompletion, ControlSealAttemptOutcome,
    ControlSealScheduleClaim, ControlSealScheduleRepairStats, ControlSealScheduleStats,
    EventCellBottom, PendingControlEventRecord, SealStore, SealedControlEventRecord, StoreError,
    StoreResult, control_event_digest,
};
pub use verify::{
    ControlMoveReject, ControlMoveVerificationContext, reject_to_error_code,
    resolve_projected_write, verify_accepted_control_move_in_context, verify_control_move,
    verify_control_move_in_context,
};
