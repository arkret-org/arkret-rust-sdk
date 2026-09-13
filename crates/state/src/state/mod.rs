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
    CommandEventResult, ControlProjection, EffectiveSealView, EventDigestSetInclusionProof,
    JoinedView, OrderedControlBatchAbort, OrderedControlBatchEffect, OrderedControlUnit,
    OrderedControlUnitEvent, PreparedSealEffect, SealBasisVerificationContext, SealDigestSuites,
    SealEffect, SealLeafUnionProof, SealReject, apply_accepted_seal_in_context,
    apply_replayed_seal_in_context, apply_seal_in_context, causal_winner_for_batches,
    control_event_set_root, covered_events_for_seal_basis, data_events_for_seal_basis,
    effective_joined_view_at, effective_seal_view, effective_state_at,
    event_digest_set_inclusion_proof, event_digest_set_root, execute_ordered_control_units,
    join_cell, join_cell_seal_batches, leaf_union_proof, live_digest_suite_from_state,
    predecessor_seal_closure, prepare_accepted_seal_in_context, prepare_seal_in_context,
    project_control_writes_with_revision_guard, resolve_committed_ordered_control_units,
    verify_event_digest_set_inclusion_proof, verify_seal_basis, view_hash,
};
pub use state_root::{
    EMPTY_STATE_ROOT, GovernanceView, StateInclusionProof, compute_state_root, leaf_hash,
    sequenced_state_leaf_digest, state_inclusion_proof, state_leaf_canonical_preimage,
    state_leaf_hash_from_state_object, value_frontier_digest, verify_state_inclusion_proof,
};
pub use store::memory::{
    MemoryCellStateRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealCommitStore,
    MemorySealStore,
};
pub use store::{
    AcklessSelfPrincipalIngress, CellStateModelBinding, CellStateRegistry, CellStore,
    ControlEventStore, ControlProposalIngress, ControlProposalIngressClass,
    ControlProposalSnapshot, ControlSealAttemptCompletion, ControlSealAttemptOutcome,
    ControlSealScheduleClaim, ControlSealScheduleRepairStats, ControlSealScheduleStats,
    ControlUnitIngressMember, DecidedControlEventRecord, PendingControlEventRecord,
    PendingControlUnitRecord, SealCommandEventDecision, SealCommitStore, SealStore, StoreError,
    StoreResult, control_event_digest,
};
pub use verify::{
    ControlMoveFailureDisposition, ControlMoveReject, ControlMoveVerificationContext,
    classify_control_move_reject, reject_to_error_code, resolve_projected_write,
    verify_accepted_control_move_in_context, verify_control_move, verify_control_move_in_context,
    verify_security_revision_guards,
};
