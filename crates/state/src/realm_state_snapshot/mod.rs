//! `ak.schema.realm_state_snapshot.v1` — the signed manifest, its
//! content-addressed chunks, and the consumer half that restores them.
//!
//! Producer side: [`build_realm_state_snapshot_chunks_with_auxiliary_lists`]
//! partitions the reducer's materialized cells on whole-item boundaries and
//! [`state_digest_from_items`] commits the complete Cell state and its fixed
//! model. This snapshot root is distinct from the Seal security state root.
//! [`event_set_commitment`] commits the covered Event set, and
//! [`event_set_merkle_tree`] is the prover side of the §6.2 inclusion
//! challenge over that same commitment.
//!
//! Consumer side: [`restore_realm_state_snapshot`] runs §5's checklist —
//! signature transcript, reducer profile, acceptance window, per-chunk content
//! address, `state_digest` recomputation, auxiliary-list digests and mandatory
//! replay verification — before returning complete cells and replay evidence.
//! Per-cell causal coverage travels in each causal state; [`CoveredEventSet`]
//! separately answers membership in the manifest's committed Event set without
//! treating unavailable membership evidence as a negative answer.

mod chunking;
mod constants;
pub(crate) mod merkle;
mod restore;
mod types;

pub use chunking::*;
pub use constants::*;
pub use merkle::{RealmStateSnapshotMerkleTree, format_hash, hash_leaf, hash_node, parse_sha256};
pub use restore::*;
pub use types::*;

#[cfg(test)]
mod tests;
