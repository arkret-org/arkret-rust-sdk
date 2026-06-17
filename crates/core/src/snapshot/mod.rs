//! Snapshot chunk v2 — multi-chunk Merkle output with signed generator
//! proofs.
//!
//! The v1 snapshot wire is a single base64-url JSON blob: fine for small
//! Spaces, but doesn't scale to multi-megabyte projection dumps and
//! doesn't let receivers verify a single chunk without trusting the
//! whole bundle.
//!
//! v2 introduces three primitives:
//!
//! - [`SnapshotChunker`] — deterministically partitions a serialized snapshot blob into fixed-size
//!   byte ranges, each addressable by an ordinal `chunk_id` starting at 0. Boundaries are at exact
//!   byte offsets (`target_chunk_bytes`) so two implementations always produce the same chunk
//!   layout for the same input.
//! - [`SnapshotMerkleTree`] — a binary Merkle tree over chunk digests keyed by `chunk_id`. RFC
//!   6962-style audit paths let receivers verify a single chunk's leaf hash against the root using
//!   just `O(log n)` sibling hashes.
//! - [`GeneratorProof`] — the generator's signed commitment to a snapshot frontier (`state_root` +
//!   `merkle_root` + `chunk_count`). Receivers verify the proof against the generator DID before
//!   trusting any chunks; chunks themselves don't need per-chunk signatures because their digests
//!   are committed in the Merkle root that the proof signs.
//!
//! Wire shape (round 8): the snapshot manifest endpoint
//! (`/_cokret/self/snapshot/head`) returns `chunk_count`, `merkle_root`,
//! and `generator_proof`; the chunk endpoint
//! (`/_cokret/self/snapshot/chunk?chunk_id=N`) returns the chunk bytes
//! plus the `audit_path[]` Merkle siblings. Receivers verify per-chunk.

mod chunking;
mod constants;
mod generator_proof;
pub(crate) mod merkle;
mod types;

pub use chunking::*;
pub use constants::*;
pub use generator_proof::*;
pub use merkle::SnapshotMerkleTree;
pub use types::*;

#[cfg(test)]
mod tests;
