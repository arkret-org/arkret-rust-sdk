//! Typed current-state results committed by the governance Station.
//!
//! Selectors are domain coordinates and revisions are authority commit
//! coordinates. No legacy component identifiers, reducer state models, or causal dots are
//! exposed.

use arkret_wire::{CommitStreamHead, RealmId, Result, WireError};
pub use arkret_wire::{
    CurrentRevision, CurrentSelector, MemberStateCurrent, MembershipState, MlsGroupCurrent,
    ReactionCurrent, TypedCurrentResult,
};
use serde::{Deserialize, Serialize};

/// How much of one Realm a current-state read actually covered.
///
/// Every Realm, Circle and Sidecar keeps its own commit stream, so coverage is
/// a set of per-stream heads and never a single global position.
/// `complete_for_authorized_streams` is scoped exactly as its name says: it
/// asserts that the reader saw every stream it is authorized to read, never
/// that it saw the whole Realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `account-current-result.schema.json#/$defs/coverage`.
pub struct AccountCurrentCoverage {
    pub realm_id: RealmId,
    pub stream_heads: Vec<CommitStreamHead>,
    pub complete_for_authorized_streams: bool,
}

impl AccountCurrentCoverage {
    /// Each covered stream may appear at most once: two heads for one stream
    /// would be two answers to a single-valued question.
    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for head in &self.stream_heads {
            if !seen.insert(&head.stream_ref) {
                return Err(WireError::Protocol(
                    "current-state coverage repeats a commit stream".to_owned(),
                ));
            }
        }
        Ok(())
    }
}
