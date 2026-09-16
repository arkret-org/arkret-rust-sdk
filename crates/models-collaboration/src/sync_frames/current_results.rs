//! Typed current-state results committed by the governance Station.
//!
//! A selector is a domain coordinate and a revision is an authority commit
//! coordinate; those two are the whole vocabulary this surface exposes.

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
        unique_stream_heads(&self.stream_heads, "current-state coverage")
    }
}

/// The Account Station's view of one Realm's authority-committed current state.
///
/// `authority_generation` names which governance generation materialized these
/// entries, and `stream_heads` is the per-stream position each entry was
/// materialized at. There is deliberately no single "Realm position" here: a
/// Realm's own stream, its Circles and its Sidecars advance independently, and
/// one number could not state where this result stands in all of them.
///
/// Convergence is by stable domain selector plus `expected_revision` CAS, so a
/// caller writes back against the `revision` of the exact entry it read — never
/// against a whole-Realm token.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `account-current-result.schema.json#/$defs/current`.
pub struct AccountCurrentResult {
    pub realm_id: RealmId,
    pub authority_generation: u64,
    pub stream_heads: Vec<CommitStreamHead>,
    pub entries: Vec<TypedCurrentResult>,
}

impl AccountCurrentResult {
    /// One head per stream, and one entry per selector: a repeated selector
    /// would be two current values for one single-valued coordinate.
    pub fn validate(&self) -> Result<()> {
        unique_stream_heads(&self.stream_heads, "current-state result")?;
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.entries {
            let selector = arkret_canonical::canonical_json_bytes(selector_of(entry))?;
            if !seen.insert(selector) {
                return Err(WireError::Protocol(
                    "current-state result repeats a domain selector".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// The current entry for one domain selector, if this result carries it.
    pub fn entry(&self, selector: &CurrentSelector) -> Option<&TypedCurrentResult> {
        self.entries
            .iter()
            .find(|entry| selector_of(entry) == selector)
    }
}

const fn selector_of(entry: &TypedCurrentResult) -> &CurrentSelector {
    match entry {
        TypedCurrentResult::Value { selector, .. }
        | TypedCurrentResult::MessageReactions { selector, .. } => selector,
    }
}

fn unique_stream_heads(heads: &[CommitStreamHead], what: &str) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for head in heads {
        if !seen.insert(&head.stream_ref) {
            return Err(WireError::Protocol(format!(
                "{what} repeats a commit stream"
            )));
        }
    }
    Ok(())
}
