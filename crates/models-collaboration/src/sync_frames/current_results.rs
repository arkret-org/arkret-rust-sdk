//! Typed current-state results committed by the governance Station.
//!
//! A selector is a domain coordinate and a revision is an authority commit
//! coordinate; those two are the whole vocabulary this surface exposes.

pub use arkret_wire::{
    CircleMemberStateCurrent, CurrentRevision, CurrentSelector, MemberStateCurrent,
    MembershipState, MlsGroupCurrent, TypedCurrentRow,
};
use arkret_wire::{CommitStreamHead, RealmId, Result, WireError};
use serde::{Deserialize, Serialize};

impl AccountCurrentCoverage {
    /// Each covered stream may appear at most once: two heads for one stream
    /// would be two answers to a single-valued question.
    pub fn validate(&self) -> Result<()> {
        unique_stream_heads(&self.stream_heads, "current-state coverage")
    }
}

impl AccountCurrentView {
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
    pub fn entry(&self, selector: &CurrentSelector) -> Option<&TypedCurrentRow> {
        self.entries
            .iter()
            .find(|entry| selector_of(entry) == selector)
    }
}

const fn selector_of(entry: &TypedCurrentRow) -> &CurrentSelector {
    match entry {
        TypedCurrentRow::Value { selector, .. } => selector,
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

include!("generated/current_results_contracts.rs");
