//! Typed current-state results committed by the governance Station.
//!
//! Selectors are domain coordinates and revisions are authority commit
//! coordinates. No legacy component identifiers, reducer state models, or causal dots are
//! exposed.

pub use arkret_wire::{
    CurrentRevision, CurrentSelector, MemberStateCurrent, MembershipState, MlsGroupCurrent,
    ReactionCurrent, TypedCurrentResult,
};
