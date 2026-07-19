//! Event-draft kind registry facade retained by `arkret-core`.
//!
//! The registry, its specs, and the built-in required-field table migrated
//! to `arkret-event-draft`.

pub use arkret_event_draft::{
    EventDraftKindConformanceVector, EventDraftKindRegistry, EventDraftKindSpec,
    EventDraftKindValidation, event_draft_kind_conformance_vectors,
};
