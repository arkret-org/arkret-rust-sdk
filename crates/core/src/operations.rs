//! Operation registry, catalog, DAG validation, and semantic-reduction
//! contracts.
//!
//! The whole module moved to `arkret-event-draft` (`operations`): it is the
//! operation-semantics layer over the SDK-local `OperationEnvelope` draft
//! record owned there. `arkret-core` re-exports the surface unchanged so
//! `arkret_core::operations::*` stays a stable path until the facade retires
//! (phase 5).

pub use arkret_event_draft::operations::*;
