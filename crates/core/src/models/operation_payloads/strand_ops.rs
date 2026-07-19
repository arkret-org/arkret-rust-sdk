//! Strand-ops payload facade retained by `arkret-core`.
//!
//! The strand move / reorder / watch payloads live in
//! `arkret-models-collaboration`; the [`StrandTracksUpdatePayload`] draft
//! builder migrated to `arkret-event-draft` (re-exported below).

pub use arkret_event_draft::StrandTracksUpdatePayload;
pub use arkret_models_collaboration::events_payloads::strand_ops::*;
