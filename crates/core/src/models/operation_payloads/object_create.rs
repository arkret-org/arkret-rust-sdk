//! Object-create payload facade retained by `arkret-core`.
//!
//! The generic [`ObjectCreatePayload`] envelope and [`StrandPatchPayload`]
//! live in `arkret-models-collaboration`; the [`StrandCreateObject`] draft
//! builder migrated to `arkret-event-draft` (re-exported below).

pub use arkret_event_draft::StrandCreateObject;
pub use arkret_models_collaboration::events_payloads::object_create::*;
