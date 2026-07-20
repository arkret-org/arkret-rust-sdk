//! Federation transaction / push / pull operation bodies.
//!
//! The transaction bodies bind `arkret_event_draft::Operation` and now live
//! in `arkret-event-draft` (`federation_transaction`, re-exported below). The
//! realm-membership listing and actor-verification DTOs live in
//! `arkret-models-collaboration` (`federation::wire_dtos`, re-exported below).

pub use arkret_event_draft::{
    FederationPullOperationsOutcome, FederationPushOperationsOutcome,
    FederationPushOperationsRequestBody, FederationTransactionOutcome,
    FederationTransactionRequestBody,
};
pub use arkret_models_collaboration::federation::wire_dtos::*;
