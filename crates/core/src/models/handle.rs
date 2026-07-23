//! Handle wire-model facade.
//!
//! The canonical `Handle` scalar, localpart/domain validators, and the
//! handle-claim vocabulary enums live in `arkret-models-identity`;
//! `HandleClaim` / `DeliveryBindingHint` live in
//! `arkret-models-collaboration` (they embed the collaboration
//! delivery-binding types). This module re-exports both so the
//! internal Core re-export panel is unchanged.

pub use arkret_models_collaboration::governance::handle_claim::*;
pub use arkret_models_identity::handle::*;
