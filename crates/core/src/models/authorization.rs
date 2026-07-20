//! Authorization decision and grant/invite listing wire DTOs migrated to
//! `arkret-models-collaboration` (`governance::authorization`). Re-exported
//! so the `arkret_core::{AuthzCheckOutcome, GrantList, ...}` paths stay
//! stable.

pub use arkret_models_collaboration::governance::authorization::*;
