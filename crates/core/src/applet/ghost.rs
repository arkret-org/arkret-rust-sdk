//! Compatibility exports for Ghost Actor profile drafting.

pub use arkret_event_draft::{GhostActorProfileRequest, accountability_grant_event};
pub use arkret_models_collaboration::governance::accountability::{
    ACCOUNTABILITY_GRANT_SCHEMA, AccountabilityGrantPayload, AccountabilityGrantStatus,
    AccountabilityScope, AccountabilityScopeKind,
};
