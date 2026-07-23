//! Directory handle-resolution DTOs — facade retained by `arkret-core`.
//!
//! The directory search / resolve / announce / push / takedown DTOs and the
//! handle-resolution + user-search outcome DTOs
//! (`UserSearchOutcome`, `DirectoryUserSearchOutcome`,
//! `DirectoryHandleResolutionOutcome`, `DirectorySubjectHandleList`) live in
//! `arkret-models-discovery`; the claim-presentation and agent-selector claim
//! shapes live in `arkret-models-identity`. Both are re-exported here so the
//! internal Core directory re-export panel is unchanged.

pub use arkret_models_discovery::directory::*;
pub use arkret_models_identity::claim_presentation::{
    AgentSelectorClaim, DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, validate_agent_slug,
};
