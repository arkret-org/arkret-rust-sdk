//! Arkret v1 authorization and profile semantics.

use arkret_wire::*;

pub mod authz;
pub mod history_visibility;
pub mod minimal_metadata_author;
pub mod minimal_metadata_security;
pub mod ordinary_agent_mls;
pub mod profile_claim;
pub mod profile_feature_guard;
pub mod profile_semantics;
pub mod realm_bootstrap;
pub mod realm_organization;

pub mod models {
    pub use arkret_wire::primitives::Facet;
}

pub use authz::*;
pub use minimal_metadata_author::*;
pub use minimal_metadata_security::*;
pub use ordinary_agent_mls::*;
pub use profile_claim::{
    ClaimedProfile, ProfileClaim, ProfileClaimError, ProfileClaimKind, ProfileValidator,
};
pub use profile_feature_guard::*;
pub use profile_semantics::*;
pub use realm_organization::*;
