//! Arkret v1 authorization and profile semantics.

use arkret_wire_base::*;

pub mod authz;
pub mod generated;
pub mod profile_claim;
pub mod profile_feature_guard;
pub mod profile_semantics;

pub mod models {
    pub use arkret_wire_base::primitives::Facet;
}

pub use authz::*;
pub use profile_claim::{ProfileClaim, ProfileClaimError, ProfileClaimKind, ProfileValidator};
pub use profile_feature_guard::*;
pub use profile_semantics::*;
