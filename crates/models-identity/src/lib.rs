//! Arkret v1 identity, account, device, and handle wire models.
//!
//! Owner of the identity-domain wire shapes: account lifecycle and
//! handoff, actor profiles, attestation evidence, device verification,
//! DID continuity and operations, handles, identity-link cache
//! projections, and member identity segments. Behavior that needs
//! signature verification, schema validation, or state reduction lives
//! in `arkret-core` and its behavior crates; this crate holds data
//! shapes and type-local invariants only.

pub mod account;
pub mod actor_profile;
pub mod artifacts_account;
pub mod artifacts_device_identity;
pub mod attestation;
pub mod device_verification;
pub mod did_continuity;
pub mod handle;
pub mod identity;
pub mod identity_link_cache;
pub mod member_identity;

pub use account::*;
pub use actor_profile::*;
pub use artifacts_account::*;
pub use artifacts_device_identity::*;
pub use attestation::*;
pub use device_verification::*;
pub use did_continuity::*;
pub use handle::*;
pub use identity::*;
pub use identity_link_cache::*;
pub use member_identity::*;
