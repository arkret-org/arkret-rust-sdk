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
pub mod admin_grant;
pub mod artifacts_account;
pub mod artifacts_device_identity;
pub mod attestation;
pub mod claim_presentation;
pub mod cross_signing;
pub mod delivery_binding;
pub mod device_verification;
pub mod did_continuity;
pub mod did_document;
pub mod handle;
pub mod handle_claim;
pub mod http_bodies;
pub mod http_params;
pub mod identity;
pub mod identity_key_log;
pub mod identity_link_cache;
pub mod member_identity;
/// §3.2.1 deterministic primary-handle selection, `claim_digest`, and
/// §3.8.2 mention/subject rendering. wasm-safe, dependency-free helpers
/// shared by inkson / sodmin / soland / cotest (SOD-05-001 / SPEC-CR-019).
pub mod primary_handle;
pub mod proof;
pub mod service_identity;
pub mod session_credential;

pub use account::*;
pub use actor_profile::*;
pub use admin_grant::*;
pub use artifacts_account::*;
pub use artifacts_device_identity::*;
pub use attestation::*;
pub use claim_presentation::*;
pub use cross_signing::*;
pub use delivery_binding::*;
pub use device_verification::*;
pub use did_continuity::*;
pub use did_document::*;
pub use handle::*;
pub use handle_claim::*;
pub use http_bodies::*;
pub use http_params::*;
pub use identity::*;
pub use identity_key_log::*;
pub use identity_link_cache::*;
pub use member_identity::*;
pub use proof::*;
pub use session_credential::*;
