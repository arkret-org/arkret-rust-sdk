//! Arkret v1 identity, account, device, and handle wire models.
//!
//! Owner of the identity-domain wire shapes: account lifecycle and
//! handoff, actor profiles, device verification,
//! DID resolution and operations, handles, identity-link cache
//! projections, and member identity segments. Behavior that needs
//! signature verification, schema validation, or state reduction lives
//! in the `arkret` umbrella and its behavior crates; this crate holds data
//! shapes and type-local invariants only.

pub mod account;
pub mod actor_profile;
pub mod actor_profile_operations;
pub mod admin_grant;
pub mod agent_signer_evidence;
pub mod artifacts_account;
pub mod artifacts_device_identity;
pub mod authenticated_signer_resolution_evidence;
pub mod claim_presentation;
pub mod device_push_route;
pub mod device_verification;
pub mod did_document;
pub mod did_webvh;
pub mod handle;
pub mod handle_claim;
pub mod http_bodies;
pub mod identity;
pub mod identity_resolution;
pub mod member_identity;
pub mod organization_registration;
/// §3.2.1 deterministic primary-handle selection, `claim_digest`, and
/// §3.8.2 mention/subject rendering. wasm-safe, dependency-free helpers
/// shared by inkson / sodmin / soland / cotest (SOD-05-001 / SPEC-CR-019).
pub mod primary_handle;
pub mod principal_registration_anchor;
pub mod proof;
pub mod service_binding_results;
pub mod service_identity;
pub mod session_credential;
pub mod signer_key_operations;

pub use account::*;
pub use actor_profile::*;
pub use actor_profile_operations::*;
pub use admin_grant::*;
pub use agent_signer_evidence::*;
pub use artifacts_account::*;
pub use artifacts_device_identity::*;
pub use authenticated_signer_resolution_evidence::*;
pub use claim_presentation::*;
pub use device_push_route::*;
pub use device_verification::*;
pub use did_document::*;
pub use did_webvh::*;
pub use handle::*;
pub use handle_claim::*;
pub use http_bodies::*;
pub use identity::*;
pub use identity_resolution::*;
pub use member_identity::*;
pub use organization_registration::*;
pub use principal_registration_anchor::*;
pub use proof::*;
pub use service_binding_results::*;
pub use session_credential::*;
pub use signer_key_operations::*;
