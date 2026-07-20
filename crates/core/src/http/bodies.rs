//! HTTP JSON request/outcome DTOs re-exported by `arkret-core`.
//!
//! The events/projection/blob/MIMI bodies live in
//! `arkret-models-collaboration`, the key-package and key-backup bodies in
//! `arkret-models-crypto`, the private-contact-discovery and service-describe
//! bodies in `arkret-models-discovery`, the applet third-party lookups in
//! `arkret-models-integration`, and the identity/account request bodies and
//! identity-describe outcome wrappers in `arkret-models-identity` (all
//! re-exported below).
//!
//! `ContactListQuery` / `ContactList` also moved to
//! `arkret-models-collaboration` now that their bound `Cursor` lives in
//! `arkret-wire` (the model crate reaches it without a forbidden hlc edge);
//! they arrive through the collaboration glob re-export below.

pub use arkret_models_collaboration::http_bodies::*;
// Session-grant request/outcome DTO family migrated to
// `arkret-models-collaboration` (phase 5 http-face batch 0f). Re-exported so
// the `arkret_core::SessionGrant*` paths and the Salvo OpenAPI bindings stay
// stable.
pub use arkret_models_collaboration::session_grant_bodies::*;
pub use arkret_models_crypto::http_bodies::*;
pub use arkret_models_discovery::http_bodies::*;
// Identity/account request bodies and identity-describe outcome wrappers
// migrated to `arkret-models-identity` (phase 5 http-face batch 0g).
pub use arkret_models_identity::http_bodies::*;
pub use arkret_models_integration::http_bodies::*;
