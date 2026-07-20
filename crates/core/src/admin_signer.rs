//! Compatibility shim: the per-admin signing surface split into its layered
//! homes in core-retirement batch 4b.
//!
//! - [`SessionGrantIntrospection`] + [`admin_scopes`] — the pure introspection **data** (RFC
//!   7662-shaped session-grant view + the admin-scope vocabulary) now live in
//!   `arkret-models-identity`.
//! - [`AdminKeyStore`] — the KeyStore-backed **behavior** (addressing signing keys by
//!   `(application_id, admin_did)`) now lives in `arkret-auth`.
//!
//! `arkret-core` re-exports both so downstream `arkret_core::{AdminKeyStore,
//! SessionGrantIntrospection, admin_scopes}` paths keep resolving until the
//! facade retires (phase 5).

pub use arkret_auth::AdminKeyStore;
pub use arkret_models_identity::admin_grant::{SessionGrantIntrospection, admin_scopes};
