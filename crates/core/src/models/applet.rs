//! Applet operation bodies retained by `arkret-core`.
//!
//! The install / edge outcome DTOs and the install preview / install request
//! bodies (which embed `AppletPackage`) migrated to
//! `arkret-models-integration` (`applet_models`, re-exported below). The
//! transaction body and the revoke body (which binds the collaboration-owned
//! `EphemeralEnvelope` / `AccountLifecycleProof`) live in
//! `arkret-models-collaboration`; `AppletRevokeRequestBody` reaches
//! `arkret_core::` through the `account_lifecycle` re-export in
//! `crate::models::account`.

pub use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
pub use arkret_models_integration::applet_models::*;
