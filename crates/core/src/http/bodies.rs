//! HTTP JSON request/outcome DTOs retained by `arkret-core`.
//!
//! The events/projection/blob/MIMI bodies migrated to
//! `arkret-models-collaboration`, the key-package and key-backup bodies to
//! `arkret-models-crypto`, the private-contact-discovery and service-describe
//! bodies to `arkret-models-discovery`, the applet third-party lookups to
//! `arkret-models-integration`, and the identity/account request bodies and
//! identity-describe outcome wrappers to `arkret-models-identity` (all
//! re-exported below). The batch-0k unlock also lands `EventsQueryOutcome`,
//! `ContactRequestRequestBody`, `AccountDevicePair{RequestBody,Outcome}`,
//! `BlobUploadRequestBody`, and `GrantListOutcome` in
//! `arkret-models-collaboration` now that their blocking model types moved.
//!
//! This module keeps only `ContactListQuery` / `ContactList`, which bind the
//! core-resident `Cursor` (`arkret_hlc::Cursor`, re-exported at the core
//! root) that the model crates cannot reach without a forbidden hlc edge;
//! the contact directory row/state types they reference live in
//! `arkret-models-collaboration` and reach these definitions via the glob
//! re-export below.

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
use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ContactListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactList {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default)]
    pub has_more: bool,
}
