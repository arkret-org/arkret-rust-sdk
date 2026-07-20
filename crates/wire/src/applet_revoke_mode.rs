//! Applet revoke-mode closed vocabulary.
//!
//! Relocated from `arkret-models-integration` so the collaboration-owned
//! `AppletRevokeRequestBody` (which also binds `AccountLifecycleProof`) can
//! name it within the frozen layering. `arkret-models-integration`
//! re-exports it for path stability.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppletRevokeMode {
    RevokeAll,
    RevokeRuntimeOnly,
    RevokeWidgetOnly,
    RevokeDelegatedSessions,
}
