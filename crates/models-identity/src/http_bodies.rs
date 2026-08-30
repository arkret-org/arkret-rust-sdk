//! Identity/account HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json` / `agent-operations.schema.json`):
//! the account logout request/outcome bodies and the transparent identity
//! document view wrapper used by the Salvo OpenAPI bindings. Pure
//! identity/account wire shapes; validation and dispatch live with the auth
//! and server behavior crates.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityDocumentView;

/// `ak.gate.account.command.logout.v1` request (Station device logout).
/// Empty body — the session bearer identifies the device session to terminate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout.v1` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLogoutOutcome {
    pub revoked: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
