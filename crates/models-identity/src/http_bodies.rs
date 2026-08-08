//! Identity/account HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json` / `agent-operations.schema.json`):
//! the account logout / OIDC-callback request bodies and the
//! transparent identity-describe outcome wrappers used by the Salvo OpenAPI
//! bindings. Pure identity/account wire shapes; validation and dispatch live
//! with the auth and server behavior crates.

use serde::{Deserialize, Serialize};

use crate::identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDescription,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
};

/// `ak.gate.account.command.logout` request (Principal Server device logout).
/// Empty body — the session bearer identifies the device session to terminate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLogoutOutcome {
    pub ok: bool,
    pub revoked: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountOidcCallbackRequestBody {
    pub state: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDescribeOutcome(pub IdentityDescription);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityLogResultBody(pub IdentityLogListOutcome);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentitySubmitDidOperationRequestBody(pub DidOperationSubmitRequestBody);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentitySubmitDidOperationOutcome(pub DidOperationSubmitOutcome);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityReceiptsResultBody(pub IdentityReceiptListOutcome);
