//! Discovery HTTP query/header parameter DTOs for the Salvo OpenAPI binding.
//!
//! Directory describe/search/resolve and announce/withdraw operation
//! parameters (`service-operation-dtos.schema.json`). Header-only shapes
//! carrying request-id / traceparent correlation and idempotency keys.

use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryDescribeParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchRealmsParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveRealmParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchOrganizationsParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveOrganizationParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchActorsParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchUsersParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveHandleParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContactDiscoveryParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAnnounceParams {
    #[serde(rename = "Idempotency-Key")]
    pub idempotency_key: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryWithdrawParams {
    #[serde(rename = "Idempotency-Key")]
    pub idempotency_key: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    pub traceparent: Option<String>,
}
