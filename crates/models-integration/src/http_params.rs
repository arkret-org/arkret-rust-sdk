//! Applet HTTP query/header parameter DTOs for the Salvo OpenAPI binding.
//!
//! Applet ping/describe/transaction and applet-scoped actor/realm/protocol
//! lookups plus third-party user/location bridge queries
//! (`service-operation-dtos.schema.json`).

use arkret_wire::Did;
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletPingParams {
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
pub struct AppletDescribeParams {
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
pub struct AppletTransactionParams {
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
pub struct AppletActorParams {
    pub actor_id: Did,

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
pub struct AppletRealmParams {
    pub realm_id_or_alias: String,

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
pub struct AppletProtocolParams {
    pub protocol: String,

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
pub struct AppletThirdPartyUsersParams {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<String>>,

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
pub struct AppletThirdPartyLocationsParams {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<String>>,

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
