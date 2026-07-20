//! Applet HTTP query/header parameter DTOs for the Salvo OpenAPI binding.
//!
//! Applet ping/describe/transaction and applet-scoped actor/realm/protocol
//! lookups plus third-party user/location bridge queries
//! (`service-operation-dtos.schema.json`).

use arkret_wire::Did;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletPingParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletDescribeParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletTransactionParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletActorParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub actor_id: Did,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletRealmParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub realm_id_or_alias: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletProtocolParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub protocol: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletThirdPartyUsersParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub external_ids: Option<Vec<String>>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AppletThirdPartyLocationsParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub external_ids: Option<Vec<String>>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
