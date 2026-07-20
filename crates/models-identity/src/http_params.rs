//! Identity/account HTTP query/header parameter DTOs for the Salvo OpenAPI
//! binding.
//!
//! Server/identity describe/resolve, DID document/log/receipt lookups, DID
//! operation submission, account subscribe/describe, and the account
//! session-grant / device-pair / OIDC-callback correlation parameters
//! (`service-operation-dtos.schema.json`). Collaboration event parameters
//! live in `arkret-models-collaboration`.

use arkret_wire::{Cursor, Did, Hash};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ServerDescribeParams {
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
pub struct IdentityDescribeParams {
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
pub struct IdentityResolveParams {
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
pub struct IdentityGetDocumentParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub version: Option<String>,

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
pub struct IdentityGetLogParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

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
pub struct IdentitySubmitDidOperationParams {
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
pub struct IdentityGetReceiptsParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub head: Hash,

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
pub struct AccountSubscribeParams {
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
pub struct AccountDescribeParams {
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
pub struct AccountSessionGrantParams {
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
pub struct AccountDevicePairParams {
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
pub struct AccountOidcCallbackParams {
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
