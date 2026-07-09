use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryDescribeParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectorySearchRealmsParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryResolveRealmParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectorySearchOrganizationsParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryResolveOrganizationParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectorySearchActorsParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectorySearchUsersParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryResolveHandleParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct PrivateContactDiscoveryParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryAnnounceParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryWithdrawParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Arkret-Request-Id", parameter(parameter_in = Header)))]
    pub x_arkret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
