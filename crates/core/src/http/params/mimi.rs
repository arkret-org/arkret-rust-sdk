use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct MimiProviderDirectoryParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub features: Vec<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiKeyMaterialParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiRoomUpdateParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiNotifyParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiSubmitMessageParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiGroupInfoParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub include_proof: Option<bool>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiConsentParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiConsentUpdateParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiIdentifierQueryParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiReportAbuseParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

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
pub struct MimiProxyDownloadParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Request-Id"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Request-Id", parameter(parameter_in = Header)))]
    pub x_cokret_request_id: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Traceparent"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
