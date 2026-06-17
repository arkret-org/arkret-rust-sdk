use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AuthzEffectiveGrantsParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub realm_id: RealmId,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub subject: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub at: Option<String>,

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
pub struct AuthzInvitesParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub subject: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,

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
pub struct AuthzCheckParams {
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
pub struct PolicyCheckParams {
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
pub struct MediaIceConfigParams {
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
pub struct ModerationReportParams {
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
