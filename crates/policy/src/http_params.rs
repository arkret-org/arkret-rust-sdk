//! Authorization HTTP query/header parameter DTOs for the Salvo OpenAPI
//! binding.
//!
//! Effective-grants and invite listing selectors plus the authz/policy check
//! correlation parameters (`service-operation-dtos.schema.json`).

use arkret_wire::{Cursor, Did, RealmId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AuthzEffectiveGrantsParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub realm_id: RealmId,
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub subject: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub at: Option<String>,

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
pub struct AuthzInvitesParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub subject: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,

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
pub struct AuthzCheckParams {
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
pub struct PolicyCheckParams {
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
