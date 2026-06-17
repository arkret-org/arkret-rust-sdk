use serde::{Deserialize, Serialize};

use crate::*;

// EventsQueryOrder is defined here (in the params layer) because EventsQueryParams
// references it as a query parameter type; bodies.rs accesses it via crate::http::*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryOrder {
    Default,
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ServerDescribeParams {
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
pub struct IdentityDescribeParams {
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
pub struct IdentityResolveParams {
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
pub struct IdentityGetDocumentParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub version: Option<String>,

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
pub struct IdentityGetLogParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

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
pub struct IdentitySubmitDidOperationParams {
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
pub struct IdentityGetReceiptsParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub head: Hash,

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
pub struct AccountSubscribeParams {
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
pub struct AccountDescribeParams {
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
pub struct EventsDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub realm_id: Option<RealmId>,

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
pub struct EventsSubmitParams {
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
pub struct EventsGetParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub include_payload: Option<bool>,

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
pub struct EventsResolveParams {
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
pub struct EventsFrontierParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,

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
pub struct EventsSubscribeParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub catchup: Option<bool>,

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
pub struct EventsQueryParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub before: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub order: Option<EventsQueryOrder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

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
pub struct SnapshotHeadParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub realm_id: RealmId,

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
pub struct EphemeralSendParams {
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
pub struct ProjectionLifecycleParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub include_terminal: Option<bool>,

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
