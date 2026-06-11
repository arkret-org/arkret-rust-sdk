//! Salvo OpenAPI-facing HTTP DTOs for the Cokret service binding.
//!
//! These types model endpoint transport roles explicitly:
//! - path, query-string and header inputs are grouped as `<Operation>Params`;
//! - JSON request bodies are `<Operation>RequestBody`;
//! - successful responses are `<Operation>Outcome`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

pub const PATH_SELF_CONTACTS_REQUEST: &str = "/_cokret/self/contacts/request";
pub const PATH_SELF_CONTACTS_RESPOND: &str = "/_cokret/self/contacts/respond";
pub const PATH_SELF_CONTACTS: &str = "/_cokret/self/contacts";
pub const PATH_SELF_CONTACTS_TOMBSTONE: &str = "/_cokret/self/contacts/tombstone";
pub const PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE: &str =
    "/_cokret/self/direct-conversations/resolve";

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct DirectoryDescribeParams {
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
pub struct DirectorySearchRealmsParams {
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
pub struct DirectoryResolveRealmParams {
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
pub struct DirectorySearchOrganizationsParams {
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
pub struct DirectoryResolveOrganizationParams {
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
pub struct DirectorySearchActorsParams {
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
pub struct DirectorySearchUsersParams {
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
pub struct DirectoryResolveHandleParams {
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
pub struct PrivateContactDiscoveryParams {
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
pub struct DirectoryAnnounceParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

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
pub struct DirectoryWithdrawParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

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
pub struct BlobUploadParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Cokret-Blob-Metadata"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Cokret-Blob-Metadata", parameter(parameter_in = Header)))]
    pub x_cokret_blob_metadata: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Content-Type"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Content-Type", parameter(parameter_in = Header)))]
    pub content_type: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Content-Disposition"
    )]
    #[cfg_attr(feature = "salvo", salvo(rename = "Content-Disposition", parameter(parameter_in = Header)))]
    pub content_disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Digest")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Digest", parameter(parameter_in = Header)))]
    pub digest: Option<Hash>,

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
pub struct BlobHeadParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub blob_ref: BlobRef,

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
pub struct BlobGetParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub blob_ref: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Range")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Range", parameter(parameter_in = Header)))]
    pub range: Option<String>,

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
pub struct PushRegisterDeviceParams {
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
pub struct PushUnregisterDeviceParams {
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
pub struct PushNotifyParams {
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
pub struct DeviceMessagesPutParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

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
pub struct DeviceMessagesGetParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub from: Option<Cursor>,
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
pub struct KeysUploadParams {
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
pub struct KeysQueryParams {
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
pub struct KeysClaimParams {
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
pub struct KeysBackupsPutParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

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
pub struct KeysBackupsListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub backup_class: Option<BackupClass>,
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
pub struct KeysBackupsGetParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,

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
pub struct KeysBackupsDeleteParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

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
pub struct KeyPackagesUploadParams {
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
pub struct KeyPackagesClaimParams {
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
pub struct KeyPackagesConsumeParams {
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
pub struct KeyPackagesRevokeParams {
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
    pub flow_id: FlowId,

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
    pub flow_id: FlowId,

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
    pub flow_id: FlowId,

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
    pub flow_id: FlowId,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AccountSessionGrantParams {
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
pub struct AccountDevicePairParams {
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
pub struct AccountOidcCallbackParams {
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
pub struct AdminServerStatusParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub include: Vec<String>,

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
pub struct AdminAccountStatusParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub account_id: String,

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
pub struct AdminRevokeDeviceParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub device_id: DeviceId,

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
pub struct AdminModerationQueueParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub status: Option<String>,
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
pub struct AppletPingParams {
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
pub struct AppletDescribeParams {
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
pub struct AppletTransactionParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

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
pub struct AppletActorParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub actor_id: Did,

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
pub struct AppletRealmParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub realm_id_or_alias: String,

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
pub struct AppletProtocolParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub protocol: String,

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
pub struct AppletThirdPartyUsersParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = DeepObject)))]
    pub external_ids: Option<Value>,

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
pub struct AppletThirdPartyLocationsParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = DeepObject)))]
    pub external_ids: Option<Value>,

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryOrder {
    Default,
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsDescribeOutcome {
    pub service_did: Did,
    #[serde(default)]
    pub supported_event_schemas: Vec<String>,
    #[serde(default)]
    pub supported_reducer_profiles: Vec<String>,
    #[serde(default)]
    pub supported_signatures: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsSubmitStatus {
    Accepted,
    Duplicate,
    Partial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitOutcome {
    pub status: EventsSubmitStatus,
    #[serde(default)]
    pub accepted: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub actor_frontier: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub realm_frontier: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventView {
    pub event: Event,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub visibility: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsResolveRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsResolveOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EphemeralSubmitOutcome {
    pub accepted: bool,
    pub kind: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatched_to: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_received_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProjectionSpaceState {
    Active,
    Archived,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProjectionObjectState {
    Active,
    Archived,
    Redacted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionSpaceRow {
    pub space_id: SpaceId,
    pub realm_id: RealmId,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    pub state: ProjectionSpaceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionSpaceList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub spaces: Vec<ProjectionSpaceRow>,
    pub total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionFlowRow {
    pub flow_id: FlowId,
    pub realm_id: RealmId,
    pub state: ProjectionObjectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Derived board Space id from `ck.component.flow.position.v1`.
    /// This is read-model state, not canonical Flow object state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_space_id: Option<SpaceId>,
    /// Derived list Space id from `ck.component.flow.position.v1`.
    /// This is read-model state, not canonical Flow object state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_space_id: Option<SpaceId>,
    /// Derived rank inside `list_space_id` from
    /// `ck.component.flow.position.v1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    /// Derived current assignee Actor DIDs from visible active
    /// `assigned_to` Relations. Empty means the Flow is unassigned for
    /// this projection caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_actor_ids: Vec<Did>,
    /// Active assignment Relation edges backing `assigned_actor_ids`.
    /// Clients use `relation_id` to tombstone an assignment during edits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_to_relations: Vec<ProjectionAssignedToRelation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionAssignedToRelation {
    pub relation_id: RelationId,
    pub actor_id: Did,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionFlowList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub flows: Vec<ProjectionFlowRow>,
    pub total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionMorphRow {
    pub morph_id: MorphId,
    pub realm_id: RealmId,
    pub morph_type: String,
    pub state: ProjectionObjectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProjectionMorphList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub morphs: Vec<ProjectionMorphRow>,
    pub total: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsSubscribeFrameKind {
    Event,
    Frontier,
    Heartbeat,
    CatchupComplete,
    EpochRotation,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubscribeFrame {
    pub kind: EventsSubscribeFrameKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = EventsSubscribeFrame)))]
pub struct EventsSubscribeFrameOutcome(pub EventsSubscribeFrame);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsQueryOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobHeadOutcome {
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Length")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Digest")]
    pub digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Cache-Control")]
    pub cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Type")]
    pub content_type: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "Content-Disposition"
    )]
    pub content_disposition: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = String, format = Binary)))]
pub struct BlobGetOutcome(pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContactState {
    PendingOutgoing,
    PendingIncoming,
    Accepted,
    Rejected,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationBindingState {
    Active,
    Retired,
    Duplicate,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationResolveState {
    Found,
    Created,
    NotFound,
    Retired,
    NonCanonical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_flow_id: FlowId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    pub state: DirectConversationBindingState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactListRow {
    pub peer: Did,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<EventId>,
    #[serde(default)]
    pub granted_by_me: Vec<String>,
    #[serde(default)]
    pub granted_to_me: Vec<String>,
    #[serde(default)]
    pub bidirectional_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_consent_grant_ref: Option<EventId>,
    /// Principal Server service DID hosting the peer, when known (e.g. learned
    /// from a cross-Principal-Server contact delivery). Lets the holder address
    /// responses/invites to the peer's home server. Omitted for
    /// same-Principal-Server contacts (spec contact-operations.schema.json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_service_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestRequestBody {
    pub target: Did,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `target` is hosted on a different Principal Server, the
    /// requester MUST supply the target's home service DID so the issuer-side
    /// server can federate the signed `ck.contact.requested` fact via
    /// `ck.peer.contacts.submit`. Omit for same-server requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_did: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestOutcome {
    pub request_event_ref: EventId,
    #[serde(default)]
    pub requester_consent_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRespondRequestBody {
    pub request_id: EventId,
    pub requester: Did,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scopes: Vec<String>,
    /// Cross-Principal-Server addressing (spec §4.1): when the original
    /// `requester` is hosted on a different Principal Server, the responder
    /// supplies the requester's home service DID so the accept / reject fact
    /// is federated back via `ck.peer.contacts.submit`. Omit for same-server
    /// responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_service_did: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRespondOutcome {
    pub response_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grant_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ContactListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactList {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactTombstoneRequestBody {
    pub contact: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoke_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub full_peer_revoke: bool,
    #[serde(default)]
    pub block_peer: bool,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `contact` (the peer) is hosted on a different Principal
    /// Server, the holder supplies the peer's home service DID so the
    /// `ck.contact.tombstoned` fact is federated to the peer's server via
    /// `ck.peer.contacts.submit`. Omit for same-server tombstones; when absent
    /// the issuer falls back to the peer's recorded `peer_service_did` on the
    /// stored contact row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_service_did: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactTombstone {
    pub tombstone_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_revoke_refs: Vec<EventId>,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationResolveRequestBody {
    pub peer: Did,
    #[serde(default, skip_serializing_if = "is_false")]
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationResolveOutcome {
    pub state: DirectConversationResolveState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_flow_id: Option<FlowId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryPrivateContactDiscoveryRequestBody {
    pub requester: Did,
    #[serde(default)]
    pub contacts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub padding: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryPrivateContactDiscoveryOutcome {
    #[serde(default)]
    pub matches: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesUploadRequestBody {
    pub device_id: DeviceId,
    #[serde(default)]
    pub key_packages: Vec<Value>,
    pub device_signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesUploadOutcome {
    pub accepted: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_package_refs: Vec<KeyEventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesClaimRequestBody {
    #[serde(default)]
    pub claims: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesClaimOutcome {
    #[serde(default)]
    pub key_packages: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeRequestBody {
    #[serde(default)]
    pub key_package_refs: Vec<KeyEventId>,
    pub consumer_device_id: DeviceId,
    pub signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeOutcome {
    #[serde(default)]
    pub consumed: Vec<KeyEventId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeRequestBody {
    #[serde(default)]
    pub key_package_refs: Vec<KeyEventId>,
    pub device_id: DeviceId,
    pub signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeOutcome {
    #[serde(default)]
    pub revoked: Vec<KeyEventId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiProviderDirectory {
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub features: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiKeyMaterialRequestBody {
    pub requester: Did,
    pub flow_id: FlowId,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiKeyMaterialOutcome {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_packages: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub group_info: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateRequestBody {
    pub mls_group_id: String,
    pub update: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_transcript_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_actor_id: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_state_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiNotifyRequestBody {
    pub notification: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub routing: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiNotifyOutcome {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiSubmitMessageRequestBody {
    pub sender_actor_id: Did,
    pub device_id: DeviceId,
    pub ciphertext: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub associated_data: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiSubmitMessageOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub delivery: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiGroupInfoOutcome {
    pub group_info: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_binding_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiRequestConsentRequestBody {
    pub requester: Did,
    pub target: Value,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiRequestConsentOutcome {
    pub consent_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MimiConsentDecision {
    Accept,
    Deny,
    Revoke,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiUpdateConsentRequestBody {
    pub consent_id: String,
    pub decision: MimiConsentDecision,
    pub actor: Did,
    pub signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiUpdateConsentOutcome {
    pub status: String,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiIdentifierQueryRequestBody {
    #[serde(default)]
    pub identifiers: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiIdentifierQueryOutcome {
    #[serde(default)]
    pub results: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiReportAbuseRequestBody {
    pub flow_id: FlowId,
    pub target_ref: String,
    pub reporter: Did,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub evidence_package: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub frank: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiProxyDownloadRequestBody {
    pub asset_ref: String,
    pub requester: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub ohttp_context: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiProxyDownloadOutcome {
    pub download_ref: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRequestBody {
    pub principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_scope: Vec<String>,
    pub proof: SessionGrantRequestProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantProofKind {
    DidBoundSignature,
    PairedDeviceProof,
    PasskeyAssertion,
    OidcCodeExchange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRequestProof {
    pub proof_kind: SessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantOutcome {
    pub principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub session_grant: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scope: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: String,
    pub new_device_pubkey: Value,
    pub challenge_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDevicePairOutcome {
    pub device_id: DeviceId,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_grant: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub key_backup_hint: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackRequestBody {
    pub state: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionGrantOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminServerStatusOutcome {
    pub status: String,
    pub protocol_version: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub capacity: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminAccountStatusRequestBody {
    pub status: String,
    pub moderator: Did,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub notify: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminAccountStatusOutcome {
    pub account_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminRevokeDeviceRequestBody {
    pub moderator: Did,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoke_sessions: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminRevokeDeviceOutcome {
    pub device_id: DeviceId,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationQueueView {
    #[serde(default)]
    pub items: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub counts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletThirdPartyUserList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletThirdPartyLocationList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = ServerDescription)))]
pub struct ServerDescribeOutcome(pub ServerDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityDescription)))]
pub struct IdentityDescribeOutcome(pub IdentityDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityDocumentView)))]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityLogOutcome)))]
pub struct IdentityLogResultBody(pub IdentityLogOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DidOperationSubmitRequestBody)))]
pub struct IdentitySubmitDidOperationRequestBody(pub DidOperationSubmitRequestBody);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DidOperationSubmitOutcome)))]
pub struct IdentitySubmitDidOperationOutcome(pub DidOperationSubmitOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityReceiptsOutcome)))]
pub struct IdentityReceiptsResultBody(pub IdentityReceiptsOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncRequestBody)))]
pub struct AccountSubscribeRequestBody(pub SyncRequestBody);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncOutcome)))]
pub struct AccountSubscribeOutcome(pub SyncOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncDescription)))]
pub struct AccountDescribeOutcome(pub SyncDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryDescription)))]
pub struct DirectoryDescribeOutcome(pub DirectoryDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = BlobUploadMetadata)))]
pub struct BlobUploadRequestBody(pub BlobUploadMetadata);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsPutRequestBody(pub KeyBackup);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsGetOutcome(pub KeyBackup);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = GrantList)))]
pub struct GrantListOutcome(pub GrantList);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = OkOutcome)))]
pub struct MimiReportAbuseOutcome(pub OkOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletDescription)))]
pub struct AppletDescribeOutcome(pub AppletDescription);

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn mimi_room_update_wire_uses_sender_actor_id_only() {
        let actor = did("alice");
        let body = MimiRoomUpdateRequestBody {
            mls_group_id: "group-1".to_owned(),
            update: json!({"kind": "room_update", "payload": {}}),
            epoch: Some(7),
            confirmed_transcript_hash: Some(
                Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
            sender_actor_id: Some(actor.clone()),
        };
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(value["sender_actor_id"], json!(actor));
        assert!(value.get("sender").is_none());
        assert!(value.get("confirmed_transcript_hash").is_some());
        assert!(value.get("transcript_hash").is_none());

        let old_sender = json!({
            "mls_group_id": "group-1",
            "update": {"kind": "room_update", "payload": {}},
            "sender": "did:web:alice.example"
        });
        assert!(serde_json::from_value::<MimiRoomUpdateRequestBody>(old_sender).is_err());

        let old_transcript_hash = json!({
            "mls_group_id": "group-1",
            "update": {"kind": "room_update", "payload": {}},
            "transcript_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        assert!(serde_json::from_value::<MimiRoomUpdateRequestBody>(old_transcript_hash).is_err());
    }

    #[test]
    fn mimi_submit_message_wire_uses_sender_actor_id_only() {
        let actor = did("alice");
        let body = MimiSubmitMessageRequestBody {
            sender_actor_id: actor.clone(),
            device_id: device_id(),
            ciphertext: json!({
                "content_type": "application/cokret",
                "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "payload": "AA"
            }),
            mls_group_id: Some("group-1".to_owned()),
            epoch: Some(7),
            associated_data: json!({}),
        };
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(value["sender_actor_id"], json!(actor));
        assert!(value.get("sender").is_none());

        let old_sender = json!({
            "sender": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
            "ciphertext": {
                "content_type": "application/cokret",
                "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "payload": "AA"
            }
        });
        assert!(serde_json::from_value::<MimiSubmitMessageRequestBody>(old_sender).is_err());
    }
}
