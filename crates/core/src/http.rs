//! Salvo OpenAPI-facing HTTP DTOs for the Contrix service binding.
//!
//! These types model endpoint transport roles explicitly:
//! - path, query-string and header inputs are grouped as `<Operation>Params`;
//! - JSON request bodies are `<Operation>Billet`;
//! - successful responses are `<Operation>Output`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct ServerDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct IdentityDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct IdentityResolveParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct IdentityGetDocumentParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub version: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct IdentityGetLogParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct IdentitySubmitDidOperationParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct IdentityGetReceiptsParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub did: Did,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub head: Hash,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct SyncAccountParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct SyncDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub space_id: Option<SpaceId>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsSubmitParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsGetParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub include_payload: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsBatchGetParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsFrontierParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub spaces: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsSubscribeParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub spaces: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub from: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub include_history: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct EventsQueryParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub spaces: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub from: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub until: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub direction: Option<EventsQueryDirection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct SyncSnapshotHeadParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub space_id: SpaceId,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectoryDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectorySearchSpacesParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectoryResolveSpaceParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectorySearchOrganizationsParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectoryResolveOrganizationParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectorySearchActorsParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectorySearchUsersParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub q: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectoryResolveHandleParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct PrivateContactDiscoveryParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectoryAnnounceParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DirectoryWithdrawParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct BlobUploadParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Blob-Metadata")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Blob-Metadata", parameter(parameter_in = Header)))]
    pub x_contrix_blob_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Content-Type")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Content-Type", parameter(parameter_in = Header)))]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Content-Disposition")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Content-Disposition", parameter(parameter_in = Header)))]
    pub content_disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Digest")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Digest", parameter(parameter_in = Header)))]
    pub digest: Option<Hash>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct BlobHeadParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub blob_ref: BlobRef,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct BlobGetParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub blob_ref: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Range")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Range", parameter(parameter_in = Header)))]
    pub range: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct PushRegisterDeviceParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct PushUnregisterDeviceParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct PushNotifyParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DeviceMessagesPutParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct DeviceMessagesGetParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub from: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeysUploadParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeysQueryParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeysClaimParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeysBackupsPutParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
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

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeysBackupsGetParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeysBackupsDeleteParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeyPackagesUploadParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeyPackagesClaimParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AuthzEffectiveGrantsParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub space_id: SpaceId,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub subject: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub at: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AuthzInvitesParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub subject: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AuthzCheckParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct PolicyCheckParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MediaIceConfigParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct ModerationReportParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiProviderDirectoryParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub features: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiKeyMaterialParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub flow_id: FlowId,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiNotifyParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub flow_id: FlowId,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiSubmitMessageParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub flow_id: FlowId,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiGroupInfoParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub flow_id: FlowId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub include_proof: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiConsentParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiConsentUpdateParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiIdentifierQueryParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiReportAbuseParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct MimiProxyDownloadParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AccountSessionGrantParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AccountDevicePairParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AdminServerStatusParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub include: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AdminAccountStatusParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub account_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AdminRevokeDeviceParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub device_id: DeviceId,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AdminModerationQueueParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletPingParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletTransactionParams {
    #[serde(rename = "Idempotency-Key")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Idempotency-Key", parameter(parameter_in = Header)))]
    pub idempotency_key: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletActorParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub actor_id: Did,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletSpaceParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub space_id_or_alias: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletProtocolParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub protocol: String,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletThirdPartyUsersParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = DeepObject)))]
    pub external_ids: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema))]
pub struct AppletThirdPartyLocationsParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query, style = DeepObject)))]
    pub external_ids: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "X-Contrix-Request-Id")]
    #[cfg_attr(feature = "salvo", salvo(rename = "X-Contrix-Request-Id", parameter(parameter_in = Header)))]
    pub x_contrix_request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Traceparent")]
    #[cfg_attr(feature = "salvo", salvo(rename = "Traceparent", parameter(parameter_in = Header)))]
    pub traceparent: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryDirection {
    Forward,
    Backward,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsDescribeOutput {
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
    Partial,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitBillet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitOutput {
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
    pub space_frontier: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsGetOutput {
    pub event: Event,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub visibility: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsBatchGetBillet {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_hashes: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_payload: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsBatchGetOutput {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierOutput {
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub frontier: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
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
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = EventsSubscribeFrame)))]
pub struct EventsSubscribeOutput(pub EventsSubscribeFrame);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsQueryOutput {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobHeadOutput {
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Length")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Digest")]
    pub digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Cache-Control")]
    pub cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Type")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Content-Disposition")]
    pub content_disposition: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = String, format = Binary)))]
pub struct BlobGetOutput(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PrivateContactDiscoveryBillet {
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
pub struct PrivateContactDiscoveryOutput {
    #[serde(default)]
    pub matches: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesUploadBillet {
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
pub struct KeyPackagesUploadOutput {
    pub accepted: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_package_refs: Vec<KeyevtId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesClaimBillet {
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
pub struct KeyPackagesClaimOutput {
    #[serde(default)]
    pub key_packages: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeBillet {
    #[serde(default)]
    pub key_package_refs: Vec<KeyevtId>,
    pub consumer_device_id: DeviceId,
    pub signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeOutput {
    #[serde(default)]
    pub consumed: Vec<KeyevtId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeBillet {
    #[serde(default)]
    pub key_package_refs: Vec<KeyevtId>,
    pub device_id: DeviceId,
    pub signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeOutput {
    #[serde(default)]
    pub revoked: Vec<KeyevtId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiProviderDirectoryOutput {
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub features: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiKeyMaterialBillet {
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
pub struct MimiKeyMaterialOutput {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_packages: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub group_info: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub failures: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateBillet {
    pub mls_group_id: String,
    pub update: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiRoomUpdateOutput {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_state_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiNotifyBillet {
    pub notification: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub routing: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiNotifyOutput {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiSubmitMessageBillet {
    pub sender: Did,
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
pub struct MimiSubmitMessageOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub delivery: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiGroupInfoOutput {
    pub group_info: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_binding_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiConsentBillet {
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
pub struct MimiConsentOutput {
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
pub struct MimiConsentUpdateBillet {
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
pub struct MimiConsentUpdateOutput {
    pub status: String,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiIdentifierQueryBillet {
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
pub struct MimiIdentifierQueryOutput {
    #[serde(default)]
    pub results: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MimiReportAbuseBillet {
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
pub struct MimiProxyDownloadBillet {
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
pub struct MimiProxyDownloadOutput {
    pub download_ref: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSessionGrantBillet {
    pub principal_did: Did,
    pub device_id: DeviceId,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub constraints: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountSessionGrantOutput {
    pub session_grant: Value,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_refs: Vec<CapabilityId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDevicePairBillet {
    pub principal_did: Did,
    pub new_device_key: Value,
    pub pairing_proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDevicePairOutput {
    pub device_id: DeviceId,
    pub device_grant: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub key_backup_hint: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackBillet {
    pub issuer: String,
    pub code: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackOutput {
    pub principal_did: Did,
    pub session_grant: Value,
    pub account_status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminServerStatusOutput {
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
pub struct AdminAccountStatusBillet {
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
pub struct AdminAccountStatusOutput {
    pub account_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminRevokeDeviceBillet {
    pub moderator: Did,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoke_sessions: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminRevokeDeviceOutput {
    pub device_id: DeviceId,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminModerationQueueOutput {
    #[serde(default)]
    pub items: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub counts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletThirdPartyUsersOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletThirdPartyLocationsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = ServerDescription)))]
pub struct ServerDescribeOutput(pub ServerDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityDescription)))]
pub struct IdentityDescribeOutput(pub IdentityDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityResolveRequest)))]
pub struct IdentityResolveBillet(pub IdentityResolveRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityResolveResponse)))]
pub struct IdentityResolveOutput(pub IdentityResolveResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityDocumentResponse)))]
pub struct IdentityGetDocumentOutput(pub IdentityDocumentResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityLogResponse)))]
pub struct IdentityGetLogOutput(pub IdentityLogResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SubmitDidOperationRequest)))]
pub struct IdentitySubmitDidOperationBillet(pub SubmitDidOperationRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SubmitDidOperationResponse)))]
pub struct IdentitySubmitDidOperationOutput(pub SubmitDidOperationResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityReceiptsResponse)))]
pub struct IdentityGetReceiptsOutput(pub IdentityReceiptsResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncRequest)))]
pub struct SyncAccountBillet(pub SyncRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncResponse)))]
pub struct SyncAccountOutput(pub SyncResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncDescription)))]
pub struct SyncDescribeOutput(pub SyncDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncSnapshotHeadResponse)))]
pub struct SyncSnapshotHeadOutput(pub SyncSnapshotHeadResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryDescription)))]
pub struct DirectoryDescribeOutput(pub DirectoryDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchSpacesRequest)))]
pub struct DirectorySearchSpacesBillet(pub DirectorySearchSpacesRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchSpacesResponse)))]
pub struct DirectorySearchSpacesOutput(pub DirectorySearchSpacesResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryResolveSpaceRequest)))]
pub struct DirectoryResolveSpaceBillet(pub DirectoryResolveSpaceRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryResolveSpaceResponse)))]
pub struct DirectoryResolveSpaceOutput(pub DirectoryResolveSpaceResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchOrganizationsRequest)))]
pub struct DirectorySearchOrganizationsBillet(pub DirectorySearchOrganizationsRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchOrganizationsResponse)))]
pub struct DirectorySearchOrganizationsOutput(pub DirectorySearchOrganizationsResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryResolveOrganizationRequest)))]
pub struct DirectoryResolveOrganizationBillet(pub DirectoryResolveOrganizationRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryResolveOrganizationResponse)))]
pub struct DirectoryResolveOrganizationOutput(pub DirectoryResolveOrganizationResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchActorsRequest)))]
pub struct DirectorySearchActorsBillet(pub DirectorySearchActorsRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchActorsResponse)))]
pub struct DirectorySearchActorsOutput(pub DirectorySearchActorsResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectorySearchUsersResponse)))]
pub struct DirectorySearchUsersOutput(pub DirectorySearchUsersResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryResolveHandleRequest)))]
pub struct DirectoryResolveHandleBillet(pub DirectoryResolveHandleRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryResolveHandleResponse)))]
pub struct DirectoryResolveHandleOutput(pub DirectoryResolveHandleResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryAnnounceRequest)))]
pub struct DirectoryAnnounceBillet(pub DirectoryAnnounceRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryAnnounceResponse)))]
pub struct DirectoryAnnounceOutput(pub DirectoryAnnounceResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryWithdrawRequest)))]
pub struct DirectoryWithdrawBillet(pub DirectoryWithdrawRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DirectoryWithdrawResponse)))]
pub struct DirectoryWithdrawOutput(pub DirectoryWithdrawResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = BlobUploadMetadata)))]
pub struct BlobUploadBillet(pub BlobUploadMetadata);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = BlobUploadResponse)))]
pub struct BlobUploadOutput(pub BlobUploadResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PushRegisterDeviceRequest)))]
pub struct PushRegisterDeviceBillet(pub PushRegisterDeviceRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PushRegisterDeviceResponse)))]
pub struct PushRegisterDeviceOutput(pub PushRegisterDeviceResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PushUnregisterDeviceRequest)))]
pub struct PushUnregisterDeviceBillet(pub PushUnregisterDeviceRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = OkResponse)))]
pub struct PushUnregisterDeviceOutput(pub OkResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PushNotifyRequest)))]
pub struct PushNotifyBillet(pub PushNotifyRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PushNotifyResponse)))]
pub struct PushNotifyOutput(pub PushNotifyResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DeviceMessagesSendRequest)))]
pub struct DeviceMessagesPutBillet(pub DeviceMessagesSendRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DeviceMessagesSendResponse)))]
pub struct DeviceMessagesPutOutput(pub DeviceMessagesSendResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DeviceMessagesReceiveResponse)))]
pub struct DeviceMessagesGetOutput(pub DeviceMessagesReceiveResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeysUploadRequest)))]
pub struct KeysUploadBillet(pub KeysUploadRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeysUploadResponse)))]
pub struct KeysUploadOutput(pub KeysUploadResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeysQueryRequest)))]
pub struct KeysQueryBillet(pub KeysQueryRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeysQueryResponse)))]
pub struct KeysQueryOutput(pub KeysQueryResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeysClaimRequest)))]
pub struct KeysClaimBillet(pub KeysClaimRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeysClaimResponse)))]
pub struct KeysClaimOutput(pub KeysClaimResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsPutBillet(pub KeyBackup);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackupPutResponse)))]
pub struct KeysBackupsPutOutput(pub KeyBackupPutResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackupsListResponse)))]
pub struct KeysBackupsListOutput(pub KeyBackupsListResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsGetOutput(pub KeyBackup);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackupDeleteResponse)))]
pub struct KeysBackupsDeleteOutput(pub KeyBackupDeleteResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = EffectiveGrantsResponse)))]
pub struct AuthzEffectiveGrantsOutput(pub EffectiveGrantsResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AuthzInvitesResponse)))]
pub struct AuthzInvitesOutput(pub AuthzInvitesResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AuthzCheckRequest)))]
pub struct AuthzCheckBillet(pub AuthzCheckRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AuthzCheckResponse)))]
pub struct AuthzCheckOutput(pub AuthzCheckResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PolicyCheckRequest)))]
pub struct PolicyCheckBillet(pub PolicyCheckRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = PolicyCheckResponse)))]
pub struct PolicyCheckOutput(pub PolicyCheckResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = MediaIceConfigRequest)))]
pub struct MediaIceConfigBillet(pub MediaIceConfigRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = MediaIceConfigResponse)))]
pub struct MediaIceConfigOutput(pub MediaIceConfigResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = ModerationReportRequest)))]
pub struct ModerationReportBillet(pub ModerationReportRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = ModerationReportResponse)))]
pub struct ModerationReportOutput(pub ModerationReportResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = OkResponse)))]
pub struct MimiReportAbuseOutput(pub OkResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletPingResponse)))]
pub struct AppletPingOutput(pub AppletPingResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletDescription)))]
pub struct AppletDescribeOutput(pub AppletDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletTransactionRequest)))]
pub struct AppletTransactionBillet(pub AppletTransactionRequest);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletTransactionResponse)))]
pub struct AppletTransactionOutput(pub AppletTransactionResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletActorResponse)))]
pub struct AppletActorOutput(pub AppletActorResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletSpaceResponse)))]
pub struct AppletSpaceOutput(pub AppletSpaceResponse);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = AppletProtocolResponse)))]
pub struct AppletProtocolOutput(pub AppletProtocolResponse);

fn is_false(value: &bool) -> bool {
    !*value
}
