//! Collaboration HTTP query/header parameter DTOs for the Salvo OpenAPI
//! binding.
//!
//! Event stream describe/submit/get/resolve/frontier/subscribe/query
//! selectors, snapshot-head, ephemeral send, and projection lifecycle; blob
//! transfer, push registration/notify, device-message, key and key-package
//! operation headers; the MIMI interop operation parameters; media ICE /
//! moderation-report correlation; and the admin server/account/device/
//! moderation-queue operation parameters
//! (`service-operation-dtos.schema.json`).

use arkret_models_crypto::key_backup::BackupClass;
use arkret_wire::{
    BackupId, BlobRef, Cursor, DeviceId, Did, Error, EventId, Hash, RealmId, Result, StrandId,
};
use serde::{Deserialize, Serialize};

// EventsQueryOrder is defined here (in the params layer) because EventsQueryParams
// references it as a query parameter type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryOrder {
    #[default]
    Default,
    Ascending,
    Descending,
}

impl EventsQueryOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct EventsDescribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub realm_id: Option<RealmId>,

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
pub struct EventsSubmitParams {
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
pub struct EventsGetParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub include_payload: Option<bool>,

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
pub struct EventsResolveParams {
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
pub struct EventsFrontierParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,

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
pub struct EventsSubscribeParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub catchup: Option<bool>,

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
pub struct EventsQueryParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub before: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub order: Option<EventsQueryOrder>,
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

impl EventsQueryParams {
    /// Validate the selector part of `ak.self.events.query.scan`.
    pub fn validate_non_empty(&self) -> Result<()> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(Error::Protocol(
                "events.query selector requires at least one of realms[] / actors[]".to_owned(),
            ));
        }
        Ok(())
    }

    /// Render repeated query-string key/value pairs.
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        for realm in &self.realms {
            pairs.push(("realms", realm.as_str().to_owned()));
        }
        for actor in &self.actors {
            pairs.push(("actors", actor.as_str().to_owned()));
        }
        if let Some(before) = &self.before {
            pairs.push(("before", before.as_str().to_owned()));
        }
        if let Some(after) = &self.after {
            pairs.push(("after", after.as_str().to_owned()));
        }
        if let Some(order) = self.order {
            pairs.push(("order", order.as_str().to_owned()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        pairs
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct SnapshotHeadParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub realm_id: RealmId,

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
pub struct EphemeralSendParams {
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
pub struct ProjectionLifecycleParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub include_terminal: Option<bool>,

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

// --- blob / push / device-message / key operations ---

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct BlobUploadParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "X-Arkret-Blob-Metadata"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "X-Arkret-Blob-Metadata", parameter(parameter_in = Header)))]
    pub x_arkret_blob_metadata: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Content-Type"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Content-Type", parameter(parameter_in = Header)))]
    pub content_type: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "Content-Disposition"
    )]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Content-Disposition", parameter(parameter_in = Header)))]
    pub content_disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Digest")]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Digest", parameter(parameter_in = Header)))]
    pub digest: Option<Hash>,

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
pub struct BlobHeadParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub blob_ref: BlobRef,

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
pub struct BlobGetParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub blob_ref: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "Range")]
    #[cfg_attr(feature = "salvo-oapi", salvo(rename = "Range", parameter(parameter_in = Header)))]
    pub range: Option<String>,

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
pub struct PushRegisterDeviceParams {
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
pub struct PushUnregisterDeviceParams {
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
pub struct PushNotifyParams {
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
pub struct DeviceMessagesSendParams {
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
pub struct DeviceMessagesGetParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub from: Option<Cursor>,
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
pub struct KeysUploadParams {
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
pub struct KeysQueryParams {
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
pub struct KeysClaimParams {
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
pub struct KeysBackupsPutParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,
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
pub struct KeysBackupsListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub backup_class: Option<BackupClass>,
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
pub struct KeysBackupsGetParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,

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
pub struct KeysBackupsDeleteParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub backup_id: BackupId,
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
pub struct KeyPackagesUploadParams {
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
pub struct KeyPackagesClaimParams {
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
pub struct KeyPackagesConsumeParams {
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
pub struct KeyPackagesRevokeParams {
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

// --- MIMI interop operations ---

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct MimiProviderDirectoryParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub features: Vec<String>,

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
pub struct MimiKeyMaterialParams {
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
pub struct MimiRoomUpdateParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,

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
pub struct MimiNotifyParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,

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
pub struct MimiSubmitMessageParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,

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
pub struct MimiGroupInfoParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub include_proof: Option<bool>,

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
pub struct MimiConsentParams {
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
pub struct MimiConsentUpdateParams {
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
pub struct MimiIdentifierQueryParams {
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
pub struct MimiReportAbuseParams {
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
pub struct MimiProxyDownloadParams {
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

// --- media / moderation-report ---

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct MediaIceConfigParams {
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
pub struct ModerationReportParams {
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

// --- admin server / account / device / moderation-queue ---

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo-oapi",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct AdminServerStatusParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query, style = Form, explode)))]
    pub include: Vec<String>,

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
pub struct AdminAccountStatusParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub account_id: String,

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
pub struct AdminRevokeDeviceParams {
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Path)))]
    pub device_id: DeviceId,

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
pub struct AdminModerationQueueParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(parameter(parameter_in = Query)))]
    pub status: Option<String>,
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
