//! Shim: identity/account query parameters moved to `arkret-models-identity`;
//! event/collaboration query parameters moved to
//! `arkret-models-collaboration`. Re-exported to preserve the
//! `arkret_core::http::params::*` path for downstream consumers.

pub use arkret_models_collaboration::http_params::{
    EphemeralSendParams, EventsDescribeParams, EventsFrontierParams, EventsGetParams,
    EventsQueryOrder, EventsQueryParams, EventsResolveParams, EventsSubmitParams,
    EventsSubscribeParams, ProjectionLifecycleParams, SnapshotHeadParams,
};
pub use arkret_models_identity::http_params::{
    AccountDescribeParams, AccountSubscribeParams, IdentityDescribeParams,
    IdentityGetDocumentParams, IdentityGetLogParams, IdentityGetReceiptsParams,
    IdentityResolveParams, IdentitySubmitDidOperationParams, ServerDescribeParams,
};
