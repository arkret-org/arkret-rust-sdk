//! Shim: account query parameters moved to `arkret-models-identity`; admin
//! query parameters moved to `arkret-models-collaboration`; applet query
//! parameters moved to `arkret-models-integration`. Re-exported to preserve
//! the `arkret_core::http::params::*` path for downstream consumers.

pub use arkret_models_collaboration::http_params::{
    AdminAccountStatusParams, AdminModerationQueueParams, AdminRevokeDeviceParams,
    AdminServerStatusParams,
};
pub use arkret_models_identity::http_params::{
    AccountDevicePairParams, AccountOidcCallbackParams, AccountSessionGrantParams,
};
pub use arkret_models_integration::http_params::{
    AppletActorParams, AppletDescribeParams, AppletPingParams, AppletProtocolParams,
    AppletRealmParams, AppletThirdPartyLocationsParams, AppletThirdPartyUsersParams,
    AppletTransactionParams,
};
