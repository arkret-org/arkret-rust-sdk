//! Shim: blob / push / device-message / key-operation query parameters moved
//! to `arkret-models-collaboration`. Re-exported to preserve the
//! `arkret_core::http::params::*` path for downstream consumers.

pub use arkret_models_collaboration::http_params::{
    BlobGetParams, BlobHeadParams, BlobUploadParams, DeviceMessagesGetParams,
    DeviceMessagesSendParams, KeyPackagesClaimParams, KeyPackagesConsumeParams,
    KeyPackagesRevokeParams, KeyPackagesUploadParams, KeysBackupsDeleteParams,
    KeysBackupsGetParams, KeysBackupsListParams, KeysBackupsPutParams, KeysClaimParams,
    KeysQueryParams, KeysUploadParams, PushNotifyParams, PushRegisterDeviceParams,
    PushUnregisterDeviceParams,
};
