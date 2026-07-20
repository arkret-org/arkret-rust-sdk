//! Shim: MIMI interop query parameters moved to
//! `arkret-models-collaboration`. Re-exported to preserve the
//! `arkret_core::http::params::*` path for downstream consumers.

pub use arkret_models_collaboration::http_params::{
    MimiConsentParams, MimiConsentUpdateParams, MimiGroupInfoParams, MimiIdentifierQueryParams,
    MimiKeyMaterialParams, MimiNotifyParams, MimiProviderDirectoryParams, MimiProxyDownloadParams,
    MimiReportAbuseParams, MimiRoomUpdateParams, MimiSubmitMessageParams,
};
