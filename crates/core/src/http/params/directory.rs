//! Shim: directory query/header parameter DTOs moved to
//! `arkret-models-discovery`. Re-exported to preserve the
//! `arkret_core::http::params::*` path for downstream consumers.

pub use arkret_models_discovery::http_params::{
    DirectoryAnnounceParams, DirectoryDescribeParams, DirectoryResolveHandleParams,
    DirectoryResolveOrganizationParams, DirectoryResolveRealmParams, DirectorySearchActorsParams,
    DirectorySearchOrganizationsParams, DirectorySearchRealmsParams, DirectorySearchUsersParams,
    DirectoryWithdrawParams, PrivateContactDiscoveryParams,
};
