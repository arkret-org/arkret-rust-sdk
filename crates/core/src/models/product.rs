//! Deployment-local product and operator contracts.
//!
//! Nothing in this module is part of the `/_arkret/` protocol surface. These
//! DTOs are shared by Arkret products so producers and consumers still use one
//! strong type without presenting product-local endpoints as protocol models.

use serde::{Deserialize, Serialize};

use super::{DeviceId, DeviceStatus, Did, EventId};

#[path = "admin.rs"]
pub mod admin;
pub use admin::*;

/// Request for the product-local device signing-key directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceSigningKeyDirectoryQueryRequestBody {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_ids: Vec<DeviceId>,
}

/// One authorized, non-revoked device signing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthorizedDeviceSigningKey {
    pub device_id: DeviceId,
    pub device_signing_key: String,
    pub device_status: DeviceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
}

/// Response from the product-local device signing-key directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceSigningKeyDirectoryOutcome {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<AuthorizedDeviceSigningKey>,
}
