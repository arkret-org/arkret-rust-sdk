//! Applet third-party lookup HTTP body DTOs.

use arkret_wire::{Did, RealmId};
use serde::{Deserialize, Serialize};

use crate::artifacts_applet::ExternalRef;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletThirdPartyUserList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletThirdPartyLocationList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}
