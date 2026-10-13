//! Applet-registration and bridge event payload counterparts.

use std::collections::BTreeMap;

use arkret_wire::{AppletId, NonEmptyString, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeVisibilityScope {
    RealmAdmins,
    AppletController,
    RealmMembers,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeErrorClass {
    ExternalNetwork,
    Auth,
    Schema,
    RateLimit,
    Policy,
}

include!("generated/applet_audit_payload_contracts.rs");
