//! Account-private device push-route event payloads.

use arkret_wire::{AccountId, DeviceId, DidCoreId, PushTargetId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PushRouteScope {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub push_route: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DevicePushRoutePayload {
    Active(DevicePushRouteActivePayload),
    Revoked(DevicePushRouteRevokedPayload),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePushRouteActivePayload {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub push_route: String,
    pub expected_server_revision: u64,
    pub push_target_id: PushTargetId,
    pub push_gateway_id: DidCoreId,
    pub encryption_key: String,
    pub capabilities: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePushRouteRevokedPayload {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub push_route: String,
    pub expected_server_revision: u64,
    pub revoked: PushRouteRevokedMarker,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PushRouteRevokedMarker;

impl Serialize for PushRouteRevokedMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for PushRouteRevokedMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(de::Error::custom("revoked must be true"))
        }
    }
}

impl DevicePushRoutePayload {
    pub fn scope(&self) -> PushRouteScope {
        let (account_id, device_id, push_route) = match self {
            Self::Active(value) => (&value.account_id, &value.device_id, &value.push_route),
            Self::Revoked(value) => (&value.account_id, &value.device_id, &value.push_route),
        };
        PushRouteScope {
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            push_route: push_route.clone(),
        }
    }

    pub const fn expected_server_revision(&self) -> u64 {
        match self {
            Self::Active(value) => value.expected_server_revision,
            Self::Revoked(value) => value.expected_server_revision,
        }
    }
}
