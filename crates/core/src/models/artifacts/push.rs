//! Push schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PushOperations {
    PushRegisterDeviceRequestBody(PushRegisterDeviceRequestBody),
    PushRegisterDeviceOutcome(PushRegisterDeviceOutcome),
    PushUnregisterDeviceRequestBody(PushUnregisterDeviceRequestBody),
    PushUnregisterDeviceOutcome(PushUnregisterDeviceOutcome),
    PushNotifyRequestBody(PushNotifyRequestBody),
    PushNotifyOutcome(PushNotifyOutcome),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/blind_notification`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_redirect_target_route_tokens: Option<Vec<PushRouteToken>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding_frontier_token: Option<PushRouteToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindNotification {
    pub push_target_id: PushTargetId,
    pub wakeup_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_locus_unresolved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Counts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tokens: Option<RouteTokens>,
    pub devices: Vec<DeviceRoute>,
}

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/counts`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_increment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missed_call: Option<u64>,
}

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/device_route`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRoute {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key: Option<PushKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub visible_notification_opt_in: bool,
}

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/notify_rejection`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyRejection {
    pub push_target_id: PushTargetId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_key`.
pub type PushKey = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_target_id`.
pub type PushTargetId = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/registration_id`.
pub type RegistrationId = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/url`.
pub type Url = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisibleNotification {
    pub push_target_id: PushTargetId,
    pub wakeup_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_locus_unresolved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Counts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tokens: Option<RouteTokens>,
    pub devices: Vec<DeviceRoute>,
    pub event_id: EventId,
    pub realm_id: RealmId,
    pub sender_actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_is_target: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<String>,
}
