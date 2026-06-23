use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushRegisterDeviceRequestBody {
    pub device_id: DeviceId,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_did: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRegisterDeviceOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushUnregisterDeviceRequestBody {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushUnregisterDeviceOutcome {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OkOutcome {
    pub ok: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_increment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missed_call: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushDeviceRoute {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub visible_notification_opt_in: bool,
}

pub type PushRouteToken = String;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushRouteTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_route_token: Option<PushRouteToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mention_redirect_target_route_tokens: Vec<PushRouteToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding_frontier_token: Option<PushRouteToken>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushNotificationEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_locus_unresolved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<PushCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tokens: Option<PushRouteTokens>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<PushDeviceRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushAuditEnvelopeMetadata {
    pub access_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushNotifyRequestBody {
    pub notification: PushNotificationEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_envelope: Option<PushAuditEnvelopeMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushNotifyOutcome {
    #[serde(default)]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushNotifyRejection {
    pub push_target_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
