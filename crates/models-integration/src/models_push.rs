use std::collections::HashSet;

use arkret_wire::{
    DeviceId, DidCoreId, EventId, MessageId, NonEmptyString, ProfileId, RealmId, ReasonCode,
    SchemaId, StrandId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub recipient_service_id: Option<DidCoreId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegisterDeviceOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushUnregisterDeviceRequestBody {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushUnregisterDeviceOutcome {
    pub ok: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OkOutcome {
    pub ok: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<PushCountIndicator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_increment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missed_call: Option<PushCountIndicator>,
}

/// Privacy-preserving absolute-count indicator used by blind push payloads.
///
/// The wire value is either a boolean presence bit or a policy-declared bucket
/// label. Plain integer absolute counts are deliberately not representable.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PushCountIndicator {
    Present(bool),
    Bucket(String),
}

impl<'de> Deserialize<'de> for PushCountIndicator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Bool(value) => Ok(Self::Present(value)),
            Value::String(value) if is_valid_push_count_bucket(&value) => Ok(Self::Bucket(value)),
            Value::String(_) => Err(serde::de::Error::custom("invalid push count bucket")),
            _ => Err(serde::de::Error::custom(
                "push count indicator must be a boolean or bucket string",
            )),
        }
    }
}

impl PushCountIndicator {
    #[must_use]
    pub fn is_present(&self) -> bool {
        match self {
            Self::Present(value) => *value,
            Self::Bucket(value) => value != "0",
        }
    }

    #[must_use]
    pub fn bucket(&self) -> Option<&str> {
        match self {
            Self::Present(_) => None,
            Self::Bucket(value) => Some(value),
        }
    }
}

fn is_valid_push_count_bucket(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    if value == "0" {
        return true;
    }
    let parse_positive = |digits: &str| {
        !digits.is_empty()
            && !digits.starts_with('0')
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    };
    if let Some(lower) = value.strip_suffix('+') {
        return parse_positive(lower);
    }
    if let Some((lower, upper)) = value.split_once('-') {
        return parse_positive(lower)
            && parse_positive(upper)
            && matches!(
                (lower.parse::<u128>(), upper.parse::<u128>()),
                (Ok(lower), Ok(upper)) if lower < upper
            );
    }
    parse_positive(value)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Canonical v1 wire values for the Realm `mention_routing_hint` policy.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionRoutingHint {
    /// Do not register, compare, or persist mention-routing sidecars.
    #[default]
    Disabled,
    /// Allow recipient opt-in opaque token matching in an ordinary E2EE Realm.
    RecipientRegisteredToken,
}

impl MentionRoutingHint {
    /// Parse only the closed v1 wire set.
    pub fn parse_wire(value: &str) -> Option<Self> {
        match value {
            "disabled" => Some(Self::Disabled),
            "recipient_registered_token" => Some(Self::RecipientRegisteredToken),
            _ => None,
        }
    }

    /// Parse a possibly newer policy value without treating it as enabled.
    pub fn parse_open(value: &str) -> OpenMentionRoutingHint {
        Self::parse_wire(value).map_or_else(
            || OpenMentionRoutingHint::Unknown(value.to_owned()),
            OpenMentionRoutingHint::Known,
        )
    }

    /// Return the canonical wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::RecipientRegisteredToken => "recipient_registered_token",
        }
    }
}

/// Open parse result used at policy boundaries where unknown values must be
/// observed and then evaluated fail-closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenMentionRoutingHint {
    /// A canonical v1 wire value.
    Known(MentionRoutingHint),
    /// An unrecognized value that must never enable sidecar processing.
    Unknown(String),
}

impl OpenMentionRoutingHint {
    /// Resolve the parsed value to its safe effective behavior.
    pub fn fail_closed(self) -> MentionRoutingHint {
        match self {
            Self::Known(hint) => hint,
            Self::Unknown(_) => MentionRoutingHint::Disabled,
        }
    }
}

/// Realm profiles that always disable mention-routing sidecars.
pub const HARDENED_MENTION_ROUTING_PROFILES: &[&str] = &[
    ProfileId::MLS_MINIMAL_METADATA_REALM_V1,
    ProfileId::ATTESTED_AUDIT_E2EE_V1,
    ProfileId::DISCLOSED_AUDIT_E2EE_V1,
];

/// Compute the canonical effective mention-routing policy.
///
/// Hardened profiles win over every declared value. Other Realms may enable
/// recipient-registered tokens only when they declare the ordinary E2EE
/// baseline and explicitly opt in. Missing and unknown values are disabled.
pub fn effective_mention_routing_hint<S: AsRef<str>>(
    realm_profiles: &[S],
    declared_hint: Option<&str>,
) -> MentionRoutingHint {
    let has_profile = |profile: &str| {
        realm_profiles
            .iter()
            .any(|candidate| candidate.as_ref() == profile)
    };

    if HARDENED_MENTION_ROUTING_PROFILES
        .iter()
        .any(|profile| has_profile(profile))
        || !has_profile(ProfileId::E2EE_CLIENT_V1)
    {
        return MentionRoutingHint::Disabled;
    }

    declared_hint
        .map(MentionRoutingHint::parse_open)
        .map(OpenMentionRoutingHint::fail_closed)
        .unwrap_or_default()
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTimingProfileHint {
    #[default]
    Default,
    TrafficMetadataHardened,
}

impl PushTimingProfileHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::TrafficMetadataHardened => "traffic_metadata_hardened",
        }
    }

    pub fn is_traffic_metadata_hardened(self) -> bool {
        matches!(self, Self::TrafficMetadataHardened)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing_profile_hint: Option<PushTimingProfileHint>,
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
    pub sender_actor_id: Option<DidCoreId>,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushAuditEnvelopeMetadata {
    pub access_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
}

/// Open, validated `reason_code` for a push-notify request.
///
/// The request-side vocabulary is deliberately not an enum: the push wire
/// contract accepts every value matching `^[a-z][a-z0-9_]{0,63}$`, including
/// values introduced by newer specifications such as `historical_only`.
/// Gateway outcome reason codes remain a separate closed enum because their
/// schema is closed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PushNotifyRequestReasonCode(String);

impl PushNotifyRequestReasonCode {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !ReasonCode::is_valid_wire(&value) {
            return Err("push notify request reason_code must match ^[a-z][a-z0-9_]{0,63}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for PushNotifyRequestReasonCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<String> for PushNotifyRequestReasonCode {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PushNotifyRequestReasonCode> for String {
    fn from(value: PushNotifyRequestReasonCode) -> Self {
        value.into_string()
    }
}

impl Serialize for PushNotifyRequestReasonCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PushNotifyRequestReasonCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for PushNotifyRequestReasonCode {
    fn to_schema(
        _components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::schema::Object::new()
            .schema_type(salvo_oapi::schema::BasicType::String)
            .pattern("^[a-z][a-z0-9_]{0,63}$")
            .max_length(64)
            .into()
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ComposeSchema for PushNotifyRequestReasonCode {
    fn compose(
        components: &mut salvo_oapi::Components,
        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        let _ = generics;
        <Self as salvo_oapi::ToSchema>::to_schema(components)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyRequestBody {
    pub notification: PushNotificationEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<PushNotifyRequestReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_envelope: Option<PushAuditEnvelopeMetadata>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyOutcome {
    pub push_target_id: String,
    pub outcomes: Vec<PushNotifyDeviceOutcome>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_notify_device_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyDeviceOutcome {
    pub device_id: DeviceId,
    pub gateway_status: PushNotifyGatewayStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<PushNotifyReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl PushNotifyDeviceOutcome {
    pub fn accepted(device_id: DeviceId) -> Self {
        Self {
            device_id,
            gateway_status: PushNotifyGatewayStatus::Accepted,
            reason_code: None,
            retry_after_ms: None,
        }
    }

    pub fn duplicate(device_id: DeviceId) -> Self {
        Self {
            device_id,
            gateway_status: PushNotifyGatewayStatus::Duplicate,
            reason_code: None,
            retry_after_ms: None,
        }
    }

    pub fn rejected(
        device_id: DeviceId,
        reason_code: PushNotifyReasonCode,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            device_id,
            gateway_status: PushNotifyGatewayStatus::Rejected,
            reason_code: Some(reason_code),
            retry_after_ms,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.gateway_status {
            PushNotifyGatewayStatus::Accepted | PushNotifyGatewayStatus::Duplicate => {
                if self.reason_code.is_some() || self.retry_after_ms.is_some() {
                    return Err(
                        "accepted and duplicate push notify outcomes must not carry rejection fields"
                            .to_owned(),
                    );
                }
            }
            PushNotifyGatewayStatus::Rejected => {
                let Some(reason_code) = self.reason_code else {
                    return Err("rejected push notify outcomes require reason_code".to_owned());
                };
                if self.retry_after_ms == Some(0) {
                    return Err("retry_after_ms must be greater than zero".to_owned());
                }
                if self.retry_after_ms.is_some() && !reason_code.is_caller_retryable() {
                    return Err(
                        "retry_after_ms is only valid for caller-retryable push notify reasons"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushNotifyGatewayStatus {
    Accepted,
    Duplicate,
    Rejected,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushNotifyReasonCode {
    PushTargetUnknown,
    PushPayloadTooLarge,
    UnsupportedProfile,
    DeliveryBindingStale,
    PushTokenUnknown,
    PushTokenInvalid,
    PushGatewayUnreachable,
    RateLimited,
}

impl PushNotifyReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PushTargetUnknown => "push_target_unknown",
            Self::PushPayloadTooLarge => "push_payload_too_large",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::DeliveryBindingStale => "delivery_binding_stale",
            Self::PushTokenUnknown => "push_token_unknown",
            Self::PushTokenInvalid => "push_token_invalid",
            Self::PushGatewayUnreachable => "push_gateway_unreachable",
            Self::RateLimited => "rate_limited",
        }
    }

    pub const fn is_caller_retryable(self) -> bool {
        matches!(self, Self::PushGatewayUnreachable | Self::RateLimited)
    }
}

const FORBIDDEN_PLAINTEXT_PARENT_LEAF: &[(&str, &str)] = &[
    ("binding_proof", "signature"),
    ("subject_proof", "signature"),
];

pub const AGENT_LIFECYCLE_SILENT_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::SELF_AGENT_PAUSE,
    arkret_wire::event_kind_str::SELF_AGENT_RESUME,
    arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE,
];

pub const AGENT_ACTOR_PRIVATE_KINDS: &[&str] = &[
    arkret_wire::event_kind_str::AGENT_DRAFT_PROPOSE,
    arkret_wire::event_kind_str::AGENT_ACTION_REQUEST,
    arkret_wire::event_kind_str::AGENT_ACTION_APPROVE,
    arkret_wire::event_kind_str::AGENT_ACTION_REJECT,
];

pub const PHASE_P2_AGENT_TYPED_ID_PREFIXES: &[&str] = &[
    "ak:agent_session:",
    "ak:agent_key:",
    "ak:agent_draft:",
    "ak:accountability_grant:",
    "ak:sidecar_circle:",
    "ak:backup_series:",
    "ak:recovery_session:",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentEventRouting {
    DurableLifecycle,
    ActorPrivateDrop,
}

pub fn classify_agent_event_kind(event_kind: &str) -> Option<AgentEventRouting> {
    if AGENT_LIFECYCLE_SILENT_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::DurableLifecycle);
    }
    if AGENT_ACTOR_PRIVATE_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::ActorPrivateDrop);
    }
    None
}

pub fn is_phase_p2_agent_typed_id(value: &str) -> bool {
    PHASE_P2_AGENT_TYPED_ID_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

pub fn validate_push_notify_contract_shape(request: &PushNotifyRequestBody) -> Result<(), String> {
    let raw = serde_json::to_value(request)
        .map_err(|error| format!("push notify request serialization failed: {error}"))?;
    reject_forbidden_plaintext_fields("", &raw)?;

    let notification = &request.notification;
    validate_push_target_id(notification.push_target_id.as_deref())?;
    validate_wakeup_kind(notification.wakeup_kind.as_deref())?;
    validate_timing_profile_hint(notification.timing_profile_hint)?;

    if notification.devices.is_empty() {
        return Err("notification.devices must contain at least one device".to_owned());
    }
    let mut device_ids = HashSet::with_capacity(notification.devices.len());
    for device in &notification.devices {
        if !device_ids.insert(device.device_id.as_str()) {
            return Err(format!(
                "notification.devices contains duplicate device_id `{}`",
                device.device_id.as_str()
            ));
        }
    }

    if let Some(route_tokens) = &notification.route_tokens {
        validate_push_route_token(
            route_tokens.realm_route_token.as_deref(),
            "notification.route_tokens.realm_route_token",
        )?;
        validate_push_route_token(
            route_tokens.scope_route_token.as_deref(),
            "notification.route_tokens.scope_route_token",
        )?;
        validate_push_route_token(
            route_tokens.delivery_binding_frontier_token.as_deref(),
            "notification.route_tokens.delivery_binding_frontier_token",
        )?;
        for (index, item) in route_tokens
            .mention_redirect_target_route_tokens
            .iter()
            .enumerate()
        {
            validate_push_route_token(
                Some(item),
                &format!("notification.route_tokens.mention_redirect_target_route_tokens[{index}]"),
            )?;
        }
    }

    Ok(())
}

pub fn validate_push_notify_outcome_conservation(
    request: &PushNotifyRequestBody,
    outcome: &PushNotifyOutcome,
) -> Result<(), String> {
    let expected_push_target_id = request
        .notification
        .push_target_id
        .as_deref()
        .ok_or_else(|| "notification.push_target_id is required".to_owned())?;
    if outcome.push_target_id != expected_push_target_id {
        return Err("push notify outcome push_target_id does not match the request".to_owned());
    }

    let requested_device_ids = request
        .notification
        .devices
        .iter()
        .map(|device| device.device_id.as_str())
        .collect::<HashSet<_>>();
    if requested_device_ids.is_empty() {
        return Err("notification.devices must contain at least one device".to_owned());
    }
    if requested_device_ids.len() != request.notification.devices.len() {
        return Err("notification.devices contains duplicate device_id values".to_owned());
    }
    let mut outcome_device_ids = HashSet::with_capacity(outcome.outcomes.len());
    for device_outcome in &outcome.outcomes {
        device_outcome.validate()?;
        let device_id = device_outcome.device_id.as_str();
        if !requested_device_ids.contains(device_id) {
            return Err(format!(
                "push notify outcome contains unrequested device_id `{device_id}`"
            ));
        }
        if !outcome_device_ids.insert(device_id) {
            return Err(format!(
                "push notify outcome contains duplicate device_id `{device_id}`"
            ));
        }
    }
    if outcome_device_ids.len() != requested_device_ids.len() {
        let missing = requested_device_ids
            .difference(&outcome_device_ids)
            .copied()
            .collect::<Vec<_>>();
        return Err(format!(
            "push notify outcome is missing requested device_id values: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

fn reject_forbidden_plaintext_fields(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let leaf = key.to_ascii_lowercase();
                let next_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(parent_key) = path.rsplit('.').next() {
                    let parent_lower = parent_key.to_ascii_lowercase();
                    if FORBIDDEN_PLAINTEXT_PARENT_LEAF
                        .iter()
                        .any(|(parent, leaf_name)| {
                            parent.eq_ignore_ascii_case(&parent_lower)
                                && leaf_name.eq_ignore_ascii_case(&leaf)
                        })
                    {
                        return Err(format!(
                            "field `{next_path}` is forbidden on the push wire model"
                        ));
                    }
                }
                reject_forbidden_plaintext_fields(&next_path, nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                reject_forbidden_plaintext_fields(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_push_target_id(value: Option<&str>) -> Result<(), String> {
    const PREFIX: &str = "ak:pseudonym:push:";
    let Some(value) = value else {
        return Err("notification.push_target_id is required".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.push_target_id must not be empty".to_owned());
    }
    let Some(token) = value.strip_prefix(PREFIX) else {
        return Err(format!(
            "notification.push_target_id must use `{PREFIX}*` typed IDs"
        ));
    };
    if !(22..=128).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("notification.push_target_id must be an opaque base64url token".to_owned());
    }
    Ok(())
}

fn validate_push_route_token(value: Option<&str>, path: &str) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.len() < 22
        || value.len() > 512
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-'))
    {
        return Err(format!("{path} must be an opaque route token"));
    }
    Ok(())
}

fn validate_wakeup_kind(value: Option<&str>) -> Result<(), String> {
    let Some(value) = value else {
        return Err("notification.wakeup_kind is required".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.wakeup_kind must not be empty".to_owned());
    }
    if !crate::push_vocab::is_valid_wakeup_kind(value) {
        return Err(format!(
            "notification.wakeup_kind must be one of {}",
            crate::push_vocab::ALLOWED_WAKEUP_KINDS.join(", ")
        ));
    }
    Ok(())
}

fn validate_timing_profile_hint(value: Option<PushTimingProfileHint>) -> Result<(), String> {
    let Some(_) = value else {
        return Err("notification.timing_profile_hint is required".to_owned());
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid_request() -> PushNotifyRequestBody {
        PushNotifyRequestBody {
            notification: PushNotificationEnvelope {
                push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
                wakeup_kind: Some("message".to_owned()),
                timing_profile_hint: Some(PushTimingProfileHint::Default),
                devices: vec![
                    PushDeviceRoute {
                        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                            .unwrap(),
                        push_key: Some("token-1".to_owned()),
                        app_id: Some("com.example.app".to_owned()),
                        platform: None,
                        target_route_token: None,
                        visible_notification_opt_in: false,
                    },
                    PushDeviceRoute {
                        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002")
                            .unwrap(),
                        push_key: Some("token-2".to_owned()),
                        app_id: Some("com.example.app".to_owned()),
                        platform: None,
                        target_route_token: None,
                        visible_notification_opt_in: false,
                    },
                ],
                ..PushNotificationEnvelope::default()
            },
            event_kind: None,
            reason_code: None,
            audit_envelope: None,
        }
    }

    #[test]
    fn push_notify_request_reason_code_is_open_and_wire_validated() {
        for code in ["historical_only", "future_reason_42"] {
            let parsed: PushNotifyRequestReasonCode =
                serde_json::from_value(json!(code)).expect("valid open request reason code");
            assert_eq!(parsed.as_str(), code);
            assert_eq!(serde_json::to_value(parsed).unwrap(), json!(code));
        }

        let max_length = format!("a{}", "_".repeat(63));
        assert!(PushNotifyRequestReasonCode::new(max_length).is_ok());

        for invalid in ["", "HistoricalOnly", "historical-only", "1historical_only"] {
            assert!(
                serde_json::from_value::<PushNotifyRequestReasonCode>(json!(invalid)).is_err(),
                "{invalid:?} must not be a legal reason_code"
            );
        }

        let mut request = valid_request();
        request.reason_code = Some(PushNotifyRequestReasonCode::new("historical_only").unwrap());
        assert_eq!(
            serde_json::to_value(request).unwrap()["reason_code"],
            "historical_only"
        );
    }

    #[test]
    fn mention_routing_hint_uses_only_canonical_wire_values() {
        for (wire, expected) in [
            ("disabled", MentionRoutingHint::Disabled),
            (
                "recipient_registered_token",
                MentionRoutingHint::RecipientRegisteredToken,
            ),
        ] {
            assert_eq!(MentionRoutingHint::parse_wire(wire), Some(expected));
            assert_eq!(expected.as_str(), wire);
            assert_eq!(serde_json::to_value(expected).unwrap(), json!(wire));
            assert_eq!(
                serde_json::from_value::<MentionRoutingHint>(json!(wire)).unwrap(),
                expected
            );
        }

        assert!(MentionRoutingHint::parse_wire("unknown_hint").is_none());
        assert!(serde_json::from_value::<MentionRoutingHint>(json!("unknown_hint")).is_err());
    }

    #[test]
    fn open_mention_routing_hint_parse_preserves_unknown_but_fails_closed() {
        assert_eq!(
            MentionRoutingHint::parse_open("recipient_registered_token"),
            OpenMentionRoutingHint::Known(MentionRoutingHint::RecipientRegisteredToken)
        );
        assert_eq!(
            MentionRoutingHint::parse_open("unknown_hint"),
            OpenMentionRoutingHint::Unknown("unknown_hint".to_owned())
        );
        assert_eq!(
            MentionRoutingHint::parse_open("unknown_hint").fail_closed(),
            MentionRoutingHint::Disabled
        );
    }

    #[test]
    fn hardened_profiles_force_mention_routing_disabled() {
        for hardened_profile in HARDENED_MENTION_ROUTING_PROFILES {
            assert_eq!(
                effective_mention_routing_hint(
                    &[*hardened_profile],
                    Some("recipient_registered_token")
                ),
                MentionRoutingHint::Disabled
            );
        }

        assert_eq!(
            effective_mention_routing_hint(
                &[
                    ProfileId::E2EE_CLIENT_V1,
                    "ak.profile.kanban_mvp.v1",
                    ProfileId::ATTESTED_AUDIT_E2EE_V1,
                    ProfileId::MLS_MINIMAL_METADATA_REALM_V1,
                ],
                Some("recipient_registered_token")
            ),
            MentionRoutingHint::Disabled
        );
    }

    #[test]
    fn ordinary_e2ee_requires_explicit_known_mention_routing_opt_in() {
        assert_eq!(
            effective_mention_routing_hint(
                &[ProfileId::E2EE_CLIENT_V1, "ak.profile.kanban_mvp.v1"],
                Some("recipient_registered_token")
            ),
            MentionRoutingHint::RecipientRegisteredToken
        );
        assert_eq!(
            effective_mention_routing_hint(&[ProfileId::E2EE_CLIENT_V1], None),
            MentionRoutingHint::Disabled
        );
        assert_eq!(
            effective_mention_routing_hint(&[ProfileId::E2EE_CLIENT_V1], Some("unknown_hint")),
            MentionRoutingHint::Disabled
        );
        assert_eq!(
            effective_mention_routing_hint(
                &["ak.profile.kanban_mvp.v1"],
                Some("recipient_registered_token")
            ),
            MentionRoutingHint::Disabled
        );
    }

    #[test]
    fn classifies_agent_event_kinds() {
        assert_eq!(
            classify_agent_event_kind("ak.self.agent.pause"),
            Some(AgentEventRouting::DurableLifecycle)
        );
        assert_eq!(
            classify_agent_event_kind("ak.agent.action_request"),
            Some(AgentEventRouting::ActorPrivateDrop)
        );
        assert_eq!(classify_agent_event_kind("ak.message.create"), None);
    }

    #[test]
    fn validates_push_notify_shape() {
        let request = valid_request();
        validate_push_notify_contract_shape(&request).unwrap();
    }

    #[test]
    fn rejects_duplicate_push_notify_request_device_ids() {
        let mut request = valid_request();
        request.notification.devices[1].device_id =
            request.notification.devices[0].device_id.clone();

        let error = validate_push_notify_contract_shape(&request).unwrap_err();
        assert!(error.contains("duplicate device_id"));
    }

    #[test]
    fn validates_push_notify_outcome_conservation() {
        let request = valid_request();
        let outcome = PushNotifyOutcome {
            push_target_id: request.notification.push_target_id.clone().unwrap(),
            outcomes: vec![
                PushNotifyDeviceOutcome::accepted(
                    request.notification.devices[0].device_id.clone(),
                ),
                PushNotifyDeviceOutcome::rejected(
                    request.notification.devices[1].device_id.clone(),
                    PushNotifyReasonCode::RateLimited,
                    Some(500),
                ),
            ],
        };

        validate_push_notify_outcome_conservation(&request, &outcome).unwrap();
        let encoded = serde_json::to_value(&outcome).unwrap();
        assert_eq!(encoded["outcomes"][0]["gateway_status"], "accepted");
        assert_eq!(encoded["outcomes"][1]["reason_code"], "rate_limited");
        assert!(encoded["outcomes"][0].get("reason_code").is_none());
    }

    #[test]
    fn rejects_non_conserving_push_notify_outcomes() {
        let request = valid_request();
        let push_target_id = request.notification.push_target_id.clone().unwrap();
        let first_device_id = request.notification.devices[0].device_id.clone();
        let second_device_id = request.notification.devices[1].device_id.clone();

        let missing = PushNotifyOutcome {
            push_target_id: push_target_id.clone(),
            outcomes: vec![PushNotifyDeviceOutcome::accepted(first_device_id.clone())],
        };
        assert!(
            validate_push_notify_outcome_conservation(&request, &missing)
                .unwrap_err()
                .contains("missing")
        );

        let duplicate = PushNotifyOutcome {
            push_target_id: push_target_id.clone(),
            outcomes: vec![
                PushNotifyDeviceOutcome::accepted(first_device_id.clone()),
                PushNotifyDeviceOutcome::duplicate(first_device_id),
            ],
        };
        assert!(
            validate_push_notify_outcome_conservation(&request, &duplicate)
                .unwrap_err()
                .contains("duplicate")
        );

        let unrequested = PushNotifyOutcome {
            push_target_id,
            outcomes: vec![
                PushNotifyDeviceOutcome::accepted(second_device_id),
                PushNotifyDeviceOutcome::accepted(
                    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000099").unwrap(),
                ),
            ],
        };
        assert!(
            validate_push_notify_outcome_conservation(&request, &unrequested)
                .unwrap_err()
                .contains("unrequested")
        );
    }

    #[test]
    fn rejects_invalid_push_notify_device_outcome_fields() {
        let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let accepted_with_reason = PushNotifyDeviceOutcome {
            device_id: device_id.clone(),
            gateway_status: PushNotifyGatewayStatus::Accepted,
            reason_code: Some(PushNotifyReasonCode::PushTokenInvalid),
            retry_after_ms: None,
        };
        assert!(accepted_with_reason.validate().is_err());

        let rejected_without_reason = PushNotifyDeviceOutcome {
            device_id: device_id.clone(),
            gateway_status: PushNotifyGatewayStatus::Rejected,
            reason_code: None,
            retry_after_ms: None,
        };
        assert!(rejected_without_reason.validate().is_err());

        let non_retryable_backoff = PushNotifyDeviceOutcome::rejected(
            device_id,
            PushNotifyReasonCode::PushTokenInvalid,
            Some(500),
        );
        assert!(non_retryable_backoff.validate().is_err());
    }

    #[test]
    fn push_count_indicators_reject_absolute_counts_and_invalid_buckets() {
        for invalid in [
            json!(1),
            json!(-1),
            json!("01"),
            json!("5-2"),
            json!("1--2"),
        ] {
            assert!(serde_json::from_value::<PushCountIndicator>(invalid).is_err());
        }
        assert_eq!(
            serde_json::from_value::<PushCountIndicator>(json!(true)).unwrap(),
            PushCountIndicator::Present(true)
        );
        assert_eq!(
            serde_json::from_value::<PushCountIndicator>(json!("6-20")).unwrap(),
            PushCountIndicator::Bucket("6-20".to_owned())
        );
    }
}

// ── Push schema artifact counterparts ────────────────────────────────────
// The `arkret` umbrella re-exports these owner-defined shapes at its root.

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum PushOperations {
    PushRegisterDeviceRequestBody(PushRegisterDeviceRequestBody),
    PushRegisterDeviceOutcome(PushRegisterDeviceOutcome),
    PushUnregisterDeviceRequestBody(PushUnregisterDeviceRequestBody),
    PushUnregisterDeviceOutcome(PushUnregisterDeviceOutcome),
    PushNotifyRequestBody(PushNotifyRequestBody),
    PushNotifyOutcome(PushNotifyOutcome),
}

impl PushOperations {
    pub const SCHEMA: &'static str = SchemaId::PUSH_OPERATIONS_V1;
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/blind_notification`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindNotification {
    pub push_target_id: PushTargetId,
    pub wakeup_kind: String,
    pub timing_profile_hint: PushTimingProfileHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_locus_unresolved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Counts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tokens: Option<RouteTokens>,
    pub devices: Vec<DeviceRoute>,
}

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/counts`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<PushCountIndicator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_increment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missed_call: Option<PushCountIndicator>,
}

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/device_route`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRoute {
    pub device_id: DeviceId,
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

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_key`.
pub type PushKey = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_target_id`.
pub type PushTargetId = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/registration_id`.
pub type RegistrationId = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/url`.
pub type Url = String;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisibleNotification {
    pub push_target_id: PushTargetId,
    pub wakeup_kind: String,
    pub timing_profile_hint: PushTimingProfileHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_locus_unresolved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Counts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tokens: Option<RouteTokens>,
    pub devices: Vec<DeviceRoute>,
    pub event_id: EventId,
    pub realm_id: RealmId,
    pub sender_actor_id: DidCoreId,
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
