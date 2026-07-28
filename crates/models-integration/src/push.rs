//! Arkret push surface models and helpers.

use std::time::Duration;

use arkret_wire::{DeviceId, Did, EventId, RealmId};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

#[cfg(test)]
use crate::integration::IntegrationDependencyDescriptor;
use crate::integration::IntegrationDescribeOutcome;
use crate::models_push::PushRegisterDeviceRequestBody;

fn list_contains_ignore_ascii_case(haystack: &[String], needle: &str) -> bool {
    haystack
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(needle))
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PushPlatform(String);

impl PushPlatform {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        (!value.is_empty()).then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn apns() -> Self {
        Self::new("apns").expect("apns is non-empty")
    }

    pub fn fcm() -> Self {
        Self::new("fcm").expect("fcm is non-empty")
    }

    pub fn web_push() -> Self {
        Self::new("web_push").expect("web_push is non-empty")
    }
}

impl<'de> Deserialize<'de> for PushPlatform {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| serde::de::Error::custom("push platform must be non-empty"))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pusher {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub platform: PushPlatform,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl Pusher {
    pub fn from_register(user_id: Did, request: PushRegisterDeviceRequestBody) -> Self {
        Self {
            user_id,
            device_id: request.device_id,
            platform: request
                .platform
                .as_deref()
                .and_then(parse_platform)
                .unwrap_or_else(PushPlatform::web_push),
            push_gateway: request.push_gateway,
            push_key: request.push_key,
            app_id: request.app_id,
            display_name: request.display_name,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRule {
    pub rule_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "default_push_rule_enabled")]
    pub enabled: bool,
    #[serde(default = "default_push_rule_locus")]
    pub evaluation_locus: String,
    #[serde(default)]
    pub conditions: Vec<PushCondition>,
    #[serde(default)]
    pub actions: Vec<String>,
}

impl PushRule {
    pub fn delivery_priority(&self) -> PushPriority {
        if self.actions.iter().any(|action| action == "sound_critical") {
            PushPriority::Urgent
        } else {
            PushPriority::Normal
        }
    }

    pub fn server_metadata_matches(&self, event_kind: &str, realm_id: Option<&str>) -> bool {
        self.evaluation_locus == "server"
            && self.conditions.iter().all(|condition| {
                if condition.kind != "field_match" {
                    return false;
                }
                let Some(field) = condition.field.as_deref() else {
                    return false;
                };
                let Some(pattern) = condition.pattern.as_ref() else {
                    return false;
                };
                match field {
                    "kind" | "event_kind" => push_pattern_matches(pattern, event_kind),
                    "realm_id" => {
                        realm_id.is_some_and(|realm_id| push_pattern_matches(pattern, realm_id))
                    }
                    _ => false,
                }
            })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushCondition {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRulesConfig {
    #[serde(default)]
    pub rules: Vec<PushRule>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DndSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub schedule: DndSchedule,
    #[serde(default)]
    pub exceptions: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DndSchedule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default)]
    pub periods: Vec<DndPeriod>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DndPeriod {
    pub start: String,
    pub end: String,
}

fn default_push_rule_locus() -> String {
    "server".to_owned()
}

fn default_push_rule_enabled() -> bool {
    true
}

fn push_pattern_matches(pattern: &Value, value: &str) -> bool {
    match pattern {
        Value::String(pattern) => pattern == "*" || pattern == value,
        Value::Array(patterns) => patterns
            .iter()
            .any(|pattern| push_pattern_matches(pattern, value)),
        _ => false,
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushEventNotification {
    pub event_id: EventId,
    pub user_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub event_kind: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushPayload {
    pub platform: PushPlatform,
    pub push_key: String,
    pub title: String,
    pub body: String,
    pub priority: PushPriority,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

pub fn format_push_payload(
    pusher: &Pusher,
    rule: &PushRule,
    notification: &PushEventNotification,
) -> PushPayload {
    let wakeup_kind = wakeup_kind_for_event_kind(&notification.event_kind);
    let body = blind_push_body_for_wakeup_kind(wakeup_kind).to_owned();
    let title = match pusher.platform.as_str() {
        "apns" => "Arkret",
        "fcm" => "Arkret update",
        _ => "Arkret notification",
    }
    .to_owned();
    PushPayload {
        platform: pusher.platform.clone(),
        push_key: pusher.push_key.clone(),
        title,
        body,
        priority: rule.delivery_priority(),
        data: blind_payload_data_for_event_kind(&notification.event_kind),
    }
}

pub fn wakeup_kind_for_event_kind(event_kind: &str) -> &'static str {
    if event_kind.contains("call") {
        "call_invite"
    } else if event_kind.contains("mention") {
        "mention"
    } else if event_kind.contains("assignment") {
        "assignment"
    } else if event_kind.contains("scheduled_send") {
        "scheduled_send"
    } else if event_kind.contains("schedule") {
        "schedule"
    } else if event_kind.contains("reaction") {
        "reaction"
    } else if event_kind.contains("reminder") {
        "reminder"
    } else if event_kind.contains("expiry") {
        "expiry_invalidation"
    } else {
        "message"
    }
}

pub fn push_hint_for_wakeup_kind(wakeup_kind: &str) -> Option<&'static str> {
    match wakeup_kind {
        "message" => Some("new_message"),
        "mention" => Some("mention_self"),
        "call_invite" => Some("incoming_call"),
        _ => None,
    }
}

pub fn blind_push_body_for_wakeup_kind(wakeup_kind: &str) -> &'static str {
    match wakeup_kind {
        "call_invite" => "Incoming call",
        "mention" => "New mention",
        "message" => "New message",
        _ => "New activity",
    }
}

pub fn blind_payload_data_for_event_kind(event_kind: &str) -> Value {
    let wakeup_kind = wakeup_kind_for_event_kind(event_kind);
    let mut data = Map::new();
    data.insert(
        "wakeup_kind".to_owned(),
        Value::String(wakeup_kind.to_owned()),
    );
    if let Some(push_hint) = push_hint_for_wakeup_kind(wakeup_kind) {
        data.insert("push_hint".to_owned(), Value::String(push_hint.to_owned()));
    }
    Value::Object(data)
}

fn parse_platform(value: &str) -> Option<PushPlatform> {
    PushPlatform::new(value)
}

impl PushRulesConfig {
    pub fn matching_server_metadata_rule(
        &self,
        event_kind: &str,
        realm_id: Option<&str>,
    ) -> Option<&PushRule> {
        self.rules
            .iter()
            .find(|rule| rule.enabled && rule.server_metadata_matches(event_kind, realm_id))
    }
}

/// B.5 #6 — spec revision chime was compiled against. Used by
/// [`PushBridgeDescribeOutcome::warn_on_spec_version_mismatch`] to flag
/// gateway responses pinned to a different revision.
pub const EXPECTED_SPEC_VERSION: &str = "arkret-spec@2026-05-26";

/// Response body for `GET /_floria/push/bridge/describe`.
///
/// This is a product-local push-gateway contract shared by the gateway
/// implementation and clients that probe it before registration / notify
/// strands. It intentionally lives in the `arkret` umbrella rather than individual
/// services so bridge producers and consumers cannot drift silently.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeOutcome {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    /// Optional spec revision the gateway is built against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    pub gateway: PushBridgeDescribeGatewayDescriptor,
    pub notify: PushBridgeDescribeNotifyDescriptor,
    pub privacy: PushBridgeDescribePrivacyDescriptor,
    #[serde(default)]
    pub examples: PushBridgeDescribeExamples,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_capabilities_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_capabilities: Vec<ProviderCapabilityDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_reason_codes: Vec<PushBridgeFailureCodeDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
}

impl PushBridgeDescribeOutcome {
    /// Emit a warning when the gateway's advertised `spec_version` does not
    /// match the SDK's compiled-in [`EXPECTED_SPEC_VERSION`].
    ///
    /// Returns `true` when the response carried a matching spec version,
    /// `false` when it carried a mismatch or did not advertise the field.
    pub fn warn_on_spec_version_mismatch(&self) -> bool {
        match self.spec_version.as_deref() {
            Some(advertised) if advertised == EXPECTED_SPEC_VERSION => true,
            Some(advertised) => {
                tracing::warn!(
                    advertised_spec_version = advertised,
                    expected_spec_version = EXPECTED_SPEC_VERSION,
                    contract = %self.contract,
                    version = %self.version,
                    "push bridge spec_version mismatch; gateway/SDK may drift",
                );
                false
            }
            None => false,
        }
    }

    /// Look up a per-app provider capability descriptor by configured app
    /// name (case-insensitive).
    pub fn provider_capability(&self, name: &str) -> Option<&ProviderCapabilityDescriptor> {
        self.provider_capabilities
            .iter()
            .find(|cap| cap.name.eq_ignore_ascii_case(name))
    }

    /// Look up the first capability descriptor whose stable provider `kind`
    /// matches (case-insensitive).
    pub fn provider_capability_by_kind(&self, kind: &str) -> Option<&ProviderCapabilityDescriptor> {
        self.provider_capabilities
            .iter()
            .find(|cap| cap.kind.eq_ignore_ascii_case(kind))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeGatewayDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_modes: Vec<String>,
}

impl PushBridgeDescribeGatewayDescriptor {
    /// Whether this gateway advertises support for `name` as a push profile
    /// (case-insensitive).
    pub fn supports_profile(&self, name: &str) -> bool {
        list_contains_ignore_ascii_case(&self.supported_profiles, name)
    }

    /// Whether this gateway advertises support for `name` as a downstream
    /// provider (case-insensitive).
    pub fn supports_provider(&self, name: &str) -> bool {
        list_contains_ignore_ascii_case(&self.supported_providers, name)
    }

    /// Whether the gateway will accept the requested auth mode such as
    /// `"http-message-signature"` or `"bearer"`.
    pub fn supports_auth_mode(&self, name: &str) -> bool {
        list_contains_ignore_ascii_case(&self.auth_modes, name)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeNotifyDescriptor {
    pub notify_path: String,
    pub operation_id: String,
    pub request_id_header: String,
    pub idempotency_key_header: String,
    pub source_service_id_header: String,
    pub destination_service_id_header: String,
    pub max_request_size_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limit_scopes: Vec<String>,
}

impl PushBridgeDescribeNotifyDescriptor {
    /// Whether the gateway has any deduplication backend configured.
    pub fn supports_dedup(&self) -> bool {
        self.dedup_backend
            .as_deref()
            .is_some_and(|backend| !backend.trim().is_empty())
    }

    /// Deduplication retention window, when advertised.
    pub fn dedup_window(&self) -> Option<Duration> {
        self.dedup_ttl_seconds.map(Duration::from_secs)
    }

    /// Rate-limit window length, when advertised.
    pub fn rate_limit_window(&self) -> Option<Duration> {
        self.rate_limit_window_seconds.map(Duration::from_secs)
    }

    /// Whether the gateway advertises the named rate-limit scope.
    pub fn rate_limits_by(&self, scope: &str) -> bool {
        list_contains_ignore_ascii_case(&self.rate_limit_scopes, scope)
    }

    /// Maximum request size in bytes, exposed as `usize` for convenience.
    pub fn max_request_size(&self) -> usize {
        self.max_request_size_bytes
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribePrivacyDescriptor {
    pub default_mode: String,
    pub plaintext_visibility_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_reference_fields: Vec<String>,
}

/// Per-app frozen capability matrix entry, surfaced by the gateway via
/// `bridge/describe.provider_capabilities[]`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilityDescriptor {
    /// Configured app name as known to the gateway registry.
    pub name: String,
    /// Stable provider kind, e.g. `"apns"`, `"fcm"`, `"webpush"`.
    pub kind: String,
    /// Multi-recipient send shape: `"none"`, `"multicast"`, or `"topic"`.
    pub batch: String,
    /// Maximum TTL in seconds the upstream provider accepts.
    #[serde(default)]
    pub ttl_seconds_max: Option<u64>,
    /// Whether the provider supports a collapse / replace key.
    #[serde(default)]
    pub supports_collapse: bool,
    /// Whether the provider has first-class badge / unread count support.
    #[serde(default)]
    pub supports_badge: bool,
    /// Outbound provider payload shape.
    pub provider_payload_shape: String,
    /// Credential material this provider expects.
    #[serde(default)]
    pub credential_kinds: Vec<String>,
    /// Documented credential rotation cadence for this provider kind.
    pub credential_rotation: String,
    /// Whether the provider can carry an encrypted body that the gateway must
    /// not inspect.
    #[serde(default)]
    pub blind_wakeup_required: bool,
}

impl ProviderCapabilityDescriptor {
    /// TTL cap exposed as `Duration`, when advertised.
    pub fn ttl_max(&self) -> Option<Duration> {
        self.ttl_seconds_max.map(Duration::from_secs)
    }

    /// Whether this provider accepts a multi-recipient batch shape.
    pub fn supports_batch(&self) -> bool {
        !self.batch.eq_ignore_ascii_case("none") && !self.batch.is_empty()
    }

    /// Whether this provider lists `kind` among its accepted credential
    /// material (case-insensitive).
    pub fn accepts_credential(&self, kind: &str) -> bool {
        list_contains_ignore_ascii_case(&self.credential_kinds, kind)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeFailureCodeDescriptor {
    pub code: String,
    pub http_status: u16,
    pub retryable: bool,
    pub description: String,
}

impl PushBridgeFailureCodeDescriptor {
    pub fn new(
        code: impl Into<String>,
        http_status: u16,
        retryable: bool,
        description: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            http_status,
            retryable,
            description: description.into(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeExamples {
    #[serde(default)]
    pub notify_headers: Value,
    #[serde(default)]
    pub blind_wakeup_request: Value,
    #[serde(default)]
    pub plaintext_visible_service_request: Value,
}

/// Combined view of a push gateway's high-level integration manifest plus its
/// active bridge contract.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntegrationView {
    /// Service-level integration manifest (`/_floria/integration/describe`).
    pub manifest: IntegrationDescribeOutcome,
    /// Active bridge contract (`/_floria/push/bridge/describe`).
    pub bridge: PushBridgeDescribeOutcome,
}

impl IntegrationView {
    /// Construct an integration view from the two describe responses.
    pub fn new(manifest: IntegrationDescribeOutcome, bridge: PushBridgeDescribeOutcome) -> Self {
        Self { manifest, bridge }
    }

    /// Whether the manifest declares a dependency on the given service kind
    /// with the given purpose.
    pub fn requires(&self, service: &str, purpose: &str) -> bool {
        self.manifest.requires(service, purpose)
    }

    /// The active bridge contract id.
    pub fn contract_digest(&self) -> &str {
        &self.bridge.contract
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn pusher_builds_from_register_request() {
        let request = PushRegisterDeviceRequestBody {
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            push_gateway: "https://push.example".to_owned(),
            push_key: "token".to_owned(),
            platform: Some("fcm".to_owned()),
            app_id: Some("app".to_owned()),
            display_name: None,
            recipient_service_id: None,
        };
        let pusher = Pusher::from_register(did("alice"), request);
        assert_eq!(pusher.platform, PushPlatform::fcm());
    }

    #[test]
    fn payload_uses_blind_wakeup_shape() {
        let pusher = Pusher {
            user_id: did("alice"),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            platform: PushPlatform::apns(),
            push_gateway: "https://push.example".to_owned(),
            push_key: "token".to_owned(),
            app_id: None,
            display_name: None,
        };
        let rule = PushRule {
            rule_id: "default".to_owned(),
            kind: "underride".to_owned(),
            enabled: true,
            evaluation_locus: "server".to_owned(),
            conditions: Vec::new(),
            actions: vec!["notify".to_owned(), "sound_critical".to_owned()],
        };
        let payload = format_push_payload(
            &pusher,
            &rule,
            &PushEventNotification {
                event_id: EventId::new("ak:event:01904100-0000-7000-8000-834e21b98552").unwrap(),
                user_id: did("alice"),
                realm_id: None,
                event_kind: "ak.message.create".to_owned(),
            },
        );
        assert_eq!(payload.body, "New message");
        assert_eq!(payload.data["wakeup_kind"], "message");
        assert_eq!(payload.data["push_hint"], "new_message");
        assert!(payload.data.get("event_id").is_none());
        assert!(payload.data.get("realm_id").is_none());
    }

    #[test]
    fn bridge_descriptor_helpers_match_supported_lists() {
        let descriptor = PushBridgeDescribeGatewayDescriptor {
            service_id: Some("did:webvh:z6mkfixture:gateway.example".to_owned()),
            supported_profiles: vec!["fcm".to_owned(), "APNs".to_owned()],
            supported_providers: vec!["huawei".to_owned()],
            auth_modes: vec!["http-message-signature".to_owned()],
        };

        assert!(descriptor.supports_profile("FCM"));
        assert!(descriptor.supports_profile("apns"));
        assert!(!descriptor.supports_profile("webpush"));
        assert!(descriptor.supports_provider("Huawei"));
        assert!(!descriptor.supports_provider("xiaomi"));
        assert!(descriptor.supports_auth_mode("HTTP-Message-Signature"));
    }

    #[test]
    fn bridge_notify_descriptor_exposes_dedup_and_rate_limit_windows() {
        let descriptor = PushBridgeDescribeNotifyDescriptor {
            notify_path: "/_arkret/edge/push/notify".to_owned(),
            operation_id: "ak.edge.push.command.notify".to_owned(),
            request_id_header: "X-Arkret-Request-Id".to_owned(),
            idempotency_key_header: "X-Arkret-Idempotency-Key".to_owned(),
            source_service_id_header: "Source-Service-ID".to_owned(),
            destination_service_id_header: "Destination-Service-ID".to_owned(),
            max_request_size_bytes: 16 * 1024,
            dedup_backend: Some("redis".to_owned()),
            dedup_ttl_seconds: Some(300),
            rate_limit_window_seconds: Some(60),
            rate_limit_scopes: vec!["per-app".to_owned()],
        };

        assert!(descriptor.supports_dedup());
        assert_eq!(descriptor.dedup_window(), Some(Duration::from_secs(300)));
        assert_eq!(
            descriptor.rate_limit_window(),
            Some(Duration::from_secs(60))
        );
        assert!(descriptor.rate_limits_by("per-app"));
        assert!(!descriptor.rate_limits_by("per-actor"));
        assert_eq!(descriptor.max_request_size(), 16 * 1024);

        let empty = PushBridgeDescribeNotifyDescriptor::default();
        assert!(!empty.supports_dedup());
        assert!(empty.dedup_window().is_none());
    }

    #[test]
    fn provider_capability_descriptor_roundtrips_fcm_fixture() {
        let json = serde_json::json!({
            "name": "default-fcm-app",
            "kind": "fcm",
            "batch": "multicast",
            "ttl_seconds_max": 28u64 * 24 * 60 * 60,
            "supports_collapse": true,
            "supports_badge": true,
            "provider_payload_shape": "data_only_blind_wakeup",
            "credential_kinds": ["service_account_v1"],
            "credential_rotation": "rotate_service_account_yearly_or_on_compromise",
            "blind_wakeup_required": true,
        });

        let cap: ProviderCapabilityDescriptor =
            serde_json::from_value(json.clone()).expect("deserialize fixture");
        assert_eq!(cap.name, "default-fcm-app");
        assert_eq!(cap.kind, "fcm");
        assert_eq!(cap.batch, "multicast");
        assert_eq!(cap.ttl_max(), Some(Duration::from_secs(28 * 24 * 60 * 60)));
        assert!(cap.supports_collapse);
        assert!(cap.supports_badge);
        assert!(cap.supports_batch());
        assert!(cap.accepts_credential("service_account_v1"));
        assert!(!cap.accepts_credential("vapid_keypair"));
        assert!(cap.blind_wakeup_required);

        let reserialized = serde_json::to_value(&cap).expect("serialize fixture");
        assert_eq!(reserialized, json);
    }

    #[test]
    fn bridge_describe_response_decodes_without_optional_matrices() {
        let json = serde_json::json!({
            "contract": "ak.push.bridge.v1",
            "version": "1.0.0",
            "api_base_path": "/_arkret/edge/push",
            "gateway": {},
            "notify": {
                "notify_path": "/_arkret/edge/push/notify",
                "operation_id": "ak.edge.push.command.notify",
                "request_id_header": "X-Arkret-Request-Id",
                "idempotency_key_header": "X-Arkret-Idempotency-Key",
                "source_service_id_header": "Source-Service-ID",
                "destination_service_id_header": "Destination-Service-ID",
                "max_request_size_bytes": 16384,
            },
            "privacy": {
                "default_mode": "blind_wakeup",
                "plaintext_visibility_class": "service-visible",
            },
        });

        let response: PushBridgeDescribeOutcome =
            serde_json::from_value(json).expect("decode response");
        assert!(response.provider_capabilities_version.is_none());
        assert!(response.provider_capabilities.is_empty());
        assert!(response.failure_reason_codes.is_empty());
        assert!(response.provider_capability("anything").is_none());

        let reserialized = serde_json::to_value(&response).expect("re-serialize");
        let obj = reserialized.as_object().expect("object");
        assert!(!obj.contains_key("provider_capabilities_version"));
        assert!(!obj.contains_key("provider_capabilities"));
        assert!(!obj.contains_key("failure_reason_codes"));
    }

    #[test]
    fn integration_view_exposes_manifest_dependency_lookup() {
        let manifest = IntegrationDescribeOutcome {
            contract: "ak.integration.push_gateway.v1".to_owned(),
            version: "1.0.0".to_owned(),
            service: "push-gateway".to_owned(),
            service_kind: "push-gateway".to_owned(),
            api_base_path: "/_floria".to_owned(),
            describe_path: "/_floria/integration/describe".to_owned(),
            dependencies: vec![IntegrationDependencyDescriptor {
                service: "soland".to_owned(),
                purpose: "register-device".to_owned(),
                required_contract: "ak.auth.bridge.v1".to_owned(),
                discovery_path: "/_soland/gate/auth/bridge/describe".to_owned(),
                mode: "required".to_owned(),
            }],
            surfaces: Vec::new(),
            examples: Value::Null,
            todos: Vec::new(),
        };
        let bridge = PushBridgeDescribeOutcome {
            contract: "ak.push.bridge.v1".to_owned(),
            ..Default::default()
        };

        let view = IntegrationView::new(manifest, bridge);
        assert!(view.requires("soland", "register-device"));
        assert!(!view.requires("soland", "unregister-device"));
        assert_eq!(view.contract_digest(), "ak.push.bridge.v1");
    }

    #[test]
    fn server_metadata_rule_matching_fails_closed_for_client_conditions() {
        let config = PushRulesConfig {
            rules: vec![
                PushRule {
                    rule_id: "client-mention".to_owned(),
                    kind: "underride".to_owned(),
                    enabled: true,
                    evaluation_locus: "client".to_owned(),
                    conditions: vec![PushCondition {
                        kind: "mentions_actor".to_owned(),
                        ..Default::default()
                    }],
                    actions: vec!["notify".to_owned()],
                },
                PushRule {
                    rule_id: "server-message".to_owned(),
                    kind: "underride".to_owned(),
                    enabled: true,
                    evaluation_locus: "server".to_owned(),
                    conditions: vec![PushCondition {
                        kind: "field_match".to_owned(),
                        field: Some("kind".to_owned()),
                        pattern: Some(Value::String("ak.message.create".to_owned())),
                        ..Default::default()
                    }],
                    actions: vec!["notify".to_owned()],
                },
            ],
        };

        let matched = config
            .matching_server_metadata_rule("ak.message.create", None)
            .expect("server metadata rule");
        assert_eq!(matched.rule_id, "server-message");
        assert!(
            config
                .matching_server_metadata_rule("ak.reaction.add", None)
                .is_none()
        );
    }
}
