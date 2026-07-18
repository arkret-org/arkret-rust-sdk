use super::*;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    pub recipient_service_id: Option<Did>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushRegisterDeviceOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushUnregisterDeviceRequestBody {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushUnregisterDeviceOutcome {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OkOutcome {
    pub ok: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum PushCountIndicator {
    Present(bool),
    Bucket(String),
}

impl<'de> Deserialize<'de> for PushCountIndicator {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    PROFILE_MLS_MINIMAL_METADATA_REALM,
    PROFILE_ATTESTED_AUDIT_E2EE,
    PROFILE_DISCLOSED_AUDIT_E2EE,
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
        || !has_profile(PROFILE_E2EE_CLIENT)
    {
        return MentionRoutingHint::Disabled;
    }

    declared_hint
        .map(MentionRoutingHint::parse_open)
        .map(OpenMentionRoutingHint::fail_closed)
        .unwrap_or_default()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushAuditEnvelopeMetadata {
    pub access_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushNotifyOutcome {
    #[serde(default)]
    pub rejected: Vec<PushNotifyRejection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PushNotifyRejection {
    pub push_target_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

const FORBIDDEN_PLAINTEXT_PARENT_LEAF: &[(&str, &str)] = &[
    ("binding_proof", "signature"),
    ("subject_proof", "signature"),
];

pub const AGENT_LIFECYCLE_SILENT_KINDS: &[&str] = &[
    "ak.self.agent.pause",
    "ak.self.agent.resume",
    "ak.self.agent.deactivate",
];

pub const AGENT_ACTOR_PRIVATE_KINDS: &[&str] = &[
    "ak.agent.draft.propose",
    "ak.agent.action_request",
    "ak.agent.action_approve",
    "ak.agent.action_reject",
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

pub fn validate_push_notify_contract_shape(
    request: &PushNotifyRequestBody,
) -> std::result::Result<(), String> {
    let raw = serde_json::to_value(request)
        .map_err(|error| format!("push notify request serialization failed: {error}"))?;
    reject_forbidden_plaintext_fields("", &raw)?;

    let notification = &request.notification;
    validate_push_target_id(notification.push_target_id.as_deref())?;
    validate_wakeup_kind(notification.wakeup_kind.as_deref())?;
    validate_timing_profile_hint(notification.timing_profile_hint)?;

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

fn reject_forbidden_plaintext_fields(path: &str, value: &Value) -> std::result::Result<(), String> {
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

fn validate_push_target_id(value: Option<&str>) -> std::result::Result<(), String> {
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

fn validate_push_route_token(value: Option<&str>, path: &str) -> std::result::Result<(), String> {
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

fn validate_wakeup_kind(value: Option<&str>) -> std::result::Result<(), String> {
    let Some(value) = value else {
        return Err("notification.wakeup_kind is required".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.wakeup_kind must not be empty".to_owned());
    }
    if !blind_payload_sanitizer::is_valid_wakeup_kind(value) {
        return Err(format!(
            "notification.wakeup_kind must be one of {}",
            blind_payload_sanitizer::ALLOWED_WAKEUP_KINDS.join(", ")
        ));
    }
    Ok(())
}

fn validate_timing_profile_hint(
    value: Option<PushTimingProfileHint>,
) -> std::result::Result<(), String> {
    let Some(_) = value else {
        return Err("notification.timing_profile_hint is required".to_owned());
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> PushNotifyRequestBody {
        PushNotifyRequestBody {
            notification: PushNotificationEnvelope {
                push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
                wakeup_kind: Some("message".to_owned()),
                timing_profile_hint: Some(PushTimingProfileHint::Default),
                ..PushNotificationEnvelope::default()
            },
            event_kind: None,
            reason_code: None,
            audit_envelope: None,
        }
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
                    PROFILE_E2EE_CLIENT,
                    "ak.profile.kanban_mvp.v1",
                    PROFILE_ATTESTED_AUDIT_E2EE,
                    PROFILE_MLS_MINIMAL_METADATA_REALM,
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
                &[PROFILE_E2EE_CLIENT, "ak.profile.kanban_mvp.v1"],
                Some("recipient_registered_token")
            ),
            MentionRoutingHint::RecipientRegisteredToken
        );
        assert_eq!(
            effective_mention_routing_hint(&[PROFILE_E2EE_CLIENT], None),
            MentionRoutingHint::Disabled
        );
        assert_eq!(
            effective_mention_routing_hint(&[PROFILE_E2EE_CLIENT], Some("unknown_hint")),
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
