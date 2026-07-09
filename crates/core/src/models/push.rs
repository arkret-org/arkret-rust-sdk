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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

const FORBIDDEN_PLAINTEXT_PARENT_LEAF: &[(&str, &str)] = &[
    ("binding_proof", "signature"),
    ("subject_proof", "signature"),
];

pub const AGENT_LIFECYCLE_SILENT_KINDS: &[&str] = &[
    "ck.self.agent.pause",
    "ck.self.agent.resume",
    "ck.self.agent.deactivate",
];

pub const AGENT_ACTOR_PRIVATE_KINDS: &[&str] = &[
    "ck.agent.draft.propose",
    "ck.agent.action_request",
    "ck.agent.action_approve",
    "ck.agent.action_reject",
];

pub const PHASE_P2_AGENT_TYPED_ID_PREFIXES: &[&str] = &[
    "ck:agent_session:",
    "ck:agent_key:",
    "ck:agent_draft:",
    "ck:accountability_grant:",
    "ck:sidecar_circle:",
    "ck:backup_series:",
    "ck:recovery_session:",
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
    const PREFIX: &str = "ck:pseudonym:push:";
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
    if !crate::blind_payload_sanitizer::is_valid_wakeup_kind(value) {
        return Err(format!(
            "notification.wakeup_kind must be one of {}",
            crate::blind_payload_sanitizer::ALLOWED_WAKEUP_KINDS.join(", ")
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
                push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
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
    fn classifies_agent_event_kinds() {
        assert_eq!(
            classify_agent_event_kind("ck.self.agent.pause"),
            Some(AgentEventRouting::DurableLifecycle)
        );
        assert_eq!(
            classify_agent_event_kind("ck.agent.action_request"),
            Some(AgentEventRouting::ActorPrivateDrop)
        );
        assert_eq!(classify_agent_event_kind("ck.message.create"), None);
    }

    #[test]
    fn validates_push_notify_shape() {
        let request = valid_request();
        validate_push_notify_contract_shape(&request).unwrap();
    }

    #[test]
    fn rejects_forbidden_proof_signature_inside_opaque_counts() {
        let mut request = valid_request();
        request.notification.counts = Some(PushCounts {
            badge: Some(json!({
                "binding_proof": {
                    "signature": "leak"
                }
            })),
            ..PushCounts::default()
        });
        let error = validate_push_notify_contract_shape(&request).unwrap_err();
        assert!(error.contains("binding_proof.signature"));
    }
}
