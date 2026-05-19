//! Contrix push surface models and helpers.

use std::collections::BTreeMap;

use contrix_core::{
    DeviceId, Did, EventId, PushNotifyReqBody, PushNotifyOutput, PushRegisterDeviceReqBody,
    SpaceId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub mod protocol {
    pub use contrix_core::{
        PushNotifyReqBody, PushNotifyOutput, PushRegisterDeviceReqBody,
        PushRegisterDeviceOutput, PushUnregisterDeviceReqBody,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PushPlatform {
    Apns,
    Fcm,
    WebPush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PushPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub fn from_register(user_id: Did, request: PushRegisterDeviceReqBody) -> Self {
        Self {
            user_id,
            device_id: request.device_id,
            platform: request
                .platform
                .as_deref()
                .and_then(parse_platform)
                .unwrap_or(PushPlatform::WebPush),
            push_gateway: request.push_gateway,
            push_key: request.push_key,
            app_id: request.app_id,
            display_name: request.display_name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRule {
    pub rule_id: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    pub priority: PushPriority,
    #[serde(default)]
    pub redact_content: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushNotification {
    pub event_id: EventId,
    pub user_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub event_kind: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub content: Value,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushPayload {
    pub platform: PushPlatform,
    pub push_key: String,
    pub title: String,
    pub body: String,
    pub priority: PushPriority,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushDeliveryReceipt {
    pub event_id: EventId,
    pub device_id: DeviceId,
    pub platform: PushPlatform,
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn format_push_payload(
    pusher: &Pusher,
    rule: &PushRule,
    notification: &PushNotification,
) -> PushPayload {
    let redacted = notification.encrypted || rule.redact_content;
    let body = if redacted {
        "Encrypted message".to_owned()
    } else {
        notification
            .content
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("New activity")
            .chars()
            .take(120)
            .collect()
    };
    let title = match pusher.platform {
        PushPlatform::Apns => "Contrix",
        PushPlatform::Fcm => "Contrix update",
        PushPlatform::WebPush => "Contrix notification",
    }
    .to_owned();
    PushPayload {
        platform: pusher.platform,
        push_key: pusher.push_key.clone(),
        title,
        body,
        priority: rule.priority,
        data: json!({
            "event_id": notification.event_id.as_str(),
            "space_id": notification.space_id.as_ref().map(|space_id| space_id.as_str()),
            "event_kind": notification.event_kind,
        }),
    }
}

pub fn notification_from_gateway_request(request: PushNotifyReqBody) -> Option<PushNotification> {
    serde_json::from_value(request.notification).ok()
}

pub fn rejected_response(
    receipts: impl IntoIterator<Item = PushDeliveryReceipt>,
) -> PushNotifyOutput {
    PushNotifyOutput {
        rejected: receipts
            .into_iter()
            .filter(|receipt| !receipt.accepted)
            .map(|receipt| {
                json!({
                    "event_id": receipt.event_id.as_str(),
                    "device_id": receipt.device_id.as_str(),
                    "platform": receipt.platform,
                    "error": receipt.error,
                })
            })
            .collect(),
    }
}

fn parse_platform(value: &str) -> Option<PushPlatform> {
    match value {
        "apns" => Some(PushPlatform::Apns),
        "fcm" => Some(PushPlatform::Fcm),
        "web_push" | "webpush" => Some(PushPlatform::WebPush),
        _ => None,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRuleSet {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, PushRule>,
}

impl PushRuleSet {
    pub fn matching_rule(&self, event_kind: &str) -> Option<&PushRule> {
        self.rules
            .values()
            .find(|rule| {
                rule.enabled && rule.event_kind.as_deref().is_some_and(|kind| kind == event_kind)
            })
            .or_else(|| self.rules.values().find(|rule| rule.enabled && rule.event_kind.is_none()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn pusher_builds_from_register_request() {
        let request = PushRegisterDeviceReqBody {
            device_id: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap(),
            push_gateway: "https://push.example".to_owned(),
            push_key: "token".to_owned(),
            platform: Some("fcm".to_owned()),
            app_id: Some("app".to_owned()),
            display_name: None,
        };
        let pusher = Pusher::from_register(did("alice"), request);
        assert_eq!(pusher.platform, PushPlatform::Fcm);
    }

    #[test]
    fn payload_redacts_encrypted_notifications() {
        let pusher = Pusher {
            user_id: did("alice"),
            device_id: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap(),
            platform: PushPlatform::Apns,
            push_gateway: "https://push.example".to_owned(),
            push_key: "token".to_owned(),
            app_id: None,
            display_name: None,
        };
        let rule = PushRule {
            rule_id: "default".to_owned(),
            enabled: true,
            event_kind: None,
            priority: PushPriority::High,
            redact_content: false,
        };
        let payload = format_push_payload(
            &pusher,
            &rule,
            &PushNotification {
                event_id: EventId::new("cx:event:01904100-0000-7000-8000-834e21b98552").unwrap(),
                user_id: did("alice"),
                space_id: None,
                event_kind: "cx.message.create".to_owned(),
                content: json!({"body": "secret"}),
                encrypted: true,
            },
        );
        assert_eq!(payload.body, "Encrypted message");
    }

    #[test]
    fn rejected_response_keeps_only_failures() {
        let rejected = rejected_response([
            PushDeliveryReceipt {
                event_id: EventId::new("cx:event:01904100-0000-7000-8000-834e21b98552").unwrap(),
                device_id: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000002").unwrap(),
                platform: PushPlatform::Fcm,
                accepted: true,
                error: None,
            },
            PushDeliveryReceipt {
                event_id: EventId::new("cx:event:01904100-0000-7000-8000-6008ddd67225").unwrap(),
                device_id: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000003").unwrap(),
                platform: PushPlatform::Fcm,
                accepted: false,
                error: Some("invalid_token".to_owned()),
            },
        ]);
        assert_eq!(rejected.rejected.len(), 1);
    }
}
