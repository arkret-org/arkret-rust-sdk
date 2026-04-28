//! Push notification gateway helpers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{AEAD_ALGORITHM, DeviceId, Did, EventId, Result, SpaceId, crypto};

pub const PUSH_ENCRYPTION_ALGORITHM: &str = AEAD_ALGORITHM;

/// Push platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushPlatform {
    Apns,
    Fcm,
    WebPush,
}

/// Push priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushPriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Registered push token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushToken {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub platform: PushPlatform,
    pub token: String,
}

/// Push rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRule {
    pub rule_id: String,
    pub enabled: bool,
    pub event_kind: Option<String>,
    pub priority: PushPriority,
    pub redact_content: bool,
}

/// Event considered for push.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushEvent {
    pub event_id: EventId,
    pub user_id: Did,
    pub space_id: Option<SpaceId>,
    pub event_kind: String,
    pub content: Value,
    pub encrypted: bool,
}

/// Platform-specific push payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushPayload {
    pub platform: PushPlatform,
    pub token: String,
    pub title: String,
    pub body: String,
    pub priority: PushPriority,
    pub data: Value,
}

/// Encrypted push payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPushPayload {
    pub algorithm: String,
    pub ciphertext: Vec<u8>,
    pub digest: String,
}

/// Push gateway state.
#[derive(Clone, Debug, Default)]
pub struct PushGateway {
    tokens: BTreeMap<Did, Vec<PushToken>>,
    rules: BTreeMap<String, PushRule>,
    delivered: BTreeSet<(EventId, String)>,
}

impl PushGateway {
    /// Create an empty gateway.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a push token.
    pub fn register_token(&mut self, token: PushToken) {
        let tokens = self.tokens.entry(token.user_id.clone()).or_default();
        tokens.retain(|existing| {
            !(existing.device_id == token.device_id && existing.platform == token.platform)
        });
        tokens.push(token);
    }

    /// Unregister a push token.
    pub fn unregister_token(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        platform: PushPlatform,
    ) -> bool {
        let Some(tokens) = self.tokens.get_mut(user_id) else {
            return false;
        };
        let before = tokens.len();
        tokens.retain(|token| !(token.device_id == *device_id && token.platform == platform));
        before != tokens.len()
    }

    /// Add or replace a push rule.
    pub fn upsert_rule(&mut self, rule: PushRule) {
        self.rules.insert(rule.rule_id.clone(), rule);
    }

    /// Process an event into platform payloads, with filtering and deduplication.
    pub fn process_event(&mut self, event: &PushEvent) -> Vec<PushPayload> {
        let Some(tokens) = self.tokens.get(&event.user_id).cloned() else {
            return Vec::new();
        };
        let Some(rule) = self.match_rule(&event.event_kind).cloned() else {
            return Vec::new();
        };

        let mut payloads = Vec::new();
        for token in tokens {
            if !self.delivered.insert((event.event_id.clone(), token.token.clone())) {
                continue;
            }
            payloads.push(self.format_payload(event, &token, &rule));
        }
        payloads
    }

    /// Format a platform-specific payload.
    pub fn format_payload(
        &self,
        event: &PushEvent,
        token: &PushToken,
        rule: &PushRule,
    ) -> PushPayload {
        let redact = event.encrypted || rule.redact_content;
        let body = if redact {
            "Encrypted message".to_owned()
        } else {
            truncate(
                event.content.get("body").and_then(Value::as_str).unwrap_or("New activity"),
                120,
            )
        };
        let title = match token.platform {
            PushPlatform::Apns => "Contrix",
            PushPlatform::Fcm => "Contrix update",
            PushPlatform::WebPush => "Contrix notification",
        }
        .to_owned();
        PushPayload {
            platform: token.platform,
            token: token.token.clone(),
            title,
            body,
            priority: rule.priority,
            data: json!({
                "event_id": event.event_id.as_str(),
                "space_id": event.space_id.as_ref().map(|space_id| space_id.as_str()),
                "event_kind": event.event_kind,
                "platform": format!("{:?}", token.platform).to_lowercase(),
            }),
        }
    }

    /// Encrypt a push payload for E2EE transport using authenticated encryption.
    pub fn encrypt_payload(payload: &PushPayload, key: &[u8]) -> Result<EncryptedPushPayload> {
        let plaintext = serde_json::to_vec(payload).unwrap_or_default();
        let ciphertext = crypto::seal(&plaintext, key, b"contrix-push-payload-v1")?;
        Ok(EncryptedPushPayload {
            algorithm: PUSH_ENCRYPTION_ALGORITHM.to_owned(),
            digest: sha256_hex(&plaintext),
            ciphertext,
        })
    }

    fn match_rule(&self, event_kind: &str) -> Option<&PushRule> {
        self.rules.values().find(|rule| {
            rule.enabled
                && rule.event_kind.as_deref().map(|kind| kind == event_kind).unwrap_or(true)
        })
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max { value.to_owned() } else { value.chars().take(max).collect() }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        DeviceId::new(format!("dev_{id}")).unwrap()
    }

    fn event(encrypted: bool) -> PushEvent {
        PushEvent {
            event_id: EventId::new("cx:event:01").unwrap(),
            user_id: did("alice"),
            space_id: Some(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap()),
            event_kind: "cx.message".to_owned(),
            content: json!({"body": "hello"}),
            encrypted,
        }
    }

    #[test]
    fn push_registers_tokens_rules_formats_and_deduplicates() {
        let alice = did("alice");
        let mut gateway = PushGateway::new();
        gateway.register_token(PushToken {
            user_id: alice,
            device_id: device("phone"),
            platform: PushPlatform::Apns,
            token: "token1".to_owned(),
        });
        gateway.upsert_rule(PushRule {
            rule_id: "messages".to_owned(),
            enabled: true,
            event_kind: Some("cx.message".to_owned()),
            priority: PushPriority::High,
            redact_content: false,
        });

        let first = gateway.process_event(&event(false));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].body, "hello");
        assert_eq!(gateway.process_event(&event(false)).len(), 0);
    }

    #[test]
    fn push_redacts_and_encrypts_e2ee_payloads() {
        let alice = did("alice");
        let mut gateway = PushGateway::new();
        gateway.register_token(PushToken {
            user_id: alice,
            device_id: device("web"),
            platform: PushPlatform::WebPush,
            token: "token2".to_owned(),
        });
        gateway.upsert_rule(PushRule {
            rule_id: "all".to_owned(),
            enabled: true,
            event_kind: None,
            priority: PushPriority::Normal,
            redact_content: false,
        });

        let payload = gateway.process_event(&event(true)).pop().unwrap();
        assert_eq!(payload.body, "Encrypted message");
        let encrypted = PushGateway::encrypt_payload(&payload, b"push-key").unwrap();
        assert_ne!(encrypted.ciphertext, serde_json::to_vec(&payload).unwrap());
    }

    #[test]
    fn push_supports_fcm_and_unregister() {
        let alice = did("alice");
        let mut gateway = PushGateway::new();
        gateway.register_token(PushToken {
            user_id: alice.clone(),
            device_id: device("android"),
            platform: PushPlatform::Fcm,
            token: "token3".to_owned(),
        });
        assert!(gateway.unregister_token(&alice, &device("android"), PushPlatform::Fcm));
    }
}
