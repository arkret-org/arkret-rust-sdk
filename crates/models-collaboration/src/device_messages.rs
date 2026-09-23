//! Ephemeral per-device queue DTOs.
//!
//! Device messages are not Realm Events and never participate in an authority
//! commit stream. They are retained here only as the typed HTTP queue surface.

use std::collections::BTreeMap;

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, DeviceId, DeviceMessageId, DidCoreId, DidUrl, EventId, MlsWelcomeDelivery,
    ProtocolKind,
};
use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceMessageSender {
    Account {
        sender_account_id: AccountId,
        sender_device_id: DeviceId,
    },
    Agent {
        sender_agent_id: DidCoreId,
        sender_agent_verification_method: DidUrl,
        sender_agent_key_authorize_event_id: EventId,
    },
    Station {
        sender_id: DidCoreId,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceMessageEnvelope {
    pub device_message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    #[serde(flatten)]
    pub sender: DeviceMessageSender,
    pub recipient_account_id: AccountId,
    pub recipient_device_id: DeviceId,
    #[serde(with = "canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<BTreeMap<String, Value>>,
}

// `deny_unknown_fields` and a flattened untagged enum do not deserialize
// together. Split the sender branch from the closed common object explicitly.
impl<'de> Deserialize<'de> for DeviceMessageEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| D::Error::custom("device message must be an object"))?;
        fn take<T: serde::de::DeserializeOwned, E: serde::de::Error>(
            object: &mut serde_json::Map<String, Value>,
            field: &'static str,
        ) -> Result<T, E> {
            let value = object
                .remove(field)
                .ok_or_else(|| E::missing_field(field))?;
            serde_json::from_value(value).map_err(E::custom)
        }
        let sender = if object.contains_key("sender_account_id") {
            DeviceMessageSender::Account {
                sender_account_id: take::<_, D::Error>(object, "sender_account_id")?,
                sender_device_id: take::<_, D::Error>(object, "sender_device_id")?,
            }
        } else if object.contains_key("sender_agent_id") {
            DeviceMessageSender::Agent {
                sender_agent_id: take::<_, D::Error>(object, "sender_agent_id")?,
                sender_agent_verification_method: take::<_, D::Error>(
                    object,
                    "sender_agent_verification_method",
                )?,
                sender_agent_key_authorize_event_id: take::<_, D::Error>(
                    object,
                    "sender_agent_key_authorize_event_id",
                )?,
            }
        } else {
            DeviceMessageSender::Station {
                sender_id: take::<_, D::Error>(object, "sender_id")?,
            }
        };
        let common: DeviceMessageEnvelopeCommon =
            serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self {
            device_message_id: common.device_message_id,
            kind: common.kind,
            sender,
            recipient_account_id: common.recipient_account_id,
            recipient_device_id: common.recipient_device_id,
            sent_at: common.sent_at,
            expires_at: common.expires_at,
            content: common.content,
            unsigned: common.unsigned,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceMessageEnvelopeCommon {
    device_message_id: DeviceMessageId,
    kind: ProtocolKind,
    recipient_account_id: AccountId,
    recipient_device_id: DeviceId,
    #[serde(with = "canonical_timestamp")]
    sent_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    expires_at: DateTime<Utc>,
    content: BTreeMap<String, Value>,
    #[serde(default)]
    unsigned: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageTarget {
    pub device_message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessagesSendRequestBody {
    pub messages: BTreeMap<DidCoreId, BTreeMap<DeviceId, DeviceMessageTarget>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageDeliveredRow {
    pub device_message_id: DeviceMessageId,
    pub status: DeviceMessageDeliveredStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceMessageDeliveredStatus {
    #[serde(rename = "delivered")]
    Delivered,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageUnknownRow {
    pub device_message_id: DeviceMessageId,
    pub status: DeviceMessageUnknownStatus,
    pub reason_code: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceMessageUnknownStatus {
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessagesSendOutcome {
    pub delivered: BTreeMap<DidCoreId, BTreeMap<DeviceId, DeviceMessageDeliveredRow>>,
    pub unknown_devices: BTreeMap<DidCoreId, BTreeMap<DeviceId, DeviceMessageUnknownRow>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessagesGetOutcome {
    pub deliveries: Vec<RecipientDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost: Option<bool>,
}

/// One item from the recipient-private queue shared by device messages and
/// producer-signed MLS Welcome deliveries. The original payload is preserved
/// byte-for-byte at the object boundary; it is never rewrapped as the other
/// protocol object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "delivery_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipientDelivery {
    DeviceMessage {
        device_message: DeviceMessageEnvelope,
    },
    MlsWelcome {
        mls_welcome: MlsWelcomeDelivery,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessagesAckRequestBody {
    pub ack_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessagesAckOutcome {
    pub pruned_count: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{DeviceMessageEnvelope, RecipientDelivery};

    fn base_message() -> Value {
        json!({
            "device_message_id": "ak:device_message:01964137-2000-7000-8000-000000000021",
            "kind": "ak.device_message.test",
            "recipient_account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "recipient_device_id": "ak:device:01964139-0000-7000-8000-000000000000",
            "sent_at": "2026-04-27T00:00:00.000Z",
            "expires_at": "2026-04-27T00:05:00.000Z",
            "content": {"ciphertext": "fixture"}
        })
    }

    #[test]
    fn sender_branches_roundtrip_in_the_closed_envelope() {
        let mut account = base_message();
        account["sender_account_id"] = account["recipient_account_id"].clone();
        account["sender_device_id"] = account["recipient_device_id"].clone();

        let mut agent = base_message();
        agent["sender_agent_id"] = json!("ak:did_core:web:agent.example");
        agent["sender_agent_verification_method"] = json!("did:web:agent.example#key-1");
        agent["sender_agent_key_authorize_event_id"] =
            json!("ak:event:AUJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC");

        let mut station = base_message();
        station["sender_id"] = json!("ak:did_core:web:station.example");

        for input in [account, agent, station] {
            let message: DeviceMessageEnvelope = serde_json::from_value(input.clone()).unwrap();
            let bytes = serde_json::to_vec(&message).unwrap();
            let restored: DeviceMessageEnvelope = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_value(restored).unwrap(), input);
        }
    }

    #[test]
    fn mixed_and_unknown_sender_fields_are_rejected() {
        let mut account = base_message();
        account["sender_account_id"] = account["recipient_account_id"].clone();
        account["sender_device_id"] = account["recipient_device_id"].clone();
        account["sender_id"] = json!("ak:did_core:web:station.example");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(account).is_err());

        let mut station = base_message();
        station["sender_id"] = json!("ak:did_core:web:station.example");
        station["unexpected"] = json!(true);
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(station).is_err());
    }

    #[test]
    fn recipient_delivery_keeps_a_closed_device_message_branch() {
        let mut message = base_message();
        message["sender_id"] = json!("ak:did_core:web:station.example");
        let item = json!({"delivery_kind": "device_message", "device_message": message});
        let delivery: RecipientDelivery = serde_json::from_value(item.clone()).unwrap();
        assert!(matches!(delivery, RecipientDelivery::DeviceMessage { .. }));
        assert_eq!(serde_json::to_value(delivery).unwrap(), item);

        let mut extra = item.clone();
        extra["mls_welcome"] = json!({});
        assert!(serde_json::from_value::<RecipientDelivery>(extra).is_err());
        let mut wrong_kind = item;
        wrong_kind["delivery_kind"] = json!("mls_welcome");
        assert!(serde_json::from_value::<RecipientDelivery>(wrong_kind).is_err());
    }
}
