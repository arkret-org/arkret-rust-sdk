//! Ephemeral per-device queue DTOs.
//!
//! Device messages are not Realm Events and never participate in an authority
//! commit stream. They are retained here only as the typed HTTP queue surface.

use std::collections::BTreeMap;

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{AccountId, DeviceId, DeviceMessageId, DidCoreId, DidUrl, EventId, ProtocolKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub messages: Vec<DeviceMessageEnvelope>,
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
