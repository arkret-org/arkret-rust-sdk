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

/// To-device queue envelope, `device-message.schema.json`.
///
/// `kind` is an open `ak.*` transport discriminator, so `content` stays the
/// schema's open object; closed kinds such as `ak.read_cursor.update` are
/// authored from their typed content and decoded before use.
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

#[derive(Deserialize)]
struct DeviceMessageEnvelopeFields {
    device_message_id: DeviceMessageId,
    kind: ProtocolKind,
    sender_account_id: Option<AccountId>,
    sender_device_id: Option<DeviceId>,
    sender_agent_id: Option<DidCoreId>,
    sender_agent_verification_method: Option<DidUrl>,
    sender_agent_key_authorize_event_id: Option<EventId>,
    sender_id: Option<DidCoreId>,
    recipient_account_id: AccountId,
    recipient_device_id: DeviceId,
    #[serde(with = "canonical_timestamp")]
    sent_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    expires_at: DateTime<Utc>,
    content: BTreeMap<String, Value>,
    unsigned: Option<BTreeMap<String, Value>>,
}

impl<'de> Deserialize<'de> for DeviceMessageEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("device message must be an object"))?;
        const FIELDS: &[&str] = &[
            "device_message_id",
            "kind",
            "sender_account_id",
            "sender_device_id",
            "sender_agent_id",
            "sender_agent_verification_method",
            "sender_agent_key_authorize_event_id",
            "sender_id",
            "recipient_account_id",
            "recipient_device_id",
            "sent_at",
            "expires_at",
            "content",
            "unsigned",
        ];
        if let Some(key) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
            return Err(D::Error::custom(format!(
                "unknown device message field {key}"
            )));
        }
        if object.get("unsigned") == Some(&Value::Null) {
            return Err(D::Error::custom("unsigned must be an object when present"));
        }
        let has = |key: &str| object.contains_key(key);
        let account = has("sender_account_id")
            && has("sender_device_id")
            && !has("sender_agent_id")
            && !has("sender_agent_verification_method")
            && !has("sender_agent_key_authorize_event_id")
            && !has("sender_id");
        let agent = has("sender_agent_id")
            && has("sender_agent_verification_method")
            && has("sender_agent_key_authorize_event_id")
            && !has("sender_account_id")
            && !has("sender_device_id")
            && !has("sender_id");
        let station = has("sender_id")
            && !has("sender_account_id")
            && !has("sender_device_id")
            && !has("sender_agent_id")
            && !has("sender_agent_verification_method")
            && !has("sender_agent_key_authorize_event_id");
        if !(account || agent || station) {
            return Err(D::Error::custom(
                "device message sender branch is incomplete or mixed",
            ));
        }
        let fields: DeviceMessageEnvelopeFields =
            serde_json::from_value(value).map_err(D::Error::custom)?;
        let sender = if account {
            DeviceMessageSender::Account {
                sender_account_id: fields
                    .sender_account_id
                    .ok_or_else(|| D::Error::custom("sender_account_id must be an AccountId"))?,
                sender_device_id: fields
                    .sender_device_id
                    .ok_or_else(|| D::Error::custom("sender_device_id must be a DeviceId"))?,
            }
        } else if agent {
            DeviceMessageSender::Agent {
                sender_agent_id: fields
                    .sender_agent_id
                    .ok_or_else(|| D::Error::custom("sender_agent_id must be a DidCoreId"))?,
                sender_agent_verification_method: fields
                    .sender_agent_verification_method
                    .ok_or_else(|| {
                        D::Error::custom("sender_agent_verification_method must be a DidUrl")
                    })?,
                sender_agent_key_authorize_event_id: fields
                    .sender_agent_key_authorize_event_id
                    .ok_or_else(|| {
                        D::Error::custom("sender_agent_key_authorize_event_id must be an EventId")
                    })?,
            }
        } else {
            if !matches!(
                fields.kind.as_str(),
                "ak.account_data.update" | "ak.read_cursor.update"
            ) {
                return Err(D::Error::custom(
                    "Station sender requires an actor-private update kind",
                ));
            }
            if fields.sender_id.as_ref() != Some(&fields.recipient_account_id.station_id) {
                return Err(D::Error::custom(
                    "Station sender must equal the recipient Account station_id",
                ));
            }
            DeviceMessageSender::Station {
                sender_id: fields
                    .sender_id
                    .ok_or_else(|| D::Error::custom("sender_id must be a DidCoreId"))?,
            }
        };
        Ok(Self {
            device_message_id: fields.device_message_id,
            kind: fields.kind,
            sender,
            recipient_account_id: fields.recipient_account_id,
            recipient_device_id: fields.recipient_device_id,
            sent_at: fields.sent_at,
            expires_at: fields.expires_at,
            content: fields.content,
            unsigned: fields.unsigned,
        })
    }
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

/// A target the recipient Station cannot deliver to and will not enumerate.
/// Presence in `unknown_devices` is the whole signal; sender-side `expires_at`
/// defects fail the entire send request instead of producing a row.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageUnknownRow {
    pub device_message_id: DeviceMessageId,
    pub status: DeviceMessageUnknownStatus,
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
    use serde_json::json;

    use super::*;

    fn device_message() -> Value {
        json!({
            "device_message_id": "ak:device_message:01964137-0000-7000-8000-000000000001",
            "kind": "ak.secret.request",
            "sender_account_id": {
                "principal_id": "ak:did_core:web:sender.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "sender_device_id": "ak:device:01964137-0000-7000-8000-000000000002",
            "recipient_account_id": {
                "principal_id": "ak:did_core:web:recipient.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "recipient_device_id": "ak:device:01964137-0000-7000-8000-000000000003",
            "sent_at": "2026-09-23T00:00:00.000Z",
            "expires_at": "2026-09-24T00:00:00.000Z",
            "content": {
                "request_id": "req-1",
                "secret_id": "example_mls_account_secret",
                "from_device_id": "ak:device:01964137-0000-7000-8000-000000000002",
                "recipient_hpke_public_key": "example-key"
            }
        })
    }

    #[test]
    fn accepts_flat_account_sender_and_rejects_invalid_branch_shapes() {
        let wire = device_message();
        let parsed: DeviceMessageEnvelope = serde_json::from_value(wire.clone()).unwrap();
        assert!(matches!(parsed.sender, DeviceMessageSender::Account { .. }));
        assert_eq!(serde_json::to_value(parsed).unwrap(), wire);

        let mut half = wire.clone();
        half.as_object_mut().unwrap().remove("sender_device_id");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(half).is_err());

        let mut mixed = wire.clone();
        mixed["sender_id"] = json!("ak:did_core:web:station.example");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(mixed).is_err());

        let mut null_sender = wire.clone();
        null_sender["sender_account_id"] = Value::Null;
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(null_sender).is_err());

        let mut unknown = wire;
        unknown["extra"] = json!(true);
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(unknown).is_err());

        let mut null_unsigned = device_message();
        null_unsigned["unsigned"] = Value::Null;
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(null_unsigned).is_err());
    }

    #[test]
    fn accepts_complete_agent_and_restricted_station_senders() {
        let mut agent = device_message();
        agent.as_object_mut().unwrap().remove("sender_account_id");
        agent.as_object_mut().unwrap().remove("sender_device_id");
        agent["sender_agent_id"] = json!("ak:did_core:web:agent.example");
        agent["sender_agent_verification_method"] = json!("did:web:agent.example#key-1");
        agent["sender_agent_key_authorize_event_id"] =
            json!("ak:event:ARn9Y97Ha81FH12YY8HLiDixId_wA5Wx2c25p82mJcJ5");
        let parsed: DeviceMessageEnvelope = serde_json::from_value(agent.clone()).unwrap();
        assert!(matches!(parsed.sender, DeviceMessageSender::Agent { .. }));
        assert_eq!(serde_json::to_value(parsed).unwrap(), agent);

        let mut station = device_message();
        station.as_object_mut().unwrap().remove("sender_account_id");
        station.as_object_mut().unwrap().remove("sender_device_id");
        station["sender_id"] = json!("ak:did_core:web:station.example");
        station["kind"] = json!("ak.account_data.update");
        station["content"] = json!({});
        let parsed: DeviceMessageEnvelope = serde_json::from_value(station.clone()).unwrap();
        assert!(matches!(parsed.sender, DeviceMessageSender::Station { .. }));
        assert_eq!(serde_json::to_value(parsed).unwrap(), station);
        station["sender_id"] = json!("ak:did_core:web:other-station.example");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(station.clone()).is_err());
        station["sender_id"] = json!("ak:did_core:web:station.example");
        station["kind"] = json!("ak.secret.request");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(station).is_err());
    }

    #[test]
    fn unknown_device_row_carries_no_reason_code() {
        let row = json!({
            "device_message_id": "ak:device_message:01964137-0000-7000-8000-000000000001",
            "status": "unknown"
        });
        let parsed: DeviceMessageUnknownRow = serde_json::from_value(row.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), row);
        let mut retired = row;
        retired["reason_code"] = json!("device_result_unavailable");
        assert!(serde_json::from_value::<DeviceMessageUnknownRow>(retired).is_err());
    }
}
