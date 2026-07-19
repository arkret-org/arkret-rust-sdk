//! Device-message DTO counterparts; the key claim and distribution
//! DTOs migrated to `arkret-models-crypto` (re-exported below).

pub use arkret_models_crypto::keys::*;

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendRequestBody {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, DeviceMessageTarget>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageTarget {
    pub message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    pub content: BTreeMap<String, Value>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesGetOutcome {
    pub messages: Vec<DeviceMessageEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub limited: bool,
    #[serde(default)]
    pub lost: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesAckRequestBody {
    pub ack_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesAckOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned_count: Option<u64>,
}

#[cfg(test)]
mod device_message_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn device_message_target_rejects_non_object_content_and_invalid_kind() {
        let valid = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(valid).is_ok());

        let missing_message_id = json!({
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(missing_message_id).is_err());

        let invalid_kind = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "key.verification.request",
            "content": {},
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(invalid_kind).is_err());

        let scalar_content = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": "legacy payload",
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(scalar_content).is_err());
    }
}
