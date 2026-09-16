//! Account-data event payloads.

use serde::de;

use crate::internal_prelude::*;
use crate::objects::read_receipts::NotificationIdentity;

/// `ak.views.private.<view_id>` per the account-data key registry. The
/// namespace literal is spelled only in the generated [`AccountDataKey`].
pub fn private_view_account_data_key(view_id: &ViewId) -> String {
    format!("{}.{}", AccountDataKey::VIEWS_PRIVATE, view_id.as_str())
}

/// Inverse of [`private_view_account_data_key`]. `None` for any key outside
/// the namespace or whose tail is not a canonical `ak:view:` id, so a caller
/// enumerating the account-data surface never invents a View id.
pub fn private_view_account_data_key_view_id(account_data_key: &str) -> Option<ViewId> {
    account_data_key
        .strip_prefix(AccountDataKey::VIEWS_PRIVATE)?
        .strip_prefix('.')
        .and_then(|view_id| ViewId::new(view_id.to_owned()).ok())
}

/// `ak.notifications.inbox.<notification_id>` per the account-data key
/// registry.
pub fn notification_inbox_account_data_key(notification_id: &NotificationIdentity) -> String {
    format!(
        "{}.{}",
        AccountDataKey::NOTIFICATIONS_INBOX,
        notification_id.as_str()
    )
}

/// Inverse of [`notification_inbox_account_data_key`].
pub fn notification_inbox_account_data_key_notification_id(
    account_data_key: &str,
) -> Option<NotificationIdentity> {
    account_data_key
        .strip_prefix(AccountDataKey::NOTIFICATIONS_INBOX)?
        .strip_prefix('.')
        .and_then(|notification_id| NotificationIdentity::new(notification_id.to_owned()).ok())
}

/// Presence-aware account-data body.
///
/// The schema permits any JSON value, including explicit `null`, so a plain
/// `Option<Value>` cannot distinguish a present null from an absent field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AccountDataBody {
    #[default]
    Absent,
    Value(Value),
}

impl AccountDataBody {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Self::Absent => None,
            Self::Value(value) => Some(value),
        }
    }
}

impl From<Value> for AccountDataBody {
    fn from(value: Value) -> Self {
        Self::Value(value)
    }
}

impl Serialize for AccountDataBody {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Absent => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AccountDataBody {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self::Value)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_data_set_payload`.
///
/// This is the canonical Event payload for `ak.account_data.set`. The
/// self-service HTTP `account_data_replace_request_body` is a separate
/// transport DTO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountDataSetPayload {
    pub key: NonEmptyString,
    /// Compare-and-set precondition. `0` creates a key that has never been
    /// written; every accepted write stores `expected_revision + 1`.
    pub expected_revision: u64,
    /// Caller-supplied opaque value. Unlike the encrypted branch, this may be
    /// any JSON value, including a scalar, array, or null.
    #[serde(default, skip_serializing_if = "AccountDataBody::is_absent")]
    pub body: AccountDataBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<BTreeMap<String, Value>>,
    /// `true` selects the schema's tombstone branch. `false` is never emitted
    /// and is rejected on deserialization.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tombstone: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountDataSetPayloadWire {
    key: NonEmptyString,
    expected_revision: u64,
    #[serde(default)]
    body: AccountDataBody,
    #[serde(default)]
    encrypted_payload: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    tombstone: Option<bool>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    updated_at: Option<DateTime<Utc>>,
}

impl<'de> Deserialize<'de> for AccountDataSetPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AccountDataSetPayloadWire::deserialize(deserializer)?;
        if wire.tombstone == Some(false) {
            return Err(de::Error::custom(
                "account_data_set_payload.tombstone must be true when present",
            ));
        }
        let payload = Self {
            key: wire.key,
            expected_revision: wire.expected_revision,
            body: wire.body,
            encrypted_payload: wire.encrypted_payload,
            tombstone: wire.tombstone.unwrap_or(false),
            updated_at: wire.updated_at,
        };
        payload.validate().map_err(de::Error::custom)?;
        Ok(payload)
    }
}

impl AccountDataSetPayload {
    /// Enforce the schema's `body | encrypted_payload | tombstone=true`
    /// any-of requirement for values constructed directly in Rust.
    pub fn validate(&self) -> Result<()> {
        if self.body.is_absent() && self.encrypted_payload.is_none() && !self.tombstone {
            return Err(WireError::Protocol(
                "account_data_set_payload requires body, encrypted_payload, or tombstone=true"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}
