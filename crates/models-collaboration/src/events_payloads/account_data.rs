//! Account-data event payloads.

use serde::de;

use crate::internal_prelude::*;

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
pub fn notification_inbox_account_data_key(notification_id: &NotificationId) -> String {
    format!(
        "{}.{}",
        AccountDataKey::NOTIFICATIONS_INBOX,
        notification_id.as_str()
    )
}

/// Inverse of [`notification_inbox_account_data_key`].
pub fn notification_inbox_account_data_key_notification_id(
    account_data_key: &str,
) -> Option<NotificationId> {
    account_data_key
        .strip_prefix(AccountDataKey::NOTIFICATIONS_INBOX)?
        .strip_prefix('.')
        .and_then(|notification_id| NotificationId::new(notification_id.to_owned()).ok())
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Did>,
    /// Compare-and-set precondition. `0` creates a key that has never been
    /// written; every accepted write stores `expected_revision + 1`.
    pub expected_revision: u64,
    /// Caller-supplied opaque value. Unlike the encrypted branch, this may be
    /// any JSON value, including a scalar, array, or null.
    #[serde(default, skip_serializing_if = "AccountDataBody::is_absent")]
    pub body: AccountDataBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_digest: Option<Hash>,
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
    #[serde(default)]
    owner: Option<Did>,
    expected_revision: u64,
    #[serde(default)]
    body: AccountDataBody,
    #[serde(default)]
    encrypted_payload: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    body_digest: Option<Hash>,
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
            owner: wire.owner,
            body: wire.body,
            encrypted_payload: wire.encrypted_payload,
            body_digest: wire.body_digest,
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
            return Err(Error::Protocol(
                "account_data_set_payload requires body, encrypted_payload, or tombstone=true"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn registry_scoped_account_data_keys_round_trip() {
        let view_id =
            ViewId::new("ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned()).unwrap();
        let key = private_view_account_data_key(&view_id);
        assert_eq!(
            key,
            "ak.views.private.ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        );
        assert_eq!(private_view_account_data_key_view_id(&key), Some(view_id));

        let notification_id =
            NotificationId::new("ak:notification:0196419b-0000-7000-8000-000000000002".to_owned())
                .unwrap();
        let key = notification_inbox_account_data_key(&notification_id);
        assert_eq!(
            key,
            "ak.notifications.inbox.ak:notification:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(
            notification_inbox_account_data_key_notification_id(&key),
            Some(notification_id)
        );
    }

    #[test]
    fn registry_scoped_account_data_key_parsers_reject_foreign_and_malformed_keys() {
        for key in [
            "ak.views.private",
            "ak.views.private.",
            "ak.views.private.ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            "ak.views.private.not-a-typed-id",
            "ak.notifications.inbox.ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        ] {
            assert_eq!(private_view_account_data_key_view_id(key), None, "{key}");
        }
        for key in [
            "ak.notifications.inbox",
            "ak.notifications.inbox.",
            "ak.notifications.inbox.ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            "ak.views.private.ak:notification:0196419b-0000-7000-8000-000000000001",
        ] {
            assert_eq!(
                notification_inbox_account_data_key_notification_id(key),
                None,
                "{key}"
            );
        }
    }

    #[test]
    fn account_data_set_payload_matches_current_spec_shape() {
        let payload: AccountDataSetPayload = serde_json::from_value(json!({
            "key": "ak.preference.theme",
            "expected_revision": 0,
            "body": "dark"
        }))
        .unwrap();
        assert_eq!(payload.body.as_value(), Some(&json!("dark")));
        assert!(payload.owner.is_none());
        assert!(payload.updated_at.is_none());

        let value = serde_json::to_value(&payload).unwrap();
        let catalog =
            arkret_schema::event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        catalog
            .validate_payload(EventKind::ACCOUNT_DATA_SET, &value)
            .unwrap();
    }

    #[test]
    fn account_data_set_payload_accepts_encrypted_and_tombstone_branches() {
        for value in [
            json!({
                "key": "ak.private.index",
                "expected_revision": 4,
                "encrypted_payload": {"ciphertext": "opaque"}
            }),
            json!({
                "key": "ak.preference.theme",
                "expected_revision": 7,
                "tombstone": true
            }),
        ] {
            let payload: AccountDataSetPayload = serde_json::from_value(value).unwrap();
            payload.validate().unwrap();
        }
    }

    #[test]
    fn account_data_set_payload_preserves_explicit_null_body() {
        let payload: AccountDataSetPayload = serde_json::from_value(json!({
            "key": "ak.preference.optional",
            "expected_revision": 0,
            "body": null
        }))
        .unwrap();
        assert_eq!(payload.body.as_value(), Some(&Value::Null));
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({
                "key": "ak.preference.optional",
                "expected_revision": 0,
                "body": null
            })
        );
    }

    #[test]
    fn account_data_set_payload_rejects_invalid_union_and_false_tombstone() {
        assert!(
            serde_json::from_value::<AccountDataSetPayload>(json!({
                "key": "ak.preference.theme",
                "expected_revision": 0
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AccountDataSetPayload>(json!({
                "key": "ak.preference.theme",
                "expected_revision": 0,
                "tombstone": false
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AccountDataSetPayload>(json!({
                "key": "ak.preference.theme",
                "expected_revision": 0,
                "body": {},
                "legacy_field": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AccountDataSetPayload>(json!({
                "key": "ak.preference.theme",
                "body": "dark"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AccountDataSetPayload>(json!({
                "key": "ak.preference.theme",
                "expected_state_digest":
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "body": "dark"
            }))
            .is_err()
        );
    }
}
