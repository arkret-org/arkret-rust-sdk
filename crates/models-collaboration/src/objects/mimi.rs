//! Shared closed MIMI operation payloads.

use std::num::NonZeroU64;

use arkret_wire::{
    Base64UrlString, DidCoreId, Hash, MimiRoomUri, MimiUri, NonEmptyString, ReasonCode,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiFailure {
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub target_ref: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = u64)))]
    pub retry_after_ms: Option<NonZeroU64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiOpaquePayload {
    pub content_type: NonEmptyString,
    pub payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub payload: Option<Base64UrlString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiCiphertext {
    pub content_type: NonEmptyString,
    pub ciphertext_digest: Hash,
    pub payload: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRoomUpdate {
    pub kind: NonEmptyString,
    pub payload: MimiOpaquePayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotification {
    pub kind: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub fanout_ref: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub delivery_hint: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotificationRouting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mimi_room_uri: Option<MimiRoomUri>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub target_provider_ids: Option<Vec<DidCoreId>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiDeliveryStatus {
    Accepted,
    Partial,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiDelivery {
    pub status: MimiDeliveryStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivered_to_ids: Vec<DidCoreId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiConsentPurpose {
    Invite,
    VoiceCall,
    VideoCall,
    Presence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MimiIdentifierKind {
    MimiUri,
    Did,
    Handle,
    Phone,
    Email,
    Opaque,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifier {
    pub kind: MimiIdentifierKind,
    pub identifier_commitment: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierMatch {
    pub identifier_commitment: Hash,
    pub matched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mimi_uri: Option<MimiUri>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub subject_id: Option<DidCoreId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiOhttpContext {
    pub context_id: NonEmptyString,
    pub request_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub relay_provider_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub encapsulated_request: Option<Base64UrlString>,
}

#[cfg(test)]
mod notification_presence_tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn closed_mimi_optional_members_reject_present_null() {
        fn check<T: serde::de::DeserializeOwned + Serialize>(value: Value, fields: &[&str]) {
            let parsed: T = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), value);
            for field in fields {
                let mut invalid = value.clone();
                invalid[*field] = Value::Null;
                assert!(serde_json::from_value::<T>(invalid).is_err(), "{field}");
            }
        }
        check::<MimiFailure>(
            json!({"reason_code":"not_found"}),
            &["target_ref", "retry_after_ms"],
        );
        check::<MimiOpaquePayload>(
            json!({"content_type":"application/octet-stream", "payload_digest":format!("sha256:{}", "a".repeat(64))}),
            &["payload"],
        );
        check::<MimiIdentifierMatch>(
            json!({"identifier_commitment":format!("sha256:{}", "a".repeat(64)), "matched":false}),
            &["mimi_uri", "subject_id"],
        );
        check::<MimiOhttpContext>(
            json!({"context_id":"opaque-context", "request_digest":format!("sha256:{}", "a".repeat(64))}),
            &["relay_provider_id", "encapsulated_request"],
        );
        check::<crate::mimi_operations::MimiNotifyResponseBody>(
            json!({"accepted":true}),
            &["retry_after_ms"],
        );
        check::<crate::mimi_operations::MimiRoomUpdateResponseBody>(
            json!({"accepted":true}),
            &["room_state_ref", "rejections"],
        );
    }

    #[test]
    fn notification_routing_preserves_absent_and_explicit_empty_targets_and_rejects_null() {
        for value in [json!({}), json!({"target_provider_ids": []})] {
            let routing: MimiNotificationRouting = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(routing).unwrap(), value);
        }
        for field in ["mimi_room_uri", "target_provider_ids"] {
            let mut invalid = json!({});
            invalid[field] = Value::Null;
            assert!(
                serde_json::from_value::<MimiNotificationRouting>(invalid).is_err(),
                "{field}"
            );
        }
        for field in ["fanout_ref", "delivery_hint"] {
            let mut invalid = json!({"kind":"refresh"});
            invalid[field] = Value::Null;
            assert!(
                serde_json::from_value::<MimiNotification>(invalid).is_err(),
                "{field}"
            );
        }
    }
}
