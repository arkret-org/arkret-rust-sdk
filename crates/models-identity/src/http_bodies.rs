//! Identity/account HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json` / `agent-operations.schema.json`):
//! the account logout / device-enroll / OIDC-callback request bodies and the
//! transparent identity-describe outcome wrappers used by the Salvo OpenAPI
//! bindings. Pure identity/account wire shapes; validation and dispatch live
//! with the auth and server behavior crates.

use arkret_wire::{DeviceId, Did, Event, EventId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDescription,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
};

/// `ak.gate.account.command.logout` request (Principal Server device logout).
/// Empty body — the session bearer identifies the device session to terminate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLogoutOutcome {
    pub ok: bool,
    pub revoked: bool,
}

/// Request body for `ak.gate.account.command.enroll_device`
/// (`POST /_arkret/gate/account/device-enroll`). The authenticated session
/// asks its designated enrollment authority to mint a `service_attested`
/// `ak.device.authorize` for this session's own device (device-lifecycle.md
/// §5.4, key-management.md §5.0.6). Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountDeviceEnrollRequestBody {
    pub device_id: DeviceId,
    /// did:key multibase (`z6Mk…`) or base64 of this session's device public key.
    pub device_public_key: String,
    /// This device's HPKE sealing public key (multibase); enters
    /// `ak.device.authorize.payload.hpke_key` verbatim (§5.4).
    pub hpke_key: String,
    /// Canonical sorted unique algorithm ids; enters
    /// `ak.device.authorize.payload.algorithms` verbatim (§5.2/§5.4).
    pub algorithms: Vec<String>,
    /// Founding-device sequence. The closed wire contract fixes this to `1`;
    /// post-bootstrap devices use pairing or recovery re-anchor instead.
    #[serde(
        serialize_with = "serialize_founding_device_actor_seq",
        deserialize_with = "deserialize_founding_device_actor_seq"
    )]
    pub actor_seq: u64,
    /// Root-signed `ak.realm.create` Event id immediately preceding the
    /// authority-signed authorize in the atomic first-device bootstrap unit.
    /// Copied to the authorize Event's sole `prev_refs` entry.
    pub bootstrap_create_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
}

fn serialize_founding_device_actor_seq<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if *value != 1 {
        return Err(serde::ser::Error::custom(
            "founding device actor_seq must be 1",
        ));
    }
    serializer.serialize_u64(*value)
}

fn deserialize_founding_device_actor_seq<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value != 1 {
        return Err(serde::de::Error::custom(
            "founding device actor_seq must be 1",
        ));
    }
    Ok(value)
}

/// Outcome for `ak.gate.account.command.enroll_device`. The account authority
/// does not contact the Principal Server; the caller submits `authorized_event`
/// verbatim to `POST /_arkret/self/events`. Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountDeviceEnrollOutcome {
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// Enrollment authority DID (= `executed_by` /
    /// `enrollment_authority_binding.authority_did`).
    pub authority_did: Did,
    /// Fully-signed `service_attested` `ak.device.authorize` Event envelope.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub authorized_event: Event,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountOidcCallbackRequestBody {
    pub state: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDescribeOutcome(pub IdentityDescription);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityLogResultBody(pub IdentityLogListOutcome);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentitySubmitDidOperationRequestBody(pub DidOperationSubmitRequestBody);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentitySubmitDidOperationOutcome(pub DidOperationSubmitOutcome);
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityReceiptsResultBody(pub IdentityReceiptListOutcome);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::AccountDeviceEnrollRequestBody;

    fn founding_request() -> serde_json::Value {
        json!({
            "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
            "device_public_key": "z6MkExamplePublicKey",
            "hpke_key": "z6LExampleHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
            "actor_seq": 1,
            "bootstrap_create_event_id": "ak:event:01964137-0000-8000-8000-000000000002"
        })
    }

    #[test]
    fn device_enroll_accepts_only_founding_actor_seq() {
        serde_json::from_value::<AccountDeviceEnrollRequestBody>(founding_request())
            .expect("founding request");

        let mut later = founding_request();
        later["actor_seq"] = json!(2);
        let decoded_error = serde_json::from_value::<AccountDeviceEnrollRequestBody>(later.clone())
            .expect_err("later device must fail");
        assert!(decoded_error.to_string().contains("actor_seq must be 1"));

        let invalid_body = AccountDeviceEnrollRequestBody {
            device_id: serde_json::from_value(later["device_id"].clone()).expect("device id"),
            device_public_key: "z6MkExamplePublicKey".to_owned(),
            hpke_key: "z6LExampleHpkeKey".to_owned(),
            algorithms: vec!["ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned()],
            actor_seq: 2,
            bootstrap_create_event_id: serde_json::from_value(
                later["bootstrap_create_event_id"].clone(),
            )
            .expect("event id"),
            not_before: None,
        };
        assert!(
            serde_json::to_value(invalid_body)
                .expect_err("invalid constructed request must not serialize")
                .to_string()
                .contains("actor_seq must be 1")
        );
    }

    #[test]
    fn device_enroll_requires_bootstrap_create_event() {
        let mut missing = founding_request();
        missing
            .as_object_mut()
            .expect("object")
            .remove("bootstrap_create_event_id");
        assert!(serde_json::from_value::<AccountDeviceEnrollRequestBody>(missing).is_err());
    }
}
