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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout` outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    pub actor_seq: u64,
    /// Root-signed `ak.realm.create` Event id immediately preceding the
    /// authority-signed authorize in the atomic first-device bootstrap unit.
    /// Required exactly when `actor_seq == 1` and copied to the authorize
    /// Event's sole `prev_refs` entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_create_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
}

/// Outcome for `ak.gate.account.command.enroll_device`. The account authority
/// does not contact the Principal Server; the caller submits `authorized_event`
/// verbatim to `POST /_arkret/self/events`. Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AccountDeviceEnrollOutcome {
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// Enrollment authority DID (= `executed_by` /
    /// `enrollment_authority_binding.authority_did`).
    pub authority_did: Did,
    /// Fully-signed `service_attested` `ak.device.authorize` Event envelope.
    pub authorized_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackRequestBody {
    pub state: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = IdentityDescription)))]
pub struct IdentityDescribeOutcome(pub IdentityDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = IdentityDocumentView)))]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = IdentityLogListOutcome)))]
pub struct IdentityLogResultBody(pub IdentityLogListOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = DidOperationSubmitRequestBody)))]
pub struct IdentitySubmitDidOperationRequestBody(pub DidOperationSubmitRequestBody);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = DidOperationSubmitOutcome)))]
pub struct IdentitySubmitDidOperationOutcome(pub DidOperationSubmitOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = IdentityReceiptListOutcome)))]
pub struct IdentityReceiptsResultBody(pub IdentityReceiptListOutcome);
