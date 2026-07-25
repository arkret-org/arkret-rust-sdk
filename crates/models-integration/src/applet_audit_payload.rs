//! Applet-registration and bridge event payload counterparts.

use std::collections::BTreeMap;

use arkret_wire::{Did, Error, Hash, NonEmptyString, RealmId, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::applet_models::AppletIdentifier;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeVisibilityScope {
    RealmAdmins,
    AppletController,
    RealmMembers,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeErrorClass {
    ExternalNetwork,
    Auth,
    Schema,
    RateLimit,
    Policy,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_bridge_error_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletBridgeErrorPayload {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub applet_id: AppletIdentifier,
    pub realm_id: RealmId,
    pub failed_transaction_ref: String,
    pub error_class: AppletBridgeErrorClass,
    pub error_code: NonEmptyString,
    pub retriable: bool,
    pub visibility_scope: AppletBridgeVisibilityScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_registration_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRegistrationPayload {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub applet_id: AppletIdentifier,
    pub service_id: Did,
    pub controller_id: Did,
    pub base_url: String,
    pub bot_actor_id: Did,
    pub protocols: Vec<String>,
    pub namespaces: BTreeMap<String, Value>,
    pub receive_events: bool,
    pub receive_ephemeral: bool,
    pub rate_limited: bool,
    pub requested_scopes: Vec<String>,
    pub registration_epoch: Hash,
    pub webhook_auth: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BTreeMap<String, Value>>,
    pub proof: BTreeMap<String, Value>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

impl AppletRegistrationPayload {
    /// Build a `ak.applet.registration` payload with the full closed field set
    /// (`event-payload.schema.json#/$defs/applet_registration_payload`). The
    /// spec marks 14 fields required plus `created_at`; the collection / flag
    /// fields default to their empty / false forms (all schema-valid) and are
    /// set through the `with_*` chain. Downstream MUST stop sending the legacy
    /// `{service_id, namespace, capabilities}` short form — it fails the strong
    /// payload validator (missing required fields + `additionalProperties:false`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applet_id: AppletIdentifier,
        service_id: Did,
        controller_id: Did,
        base_url: impl Into<String>,
        bot_actor_id: Did,
        registration_epoch: Hash,
        webhook_auth: BTreeMap<String, Value>,
        proof: BTreeMap<String, Value>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            applet_id,
            service_id,
            controller_id,
            base_url: base_url.into(),
            bot_actor_id,
            protocols: Vec::new(),
            namespaces: BTreeMap::new(),
            receive_events: false,
            receive_ephemeral: false,
            rate_limited: false,
            requested_scopes: Vec::new(),
            registration_epoch,
            webhook_auth,
            manifest: None,
            proof,
            created_at,
        }
    }

    pub fn with_protocols(mut self, protocols: Vec<String>) -> Self {
        self.protocols = protocols;
        self
    }

    pub fn with_namespaces(mut self, namespaces: BTreeMap<String, Value>) -> Self {
        self.namespaces = namespaces;
        self
    }

    pub fn with_requested_scopes(mut self, requested_scopes: Vec<String>) -> Self {
        self.requested_scopes = requested_scopes;
        self
    }

    pub fn with_receive_events(mut self, receive_events: bool) -> Self {
        self.receive_events = receive_events;
        self
    }

    pub fn with_receive_ephemeral(mut self, receive_ephemeral: bool) -> Self {
        self.receive_ephemeral = receive_ephemeral;
        self
    }

    pub fn with_rate_limited(mut self, rate_limited: bool) -> Self {
        self.rate_limited = rate_limited;
        self
    }

    pub fn with_manifest(mut self, manifest: BTreeMap<String, Value>) -> Self {
        self.manifest = Some(manifest);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        // Spec: an empty proof object MUST be rejected as schema_violation.
        if self.proof.is_empty() {
            return Err(Error::Protocol(
                "applet registration proof object must not be empty".to_owned(),
            ));
        }
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("applet registration payload serialize: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    #[test]
    fn applet_registration_builder_rejects_empty_proof() {
        let payload = AppletRegistrationPayload::new(
            AppletIdentifier::Did(did("did:webvh:z6mkfixture:applet.example")),
            did("did:webvh:z6mkfixture:svc.example"),
            did("did:webvh:z6mkfixture:controller.example"),
            "https://applet.example",
            did("did:webvh:z6mkfixture:bot.example"),
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            BTreeMap::new(),
            BTreeMap::new(),
            "2026-07-08T10:05:00.000Z".parse().unwrap(),
        );
        assert!(payload.to_value().is_err());
    }
}
