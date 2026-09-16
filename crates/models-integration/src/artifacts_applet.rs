//! Applet schema artifact counterparts.
//!
//! Includes the widget declaration shapes (`Widget`, `WidgetTokenScope`),
//! which bind the resource selector now owned by `arkret-wire`
//! (`WireResourceSelector`). The `AppletEdgeOperations` /
//! `AppletInstallOperations` aggregate enums stay in the `arkret` umbrella because
//! their variants span request bodies rehomed across model crates.

use std::collections::BTreeMap;

use arkret_wire::{
    AppletId, CircleId, CommittedEventRef, DidCoreId, DidUrl, EventId, EventProofAudience, Hash,
    RealmId, ReasonCode, SchemaId, WebOrigin, WireResourceSelector, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/external_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRef {
    pub protocol: String,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/field_definition`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub value_kind: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/protocol_instance`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolInstance {
    pub instance_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/rejected_item`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletEventRejection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-authoring.schema.json#/$defs/e2ee_policy`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2eePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_join_allowed: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/scope_grant`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeGrant {
    pub actions: Vec<String>,
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_ids: Option<Vec<CircleId>>,
    pub constraints: Vec<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/capability_constraint`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityConstraint {
    pub constraint_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, Value>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/denied_scope`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedScope {
    pub requested_scope: String,
    pub reason_code: ReasonCode,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/e2ee_effect`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2eeEffect {
    pub mls_join_required: bool,
    pub plaintext_access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_refs: Option<Vec<CommittedEventRef>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/event_submission`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSubmission {
    pub event_kind: String,
    pub payload: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/namespace_conflict`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceConflict {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_owner: Option<String>,
    pub resolution: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/widget_effect`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidgetEffect {
    pub widget_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<CommittedEventRef>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/delegation_policy`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DelegationPolicy {
    pub enabled: bool,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AppletPackageE2eePolicy {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_join_requested: Option<bool>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: XExtensionMap,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/detached_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetachedProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub audience: Option<EventProofAudience>,
    pub jws: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl DetachedProof {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.kind != arkret_wire::proof_kind::DETACHED_JWS {
            return Err(arkret_wire::WireError::Protocol(
                "detached proof kind mismatch".to_owned(),
            ));
        }
        if self.jws.is_empty() {
            return Err(arkret_wire::WireError::Protocol(
                "detached proof JWS is empty".to_owned(),
            ));
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err(arkret_wire::WireError::Protocol(
                "detached proof domain is empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/applet.schema.json#/properties/error`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Applet {
    pub schema: String,
    pub applet_id: AppletId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AppletError>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl Applet {
    pub const SCHEMA: &'static str = SchemaId::APPLET_V1;
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/applet-widget-declaration.schema.json#/properties/token_scope`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WidgetTokenScope {
    pub actions: Vec<String>,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-widget-declaration.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Widget {
    pub schema: String,
    #[serde(deserialize_with = "deserialize_https_web_origin")]
    pub widget_origin: WebOrigin,
    pub csp: String,
    pub token_scope: WidgetTokenScope,
    pub consent_required: bool,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl Widget {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.widget_origin.as_str().starts_with("https://") {
            Ok(())
        } else {
            Err(arkret_wire::WireError::Protocol(
                "widget_origin must be a canonical HTTPS Web Origin".to_owned(),
            ))
        }
    }
}

fn deserialize_https_web_origin<'de, D>(deserializer: D) -> Result<WebOrigin, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let origin = WebOrigin::deserialize(deserializer)?;
    if origin.as_str().starts_with("https://") {
        Ok(origin)
    } else {
        Err(serde::de::Error::custom(
            "widget_origin must be a canonical HTTPS Web Origin",
        ))
    }
}
