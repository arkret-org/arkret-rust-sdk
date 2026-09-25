//! Closed state payloads for the discovery, policy-action, schema-definition,
//! sovereign DID policy and device-list Event kinds.
//!
//! Each type mirrors one `event-payload.schema.json` definition field for
//! field, in schema property order, so a standard Event of these kinds has an
//! SDK-owned typed contract instead of being refused for lack of a binding.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::handle::Handle;
use arkret_wire::{
    ActorId, AppletId, DeviceId, DidCoreId, Discoverability, Hash, NonEmptyString, PolicyId,
    Result, TrustDomainId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const MAX_DIRECTORY_IDS: usize = 64;

fn invalid(reason: impl Into<String>) -> WireError {
    WireError::Protocol(reason.into())
}

fn ensure_unique<T: Ord>(values: &[T], what: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    if values.iter().all(|value| seen.insert(value)) {
        Ok(())
    } else {
        Err(invalid(format!("{what} must not repeat an item")))
    }
}

fn ensure_not_typed_identifier(value: &str, what: &str) -> Result<()> {
    if value.starts_with("ak:") {
        return Err(invalid(format!(
            "{what} must not be an ak: typed identifier"
        )));
    }
    Ok(())
}

/// Maximum directory disclosure class of one profile field
/// (`discovery_profile_visibility` values).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProfileFieldVisibility {
    Public,
    Listed,
    Restricted,
    Hidden,
}

/// `discovery_profile_visibility`: declared profile field name to its maximum
/// directory disclosure class.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiscoveryProfileVisibility(pub BTreeMap<String, DiscoveryProfileFieldVisibility>);

impl DiscoveryProfileVisibility {
    pub fn validate(&self) -> Result<()> {
        for field in self.0.keys() {
            let bytes = field.as_bytes();
            let valid = !bytes.is_empty()
                && bytes.len() <= 64
                && bytes[0].is_ascii_lowercase()
                && bytes.iter().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'
                });
            if !valid {
                return Err(invalid(format!(
                    "profile_visibility field `{field}` is not a declared profile field name"
                )));
            }
        }
        Ok(())
    }
}

fn validate_directory_ids(directory_ids: &[DidCoreId]) -> Result<()> {
    if directory_ids.len() > MAX_DIRECTORY_IDS {
        return Err(invalid(format!(
            "directory_ids carries more than {MAX_DIRECTORY_IDS} Directory services"
        )));
    }
    ensure_unique(directory_ids, "directory_ids")
}

/// `resource_discovery_state_value.resource_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryResourceKind {
    Actor,
    Applet,
    Handle,
}

/// `resource_discovery_state_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDiscoveryStateValue {
    pub resource_kind: DiscoveryResourceKind,
    pub discoverability: Discoverability,
    pub directory_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_visibility: Option<DiscoveryProfileVisibility>,
}

impl ResourceDiscoveryStateValue {
    fn validate_for(&self, kind: DiscoveryResourceKind) -> Result<()> {
        if self.resource_kind != kind {
            return Err(invalid(
                "discovery value resource_kind differs from the Event kind's resource",
            ));
        }
        validate_directory_ids(&self.directory_ids)?;
        self.profile_visibility
            .as_ref()
            .map_or(Ok(()), DiscoveryProfileVisibility::validate)
    }
}

/// `ak.actor.discovery` payload (`actor_discovery_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorDiscoveryStatePayload {
    pub resource_id: ActorId,
    pub value: ResourceDiscoveryStateValue,
}

impl ActorDiscoveryStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate_for(DiscoveryResourceKind::Actor)
    }
}

/// `ak.applet.discovery` payload (`applet_discovery_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletDiscoveryStatePayload {
    pub resource_id: AppletId,
    pub value: ResourceDiscoveryStateValue,
}

impl AppletDiscoveryStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate_for(DiscoveryResourceKind::Applet)
    }
}

/// `ak.handle.discovery` payload (`handle_discovery_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleDiscoveryStatePayload {
    pub resource_id: Handle,
    pub value: ResourceDiscoveryStateValue,
}

impl HandleDiscoveryStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate_for(DiscoveryResourceKind::Handle)
    }
}

/// `event-payload.schema.json#/$defs/organization_discovery_state_payload/properties/value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDiscoveryStateValue {
    pub discoverability: Discoverability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_visibility: Option<DiscoveryProfileVisibility>,
    pub directory_ids: Vec<DidCoreId>,
}

/// `ak.organization.discovery` payload
/// (`organization_discovery_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDiscoveryStatePayload {
    pub organization_id: DidCoreId,
    pub value: OrganizationDiscoveryStateValue,
}

impl OrganizationDiscoveryStatePayload {
    pub fn validate(&self) -> Result<()> {
        validate_directory_ids(&self.value.directory_ids)?;
        self.value
            .profile_visibility
            .as_ref()
            .map_or(Ok(()), DiscoveryProfileVisibility::validate)
    }
}

/// `policy_action_document`: the sole v1 approval-action document family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionDocument {
    pub action: arkret_wire::PolicyActionName,
    pub approval_required: bool,
    pub approval_quorum: u64,
    pub policy_scope: String,
}

impl PolicyActionDocument {
    pub fn validate(&self) -> Result<()> {
        if self.approval_quorum == 0 {
            return Err(invalid("policy action approval_quorum must be at least 1"));
        }
        if !policy_scope_is_valid(&self.policy_scope) {
            return Err(invalid(
                "policy action policy_scope must be an ak: typed ref or a DID",
            ));
        }
        Ok(())
    }
}

fn policy_scope_is_valid(scope: &str) -> bool {
    if let Some(did) = scope.strip_prefix("did:") {
        return !did.is_empty() && !did.chars().any(char::is_whitespace);
    }
    let Some(rest) = scope.strip_prefix("ak:") else {
        return false;
    };
    let mut segments = rest.split(':');
    let kind_ok = segments.next().is_some_and(|kind| {
        !kind.is_empty()
            && kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    });
    let mut value_segments = 0;
    let values_ok = segments.all(|segment| {
        value_segments += 1;
        !segment.is_empty()
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-')
            })
    });
    kind_ok && values_ok && value_segments >= 1
}

/// `ak.policy.action` subject: exactly one of the two tagged namespaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyActionSubject {
    Policy(PolicyId),
    Action(arkret_wire::RealmPolicyActionId),
}

/// `ak.policy.action` payload (`policy_action_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionStatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<arkret_wire::RealmPolicyActionId>,
    pub value: PolicyActionDocument,
}

impl PolicyActionStatePayload {
    /// The tagged subject; exactly one of `policy_id` and `action_id`.
    pub fn subject(&self) -> Result<PolicyActionSubject> {
        match (&self.policy_id, &self.action_id) {
            (Some(policy_id), None) => Ok(PolicyActionSubject::Policy(policy_id.clone())),
            (None, Some(action_id)) => Ok(PolicyActionSubject::Action(action_id.clone())),
            _ => Err(invalid(
                "policy action payload carries exactly one of policy_id and action_id",
            )),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.subject()?;
        self.value.validate()
    }
}

/// JSON Schema dialect every `ak.schema.define` document declares.
pub const SCHEMA_DEFINITION_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// `ak.schema.define` payload (`schema_define_state_payload`). `value` is an
/// open JSON Schema 2020-12 document whose `$id` is the definition subject.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDefineStatePayload {
    pub value: Map<String, Value>,
}

impl SchemaDefineStatePayload {
    /// The stable `ak.schema.<name>.v<N>` subject of the definition.
    pub fn schema_id(&self) -> Result<&str> {
        let id = self
            .value
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("schema definition requires a string $id"))?;
        let body = id
            .strip_prefix("ak.schema.")
            .ok_or_else(|| invalid("schema definition $id must start with ak.schema."))?;
        let (name, version) = body
            .rsplit_once(".v")
            .ok_or_else(|| invalid("schema definition $id must end with .v<N>"))?;
        let name_ok = !name.is_empty()
            && name.split('.').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            });
        if !name_ok || version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid(
                "schema definition $id must match ak.schema.<name>.v<N>",
            ));
        }
        Ok(id)
    }

    pub fn validate(&self) -> Result<()> {
        if self.value.get("$schema").and_then(Value::as_str) != Some(SCHEMA_DEFINITION_DIALECT) {
            return Err(invalid(format!(
                "schema definition $schema must be {SCHEMA_DEFINITION_DIALECT}"
            )));
        }
        self.schema_id().map(|_| ())
    }
}

/// Deployment method policy of one DID method
/// (`sovereign_did_policy_state_payload.value.method_policy` values).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SovereignDidMethodPolicy {
    Allowlist,
    ExternalCollaboratorOnly,
    EphemeralOnly,
}

/// `event-payload.schema.json#/$defs/sovereign_did_policy_state_payload/properties/value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SovereignDidPolicyValue {
    pub default_principal_method: String,
    pub allowed_methods: Vec<String>,
    pub trust_root_ids: Vec<DidCoreId>,
    pub public_resolver_allowed: bool,
    pub method_policy: BTreeMap<String, SovereignDidMethodPolicy>,
}

fn did_method_is_valid(method: &str) -> bool {
    method.strip_prefix("did:").is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

impl SovereignDidPolicyValue {
    pub fn validate(&self) -> Result<()> {
        let methods = std::iter::once(&self.default_principal_method)
            .chain(&self.allowed_methods)
            .chain(self.method_policy.keys());
        for method in methods {
            if !did_method_is_valid(method) {
                return Err(invalid(format!("`{method}` is not a did:<method> name")));
            }
        }
        if self.allowed_methods.is_empty() || self.trust_root_ids.is_empty() {
            return Err(invalid(
                "sovereign DID policy requires allowed_methods and trust_root_ids",
            ));
        }
        ensure_unique(&self.allowed_methods, "allowed_methods")?;
        ensure_unique(&self.trust_root_ids, "trust_root_ids")
    }
}

/// `ak.sovereign.did_policy` payload (`sovereign_did_policy_state_payload`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SovereignDidPolicyStatePayload {
    pub trust_domain: TrustDomainId,
    pub value: SovereignDidPolicyValue,
}

impl SovereignDidPolicyStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

/// `ak.device.list_update` payload (`device_list_update_payload`). The
/// AccountId subject is the Event's `actor_id`; the payload never mirrors it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListUpdatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_ids: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_ids: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<NonEmptyString>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl DeviceListUpdatePayload {
    pub fn validate(&self) -> Result<()> {
        if self.changed_ids.is_none()
            && self.left_ids.is_none()
            && self.device_list_digest.is_none()
        {
            return Err(invalid(
                "device list update carries changed_ids, left_ids or device_list_digest",
            ));
        }
        for (ids, what) in [
            (&self.changed_ids, "changed_ids"),
            (&self.left_ids, "left_ids"),
        ] {
            if let Some(ids) = ids {
                if ids.is_empty() {
                    return Err(invalid(format!("{what} must not be empty when present")));
                }
                ensure_unique(ids, what)?;
            }
        }
        self.stream_id.as_ref().map_or(Ok(()), |stream_id| {
            ensure_not_typed_identifier(stream_id.as_str(), "device list stream_id")
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const DIRECTORY: &str = "ak:did_core:web:directory.example";

    fn discovery_value(kind: &str) -> Value {
        json!({
            "resource_kind": kind,
            "discoverability": "listed",
            "directory_ids": [DIRECTORY],
            "profile_visibility": {"display_name": "public", "bio": "hidden"}
        })
    }

    #[test]
    fn discovery_payloads_bind_their_resource_kind_and_directory_bounds() {
        let applet: AppletDiscoveryStatePayload = serde_json::from_value(json!({
            "resource_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            "value": discovery_value("applet")
        }))
        .unwrap();
        applet.validate().unwrap();
        let handle: HandleDiscoveryStatePayload = serde_json::from_value(json!({
            "resource_id": "alice:example.com",
            "value": discovery_value("handle")
        }))
        .unwrap();
        handle.validate().unwrap();
        let actor: ActorDiscoveryStatePayload = serde_json::from_value(json!({
            "resource_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            }},
            "value": discovery_value("applet")
        }))
        .unwrap();
        assert!(actor.validate().is_err(), "actor payload with applet value");

        for value in [
            json!({"resource_kind": "applet", "discoverability": "listed"}),
            json!({"resource_kind": "applet", "discoverability": "listed",
                   "directory_ids": [DIRECTORY], "extra": true}),
            json!({"resource_kind": "applet", "discoverability": "everyone",
                   "directory_ids": [DIRECTORY]}),
        ] {
            assert!(
                serde_json::from_value::<AppletDiscoveryStatePayload>(json!({
                    "resource_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
                    "value": value
                }))
                .is_err()
            );
        }
        let mut duplicate = applet.clone();
        duplicate
            .value
            .directory_ids
            .push(duplicate.value.directory_ids[0].clone());
        assert!(duplicate.validate().is_err());
        let mut bad_field = applet;
        bad_field.value.profile_visibility = Some(DiscoveryProfileVisibility(BTreeMap::from([(
            "Display".to_owned(),
            DiscoveryProfileFieldVisibility::Public,
        )])));
        assert!(bad_field.validate().is_err());

        let organization: OrganizationDiscoveryStatePayload = serde_json::from_value(json!({
            "organization_id": "ak:did_core:web:org.example",
            "value": {"discoverability": "public", "directory_ids": []}
        }))
        .unwrap();
        organization.validate().unwrap();
        assert!(
            serde_json::from_value::<OrganizationDiscoveryStatePayload>(json!({
                "organization_id": "ak:did_core:web:org.example",
                "value": {"resource_kind": "actor", "discoverability": "public",
                          "directory_ids": []}
            }))
            .is_err()
        );
    }

    #[test]
    fn policy_action_selects_exactly_one_tagged_subject() {
        let document = json!({
            "action": "ak.realm.configure",
            "approval_required": true,
            "approval_quorum": 2,
            "policy_scope": "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
        });
        let by_policy: PolicyActionStatePayload = serde_json::from_value(json!({
            "policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "value": document
        }))
        .unwrap();
        by_policy.validate().unwrap();
        let by_action: PolicyActionStatePayload = serde_json::from_value(json!({
            "action_id": "approve-release",
            "value": document
        }))
        .unwrap();
        by_action.validate().unwrap();
        let neither: PolicyActionStatePayload =
            serde_json::from_value(json!({"value": document})).unwrap();
        assert!(neither.validate().is_err());
        let both: PolicyActionStatePayload = serde_json::from_value(json!({
            "policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "action_id": "approve-release",
            "value": document
        }))
        .unwrap();
        assert!(both.validate().is_err());
        assert!(
            serde_json::from_value::<PolicyActionStatePayload>(json!({
                "action_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
                "value": document
            }))
            .is_err(),
            "a Realm-local action id stays outside the ak: namespace"
        );
        let mut zero_quorum = by_policy.clone();
        zero_quorum.value.approval_quorum = 0;
        assert!(zero_quorum.validate().is_err());
        let mut bad_scope = by_policy;
        bad_scope.value.policy_scope = "realm".to_owned();
        assert!(bad_scope.validate().is_err());
    }

    #[test]
    fn schema_definition_requires_the_dialect_and_a_versioned_id() {
        let valid: SchemaDefineStatePayload = serde_json::from_value(json!({
            "value": {
                "$schema": SCHEMA_DEFINITION_DIALECT,
                "$id": "ak.schema.task_card.v1",
                "type": "object"
            }
        }))
        .unwrap();
        valid.validate().unwrap();
        assert_eq!(valid.schema_id().unwrap(), "ak.schema.task_card.v1");
        for value in [
            json!({"$id": "ak.schema.task_card.v1"}),
            json!({"$schema": SCHEMA_DEFINITION_DIALECT, "$id": "task_card"}),
            json!({"$schema": SCHEMA_DEFINITION_DIALECT, "$id": "ak.schema.Task.v1"}),
            json!({"$schema": "http://json-schema.org/draft-07/schema#",
                   "$id": "ak.schema.task_card.v1"}),
        ] {
            let payload: SchemaDefineStatePayload =
                serde_json::from_value(json!({"value": value})).unwrap();
            assert!(payload.validate().is_err());
        }
        assert!(
            serde_json::from_value::<SchemaDefineStatePayload>(json!({
                "value": {}, "extra": 1
            }))
            .is_err()
        );
    }

    #[test]
    fn sovereign_did_policy_is_closed_and_method_scoped() {
        let valid: SovereignDidPolicyStatePayload = serde_json::from_value(json!({
            "trust_domain": "ak:trust_domain:enclave.example",
            "value": {
                "default_principal_method": "did:webvh",
                "allowed_methods": ["did:webvh", "did:key"],
                "trust_root_ids": ["ak:did_core:web:root.example"],
                "public_resolver_allowed": false,
                "method_policy": {"did:key": "ephemeral_only"}
            }
        }))
        .unwrap();
        valid.validate().unwrap();
        let mut empty_roots = valid.clone();
        empty_roots.value.trust_root_ids.clear();
        assert!(empty_roots.validate().is_err());
        let mut bad_method = valid.clone();
        bad_method.value.allowed_methods.push("did:Web".to_owned());
        assert!(bad_method.validate().is_err());
        let mut duplicate = valid;
        duplicate.value.allowed_methods.push("did:key".to_owned());
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn device_list_update_needs_one_signal_and_non_empty_unique_arrays() {
        let changed: DeviceListUpdatePayload = serde_json::from_value(json!({
            "changed_ids": ["ak:device:01904100-0000-7000-8000-000000000001"],
            "updated_at": "2026-09-25T00:00:00.000Z"
        }))
        .unwrap();
        changed.validate().unwrap();
        let empty: DeviceListUpdatePayload = serde_json::from_value(json!({})).unwrap();
        assert!(empty.validate().is_err());
        let empty_array: DeviceListUpdatePayload =
            serde_json::from_value(json!({"left_ids": []})).unwrap();
        assert!(empty_array.validate().is_err());
        let typed_stream: DeviceListUpdatePayload = serde_json::from_value(json!({
            "device_list_digest": format!("sha256:{}", "0".repeat(64)),
            "stream_id": "ak:stream:1"
        }))
        .unwrap();
        assert!(typed_stream.validate().is_err());
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "changed_ids": ["ak:device:01904100-0000-7000-8000-000000000001"],
                "principal_id": "ak:did_core:web:alice.example"
            }))
            .is_err()
        );
    }
}
