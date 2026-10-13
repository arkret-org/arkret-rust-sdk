use std::collections::BTreeMap;

use arkret_wire::{
    CircleId, DidCoreId, HistoryAccess, ObjectRef, RealmId, Result, SchemaId, WireError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Closed v1 value set for `ak.realm.join_rule`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinRuleValue {
    Public,
    Invite,
    Knock,
    Restricted,
    KnockRestricted,
    Closed,
}

impl RealmJoinRulePayload {
    pub fn new(value: RealmJoinRuleValue) -> Self {
        Self { value }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm join-rule payload serialize: {err}")))
    }
}

/// Closed v1 discoverability set for `ak.realm.discovery`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmDiscoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDirectoryVisibility {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_realm_directory: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAllowedDiscoverer {
    pub selector_kind: RealmAllowedDiscovererKind,
    pub claim_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<DidCoreId>,
    pub issuer_id: DidCoreId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmAllowedDiscovererKind {
    Claim,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberCountMode {
    Exact,
    Bucketed,
    Omit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCountHysteresis {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratio: Option<f64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAntiEnumerationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlisted_exact_alias_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count_mode: Option<MemberCountMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_found_blinding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count_hysteresis: Option<MemberCountHysteresis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count_min_residence_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDiscoveryValue {
    pub discoverability: RealmDiscoverability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_visibility: Option<RealmDirectoryVisibility>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_discoverers: Vec<RealmAllowedDiscoverer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anti_enumeration: Option<RealmAntiEnumerationPolicy>,
}

impl RealmDiscoveryPayload {
    pub fn new(discoverability: RealmDiscoverability) -> Self {
        Self {
            value: RealmDiscoveryValue {
                discoverability,
                directory_visibility: None,
                allowed_discoverers: Vec::new(),
                directory_ids: Vec::new(),
                anti_enumeration: None,
            },
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm discovery payload serialize: {err}")))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetDownloadMode {
    Direct,
    ProviderProxy,
    OhttpRelay,
    ClientMirror,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetPlaintextMetadata {
    SizeBucket,
    MediaTypeFamily,
    ContentHash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAssetPrivacyPolicyValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_mode: Option<AssetDownloadMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_modes: Vec<AssetDownloadMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_download_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upload_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub download_proxy_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ohttp_gateway_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub max_plaintext_metadata: Vec<AssetPlaintextMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_digest_check_required: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAssetPrivacyPolicyPayload {
    pub value: RealmAssetPrivacyPolicyValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphKindProfile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_facets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writable_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_schema_refs: Vec<SchemaId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capability_actions: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSchemaValue {
    pub schema_refs: Vec<SchemaId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub morph_kind_profiles: BTreeMap<String, MorphKindProfile>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSchemaPayload {
    pub value: RealmSchemaValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for RealmArchivePayload {
    fn default() -> Self {
        Self::new()
    }
}

impl RealmArchivePayload {
    pub fn new() -> Self {
        Self { reason: None }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        if !reason.trim().is_empty() {
            self.reason = Some(reason);
        }
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm archive payload serialize: {err}")))
    }
}

impl RealmTombstonePayload {
    pub fn new(successor_realm_id: RealmId, reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            successor_realm_id,
            replacement_event_id: None,
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm tombstone payload serialize: {err}")))
    }
}

impl RealmDestroyPayload {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            retention_policy_id: None,
            verification_stub_required: None,
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm destroy payload serialize: {err}")))
    }
}

impl ObjectLifecyclePayload {
    pub fn new(target_ref: impl Into<ObjectRef>) -> Self {
        Self {
            target_ref: target_ref.into(),
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|err| {
            WireError::Protocol(format!("object lifecycle payload serialize: {err}"))
        })
    }
}

#[cfg(test)]
mod object_lifecycle_tests {
    use serde_json::json;

    use super::ObjectLifecyclePayload;

    #[test]
    fn lifecycle_state_is_derived_from_event_kind() {
        let target_ref = "ak:strand:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let payload: ObjectLifecyclePayload = serde_json::from_value(json!({
            "target_ref": target_ref,
            "reason": "archived by owner"
        }))
        .unwrap();
        assert_eq!(payload.reason.as_deref(), Some("archived by owner"));
        assert_eq!(
            payload.to_value().unwrap(),
            json!({
                "target_ref": target_ref,
                "reason": "archived by owner"
            })
        );
        assert!(
            serde_json::from_value::<ObjectLifecyclePayload>(json!({
                "target_ref": target_ref,
                "target_state": "active"
            }))
            .is_err()
        );
    }
}

/// Scope-local history-access state-machine transition.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryAccessPayload {
    #[serde(default)]
    pub from: Option<HistoryAccess>,
    pub to: HistoryAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl HistoryAccessPayload {
    pub fn initialize(to: HistoryAccess) -> Self {
        Self {
            from: None,
            to,
            reason: None,
        }
    }

    pub fn tighten() -> Self {
        Self {
            from: Some(HistoryAccess::AllHistoryForCurrentMembers),
            to: HistoryAccess::SinceJoin,
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn validate(&self) -> Result<()> {
        match (&self.from, &self.to) {
            (None, _) => Ok(()),
            (Some(from), to) if from == to => Ok(()),
            (
                Some(HistoryAccess::AllHistoryForCurrentMembers),
                HistoryAccess::SinceJoin,
            ) => Ok(()),
            _ => Err(WireError::Protocol(
                "history_access permits only initialization or all_history_for_current_members to since_join"
                    .to_owned(),
            )),
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("history access payload serialize: {err}")))
    }
}

/// Circle-local history-access transition. Circle state is independent of the
/// parent Realm history-access state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleHistoryAccessPayload {
    pub circle_id: CircleId,
    #[serde(default)]
    pub from: Option<HistoryAccess>,
    pub to: HistoryAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl CircleHistoryAccessPayload {
    pub fn validate(&self) -> Result<()> {
        HistoryAccessPayload {
            from: self.from,
            to: self.to,
            reason: self.reason.clone(),
        }
        .validate()
    }
}

include!("generated/realm_lifecycle_contracts.rs");
