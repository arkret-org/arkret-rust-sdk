use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::serialize_optional_canonical_timestamp;
use crate::*;

/// Strong type for `ak.realm.archive` payloads
/// (`event-payload.schema.json#/$defs/realm_archive_payload`).
///
/// Reversible boolean register (there is no separate `ak.realm.restore`):
/// `archived:false` un-archives. `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmArchivePayload {
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Canonical `Z`-suffixed timestamp; the reducer treats absence as "now".
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl RealmArchivePayload {
    pub fn new(archived: bool) -> Self {
        Self {
            archived,
            reason: None,
            effective_at: None,
        }
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
            .map_err(|err| Error::Protocol(format!("realm archive payload serialize: {err}")))
    }
}

/// Strong type for `ak.realm.tombstone` payloads
/// (`event-payload.schema.json#/$defs/realm_tombstone_payload`).
///
/// Terminal lifecycle event pointing at a successor Realm. `reason` and
/// `successor_realm_id` are both required by spec; callers without a successor
/// must use [`RealmDestroyPayload`] instead. `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmTombstonePayload {
    pub reason: String,
    pub successor_realm_id: RealmId,
    /// Optional `event_ref` (`^ak:event:` typed id) of the replacing event;
    /// carried as a bare string per the spec wire shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_event: Option<ObjectRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl RealmTombstonePayload {
    pub fn new(successor_realm_id: RealmId, reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            successor_realm_id,
            replacement_event: None,
            effective_at: None,
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("realm tombstone payload serialize: {err}")))
    }
}

/// Strong type for `ak.realm.destroy` payloads
/// (`event-payload.schema.json#/$defs/realm_destroy_payload`).
///
/// Terminal lifecycle event with no successor. `reason` is required;
/// `verification_stub_required` defaults to `true` (omitted on the wire when
/// unset so the reducer applies its default). `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmDestroyPayload {
    pub reason: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional retention-policy `object_ref` (bare string per spec wire shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_stub_required: Option<bool>,
}

impl RealmDestroyPayload {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            effective_at: None,
            retention_policy_id: None,
            verification_stub_required: None,
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("realm destroy payload serialize: {err}")))
    }
}

/// Strong type for `object_lifecycle_payload`
/// (`event-payload.schema.json#/$defs/object_lifecycle_payload`).
///
/// Generic archive / restore / tombstone-style payload for Strand, Circle, and
/// Morph lifecycle events (e.g. `ak.strand.archive` / `ak.strand.restore`). The
/// target object is single-sourced by `target_ref`. Required: `target_ref`.
/// `additionalProperties:false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ObjectLifecyclePayload {
    pub target_ref: ObjectRef,
    /// Intended lifecycle result (e.g. `archived` / `active`); descriptive
    /// only — it cannot replace `target_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ObjectLifecyclePayload {
    pub fn new(target_ref: impl Into<ObjectRef>) -> Self {
        Self {
            target_ref: target_ref.into(),
            target_state: None,
            reason: None,
            effective_at: None,
        }
    }

    pub fn with_target_state(mut self, target_state: impl Into<String>) -> Self {
        self.target_state = Some(target_state.into());
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("object lifecycle payload serialize: {err}")))
    }
}

/// Strong type for `ak.realm.history_visibility` payloads
/// (`event-payload.schema.json#/$defs/history_visibility_payload`).
///
/// `{ value, restricted_policy_digest?, reason? }`, `additionalProperties
/// :false`. Per the schema `allOf`, `restricted_policy_digest` is required
/// when `value == restricted`; [`HistoryVisibilityPayload::to_value`] enforces
/// that conditional.
///
/// The event-payload validator resolves `ak.realm.history_visibility` to this
/// named schema def, so producers and validators share the same fail-closed
/// shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct HistoryVisibilityPayload {
    pub value: HistoryVisibility,
    /// Digest of the effective `ak.realm.history_sharing_policy` value;
    /// required when `value == restricted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted_policy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl HistoryVisibilityPayload {
    pub fn new(value: HistoryVisibility) -> Self {
        Self {
            value,
            restricted_policy_digest: None,
            reason: None,
        }
    }

    /// Build a `restricted` payload with its mandatory policy digest.
    pub fn restricted(restricted_policy_digest: impl Into<String>) -> Self {
        Self {
            value: HistoryVisibility::Restricted,
            restricted_policy_digest: Some(restricted_policy_digest.into()),
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        if self.value == HistoryVisibility::Restricted && self.restricted_policy_digest.is_none() {
            return Err(Error::Protocol(
                "history_visibility=restricted requires restricted_policy_digest".to_owned(),
            ));
        }
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("history visibility payload serialize: {err}")))
    }
}
