//! Space event payloads.

use crate::internal_prelude::*;
use crate::serde_absence::deserialize_non_null_optional;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreatePayload {
    pub object: Space,
}

impl SpaceCreatePayload {
    pub fn new(object: Space) -> Self {
        Self { object }
    }

    /// Serialize the create payload, first re-checking the Space invariants
    /// (`kind` / `title` non-empty, bounded `labels`, `fields.wip_limit`).
    pub fn to_value(&self) -> Result<Value> {
        self.object.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("space create payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_parent_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceParentPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    pub expected_parent_space_id: Option<SpaceId>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "SpacePatchPayloadWire")]
pub struct SpacePatchPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_scope_policy: Option<ChildScopePolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpacePatchPayloadWire {
    space_id: SpaceId,
    #[serde(default, deserialize_with = "deserialize_non_null_optional")]
    patch: Option<Patch>,
    #[serde(default, deserialize_with = "deserialize_non_null_optional")]
    expected_state_digest: Option<Hash>,
    #[serde(default, deserialize_with = "deserialize_non_null_optional")]
    child_scope_policy: Option<ChildScopePolicy>,
}

impl TryFrom<SpacePatchPayloadWire> for SpacePatchPayload {
    type Error = WireError;
    fn try_from(value: SpacePatchPayloadWire) -> Result<Self> {
        let payload = Self {
            space_id: value.space_id,
            patch: value.patch,
            expected_state_digest: value.expected_state_digest,
            child_scope_policy: value.child_scope_policy,
        };
        payload.validate()?;
        Ok(payload)
    }
}

impl SpacePatchPayload {
    pub fn validate(&self) -> Result<()> {
        if self.patch.is_none() && self.child_scope_policy.is_none() {
            return Err(WireError::Protocol(
                "Space update requires a metadata patch or child_scope_policy".to_owned(),
            ));
        }
        if let Some(patch) = &self.patch {
            validate_patch_semantic_safety(patch, PatchTargetKind::Verified("space"))?;
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(|error| WireError::Protocol(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn payload() -> Value {
        json!({"space_id": "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"})
    }

    #[test]
    fn typed_policy_only_update_omits_the_metadata_patch() {
        let mut value = payload();
        value["child_scope_policy"] = json!({"kind": "require_e2ee"});
        let typed: SpacePatchPayload = serde_json::from_value(value.clone()).unwrap();
        assert!(typed.patch.is_none());
        assert_eq!(
            typed.child_scope_policy,
            Some(ChildScopePolicy::RequireE2ee {})
        );
        assert_eq!(typed.to_value().unwrap(), value);
    }

    #[test]
    fn space_update_requires_an_effect_and_rejects_present_null() {
        assert!(serde_json::from_value::<SpacePatchPayload>(payload()).is_err());
        for field in ["patch", "child_scope_policy", "expected_state_digest"] {
            let mut value = payload();
            value["child_scope_policy"] = json!({"kind": "allow_any"});
            value[field] = Value::Null;
            assert!(serde_json::from_value::<SpacePatchPayload>(value).is_err());
        }
    }

    #[test]
    fn ordinary_metadata_patch_cannot_reach_security_or_identity_paths() {
        for field in [
            "child_scope_policy",
            "child_scope_policy.kind",
            "scope_circle_id",
            "realm_id",
            "id",
            "created_by",
            "created_at",
            "state",
            "parent_space_id",
        ] {
            let mut value = payload();
            value["patch"] = json!({field: "forbidden"});
            assert!(
                serde_json::from_value::<SpacePatchPayload>(value).is_err(),
                "{field}"
            );
        }
    }
}
