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
    /// Required and nullable. Explicit `null` is the one spelling of "no
    /// parent" on this payload, so the `space_parent` register stays total and
    /// an omitted member can never mean the root by accident. Never skipped on
    /// serialization, never defaulted on deserialization.
    pub parent_space_id: Option<SpaceId>,
    /// Required and nullable. It is a declared `pre_state` requirement on the
    /// `space_parent` family, not an optional compare-and-set: making it
    /// optional would give one Event kind two admission semantics selected by
    /// a member's presence.
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
            validate_patch_semantic_safety(patch)?;
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(|error| WireError::Protocol(error.to_string()))
    }
}
