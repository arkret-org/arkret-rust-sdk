//! Space event payloads.

use crate::internal_prelude::*;
use crate::serde_absence::deserialize_non_null_optional;

impl SpaceCreatePayload {
    pub fn new(object: Space) -> Self {
        Self { object }
    }

    /// Serialize the create payload, first re-checking the Space invariants
    /// (`kind` / `title` non-empty, bounded `labels`, `fields.max_active_strand_count`).
    pub fn to_value(&self) -> Result<Value> {
        self.object.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("space create payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "SpacePatchPayloadWire")]
pub struct SpacePatchPayload {
    pub space_id: SpaceId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpacePatchPayloadWire {
    space_id: SpaceId,
    patch: Patch,
    #[serde(default, deserialize_with = "deserialize_non_null_optional")]
    expected_state_digest: Option<Hash>,
}

impl TryFrom<SpacePatchPayloadWire> for SpacePatchPayload {
    type Error = WireError;
    fn try_from(value: SpacePatchPayloadWire) -> Result<Self> {
        let payload = Self {
            space_id: value.space_id,
            patch: value.patch,
            expected_state_digest: value.expected_state_digest,
        };
        payload.validate()?;
        Ok(payload)
    }
}

impl SpacePatchPayload {
    pub fn validate(&self) -> Result<()> {
        validate_patch_semantic_safety(&self.patch)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(|error| WireError::Protocol(error.to_string()))
    }
}

include!("generated/space_contracts.rs");
