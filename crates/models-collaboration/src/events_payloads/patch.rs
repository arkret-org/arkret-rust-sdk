//! Generic object patch payload components.

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_operation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    #[serde(rename = "$op")]
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_path`.
pub type PatchPath = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_value`.
pub type PatchValue = BTreeMap<String, Value>;
