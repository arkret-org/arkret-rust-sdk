//! Generic object patch payload components.

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/patch.schema.json#/propertyNames`.
///
/// One to sixteen dot-separated snake_case segments; selector segments,
/// quoted identifiers and numeric array indexes are not part of v1
/// (`zh/models/event-and-patch.md` §4.2.1).
pub type PatchPath = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/patch.schema.json#/additionalProperties/oneOf/1/properties/$op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchOp {
    Set,
    Unset,
    Add,
    Remove,
}

/// Explicit op form of one patch entry, counterpart for
/// `spec/v1/artifacts/schemas/patch.schema.json#/additionalProperties/oneOf/1`.
///
/// `value` is required for `set` / `add` / `remove` and MUST be absent for
/// `unset`; that conditional is enforced by the schema, not by this type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    #[serde(rename = "$op")]
    pub op: PatchOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// One patch entry, counterpart for
/// `spec/v1/artifacts/schemas/patch.schema.json#/additionalProperties`.
///
/// The direct form is any JSON value except an object carrying a `$op`
/// discriminator, and is equivalent to `{"$op":"set","value":<value>}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PatchEntry {
    Operation(PatchOperation),
    Direct(Value),
}

/// Counterpart for `spec/v1/artifacts/schemas/patch.schema.json`, the canonical
/// `ak.schema.patch.v1` document embedded at `payload.patch` for non-create
/// updates.
pub type PatchDocument = BTreeMap<PatchPath, PatchEntry>;
