//! Shared event signature material.

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/signature_material`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignatureMaterial {
    NonEmptyString(NonEmptyString),
    Variant1(BTreeMap<String, Value>),
}
