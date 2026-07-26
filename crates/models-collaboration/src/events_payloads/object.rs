//! Generic object creation, snapshots, and stage payloads.

use crate::internal_prelude::*;

/// Generic create-event payload used by Realm / Space / Strand / Morph creates.
///
/// The concrete object type is schema-specific, but the event payload envelope
/// is shared: `{ "object": ... }` plus optional initial relations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectCreatePayload<T> {
    pub object: T,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_relations: Vec<BTreeMap<String, Value>>,
}

impl<T> ObjectCreatePayload<T> {
    pub fn new(object: T) -> Self {
        Self {
            object,
            initial_relations: Vec::new(),
        }
    }

    pub fn with_initial_relation(mut self, relation: BTreeMap<String, Value>) -> Self {
        self.initial_relations.push(relation);
        self
    }
}

impl<T: Serialize> ObjectCreatePayload<T> {
    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("object create payload serialize: {err}")))
    }
}

// `object_lifecycle_payload` now has a strong type:
// `models::operation_payloads::ObjectLifecyclePayload` (generic Strand / Circle /
// Morph archive·restore·tombstone shape, single-sourced by `target_ref`;
// `additionalProperties:false`).

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectSnapshot {
    pub id: ObjectRef,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectStageSetPayload {
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
