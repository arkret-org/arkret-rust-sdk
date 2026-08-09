//! Generic object creation, snapshots, and stage payloads.

use crate::internal_prelude::*;

/// Wire object types admissible as the `payload.object` of a create Event.
///
/// Every create payload validates its `object` against a **closed** object
/// schema (`realm.schema.json`, `space.schema.json`, …). A hand-built
/// [`serde_json::Value`] map satisfies no such schema at authoring time: any
/// member at all can be inserted, and the first thing that notices is the
/// receiver rejecting the whole Event. This trait is the compile-time gate
/// that keeps that class of defect out of the authoring path.
///
/// Implement it **only** for the concrete counterpart of a closed object
/// schema. It MUST NOT be implemented for [`serde_json::Value`],
/// `BTreeMap<String, Value>`, or any other open container — doing so
/// reintroduces the untyped authoring path this bound exists to remove.
pub trait ProtocolCreateObject: Serialize {}

/// Declare the closed set of wire objects that may be carried by
/// [`ObjectCreatePayload`].
macro_rules! impl_protocol_create_object {
    ($($ty:ty),+ $(,)?) => {
        $(impl ProtocolCreateObject for $ty {})+
    };
}

impl_protocol_create_object!(ActorProfile, Circle, Morph, Realm, Space);

/// Generic create-event payload used by Realm / Space / Strand / Morph creates.
///
/// The concrete object type is schema-specific, but the event payload envelope
/// is shared: `{ "object": ... }` plus optional initial relations. `T` is
/// bounded by [`ProtocolCreateObject`], so the envelope cannot be used to smuggle
/// an untyped object through an otherwise typed-looking call site.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectCreatePayload<T: ProtocolCreateObject> {
    pub object: T,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_relations: Vec<BTreeMap<String, Value>>,
}

impl<T: ProtocolCreateObject> ObjectCreatePayload<T> {
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
