//! Generic object-create payload envelope and strand patch payload.
//!
//! The `ak.strand.create` wire object (`StrandCreateObject`) stays in
//! the `arkret` umbrella until the strand collaboration-object module migrates.

use std::collections::BTreeMap;

use arkret_wire::{Error, Hash, Patch, Result, StrandId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// Payload for `ak.strand.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrandPatchPayload {
    pub target_ref: StrandId,
    pub patch: Patch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl StrandPatchPayload {
    pub fn for_strand(strand_id: StrandId, patch: Patch) -> Result<Self> {
        patch.validate()?;
        Ok(Self {
            target_ref: strand_id,
            patch,
            expected_state_digest: None,
        })
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("strand patch payload serialize: {err}")))
    }
}
