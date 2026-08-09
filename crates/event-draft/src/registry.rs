//! Canonical event-draft kind registry.

use std::collections::BTreeMap;

use arkret_wire::SchemaId;
use arkret_wire::events::kinds::EventKind;
use serde::{Deserialize, Serialize};

use crate::operation::OperationEnvelope;
use crate::{EventDraftError, Result};

/// Registry entry for one event draft kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraftKindSpec {
    pub kind: String,
    pub schema: String,
}

/// Result of validating an event draft kind against the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraftKindValidation {
    pub canonical_kind: String,
}

/// Canonical event draft kind registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraftKindRegistry {
    specs: BTreeMap<String, EventDraftKindSpec>,
}

impl EventDraftKindRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            specs: BTreeMap::new(),
        }
    }

    /// Register one event draft kind.
    pub fn register(&mut self, spec: EventDraftKindSpec) {
        self.specs.insert(spec.kind.clone(), spec);
    }

    /// Return the spec for a canonical kind.
    pub fn spec(&self, kind: &str) -> Option<&EventDraftKindSpec> {
        self.specs.get(kind)
    }

    /// Resolve a canonical kind.
    pub fn canonicalize(&self, kind: &str) -> Result<EventDraftKindValidation> {
        if self.specs.contains_key(kind) {
            return Ok(EventDraftKindValidation {
                canonical_kind: kind.to_owned(),
            });
        }
        Err(EventDraftError::Protocol(format!(
            "unknown event draft kind '{kind}'"
        )))
    }

    /// Validate an operation envelope against the registered kind surface.
    ///
    /// Payload field requirements belong to the spec-backed payload schema
    /// catalog. Keeping a second hand-written field table here caused the two
    /// validators to drift.
    pub fn validate_envelope(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<EventDraftKindValidation> {
        let validation = self.canonicalize(envelope.kind.as_str())?;
        self.specs.get(&validation.canonical_kind).ok_or_else(|| {
            EventDraftError::Protocol("event draft kind registry is inconsistent".to_owned())
        })?;
        if !envelope.payload.is_object() {
            return Err(EventDraftError::Protocol(
                "operation envelope payload must be a JSON object".to_owned(),
            ));
        }
        Ok(validation)
    }

    /// Iterate registered canonical event draft kinds.
    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.specs.keys().map(String::as_str)
    }
}

impl Default for EventDraftKindRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        for kind in EventKind::ALL {
            registry.register(EventDraftKindSpec {
                kind: kind.as_str().to_owned(),
                schema: SchemaId::EVENT_V1.to_owned(),
            });
        }
        registry
    }
}

/// Operation registry conformance vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraftKindConformanceVector {
    pub input_kind: String,
    pub canonical_kind: String,
}

/// Conformance vectors for every registered event draft kind.
pub fn event_draft_kind_conformance_vectors() -> Vec<EventDraftKindConformanceVector> {
    EventKind::ALL
        .iter()
        .map(|kind| EventDraftKindConformanceVector {
            input_kind: kind.as_str().to_owned(),
            canonical_kind: kind.as_str().to_owned(),
        })
        .collect()
}
