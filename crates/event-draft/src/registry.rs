//! Canonical event-draft kind registry.

use std::collections::BTreeMap;

use arkret_wire::constants::EVENT_SCHEMA;
use arkret_wire::events::kinds::EventKind;
use serde::{Deserialize, Serialize};

use crate::operation::OperationEnvelope;
use crate::{EventDraftError, Result};

/// Registry entry for one event draft kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraftKindSpec {
    pub kind: String,
    pub schema: String,
    #[serde(default)]
    pub required_content_fields: Vec<String>,
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

    /// Validate an operation envelope against registered semantic requirements.
    pub fn validate_envelope(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<EventDraftKindValidation> {
        let validation = self.canonicalize(&envelope.kind)?;
        let spec = self.specs.get(&validation.canonical_kind).ok_or_else(|| {
            EventDraftError::Protocol("event draft kind registry is inconsistent".to_owned())
        })?;
        let Some(payload) = envelope.payload.as_object() else {
            return Err(EventDraftError::Protocol(
                "operation envelope payload must be a JSON object".to_owned(),
            ));
        };
        for field in &spec.required_content_fields {
            if !payload.contains_key(field) {
                return Err(EventDraftError::Protocol(format!(
                    "event draft kind '{}' requires payload field '{}'",
                    spec.kind, field
                )));
            }
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
                schema: EVENT_SCHEMA.to_owned(),
                required_content_fields: required_fields_for_event_kind(kind.as_str()),
            });
        }
        registry
    }
}

/// Built-in required payload fields per event draft kind, mirroring the
/// event-payload schema catalog's structural minimums.
pub fn required_fields_for_event_kind(kind: &str) -> Vec<String> {
    match kind {
        EventKind::STRAND_CREATE => vec!["object".to_owned()],
        EventKind::STRAND_UPDATE => {
            vec!["target_ref".to_owned(), "patch".to_owned()]
        }
        EventKind::STRAND_ARCHIVE | EventKind::STRAND_RESTORE => {
            vec!["target_ref".to_owned()]
        }
        EventKind::STRAND_STAGE_SET => {
            vec!["strand_id".to_owned(), "stage".to_owned()]
        }
        EventKind::STRAND_MOVE => ["board_space_id", "strand_id", "target_space_id", "rank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        EventKind::STRAND_REORDER => ["board_space_id", "strand_id", "space_id", "rank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        EventKind::APPLET_REGISTRATION => {
            vec!["service_id".to_owned(), "namespace".to_owned()]
        }
        EventKind::APPLET_DISCOVERY => {
            vec!["service_id".to_owned(), "manifest".to_owned()]
        }
        EventKind::APPLET_BRIDGE_ERROR => {
            vec!["session_id".to_owned(), "errcode".to_owned()]
        }
        EventKind::AGENT_KEY_AUTHORIZE => [
            "agent_id",
            "key_id",
            "verification_method",
            "accountable_principal_id",
            "agent_key_scope",
            "audience",
            "issued_at",
            "approval_evidence",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        EventKind::AGENT_KEY_REVOKE => ["agent_id", "key_id", "revoked_at", "revoked_by"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        EventKind::MORPH_CREATE => vec!["object".to_owned()],
        EventKind::MORPH_UPDATE => vec!["target_ref".to_owned(), "patch".to_owned()],
        EventKind::MORPH_ARCHIVE | EventKind::MORPH_RESTORE => {
            vec!["target_ref".to_owned()]
        }
        EventKind::MORPH_STAGE_SET => {
            vec!["morph_id".to_owned(), "stage".to_owned()]
        }
        // Space container event kinds. The container primary key is `space_id`
        // (matching `parent_space_id`).
        EventKind::SPACE_CREATE => vec!["object".to_owned()],
        EventKind::SPACE_UPDATE => vec!["space_id".to_owned(), "patch".to_owned()],
        EventKind::SPACE_PARENT => {
            vec!["space_id".to_owned(), "parent_space_id".to_owned()]
        }
        EventKind::SPACE_ARCHIVE | EventKind::SPACE_RESTORE | EventKind::SPACE_TOMBSTONE => {
            vec!["space_id".to_owned()]
        }
        EventKind::RELATION_CREATE => ["kind", "from_ref", "to_ref"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        EventKind::RELATION_UPDATE => {
            vec!["relation_id".to_owned(), "patch".to_owned()]
        }
        EventKind::RELATION_TOMBSTONE => vec!["relation_id".to_owned()],
        EventKind::CONTAINER_MOVE_ITEM => [
            "scope_container_id",
            "relation_kind",
            "object_ref",
            "to_container_id",
            "rank",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        EventKind::CONTAINER_REBALANCE => [
            "scope_container_id",
            "container_id",
            "relation_kind",
            "expected_state_digest",
            "assignments",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        EventKind::MESSAGE_CREATE => {
            vec!["strand_id".to_owned(), "track_name".to_owned()]
        }
        _ => Vec::new(),
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
