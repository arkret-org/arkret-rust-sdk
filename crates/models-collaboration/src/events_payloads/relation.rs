//! Relation event payloads.

use crate::internal_prelude::*;
use crate::objects::relation::{RelationConflictBaseline, RelationConflictDomain};

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(WireError::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationUpdatePayload {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub expected_state_digest: Option<Hash>,
    pub patch: Patch,
    pub relation_id: RelationId,
}

#[cfg(test)]
mod update_tests {
    use super::*;

    #[test]
    fn relation_update_requires_one_canonical_target_and_patch() {
        let canonical = serde_json::json!({
            "relation_id": "ak:relation:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml",
            "patch": {"fields.label": {"$op": "set", "value": "updated"}},
            "expected_state_digest": format!("sha256:{}", "1".repeat(64)),
        });
        let parsed: RelationUpdatePayload = serde_json::from_value(canonical.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), canonical);
        for field in ["relation_id", "patch"] {
            let mut invalid = canonical.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<RelationUpdatePayload>(invalid).is_err());
        }
        for field in ["target_ref", "status"] {
            let mut invalid = canonical.clone();
            invalid[field] = canonical["relation_id"].clone();
            assert!(serde_json::from_value::<RelationUpdatePayload>(invalid).is_err());
        }
        let mut old_target = canonical.clone();
        old_target["target_ref"] = old_target
            .as_object_mut()
            .unwrap()
            .remove("relation_id")
            .unwrap();
        assert!(serde_json::from_value::<RelationUpdatePayload>(old_target).is_err());
        let mut null_guard = canonical.clone();
        null_guard["expected_state_digest"] = Value::Null;
        assert!(serde_json::from_value::<RelationUpdatePayload>(null_guard).is_err());
        let mut unguarded = canonical;
        unguarded
            .as_object_mut()
            .unwrap()
            .remove("expected_state_digest");
        assert!(serde_json::from_value::<RelationUpdatePayload>(unguarded).is_ok());
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_tombstone_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationTombstonePayload {
    pub relation_id: RelationId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationTombstonePayloadWire {
    relation_id: RelationId,
    reason: Option<NonEmptyString>,
}

impl RelationTombstonePayload {
    pub fn validate(&self) -> Result<()> {
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.chars().count() > 4096)
        {
            return schema_violation("relation tombstone reason exceeds 4096 characters");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RelationTombstonePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationTombstonePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            relation_id: wire.relation_id,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Closed outcome of one `ak.relation.resolve` Control Move.
///
/// There is deliberately no free-form `resolved_value`, no new endpoint and no
/// per-Relation patch: later content edits stay on `ak.relation.update` and
/// ending one Relation stays on `ak.relation.tombstone`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationResolveOutcome {
    /// Exactly one covered candidate head keeps producing an active edge. It
    /// keeps its original RelationId and the exact state that head determines.
    RetainCandidate { retained_event_id: EventId },
    /// No candidate in the covered group keeps producing an active edge. This
    /// voids only the candidates this Move covered: their facts stay auditable,
    /// no tombstoned or redacted object is revived, no capability changes, and
    /// a later lawful create under the same domain stays allowed.
    VoidAll,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelationResolveOutcomeKind {
    RetainCandidate,
    VoidAll,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationResolveOutcomeWire {
    kind: RelationResolveOutcomeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_event_id: Option<EventId>,
}

impl Serialize for RelationResolveOutcome {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match self {
            Self::RetainCandidate { retained_event_id } => RelationResolveOutcomeWire {
                kind: RelationResolveOutcomeKind::RetainCandidate,
                retained_event_id: Some(retained_event_id.clone()),
            },
            Self::VoidAll => RelationResolveOutcomeWire {
                kind: RelationResolveOutcomeKind::VoidAll,
                retained_event_id: None,
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelationResolveOutcome {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationResolveOutcomeWire::deserialize(deserializer)?;
        match (wire.kind, wire.retained_event_id) {
            (RelationResolveOutcomeKind::RetainCandidate, Some(retained_event_id)) => {
                Ok(Self::RetainCandidate { retained_event_id })
            }
            (RelationResolveOutcomeKind::VoidAll, None) => Ok(Self::VoidAll),
            (RelationResolveOutcomeKind::RetainCandidate, None) => Err(serde::de::Error::custom(
                "schema_violation: retain_candidate requires retained_event_id",
            )),
            (RelationResolveOutcomeKind::VoidAll, Some(_)) => Err(serde::de::Error::custom(
                "schema_violation: void_all must not name a retained candidate",
            )),
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_resolve_payload`.
///
/// The single registered carrier that settles one Relation primary conflict
/// domain. `conflict_domain` names the whole group and is the entire cell
/// subject; the Realm comes from the envelope, never from here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationResolvePayload {
    pub conflict_domain: RelationConflictDomain,
    pub baseline: RelationConflictBaseline,
    pub outcome: RelationResolveOutcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationResolvePayloadWire {
    conflict_domain: RelationConflictDomain,
    baseline: RelationConflictBaseline,
    outcome: RelationResolveOutcome,
}

impl RelationResolvePayload {
    pub fn validate(&self) -> Result<()> {
        self.conflict_domain.validate()?;
        self.baseline.validate()?;
        if let RelationResolveOutcome::RetainCandidate { retained_event_id } = &self.outcome
            && self.baseline.covers(retained_event_id) == Some(false)
        {
            return schema_violation(
                "retained candidate is not a member of this Move's own baseline",
            );
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RelationResolvePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationResolvePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            conflict_domain: wire.conflict_domain,
            baseline: wire.baseline,
            outcome: wire.outcome,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}
