//! Relation event payloads.

use crate::internal_prelude::*;
use crate::objects::relation::{RelationDefinition, RelationPrimaryConflictDomain};

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(WireError::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

fn relation_update_path_allowed(path: &str) -> bool {
    ["scope_circle_id", "rank", "fields"]
        .iter()
        .any(|root| path == *root || path.starts_with(&format!("{root}.")))
}

fn deserialize_required_nullable_revision<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<CurrentRevision>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CurrentRevision>::deserialize(deserializer)
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_create_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationCreatePayload {
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
    /// `null` is permitted only when the domain has never been written. A
    /// tombstoned domain must name that tombstone's exact revision.
    pub expected_revision: Option<CurrentRevision>,
    /// The closed six-field authoring definition. Materialized Relation
    /// identity, Realm, lifecycle, scope projection, and audit fields are
    /// reducer-owned and cannot be supplied here.
    pub relation: RelationDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationCreatePayloadWire {
    primary_conflict_domain: RelationPrimaryConflictDomain,
    #[serde(deserialize_with = "deserialize_required_nullable_revision")]
    expected_revision: Option<CurrentRevision>,
    relation: RelationDefinition,
}

impl RelationCreatePayload {
    pub fn try_new(
        primary_conflict_domain: RelationPrimaryConflictDomain,
        expected_revision: Option<CurrentRevision>,
        relation: RelationDefinition,
    ) -> Result<Self> {
        let payload = Self {
            primary_conflict_domain,
            expected_revision,
            relation,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("relation create payload serialize: {err}")))
    }

    pub fn validate(&self) -> Result<()> {
        self.primary_conflict_domain
            .validate_for_definition(&self.relation)
    }
}

impl<'de> Deserialize<'de> for RelationCreatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationCreatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            primary_conflict_domain: wire.primary_conflict_domain,
            expected_revision: wire.expected_revision,
            relation: wire.relation,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationUpdatePayload {
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
    pub expected_revision: CurrentRevision,
    pub patch: Patch,
    pub relation_id: RelationId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationUpdatePayloadWire {
    primary_conflict_domain: RelationPrimaryConflictDomain,
    expected_revision: CurrentRevision,
    patch: Patch,
    relation_id: RelationId,
}

impl RelationUpdatePayload {
    pub fn validate(&self) -> Result<()> {
        self.primary_conflict_domain.validate()?;
        self.patch.validate()?;
        if let Some(path) = self
            .patch
            .iter()
            .map(|(path, _)| path.as_str())
            .find(|path| !relation_update_path_allowed(path))
        {
            return schema_violation(format!(
                "Relation identity is create-locked; update path '{path}' is not one of scope_circle_id, rank, or fields"
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RelationUpdatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationUpdatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            primary_conflict_domain: wire.primary_conflict_domain,
            expected_revision: wire.expected_revision,
            patch: wire.patch,
            relation_id: wire.relation_id,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_tombstone_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationTombstonePayload {
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
    pub expected_revision: CurrentRevision,
    pub relation_id: RelationId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationTombstonePayloadWire {
    primary_conflict_domain: RelationPrimaryConflictDomain,
    expected_revision: CurrentRevision,
    relation_id: RelationId,
    reason: Option<NonEmptyString>,
}

impl RelationTombstonePayload {
    pub fn validate(&self) -> Result<()> {
        self.primary_conflict_domain.validate()?;
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
            primary_conflict_domain: wire.primary_conflict_domain,
            expected_revision: wire.expected_revision,
            relation_id: wire.relation_id,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn domain() -> Value {
        json!({
            "domain_kind": "tuple",
            "relation_kind": "references",
            "from_ref": "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
            "to_ref": "ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
        })
    }

    fn revision() -> Value {
        json!({
            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position": 41
        })
    }

    fn create_payload() -> Value {
        json!({
            "primary_conflict_domain": domain(),
            "expected_revision": null,
            "relation": {
                "relation_kind": "references",
                "from_ref": "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref": "ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
                "rank": "U",
                "fields": {"note": "author supplied"}
            }
        })
    }

    #[test]
    fn create_requires_nullable_revision_and_exact_primary_domain() {
        let payload: RelationCreatePayload = serde_json::from_value(create_payload()).unwrap();
        assert!(payload.expected_revision.is_none());
        assert!(payload.validate().is_ok());

        let mut missing_revision = create_payload();
        missing_revision
            .as_object_mut()
            .unwrap()
            .remove("expected_revision");
        assert!(serde_json::from_value::<RelationCreatePayload>(missing_revision).is_err());

        let mut mismatched = create_payload();
        mismatched["primary_conflict_domain"]["to_ref"] =
            json!("ak:strand:AYssTU1DU5poM_8XwT7XvjgAOgjLTIDKpPjK0QpjGYeC");
        assert!(serde_json::from_value::<RelationCreatePayload>(mismatched).is_err());

        let mut top_level_rank = create_payload();
        top_level_rank["rank"] = json!("V");
        assert!(serde_json::from_value::<RelationCreatePayload>(top_level_rank).is_err());

        for field in [
            "schema",
            "realm_id",
            "id",
            "effective_scope",
            "state",
            "state_changed_at",
            "created_by",
            "created_at",
            "updated_by",
            "updated_at",
        ] {
            let mut materialized = create_payload();
            materialized["relation"][field] = json!("forbidden");
            assert!(
                serde_json::from_value::<RelationCreatePayload>(materialized).is_err(),
                "materialized Relation field {field} must not be accepted as authoring input"
            );
        }

        for rank in [String::new(), "rank-with-dash".to_owned(), "A".repeat(129)] {
            let mut invalid_rank = create_payload();
            invalid_rank["relation"]["rank"] = json!(&rank);
            assert!(
                serde_json::from_value::<RelationCreatePayload>(invalid_rank).is_err(),
                "rank {rank:?} must fail the formal grammar"
            );
        }

        let mut nested_rank = create_payload();
        nested_rank["relation"]["fields"]["rank"] = json!("V");
        assert!(serde_json::from_value::<RelationCreatePayload>(nested_rank).is_err());
    }

    #[test]
    fn update_accepts_mutable_fields_and_rejects_identity_paths() {
        let valid = json!({
            "primary_conflict_domain": domain(),
            "expected_revision": revision(),
            "patch": {"fields.note": "updated"},
            "relation_id": "ak:relation:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
        });
        assert!(serde_json::from_value::<RelationUpdatePayload>(valid).is_ok());

        for path in ["relation_kind", "from_ref", "to_ref", "effective_scope"] {
            let invalid = json!({
                "primary_conflict_domain": domain(),
                "expected_revision": revision(),
                "patch": {(path): "forbidden"},
                "relation_id": "ak:relation:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
            });
            assert!(
                serde_json::from_value::<RelationUpdatePayload>(invalid).is_err(),
                "{path} must remain create-locked"
            );
        }
    }

    #[test]
    fn tombstone_requires_exact_revision() {
        let valid = json!({
            "primary_conflict_domain": domain(),
            "expected_revision": revision(),
            "relation_id": "ak:relation:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
        });
        assert!(serde_json::from_value::<RelationTombstonePayload>(valid).is_ok());

        let invalid = json!({
            "primary_conflict_domain": domain(),
            "relation_id": "ak:relation:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
        });
        assert!(serde_json::from_value::<RelationTombstonePayload>(invalid).is_err());
    }
}
