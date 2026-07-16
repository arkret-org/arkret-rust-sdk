//! Relation model and cardinality enforcement.

use super::*;

pub const RELATION_KIND_CONTAINS: &str = "contains";
pub const RELATION_KIND_BELONGS_TO: &str = "belongs_to";
pub const RELATION_KIND_WATCHES: &str = "watches";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Relation {
    pub schema: String,
    pub id: RelationId,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<EffectiveScope>,
    pub relation_kind: RelationKind,
    pub from_ref: String,
    pub to_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RelationState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Relation cardinality declared by a `RelationProfile` (data-structures.md
/// §relation-profile).
///
/// Resolvers MUST refuse a `ak.relation.create` event whose
/// `(from, relation_kind, to)` tuple would violate the declared
/// cardinality of its profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RelationCardinality {
    /// At most one `to` per `from` and at most one `from` per `to`.
    OneToOne,
    /// One `from` may map to many `to` values; each `to` MUST have at
    /// most one `from`.
    OneToMany,
    /// Unrestricted: many-to-many.
    ManyToMany,
}

/// Per-Space `relation_profile` row that constrains a `relation_kind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RelationProfile {
    pub relation_kind: String,
    pub cardinality: RelationCardinality,
    /// Optional schema-id for the profile body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

/// Convenience: `(from, relation_kind, to)` triple identifying a
/// candidate Relation row. Used by [`enforce_relation_cardinality`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelationEdgeRef<'a> {
    pub from: &'a str,
    pub relation_kind: &'a str,
    pub to: &'a str,
}

pub fn relation_kind_is_structural(relation_kind: &str) -> bool {
    standard_relation_kind_metadata(relation_kind)
        .map(|metadata| !metadata.weak_semantic)
        .unwrap_or(false)
}

pub fn relation_direct_write_reject_reason(
    relation_kind: &str,
    from_ref: Option<&str>,
) -> Option<&'static str> {
    let metadata = standard_relation_kind_metadata(relation_kind)?;
    if metadata.truth_source_class == RelationTruthSourceClass::DerivedProjection
        && relation_kind == RELATION_KIND_WATCHES
    {
        return Some(crate::error::ReasonCode::RELATION_KIND_WATCHES_DERIVED);
    }
    if relation_kind == RELATION_KIND_CONTAINS
        && from_ref.is_some_and(|value| value.starts_with("ak:space:"))
    {
        return Some(crate::error::ReasonCode::RELATION_KIND_CONTAINS_DERIVED);
    }
    None
}

pub fn validate_relation_direct_write(
    relation_kind: &str,
    from_ref: Option<&str>,
) -> std::result::Result<(), &'static str> {
    if let Some(reason) = relation_direct_write_reject_reason(relation_kind, from_ref) {
        Err(reason)
    } else {
        Ok(())
    }
}

pub fn validate_structural_relation_same_realm<'a, I>(
    relation_kind: &str,
    relation_realm: &str,
    endpoint_realms: I,
) -> std::result::Result<(), &'static str>
where
    I: IntoIterator<Item = &'a str>,
{
    if relation_kind_is_structural(relation_kind)
        && endpoint_realms
            .into_iter()
            .any(|endpoint_realm| endpoint_realm != relation_realm)
    {
        Err(crate::error::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
    } else {
        Ok(())
    }
}

/// Enforce the cardinality declared by the matching `RelationProfile`.
///
/// `existing` is the set of currently-active edges with the same
/// `relation_kind`. The function returns `Err(Error::Protocol("relation_cardinality_violation"))`
/// when the candidate edge would breach the cardinality rule.
///
/// Cardinality rules:
/// - `OneToOne` — a Space MAY contain at most one edge per `from` and per `to` for the given
///   `relation_kind`.
/// - `OneToMany` — many `to` per `from` are fine, but each `to` MUST have at most one `from`.
/// - `ManyToMany` — always permitted.
pub fn enforce_relation_cardinality(
    profile: &RelationProfile,
    candidate: RelationEdgeRef<'_>,
    existing: &[RelationEdgeRef<'_>],
) -> Result<()> {
    if candidate.relation_kind != profile.relation_kind {
        return Ok(());
    }
    match profile.cardinality {
        RelationCardinality::ManyToMany => Ok(()),
        RelationCardinality::OneToMany => {
            if existing.iter().any(|edge| {
                edge.relation_kind == candidate.relation_kind && edge.to == candidate.to
            }) {
                Err(Error::Protocol(format!(
                    "relation_cardinality_violation: '{}' is one_to_many but '{}' already has an inbound '{}' edge",
                    candidate.relation_kind, candidate.to, candidate.relation_kind
                )))
            } else {
                Ok(())
            }
        }
        RelationCardinality::OneToOne => {
            if existing.iter().any(|edge| {
                edge.relation_kind == candidate.relation_kind
                    && (edge.from == candidate.from || edge.to == candidate.to)
            }) {
                Err(Error::Protocol(format!(
                    "relation_cardinality_violation: '{}' is one_to_one but a conflicting edge already exists",
                    candidate.relation_kind
                )))
            } else {
                Ok(())
            }
        }
    }
}

impl Relation {
    pub fn validate_endpoints(&self) -> Result<()> {
        if self.from_ref.trim().is_empty() || self.to_ref.trim().is_empty() {
            Err(Error::Protocol(
                "relation requires non-empty from_ref and to_ref".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_direct_write_helper_rejects_derived_edges() {
        assert_eq!(
            validate_relation_direct_write(RELATION_KIND_WATCHES, Some("ak:strand:a")),
            Err(crate::error::ReasonCode::RELATION_KIND_WATCHES_DERIVED)
        );
        assert_eq!(
            validate_relation_direct_write(RELATION_KIND_CONTAINS, Some("ak:space:a")),
            Err(crate::error::ReasonCode::RELATION_KIND_CONTAINS_DERIVED)
        );
        assert!(
            validate_relation_direct_write(RELATION_KIND_CONTAINS, Some("ak:strand:a")).is_ok()
        );
        assert!(validate_relation_direct_write("references", Some("ak:space:a")).is_ok());
        assert!(validate_relation_direct_write("vendor_custom", Some("ak:space:a")).is_ok());
    }

    #[test]
    fn structural_relation_helper_rejects_cross_realm_endpoints() {
        assert_eq!(
            validate_structural_relation_same_realm(
                RELATION_KIND_CONTAINS,
                "ak:realm:a",
                ["ak:realm:a", "ak:realm:b"],
            ),
            Err(crate::error::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
        );
        assert!(
            validate_structural_relation_same_realm(
                RELATION_KIND_BELONGS_TO,
                "ak:realm:a",
                ["ak:realm:a", "ak:realm:a"],
            )
            .is_ok()
        );
        assert!(
            validate_structural_relation_same_realm("references", "ak:realm:a", ["ak:realm:b"],)
                .is_ok()
        );
        assert_eq!(
            validate_structural_relation_same_realm(
                RELATION_KIND_WATCHES,
                "ak:realm:a",
                ["ak:realm:a", "ak:realm:b"],
            ),
            Err(crate::error::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
        );
        assert!(
            validate_structural_relation_same_realm("vendor_custom", "ak:realm:a", ["ak:realm:b"],)
                .is_ok()
        );
    }

    #[test]
    fn relation_kind_custom_round_trips_without_standard_semantics() {
        let kind: RelationKind = serde_json::from_value(serde_json::json!("vendor_custom"))
            .expect("custom relation kind must deserialize");
        assert_eq!(kind.as_str(), "vendor_custom");
        assert!(!kind.is_standard());
        assert!(!kind.is_structural());
        assert_eq!(
            serde_json::to_value(&kind).unwrap(),
            serde_json::json!("vendor_custom")
        );
    }

    #[test]
    fn standard_relation_kind_metadata_matches_embedded_registry() {
        let registry =
            crate::schema::embedded_json_artifact("registry/relation-kind-registry.json")
                .expect("embedded relation registry");
        let relation_kinds = registry["relation_kinds"]
            .as_array()
            .expect("relation_kinds array");
        let registry_ids: Vec<&str> = relation_kinds
            .iter()
            .map(|row| row["canonical_id"].as_str().expect("canonical_id"))
            .collect();
        let sdk_ids: Vec<&str> = STANDARD_RELATION_KIND_METADATA
            .iter()
            .map(|metadata| metadata.canonical_id)
            .collect();
        assert_eq!(sdk_ids, registry_ids);

        for row in relation_kinds {
            let id = row["canonical_id"].as_str().expect("canonical_id");
            let metadata = standard_relation_kind_metadata(id).expect("SDK metadata row");
            assert_eq!(
                metadata.default_cardinality,
                row["default_cardinality"]
                    .as_str()
                    .expect("default_cardinality")
            );
            assert_eq!(
                metadata.truth_source_class,
                match row["truth_source_class"]
                    .as_str()
                    .expect("truth_source_class")
                {
                    "canonical" => RelationTruthSourceClass::Canonical,
                    "derived_projection" => RelationTruthSourceClass::DerivedProjection,
                    "shape_dependent" => RelationTruthSourceClass::ShapeDependent,
                    other => panic!("unexpected truth_source_class: {other}"),
                }
            );
            assert_eq!(
                metadata.weak_semantic,
                row["weak_semantic"].as_bool().expect("weak_semantic")
            );
        }
    }
}
