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
/// Resolvers MUST refuse a `ck.relation.create` event whose
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
    matches!(
        relation_kind,
        RELATION_KIND_CONTAINS | RELATION_KIND_BELONGS_TO
    )
}

pub fn relation_direct_write_reject_reason(
    relation_kind: &str,
    from_ref: Option<&str>,
) -> Option<&'static str> {
    match relation_kind {
        RELATION_KIND_WATCHES => Some(crate::error::REASON_RELATION_KIND_WATCHES_DERIVED),
        RELATION_KIND_CONTAINS if from_ref.is_some_and(|value| value.starts_with("ck:space:")) => {
            Some(crate::error::REASON_RELATION_KIND_CONTAINS_DERIVED)
        }
        _ => None,
    }
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
        Err(crate::error::REASON_CROSS_REALM_STRUCTURAL_RELATION)
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
            validate_relation_direct_write(RELATION_KIND_WATCHES, Some("ck:strand:a")),
            Err(crate::error::REASON_RELATION_KIND_WATCHES_DERIVED)
        );
        assert_eq!(
            validate_relation_direct_write(RELATION_KIND_CONTAINS, Some("ck:space:a")),
            Err(crate::error::REASON_RELATION_KIND_CONTAINS_DERIVED)
        );
        assert!(
            validate_relation_direct_write(RELATION_KIND_CONTAINS, Some("ck:strand:a")).is_ok()
        );
        assert!(validate_relation_direct_write("references", Some("ck:space:a")).is_ok());
    }

    #[test]
    fn structural_relation_helper_rejects_cross_realm_endpoints() {
        assert_eq!(
            validate_structural_relation_same_realm(
                RELATION_KIND_CONTAINS,
                "ck:realm:a",
                ["ck:realm:a", "ck:realm:b"],
            ),
            Err(crate::error::REASON_CROSS_REALM_STRUCTURAL_RELATION)
        );
        assert!(
            validate_structural_relation_same_realm(
                RELATION_KIND_BELONGS_TO,
                "ck:realm:a",
                ["ck:realm:a", "ck:realm:a"],
            )
            .is_ok()
        );
        assert!(
            validate_structural_relation_same_realm("references", "ck:realm:a", ["ck:realm:b"],)
                .is_ok()
        );
    }
}
