//! Relation model and cardinality enforcement.

use std::collections::BTreeMap;

use arkret_wire::{
    CircleId, Did, Error, RealmId, ReasonCode, RelationId, RelationKind, RelationState,
    RelationTruthSourceClass, Result, ScopeRef, standard_relation_kind_metadata,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RELATION_KIND_CONTAINS: &str = "contains";
pub const RELATION_KIND_BELONGS_TO: &str = "belongs_to";
pub const RELATION_KIND_WATCHES: &str = "watches";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relation {
    pub schema: String,
    pub id: RelationId,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
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
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Relation cardinality declared by a `RelationProfile` (data-structures.md
/// §relation-profile).
///
/// Resolvers MUST refuse a `ak.relation.create` event whose
/// `(from, relation_kind, to)` tuple would violate the declared
/// cardinality of its profile.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationCardinality {
    /// At most one `to` per `from` and at most one `from` per `to`.
    OneToOne,
    /// One `from` may map to many `to` values; each `to` MUST have at
    /// most one `from`.
    OneToMany,
    /// One `to` may receive many `from` values; each `from` MUST have at
    /// most one `to`.
    ManyToOne,
    /// Unrestricted: many-to-many.
    ManyToMany,
}

impl RelationCardinality {
    /// Parse one of the four closed cardinality values used by
    /// `relation-kind-registry.json`.
    pub fn from_registry_value(value: &str) -> Option<Self> {
        match value {
            "one_to_one" => Some(Self::OneToOne),
            "one_to_many" => Some(Self::OneToMany),
            "many_to_one" => Some(Self::ManyToOne),
            "many_to_many" => Some(Self::ManyToMany),
            _ => None,
        }
    }
}

/// Scope used to calculate Relation cardinality and deduplication keys.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationScope {
    #[default]
    Realm,
    Space,
    Board,
    Global,
}

/// Conflict handling for mutually unreachable Relation candidates.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationConflictPolicy {
    Reject,
    ClosePrevious,
    #[default]
    DeterministicWinner,
    RequireReview,
}

fn relation_scope_is_default(value: &RelationScope) -> bool {
    *value == RelationScope::Realm
}

fn relation_conflict_policy_is_default(value: &RelationConflictPolicy) -> bool {
    *value == RelationConflictPolicy::DeterministicWinner
}

fn bool_is_false(value: &bool) -> bool {
    !*value
}

/// Realm `relation_profiles` row that constrains a `relation_kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationProfile {
    pub relation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_kind: Option<String>,
    #[serde(default, skip_serializing_if = "relation_scope_is_default")]
    pub relation_scope: RelationScope,
    pub cardinality: RelationCardinality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dedupe_key: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_to_per_from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_from_per_to: Option<u64>,
    #[serde(default, skip_serializing_if = "bool_is_false")]
    pub multi_edge: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank_field: Option<String>,
    #[serde(default, skip_serializing_if = "relation_conflict_policy_is_default")]
    pub on_conflict: RelationConflictPolicy,
}

impl RelationProfile {
    /// Validate the normative `cardinality` / `max_*` consistency matrix.
    pub fn validate_cardinality_consistency(&self) -> std::result::Result<(), ReasonCode> {
        validate_relation_profile_cardinality_consistency(self)
    }
}

/// Validate a RelationProfile before registration or update.
///
/// Every failure maps directly to the normative
/// `relation_profile_cardinality_conflict` reason code.
pub fn validate_relation_profile_cardinality_consistency(
    profile: &RelationProfile,
) -> std::result::Result<(), ReasonCode> {
    let max_to_per_from = profile.max_to_per_from;
    let max_from_per_to = profile.max_from_per_to;
    let has_zero_bound = max_to_per_from == Some(0) || max_from_per_to == Some(0);
    let contradicts_cardinality = match profile.cardinality {
        RelationCardinality::OneToOne => {
            max_to_per_from.is_some_and(|value| value > 1)
                || max_from_per_to.is_some_and(|value| value > 1)
        }
        RelationCardinality::OneToMany => max_from_per_to.is_some_and(|value| value > 1),
        RelationCardinality::ManyToOne => max_to_per_from.is_some_and(|value| value > 1),
        RelationCardinality::ManyToMany => false,
    };

    if has_zero_bound || contradicts_cardinality {
        Err(ReasonCode::RelationProfileCardinalityConflict)
    } else {
        Ok(())
    }
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
        return Some(ReasonCode::RELATION_KIND_WATCHES_DERIVED);
    }
    if relation_kind == RELATION_KIND_CONTAINS
        && from_ref.is_some_and(|value| value.starts_with("ak:space:"))
    {
        return Some(ReasonCode::RELATION_KIND_CONTAINS_DERIVED);
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
        Err(ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
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
/// - `ManyToOne` — many `from` per `to` are fine, but each `from` MUST have at most one `to`.
/// - `ManyToMany` — always permitted.
///
/// Explicit `max_to_per_from` and `max_from_per_to` bounds further tighten
/// these base rules. Callers must resolve `relation_scope` before selecting
/// the `existing` slice.
pub fn enforce_relation_cardinality(
    profile: &RelationProfile,
    candidate: RelationEdgeRef<'_>,
    existing: &[RelationEdgeRef<'_>],
) -> Result<()> {
    if candidate.relation_kind != profile.relation_kind {
        return Ok(());
    }
    if let Err(reason) = profile.validate_cardinality_consistency() {
        return Err(Error::Protocol(reason.as_str().to_owned()));
    }

    let cardinality_max_to_per_from = match profile.cardinality {
        RelationCardinality::OneToOne | RelationCardinality::ManyToOne => Some(1),
        RelationCardinality::OneToMany | RelationCardinality::ManyToMany => None,
    };
    let cardinality_max_from_per_to = match profile.cardinality {
        RelationCardinality::OneToOne | RelationCardinality::OneToMany => Some(1),
        RelationCardinality::ManyToOne | RelationCardinality::ManyToMany => None,
    };
    let max_to_per_from = profile.max_to_per_from.or(cardinality_max_to_per_from);
    let max_from_per_to = profile.max_from_per_to.or(cardinality_max_from_per_to);

    if max_to_per_from.is_some_and(|limit| {
        existing
            .iter()
            .filter(|edge| {
                edge.relation_kind == candidate.relation_kind && edge.from == candidate.from
            })
            .count() as u64
            >= limit
    }) {
        return Err(Error::Protocol(format!(
            "relation_cardinality_violation: '{}' reached max_to_per_from for '{}'",
            candidate.relation_kind, candidate.from
        )));
    }
    if max_from_per_to.is_some_and(|limit| {
        existing
            .iter()
            .filter(|edge| edge.relation_kind == candidate.relation_kind && edge.to == candidate.to)
            .count() as u64
            >= limit
    }) {
        return Err(Error::Protocol(format!(
            "relation_cardinality_violation: '{}' reached max_from_per_to for '{}'",
            candidate.relation_kind, candidate.to
        )));
    }
    Ok(())
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

    fn profile(cardinality: RelationCardinality) -> RelationProfile {
        RelationProfile {
            relation_kind: "assigned_to".to_owned(),
            from_kind: None,
            to_kind: None,
            relation_scope: RelationScope::Realm,
            cardinality,
            dedupe_key: Vec::new(),
            max_to_per_from: None,
            max_from_per_to: None,
            multi_edge: false,
            rank_field: None,
            on_conflict: RelationConflictPolicy::DeterministicWinner,
        }
    }

    #[test]
    fn relation_profile_wire_shape_matches_spec_and_defaults() {
        let minimal: RelationProfile = serde_json::from_value(serde_json::json!({
            "relation_kind": "assigned_to",
            "cardinality": "many_to_many"
        }))
        .unwrap();
        assert_eq!(minimal.relation_scope, RelationScope::Realm);
        assert_eq!(
            minimal.on_conflict,
            RelationConflictPolicy::DeterministicWinner
        );
        assert!(!minimal.multi_edge);
        assert_eq!(
            serde_json::to_value(&minimal).unwrap(),
            serde_json::json!({
                "relation_kind": "assigned_to",
                "cardinality": "many_to_many"
            })
        );

        let complete = RelationProfile {
            relation_kind: "assigned_to".to_owned(),
            from_kind: Some("strand".to_owned()),
            to_kind: Some("did".to_owned()),
            relation_scope: RelationScope::Board,
            cardinality: RelationCardinality::ManyToOne,
            dedupe_key: vec!["board_space_id".to_owned(), "from_ref".to_owned()],
            max_to_per_from: Some(1),
            max_from_per_to: Some(8),
            multi_edge: true,
            rank_field: Some("rank".to_owned()),
            on_conflict: RelationConflictPolicy::RequireReview,
        };
        let value = serde_json::to_value(&complete).unwrap();
        assert_eq!(value["relation_scope"], "board");
        assert_eq!(value["cardinality"], "many_to_one");
        assert_eq!(value["on_conflict"], "require_review");
        assert_eq!(
            serde_json::from_value::<RelationProfile>(value).unwrap(),
            complete
        );
    }

    #[test]
    fn relation_profile_wire_shape_passes_embedded_realm_schema() {
        let registry = arkret_schema::schema_registry_from_embedded_spec_artifacts().unwrap();
        let value = serde_json::json!({
            "relation_kind": "assigned_to",
            "from_kind": "strand",
            "to_kind": "did",
            "relation_scope": "realm",
            "cardinality": "many_to_one",
            "dedupe_key": ["realm_id", "from_ref"],
            "max_to_per_from": 1,
            "max_from_per_to": 8,
            "multi_edge": false,
            "rank_field": "rank",
            "on_conflict": "reject"
        });
        registry
            .validate_value(
                "ak.schema.realm.v1#/properties/relation_profiles/items",
                &value,
            )
            .unwrap();

        let mut zero_bound = value;
        zero_bound["max_to_per_from"] = serde_json::json!(0);
        assert!(
            registry
                .validate_value(
                    "ak.schema.realm.v1#/properties/relation_profiles/items",
                    &zero_bound,
                )
                .is_err()
        );
    }

    #[test]
    fn relation_profile_cardinality_consistency_matches_normative_matrix() {
        for cardinality in [
            RelationCardinality::OneToOne,
            RelationCardinality::OneToMany,
            RelationCardinality::ManyToOne,
            RelationCardinality::ManyToMany,
        ] {
            assert!(
                profile(cardinality)
                    .validate_cardinality_consistency()
                    .is_ok()
            );
        }

        let mut one_to_one = profile(RelationCardinality::OneToOne);
        one_to_one.max_to_per_from = Some(2);
        assert_eq!(
            one_to_one.validate_cardinality_consistency(),
            Err(ReasonCode::RelationProfileCardinalityConflict)
        );

        let mut one_to_many = profile(RelationCardinality::OneToMany);
        one_to_many.max_to_per_from = Some(7);
        assert!(one_to_many.validate_cardinality_consistency().is_ok());
        one_to_many.max_from_per_to = Some(2);
        assert_eq!(
            one_to_many.validate_cardinality_consistency(),
            Err(ReasonCode::RelationProfileCardinalityConflict)
        );

        let mut many_to_one = profile(RelationCardinality::ManyToOne);
        many_to_one.max_from_per_to = Some(7);
        assert!(many_to_one.validate_cardinality_consistency().is_ok());
        many_to_one.max_to_per_from = Some(2);
        assert_eq!(
            many_to_one.validate_cardinality_consistency(),
            Err(ReasonCode::RelationProfileCardinalityConflict)
        );

        let mut many_to_many = profile(RelationCardinality::ManyToMany);
        many_to_many.max_to_per_from = Some(0);
        assert_eq!(
            many_to_many.validate_cardinality_consistency(),
            Err(ReasonCode::RelationProfileCardinalityConflict)
        );
        assert_eq!(
            ReasonCode::RelationProfileCardinalityConflict.as_str(),
            ReasonCode::RELATION_PROFILE_CARDINALITY_CONFLICT
        );
    }

    #[test]
    fn relation_cardinality_enforces_many_to_one_and_explicit_limits() {
        let existing = [RelationEdgeRef {
            from: "ak:strand:a",
            relation_kind: "assigned_to",
            to: "did:example:alice",
        }];
        let same_source = RelationEdgeRef {
            from: "ak:strand:a",
            relation_kind: "assigned_to",
            to: "did:example:bob",
        };
        let different_source = RelationEdgeRef {
            from: "ak:strand:b",
            relation_kind: "assigned_to",
            to: "did:example:alice",
        };

        let many_to_one = profile(RelationCardinality::ManyToOne);
        assert!(
            enforce_relation_cardinality(&many_to_one, same_source.clone(), &existing).is_err()
        );
        assert!(
            enforce_relation_cardinality(&many_to_one, different_source.clone(), &existing).is_ok()
        );

        let mut limited_many_to_many = profile(RelationCardinality::ManyToMany);
        limited_many_to_many.max_from_per_to = Some(1);
        assert!(
            enforce_relation_cardinality(&limited_many_to_many, different_source, &existing)
                .is_err()
        );
    }

    #[test]
    fn relation_cardinality_parses_registry_defaults_without_guessing_special_classes() {
        assert_eq!(
            RelationCardinality::from_registry_value(
                standard_relation_kind_metadata("belongs_to")
                    .unwrap()
                    .default_cardinality
            ),
            Some(RelationCardinality::ManyToOne)
        );
        assert_eq!(
            RelationCardinality::from_registry_value(
                standard_relation_kind_metadata("contains")
                    .unwrap()
                    .default_cardinality
            ),
            None
        );
        assert_eq!(
            RelationCardinality::from_registry_value("one_active_edge_per_pair"),
            None
        );
    }

    #[test]
    fn relation_direct_write_helper_rejects_derived_edges() {
        assert_eq!(
            validate_relation_direct_write(RELATION_KIND_WATCHES, Some("ak:strand:a")),
            Err(ReasonCode::RELATION_KIND_WATCHES_DERIVED)
        );
        assert_eq!(
            validate_relation_direct_write(RELATION_KIND_CONTAINS, Some("ak:space:a")),
            Err(ReasonCode::RELATION_KIND_CONTAINS_DERIVED)
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
            Err(ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
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
            Err(ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
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
}
