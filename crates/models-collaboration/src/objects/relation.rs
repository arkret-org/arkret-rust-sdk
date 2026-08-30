//! Relation model and cardinality enforcement.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, CircleId, EventId, Hash, RealmId, ReasonCode, RelationId, RelationKind, RelationState,
    RelationTruthSourceClass, Result, SchemaId, ScopeRef, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RELATION_KIND_CONTAINS: &str = "contains";
pub const RELATION_KIND_WATCHES: &str = "watches";

/// A collaboration graph endpoint. Actors stay structured on the wire so
/// accounts with one signing principal at different Stations never collapse.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelationEndpoint {
    Object(#[serde(deserialize_with = "deserialize_relation_object_ref")] String),
    Actor(ActorId),
}

impl RelationEndpoint {
    pub fn as_object_ref(&self) -> Option<&str> {
        match self {
            Self::Object(value) => Some(value),
            Self::Actor(_) => None,
        }
    }

    pub fn as_actor_id(&self) -> Option<&ActorId> {
        match self {
            Self::Actor(value) => Some(value),
            Self::Object(_) => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Self::Object(value) = self {
            validate_relation_object_ref(value)?;
        }
        Ok(())
    }
}

impl From<ActorId> for RelationEndpoint {
    fn from(value: ActorId) -> Self {
        Self::Actor(value)
    }
}

impl From<String> for RelationEndpoint {
    fn from(value: String) -> Self {
        Self::Object(value)
    }
}

impl From<&str> for RelationEndpoint {
    fn from(value: &str) -> Self {
        Self::Object(value.to_owned())
    }
}

fn validate_relation_object_ref(value: &str) -> Result<()> {
    use arkret_wire::{
        ActorProfileId, BlobId, BlobRef, MessageId, MorphId, SpaceId, StrandId, ViewId,
    };
    let valid = RealmId::new(value).is_ok()
        || SpaceId::new(value).is_ok()
        || ActorProfileId::new(value).is_ok()
        || StrandId::new(value).is_ok()
        || MessageId::new(value).is_ok()
        || MorphId::new(value).is_ok()
        || RelationId::new(value).is_ok()
        || EventId::new(value).is_ok()
        || ViewId::new(value).is_ok()
        || BlobId::new(value).is_ok()
        || BlobRef::new(value).is_ok();
    if valid {
        Ok(())
    } else {
        Err(WireError::Protocol("relation object endpoint must be an allowed typed object reference; Actor endpoints require structured ActorId".to_owned()))
    }
}

fn deserialize_relation_object_ref<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    validate_relation_object_ref(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relation {
    pub schema: String,
    /// The object id.
    ///
    /// Absent on the create payload: this kind's registry `id_source` is
    /// `event_derived`, so the id is `from_event_id(&create.event_id)` and a
    /// payload copy would be a second, forgeable truth (spec
    /// `zh/models/common-fields.md` section 6.0). Present on every projected
    /// snapshot, where the receiver has already derived it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<RelationId>,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    pub relation_kind: RelationKind,
    pub from_ref: RelationEndpoint,
    pub to_ref: RelationEndpoint,
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
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
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
    RequireReview,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationConflictCandidate {
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RelationConflictCandidate {
    pub fn event_digest(&self) -> Hash {
        self.event_id.event_digest()
    }
}

fn relation_scope_is_default(value: &RelationScope) -> bool {
    *value == RelationScope::Realm
}

fn relation_conflict_policy_is_default(value: &RelationConflictPolicy) -> bool {
    *value == RelationConflictPolicy::RequireReview
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

pub fn relation_kind_is_structural(relation_kind: &str) -> bool {
    RelationKind::from_wire(relation_kind)
        .descriptor()
        .map(|metadata| !metadata.weak_semantic)
        .unwrap_or(false)
}

pub fn relation_direct_write_reject_reason(
    relation_kind: &str,
    from_ref: Option<&str>,
) -> Option<&'static str> {
    let relation_kind_value = RelationKind::from_wire(relation_kind);
    let metadata = relation_kind_value.descriptor()?;
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

impl Relation {
    pub const SCHEMA: &'static str = SchemaId::RELATION_V1;
    pub fn validate_endpoints(&self) -> Result<()> {
        self.from_ref.validate()?;
        self.to_ref.validate()?;
        if self.relation_kind == RelationKind::AssignedTo
            && (self.to_ref.as_actor_id().is_none()
                || !self
                    .from_ref
                    .as_object_ref()
                    .is_some_and(|value| value.starts_with("ak:strand:")))
        {
            return Err(WireError::Protocol(
                "assigned_to requires Strand -> ActorId endpoints".to_owned(),
            ));
        }
        if self.relation_kind == RelationKind::Watches && self.from_ref.as_actor_id().is_none() {
            return Err(WireError::Protocol(
                "watches requires an ActorId source endpoint".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_endpoint(station: &str) -> RelationEndpoint {
        ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:assignee.example").unwrap(),
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}")).unwrap(),
        ))
        .into()
    }

    #[test]
    fn same_principal_station_assignments_are_distinct_typed_endpoints() {
        let first = account_endpoint("station-a.example");
        let second = account_endpoint("station-b.example");
        let mut assignments = std::collections::BTreeSet::from([first.clone(), second.clone()]);
        assert_eq!(assignments.len(), 2);
        let json = serde_json::to_value(&first).unwrap();
        assert!(json.is_object());
        assert_eq!(
            serde_json::from_value::<RelationEndpoint>(json).unwrap(),
            first
        );
        assert!(assignments.remove(&first));
        assert_eq!(assignments, std::collections::BTreeSet::from([second]));
    }

    #[test]
    fn relation_actor_endpoint_rejects_principal_and_json_strings() {
        for value in [
            serde_json::json!("did:web:assignee.example"),
            serde_json::json!("ak:did_core:web:assignee.example"),
            serde_json::json!(
                serde_json::to_string(&account_endpoint("station-a.example")).unwrap()
            ),
            serde_json::json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:assignee.example"}}),
        ] {
            assert!(serde_json::from_value::<RelationEndpoint>(value).is_err());
        }
    }

    #[test]
    fn relation_query_preserves_actor_station_endpoint() {
        let query = crate::objects::queries::RelationQuery {
            kind: RelationKind::AssignedTo,
            direction: arkret_wire::RelationDirection::Out,
            source_ref: Some("ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4".into()),
            target_ref: Some(account_endpoint("station-a.example")),
            depth: None,
        };
        query.validate_endpoints().unwrap();
        let value = serde_json::to_value(&query).unwrap();
        assert!(value["source_ref"].is_string());
        assert_eq!(
            value["target_ref"]["account_id"]["station_id"],
            "ak:did_core:web:station-a.example"
        );
    }

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
            on_conflict: RelationConflictPolicy::RequireReview,
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
        assert_eq!(minimal.on_conflict, RelationConflictPolicy::RequireReview);
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
            to_kind: Some("actor".to_owned()),
            relation_scope: RelationScope::Board,
            cardinality: RelationCardinality::ManyToOne,
            dedupe_key: vec!["board_space_id".to_owned(), "from_ref".to_owned()],
            max_to_per_from: Some(1),
            max_from_per_to: Some(8),
            multi_edge: true,
            rank_field: Some("rank".to_owned()),
            on_conflict: RelationConflictPolicy::Reject,
        };
        let value = serde_json::to_value(&complete).unwrap();
        assert_eq!(value["relation_scope"], "board");
        assert_eq!(value["cardinality"], "many_to_one");
        assert_eq!(value["on_conflict"], "reject");
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
            "to_kind": "actor",
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
    fn relation_cardinality_parses_registry_defaults_without_guessing_special_classes() {
        assert_eq!(
            RelationCardinality::from_registry_value(
                RelationKind::from_wire("belongs_to")
                    .descriptor()
                    .unwrap()
                    .default_cardinality
            ),
            Some(RelationCardinality::ManyToOne)
        );
        assert_eq!(
            RelationCardinality::from_registry_value(
                RelationKind::from_wire("contains")
                    .descriptor()
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
