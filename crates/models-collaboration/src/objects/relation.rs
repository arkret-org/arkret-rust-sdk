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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

/// Projection-only evidence for one bounded set of concurrent Relation heads.
///
/// This value is never reducer input. Construction sorts by `event_id` and
/// rejects undersized, duplicate, or over-limit head sets. The server must
/// establish group completeness separately; this DTO cannot prove it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationConflictDiagnostic {
    pub dedupe_key: String,
    pub heads: Vec<RelationConflictCandidate>,
}

impl RelationConflictDiagnostic {
    pub const MAX_HEADS: usize = 16;

    pub fn try_new(dedupe_key: String, mut heads: Vec<RelationConflictCandidate>) -> Result<Self> {
        heads.sort_by(|left, right| left.event_id.cmp(&right.event_id));
        let diagnostic = Self { dedupe_key, heads };
        diagnostic.validate()?;
        Ok(diagnostic)
    }

    pub fn validate(&self) -> Result<()> {
        if self.heads.len() < 2 || self.heads.len() > Self::MAX_HEADS {
            return Err(WireError::Protocol(
                "relation conflict diagnostic must contain between 2 and 16 heads".to_owned(),
            ));
        }
        if self
            .heads
            .windows(2)
            .any(|pair| pair[0].event_id >= pair[1].event_id)
        {
            return Err(WireError::Protocol(
                "relation conflict diagnostic heads must be unique and sorted by event_id"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Compare against this diagnostic's head identities without accepting
    /// duplicates. This is a structural check, not acceptance, authorization,
    /// or proof that the server supplied the complete current group.
    pub fn validates_resolution_heads<'a, I>(&self, supplied: I) -> bool
    where
        I: IntoIterator<Item = &'a EventId>,
    {
        if self.validate().is_err() {
            return false;
        }
        let mut supplied_set = std::collections::BTreeSet::new();
        for event_id in supplied {
            if !supplied_set.insert(event_id) {
                return false;
            }
        }
        let current = self
            .heads
            .iter()
            .map(|candidate| &candidate.event_id)
            .collect::<std::collections::BTreeSet<_>>();
        supplied_set == current
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

    fn conflict_candidate(seed: u8) -> RelationConflictCandidate {
        RelationConflictCandidate {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]),
            reason: None,
        }
    }

    #[test]
    fn relation_conflict_diagnostic_sorts_and_requires_exact_resolution_heads() {
        let diagnostic = RelationConflictDiagnostic::try_new(
            "dedupe".to_owned(),
            vec![conflict_candidate(2), conflict_candidate(1)],
        )
        .unwrap();
        assert!(diagnostic.heads[0].event_id < diagnostic.heads[1].event_id);
        assert!(
            diagnostic.validates_resolution_heads(diagnostic.heads.iter().map(|h| &h.event_id))
        );
        assert!(!diagnostic.validates_resolution_heads([&diagnostic.heads[0].event_id]));
        assert!(!diagnostic.validates_resolution_heads([
            &diagnostic.heads[0].event_id,
            &diagnostic.heads[0].event_id,
            &diagnostic.heads[1].event_id,
        ]));
        let mut invalid = diagnostic.clone();
        invalid.heads.reverse();
        assert!(!invalid.validates_resolution_heads(diagnostic.heads.iter().map(|h| &h.event_id)));
    }

    #[test]
    fn relation_conflict_diagnostic_rejects_incomplete_duplicate_and_over_limit_heads() {
        assert!(
            RelationConflictDiagnostic::try_new("dedupe".to_owned(), vec![conflict_candidate(1)])
                .is_err()
        );
        assert!(
            RelationConflictDiagnostic::try_new(
                "dedupe".to_owned(),
                vec![conflict_candidate(1), conflict_candidate(1)]
            )
            .is_err()
        );
        assert!(
            RelationConflictDiagnostic::try_new(
                "dedupe".to_owned(),
                (0..=RelationConflictDiagnostic::MAX_HEADS)
                    .map(|seed| conflict_candidate(seed as u8))
                    .collect()
            )
            .is_err()
        );
    }
}
