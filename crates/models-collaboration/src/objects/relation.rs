//! Relation model and cardinality enforcement.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, CircleId, EventId, RealmId, ReasonCode, RelationId, RelationKind, RelationState,
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

/// Closed authoring input for `ak.relation.create`.
///
/// Materialized object identity, Realm binding, effective scope, lifecycle,
/// and audit timestamps are reducer-owned and intentionally absent.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub relation_kind: RelationKind,
    pub from_ref: RelationEndpoint,
    pub to_ref: RelationEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
}

impl RelationDefinition {
    pub fn validate(&self) -> Result<()> {
        validate_relation_endpoints(&self.relation_kind, &self.from_ref, &self.to_ref)?;
        if self.fields.contains_key("rank") {
            return Err(WireError::Protocol(
                "schema_violation: Relation fields must not contain rank; use relation.rank"
                    .to_owned(),
            ));
        }
        if self.rank.as_ref().is_some_and(|rank| {
            rank.is_empty()
                || rank.len() > 128
                || !rank.bytes().all(|byte| byte.is_ascii_alphanumeric())
        }) {
            return Err(WireError::Protocol(
                "schema_violation: Relation rank must match ^[0-9A-Za-z]{1,128}$".to_owned(),
            ));
        }
        Ok(())
    }
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

/// The registered `primary_conflict_domain` of a directly writable Relation
/// shape. It is not producer-selectable: it comes from
/// `relation-kind-registry.json`, so one group can never be spelled two ways.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationPrimaryConflictDomainKind {
    Tuple,
    From,
}

impl RelationPrimaryConflictDomainKind {
    pub const fn as_registry_value(self) -> &'static str {
        match self {
            Self::Tuple => "tuple",
            Self::From => "from",
        }
    }
}

/// The unique typed-current-result subject for one directly writable Relation
/// domain.
///
/// The Realm is deliberately not a member: an Event takes it from its own
/// envelope and a read takes it from the request selector. A Circle is not a
/// component either — it authorizes reads, it does not partition the conflict
/// key, and admitting it would let a hidden candidate be excluded from the
/// group by moving it into another Circle.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelationPrimaryConflictDomain {
    pub domain_kind: RelationPrimaryConflictDomainKind,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub relation_kind: RelationKind,
    pub from_ref: RelationEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_ref: Option<RelationEndpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationPrimaryConflictDomainWire {
    domain_kind: RelationPrimaryConflictDomainKind,
    relation_kind: RelationKind,
    from_ref: RelationEndpoint,
    #[serde(default)]
    to_ref: Option<RelationEndpoint>,
}

impl<'de> Deserialize<'de> for RelationPrimaryConflictDomain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationPrimaryConflictDomainWire::deserialize(deserializer)?;
        Self::try_new(
            wire.domain_kind,
            wire.relation_kind,
            wire.from_ref,
            wire.to_ref,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl RelationPrimaryConflictDomain {
    pub fn try_new(
        domain_kind: RelationPrimaryConflictDomainKind,
        relation_kind: RelationKind,
        from_ref: RelationEndpoint,
        to_ref: Option<RelationEndpoint>,
    ) -> Result<Self> {
        let domain = Self {
            domain_kind,
            relation_kind,
            from_ref,
            to_ref,
        };
        domain.validate()?;
        Ok(domain)
    }

    pub fn validate(&self) -> Result<()> {
        self.from_ref.validate()?;
        if let Some(to_ref) = self.to_ref.as_ref() {
            to_ref.validate()?;
        }
        if self.relation_kind.as_str().is_empty() {
            return Err(WireError::Protocol(
                "schema_violation: relation primary conflict domain requires a relation_kind"
                    .to_owned(),
            ));
        }
        if let Some(reason) = relation_direct_write_reject_reason(
            self.relation_kind.as_str(),
            self.from_ref.as_object_ref(),
        ) {
            return Err(WireError::Protocol(format!("schema_violation: {reason}")));
        }
        if let Some(descriptor) = self.relation_kind.descriptor() {
            let Some(direct_domain) = descriptor.direct_write_primary_conflict_domain else {
                return Err(WireError::Protocol(format!(
                    "schema_violation: {} has no directly writable shape",
                    self.relation_kind.as_str()
                )));
            };
            if direct_domain != self.domain_kind.as_registry_value() {
                return Err(WireError::Protocol(format!(
                    "schema_violation: {} keys its primary conflict domain on {direct_domain}",
                    self.relation_kind.as_str()
                )));
            }
        }
        match (self.domain_kind, self.to_ref.is_some()) {
            (RelationPrimaryConflictDomainKind::Tuple, true)
            | (RelationPrimaryConflictDomainKind::From, false) => Ok(()),
            (RelationPrimaryConflictDomainKind::Tuple, false) => Err(WireError::Protocol(
                "schema_violation: a tuple primary conflict domain requires to_ref".to_owned(),
            )),
            (RelationPrimaryConflictDomainKind::From, true) => Err(WireError::Protocol(
                "schema_violation: a from primary conflict domain must not carry to_ref".to_owned(),
            )),
        }
    }

    /// Verify that this signed selector is the only canonical subject for the
    /// Relation value carried by a create Event.
    pub fn validate_for_definition(&self, relation: &RelationDefinition) -> Result<()> {
        self.validate()?;
        relation.validate()?;
        let identity_matches = self.relation_kind == relation.relation_kind
            && self.from_ref == relation.from_ref
            && match self.domain_kind {
                RelationPrimaryConflictDomainKind::Tuple => {
                    self.to_ref.as_ref() == Some(&relation.to_ref)
                }
                RelationPrimaryConflictDomainKind::From => self.to_ref.is_none(),
            };
        if !identity_matches {
            return Err(WireError::Protocol(
                "schema_violation: primary_conflict_domain must match the Relation's create-locked identity"
                    .to_owned(),
            ));
        }
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
        validate_relation_endpoints(&self.relation_kind, &self.from_ref, &self.to_ref)
    }
}

fn validate_relation_endpoints(
    relation_kind: &RelationKind,
    from_ref: &RelationEndpoint,
    to_ref: &RelationEndpoint,
) -> Result<()> {
    from_ref.validate()?;
    to_ref.validate()?;
    if *relation_kind == RelationKind::AssignedTo
        && (to_ref.as_actor_id().is_none()
            || !from_ref
                .as_object_ref()
                .is_some_and(|value| value.starts_with("ak:strand:")))
    {
        return Err(WireError::Protocol(
            "assigned_to requires Strand -> ActorId endpoints".to_owned(),
        ));
    }
    if *relation_kind == RelationKind::Watches && from_ref.as_actor_id().is_none() {
        return Err(WireError::Protocol(
            "watches requires an ActorId source endpoint".to_owned(),
        ));
    }
    Ok(())
}
