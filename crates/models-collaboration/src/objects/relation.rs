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

/// The registered `primary_conflict_domain` of a directly writable Relation
/// shape. It is not producer-selectable: it comes from
/// `relation-kind-registry.json`, so one group can never be spelled two ways.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationConflictDomainKind {
    Tuple,
    From,
}

impl RelationConflictDomainKind {
    pub const fn as_registry_value(self) -> &'static str {
        match self {
            Self::Tuple => "tuple",
            Self::From => "from",
        }
    }
}

/// The single primary conflict domain a `require_review` group and its
/// `ak.relation.resolve` Control Move address.
///
/// The Realm is deliberately not a member: an Event takes it from its own
/// envelope and a read takes it from the request selector. A Circle is not a
/// component either — it authorizes reads, it does not partition the conflict
/// key, and admitting it would let a hidden candidate be excluded from the
/// group by moving it into another Circle.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelationConflictDomain {
    pub domain_kind: RelationConflictDomainKind,
    pub relation_kind: RelationKind,
    pub from_ref: RelationEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_ref: Option<RelationEndpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationConflictDomainWire {
    domain_kind: RelationConflictDomainKind,
    relation_kind: RelationKind,
    from_ref: RelationEndpoint,
    #[serde(default)]
    to_ref: Option<RelationEndpoint>,
}

impl<'de> Deserialize<'de> for RelationConflictDomain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationConflictDomainWire::deserialize(deserializer)?;
        Self::try_new(
            wire.domain_kind,
            wire.relation_kind,
            wire.from_ref,
            wire.to_ref,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl RelationConflictDomain {
    pub fn try_new(
        domain_kind: RelationConflictDomainKind,
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
                "schema_violation: relation conflict domain requires a relation_kind".to_owned(),
            ));
        }
        if let Some(reason) = relation_direct_write_reject_reason(
            self.relation_kind.as_str(),
            self.from_ref.as_object_ref(),
        ) {
            return Err(WireError::Protocol(format!("schema_violation: {reason}")));
        }
        if let Some(descriptor) = self.relation_kind.descriptor()
            && descriptor.primary_conflict_domain != self.domain_kind.as_registry_value()
        {
            return Err(WireError::Protocol(format!(
                "schema_violation: {} keys its primary conflict domain on {}",
                self.relation_kind.as_str(),
                descriptor.primary_conflict_domain
            )));
        }
        match (self.domain_kind, self.to_ref.is_some()) {
            (RelationConflictDomainKind::Tuple, true)
            | (RelationConflictDomainKind::From, false) => Ok(()),
            (RelationConflictDomainKind::Tuple, false) => Err(WireError::Protocol(
                "schema_violation: a tuple conflict domain requires to_ref".to_owned(),
            )),
            (RelationConflictDomainKind::From, true) => Err(WireError::Protocol(
                "schema_violation: a from conflict domain must not carry to_ref".to_owned(),
            )),
        }
    }
}

/// Domain separator of the per-page chain commitment (`relation.md` §6.3).
pub const RELATION_CONFLICT_PAGE_DOMAIN: &str = "ak-relation-conflict-page-v1\u{0}";

/// Domain separator of the complete-set commitment (`relation.md` §6.3).
pub const RELATION_CONFLICT_MEMBERS_DOMAIN: &str = "ak-relation-conflict-members-v1\u{0}";

/// Fixed v1 page size of the frozen repair material. Only the last page may
/// hold fewer members.
pub const RELATION_CONFLICT_MATERIAL_PAGE_SIZE: usize = 256;

/// Largest member set a baseline may still inline rather than commit to.
pub const RELATION_CONFLICT_INLINE_MEMBER_LIMIT: u64 = 64;

fn relation_conflict_digest(
    domain_separator: &str,
    preimage: &impl Serialize,
    suite: arkret_canonical::DigestSuite,
) -> Result<Hash> {
    let mut bytes = domain_separator.as_bytes().to_vec();
    bytes.extend_from_slice(&arkret_canonical::canonical_json_bytes(preimage)?);
    Hash::new(arkret_canonical::canonical_digest_with_suite(
        &bytes,
        suite.as_str(),
    )?)
    .map_err(WireError::from)
}

/// Canonical `page_digest(i)` of `relation.md` §6.3.
///
/// `prev_page_digest` is encoded as JSON `null` on page 0 rather than omitted,
/// so the first page cannot be re-encoded as some later page with a missing
/// predecessor.
pub fn relation_conflict_page_digest(
    realm_id: &RealmId,
    conflict_domain: &RelationConflictDomain,
    page_index: u64,
    prev_page_digest: Option<&Hash>,
    member_event_ids: &[EventId],
    suite: arkret_canonical::DigestSuite,
) -> Result<Hash> {
    conflict_domain.validate()?;
    validate_relation_conflict_members(member_event_ids, 1, RELATION_CONFLICT_MATERIAL_PAGE_SIZE)?;
    if (page_index == 0) != prev_page_digest.is_none() {
        return Err(WireError::Protocol(
            "relation conflict page 0 has no predecessor and every later page has one".to_owned(),
        ));
    }
    #[derive(Serialize)]
    struct Preimage<'a> {
        conflict_domain: &'a RelationConflictDomain,
        member_event_ids: &'a [EventId],
        page_index: u64,
        prev_page_digest: Option<&'a Hash>,
        realm_id: &'a RealmId,
    }
    relation_conflict_digest(
        RELATION_CONFLICT_PAGE_DOMAIN,
        &Preimage {
            conflict_domain,
            member_event_ids,
            page_index,
            prev_page_digest,
            realm_id,
        },
        suite,
    )
}

/// Canonical `members_digest` of `relation.md` §6.3.
///
/// It binds the target, the baseline, the member count, the canonical ordering
/// and, through the page chain, every member. A root plus a count, or a handful
/// of inclusion proofs, proves nothing about omission.
pub fn relation_conflict_members_digest(
    realm_id: &RealmId,
    conflict_domain: &RelationConflictDomain,
    member_count: u64,
    last_page_digest: &Hash,
    suite: arkret_canonical::DigestSuite,
) -> Result<Hash> {
    conflict_domain.validate()?;
    if member_count < 2 {
        return Err(WireError::Protocol(
            "a relation conflict baseline covers at least two candidate heads".to_owned(),
        ));
    }
    #[derive(Serialize)]
    struct Preimage<'a> {
        conflict_domain: &'a RelationConflictDomain,
        last_page_digest: &'a Hash,
        member_count: u64,
        realm_id: &'a RealmId,
    }
    relation_conflict_digest(
        RELATION_CONFLICT_MEMBERS_DOMAIN,
        &Preimage {
            conflict_domain,
            last_page_digest,
            member_count,
            realm_id,
        },
        suite,
    )
}

fn validate_relation_conflict_members(
    member_event_ids: &[EventId],
    min: usize,
    max: usize,
) -> Result<()> {
    if member_event_ids.len() < min || member_event_ids.len() > max {
        return Err(WireError::Protocol(format!(
            "relation conflict member list must hold {min}..={max} entries"
        )));
    }
    if member_event_ids
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(WireError::Protocol(
            "relation conflict members must be bytewise ascending and duplicate-free".to_owned(),
        ));
    }
    Ok(())
}

/// The frozen data-plane candidate baseline an `ak.relation.resolve` signs
/// against.
///
/// `seal_basis` freezes governance state only, so it never proves that every
/// Relation DataEvent in the group was observed. This is the separate
/// data-plane commitment, and its `member_count` carries no 16-head bound: the
/// ordinary diagnostic limit governs one projection output, never repair.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelationConflictBaseline {
    pub member_count: u64,
    pub members_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_event_ids: Option<Vec<EventId>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationConflictBaselineWire {
    member_count: u64,
    members_digest: Hash,
    #[serde(default)]
    member_event_ids: Option<Vec<EventId>>,
}

impl<'de> Deserialize<'de> for RelationConflictBaseline {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationConflictBaselineWire::deserialize(deserializer)?;
        Self::try_new(
            wire.member_count,
            wire.members_digest,
            wire.member_event_ids,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl RelationConflictBaseline {
    pub fn try_new(
        member_count: u64,
        members_digest: Hash,
        member_event_ids: Option<Vec<EventId>>,
    ) -> Result<Self> {
        let baseline = Self {
            member_count,
            members_digest,
            member_event_ids,
        };
        baseline.validate()?;
        Ok(baseline)
    }

    pub fn validate(&self) -> Result<()> {
        if self.member_count < 2 {
            return Err(WireError::Protocol(
                "a relation conflict baseline covers at least two candidate heads".to_owned(),
            ));
        }
        let inlined = self.member_count <= RELATION_CONFLICT_INLINE_MEMBER_LIMIT;
        match (&self.member_event_ids, inlined) {
            (Some(members), true) => {
                validate_relation_conflict_members(
                    members,
                    2,
                    RELATION_CONFLICT_INLINE_MEMBER_LIMIT as usize,
                )?;
                if members.len() as u64 != self.member_count {
                    return Err(WireError::Protocol(
                        "relation conflict baseline member_count must equal the inline list"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            (None, false) => Ok(()),
            (None, true) => Err(WireError::Protocol(
                "a relation conflict baseline of 64 or fewer members must inline them".to_owned(),
            )),
            (Some(_), false) => Err(WireError::Protocol(
                "a relation conflict baseline above 64 members carries only members_digest"
                    .to_owned(),
            )),
        }
    }

    /// Whether `event_id` is a covered member. `None` means the baseline only
    /// carries the commitment, so membership can be decided solely from
    /// independently verified material, never from this object.
    pub fn covers(&self, event_id: &EventId) -> Option<bool> {
        self.member_event_ids
            .as_ref()
            .map(|members| members.iter().any(|member| member == event_id))
    }
}

/// One page of the frozen repair material.
///
/// A page never takes effect on its own: [`RelationConflictMaterialVerifier`]
/// is the only thing that turns a sequence of pages into a verified member set.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelationConflictMaterialPage {
    pub page_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_page_digest: Option<Hash>,
    pub page_digest: Hash,
    pub member_event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationConflictMaterialPageWire {
    page_index: u64,
    #[serde(default)]
    prev_page_digest: Option<Hash>,
    page_digest: Hash,
    member_event_ids: Vec<EventId>,
    #[serde(default)]
    next_cursor: Option<String>,
}

impl<'de> Deserialize<'de> for RelationConflictMaterialPage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RelationConflictMaterialPageWire::deserialize(deserializer)?;
        let page = Self {
            page_index: wire.page_index,
            prev_page_digest: wire.prev_page_digest,
            page_digest: wire.page_digest,
            member_event_ids: wire.member_event_ids,
            next_cursor: wire.next_cursor,
        };
        page.validate().map_err(serde::de::Error::custom)?;
        Ok(page)
    }
}

impl RelationConflictMaterialPage {
    pub fn validate(&self) -> Result<()> {
        validate_relation_conflict_members(
            &self.member_event_ids,
            1,
            RELATION_CONFLICT_MATERIAL_PAGE_SIZE,
        )?;
        if (self.page_index == 0) != self.prev_page_digest.is_none() {
            return Err(WireError::Protocol(format!(
                "{}: relation conflict page 0 has no predecessor and every later page has one",
                ReasonCode::RELATION_CONFLICT_MATERIAL_PAGE_GAP
            )));
        }
        if self
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 4_096)
        {
            return Err(WireError::Protocol(
                "relation conflict page cursor must hold 1..=4096 characters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Walks the frozen repair material in ascending `page_index`, recomputing the
/// page chain, and only then compares the final chain value with
/// `baseline.members_digest`.
///
/// This lives in the shared SDK because every failure it detects — a dropped,
/// reordered, duplicated or short page — is `relation_conflict_material_page_gap`
/// with the same recovery: discard the partial material and restart from page
/// 0. A consumer that stitched pages itself would be free to invent a laxer
/// rule for the same wire.
#[derive(Clone, Debug)]
pub struct RelationConflictMaterialVerifier {
    realm_id: RealmId,
    conflict_domain: RelationConflictDomain,
    suite: arkret_canonical::DigestSuite,
    next_page_index: u64,
    last_page_digest: Option<Hash>,
    saw_final_page: bool,
    members: Vec<EventId>,
}

impl RelationConflictMaterialVerifier {
    pub fn new(
        realm_id: RealmId,
        conflict_domain: RelationConflictDomain,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        conflict_domain.validate()?;
        Ok(Self {
            realm_id,
            conflict_domain,
            suite,
            next_page_index: 0,
            last_page_digest: None,
            saw_final_page: false,
            members: Vec::new(),
        })
    }

    fn page_gap<T>(message: &str) -> Result<T> {
        Err(WireError::Protocol(format!(
            "{}: {message}",
            ReasonCode::RELATION_CONFLICT_MATERIAL_PAGE_GAP
        )))
    }

    pub fn push_page(&mut self, page: &RelationConflictMaterialPage) -> Result<()> {
        page.validate()?;
        if self.saw_final_page {
            return Self::page_gap("the material chain already reached its final page");
        }
        if page.page_index != self.next_page_index {
            return Self::page_gap("material pages must arrive in ascending page_index order");
        }
        if page.prev_page_digest.as_ref() != self.last_page_digest.as_ref() {
            return Self::page_gap("material page does not chain onto its predecessor");
        }
        if page.next_cursor.is_some()
            && page.member_event_ids.len() != RELATION_CONFLICT_MATERIAL_PAGE_SIZE
        {
            return Self::page_gap("only the final material page may hold fewer than 256 members");
        }
        let expected = relation_conflict_page_digest(
            &self.realm_id,
            &self.conflict_domain,
            page.page_index,
            page.prev_page_digest.as_ref(),
            &page.member_event_ids,
            self.suite,
        )?;
        if expected != page.page_digest {
            return Self::page_gap("material page digest does not cover its own members");
        }
        if let Some(last) = self.members.last()
            && last.as_str() >= page.member_event_ids[0].as_str()
        {
            return Self::page_gap("material pages must stay in one canonical ascending order");
        }
        self.members.extend(page.member_event_ids.iter().cloned());
        self.last_page_digest = Some(page.page_digest.clone());
        self.next_page_index += 1;
        self.saw_final_page = page.next_cursor.is_none();
        Ok(())
    }

    /// Consume the walk and return the verified member set, or fail closed.
    pub fn finish(self, baseline: &RelationConflictBaseline) -> Result<Vec<EventId>> {
        baseline.validate()?;
        if !self.saw_final_page {
            return Self::page_gap("the material chain has no final page");
        }
        let Some(last_page_digest) = self.last_page_digest.as_ref() else {
            return Self::page_gap("the material chain delivered no pages");
        };
        if self.members.len() as u64 != baseline.member_count {
            return Self::page_gap("material member count does not match the signed baseline");
        }
        let members_digest = relation_conflict_members_digest(
            &self.realm_id,
            &self.conflict_domain,
            baseline.member_count,
            last_page_digest,
            self.suite,
        )?;
        if members_digest != baseline.members_digest {
            return Self::page_gap("material chain does not reproduce the baseline commitment");
        }
        if let Some(inline) = baseline.member_event_ids.as_ref()
            && inline != &self.members
        {
            return Self::page_gap("material members disagree with the inline baseline list");
        }
        Ok(self.members)
    }
}

/// Request body of `ak.self.relation_conflicts.read.candidates.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationConflictCandidatesRequestBody {
    pub realm_id: RealmId,
    pub conflict_domain: RelationConflictDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl RelationConflictCandidatesRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.conflict_domain.validate()?;
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 4_096)
        {
            return Err(WireError::Protocol(
                "relation conflict cursor must hold 1..=4096 characters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Server-validated result of `ak.self.relation_conflicts.read.candidates.v1`.
///
/// The client trusts its own Station for candidate completeness and admission;
/// what it still checks itself is that the echoed selector is the one it asked
/// for, that the page chain is intact, and that the chain reproduces
/// `baseline.members_digest`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationConflictCandidatesOutcome {
    pub realm_id: RealmId,
    pub conflict_domain: RelationConflictDomain,
    pub baseline: RelationConflictBaseline,
    pub page: RelationConflictMaterialPage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<RelationConflictDiagnostic>,
}

impl RelationConflictCandidatesOutcome {
    pub fn validate_for_request(
        &self,
        request: &RelationConflictCandidatesRequestBody,
    ) -> Result<()> {
        request.validate()?;
        self.baseline.validate()?;
        self.page.validate()?;
        if self.realm_id != request.realm_id || self.conflict_domain != request.conflict_domain {
            return Err(WireError::Protocol(
                "relation conflict page does not echo the requested selector".to_owned(),
            ));
        }
        if request.cursor.is_none() && self.page.page_index != 0 {
            return Err(WireError::Protocol(format!(
                "{}: a cursorless relation conflict read starts at page 0",
                ReasonCode::RELATION_CONFLICT_MATERIAL_PAGE_GAP
            )));
        }
        match self.diagnostic.as_ref() {
            Some(diagnostic) => {
                diagnostic.validate()?;
                if diagnostic.conflict_domain != self.conflict_domain
                    || self.baseline.member_count > RelationConflictDiagnostic::MAX_HEADS as u64
                {
                    return Err(WireError::Protocol(
                        "the ordinary diagnostic is present exactly for a 2..=16 member baseline"
                            .to_owned(),
                    ));
                }
            }
            None => {
                if self.baseline.member_count <= RelationConflictDiagnostic::MAX_HEADS as u64 {
                    return Err(WireError::Protocol(
                        "a 2..=16 member baseline carries its ordinary diagnostic".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Projection-only evidence for one bounded set of concurrent Relation heads.
///
/// This value is never reducer input. Construction sorts by `event_id` and
/// rejects undersized, duplicate, or over-limit head sets. The server must
/// establish group completeness separately; this DTO cannot prove it.
///
/// `heads` is capped at 16 because that bounds one diagnostic *output*, not the
/// number of candidates a domain may hold: the 17th and every later candidate
/// is retained, and [`RelationConflictBaseline::member_count`] is unbounded for
/// the same domain.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationConflictDiagnostic {
    pub conflict_domain: RelationConflictDomain,
    pub heads: Vec<RelationConflictCandidate>,
}

impl RelationConflictDiagnostic {
    pub const MAX_HEADS: usize = 16;

    pub fn try_new(
        conflict_domain: RelationConflictDomain,
        mut heads: Vec<RelationConflictCandidate>,
    ) -> Result<Self> {
        heads.sort_by(|left, right| left.event_id.cmp(&right.event_id));
        let diagnostic = Self {
            conflict_domain,
            heads,
        };
        diagnostic.validate()?;
        Ok(diagnostic)
    }

    pub fn validate(&self) -> Result<()> {
        self.conflict_domain.validate()?;
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

    fn conflict_realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x65; 32],
        ))
    }

    fn tuple_domain() -> RelationConflictDomain {
        RelationConflictDomain::try_new(
            RelationConflictDomainKind::Tuple,
            RelationKind::AssignedTo,
            "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                .to_owned()
                .into(),
            Some(account_endpoint("station-a.example")),
        )
        .unwrap()
    }

    fn conflict_members(count: usize) -> Vec<EventId> {
        let mut members = (0..count)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[0] = (seed >> 8) as u8;
                bytes[1] = seed as u8;
                EventId::from_digest(arkret_canonical::DigestSuite::Sha256, bytes)
            })
            .collect::<Vec<_>>();
        members.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        members
    }

    fn material_pages(
        realm_id: &RealmId,
        domain: &RelationConflictDomain,
        members: &[EventId],
    ) -> (Vec<RelationConflictMaterialPage>, Hash) {
        let mut pages = Vec::new();
        let mut previous: Option<Hash> = None;
        let chunks = members.chunks(RELATION_CONFLICT_MATERIAL_PAGE_SIZE);
        let last_index = chunks.len() - 1;
        for (page_index, chunk) in members
            .chunks(RELATION_CONFLICT_MATERIAL_PAGE_SIZE)
            .enumerate()
        {
            let page_digest = relation_conflict_page_digest(
                realm_id,
                domain,
                page_index as u64,
                previous.as_ref(),
                chunk,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
            pages.push(RelationConflictMaterialPage {
                page_index: page_index as u64,
                prev_page_digest: previous.clone(),
                page_digest: page_digest.clone(),
                member_event_ids: chunk.to_vec(),
                next_cursor: (page_index != last_index).then(|| format!("cursor-{page_index}")),
            });
            previous = Some(page_digest);
        }
        let last = previous.expect("material always has at least one page");
        (pages, last)
    }

    fn verified_baseline(
        realm_id: &RealmId,
        domain: &RelationConflictDomain,
        members: &[EventId],
    ) -> (Vec<RelationConflictMaterialPage>, RelationConflictBaseline) {
        let (pages, last_page_digest) = material_pages(realm_id, domain, members);
        let members_digest = relation_conflict_members_digest(
            realm_id,
            domain,
            members.len() as u64,
            &last_page_digest,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let baseline = RelationConflictBaseline::try_new(
            members.len() as u64,
            members_digest,
            (members.len() as u64 <= RELATION_CONFLICT_INLINE_MEMBER_LIMIT)
                .then(|| members.to_vec()),
        )
        .unwrap();
        (pages, baseline)
    }

    #[test]
    fn relation_conflict_diagnostic_sorts_and_requires_exact_resolution_heads() {
        let diagnostic = RelationConflictDiagnostic::try_new(
            tuple_domain(),
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
            RelationConflictDiagnostic::try_new(tuple_domain(), vec![conflict_candidate(1)])
                .is_err()
        );
        assert!(
            RelationConflictDiagnostic::try_new(
                tuple_domain(),
                vec![conflict_candidate(1), conflict_candidate(1)]
            )
            .is_err()
        );
        assert!(
            RelationConflictDiagnostic::try_new(
                tuple_domain(),
                (0..=RelationConflictDiagnostic::MAX_HEADS)
                    .map(|seed| conflict_candidate(seed as u8))
                    .collect()
            )
            .is_err()
        );
    }

    #[test]
    fn conflict_domain_binds_the_registered_primary_conflict_domain() {
        assert!(
            RelationConflictDomain::try_new(
                RelationConflictDomainKind::Tuple,
                RelationKind::AssignedTo,
                "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                    .to_owned()
                    .into(),
                None,
            )
            .is_err()
        );
        // belongs_to is registered as a `from` domain, so a tuple spelling of
        // the same group would be a second, independently adjudicable key.
        assert!(
            RelationConflictDomain::try_new(
                RelationConflictDomainKind::Tuple,
                RelationKind::BelongsTo,
                "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                    .to_owned()
                    .into(),
                Some(account_endpoint("station-a.example")),
            )
            .is_err()
        );
        assert!(
            RelationConflictDomain::try_new(
                RelationConflictDomainKind::From,
                RelationKind::BelongsTo,
                "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                    .to_owned()
                    .into(),
                Some(account_endpoint("station-a.example")),
            )
            .is_err()
        );
        // Derived shapes have no directly writable Relation to adjudicate.
        assert!(
            RelationConflictDomain::try_new(
                RelationConflictDomainKind::Tuple,
                RelationKind::Watches,
                "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                    .to_owned()
                    .into(),
                Some(account_endpoint("station-a.example")),
            )
            .is_err()
        );
    }

    #[test]
    fn conflict_baseline_inlines_small_groups_and_commits_large_ones() {
        let realm = conflict_realm();
        let domain = tuple_domain();
        let small = conflict_members(3);
        let (pages, baseline) = verified_baseline(&realm, &domain, &small);
        assert_eq!(pages.len(), 1);
        assert_eq!(baseline.member_event_ids.as_deref(), Some(small.as_slice()));
        assert_eq!(baseline.covers(&small[0]), Some(true));

        let large = conflict_members(300);
        let (large_pages, large_baseline) = verified_baseline(&realm, &domain, &large);
        assert_eq!(large_pages.len(), 2);
        assert_eq!(large_pages[0].member_event_ids.len(), 256);
        assert!(large_baseline.member_event_ids.is_none());
        assert_eq!(large_baseline.covers(&large[0]), None);

        assert!(
            RelationConflictBaseline::try_new(
                3,
                large_baseline.members_digest.clone(),
                Some(large.clone()),
            )
            .is_err()
        );
        assert!(
            RelationConflictBaseline::try_new(300, large_baseline.members_digest.clone(), None)
                .is_ok()
        );
        assert!(
            RelationConflictBaseline::try_new(65, large_baseline.members_digest, Some(large))
                .is_err()
        );
    }

    #[test]
    fn material_chain_verifies_only_a_complete_ordered_walk() {
        let realm = conflict_realm();
        let domain = tuple_domain();
        let members = conflict_members(300);
        let (pages, baseline) = verified_baseline(&realm, &domain, &members);

        let mut verifier = RelationConflictMaterialVerifier::new(
            realm.clone(),
            domain.clone(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        for page in &pages {
            verifier.push_page(page).unwrap();
        }
        assert_eq!(verifier.finish(&baseline).unwrap(), members);

        // A dropped first page cannot be compensated by the second.
        let mut skipped = RelationConflictMaterialVerifier::new(
            realm.clone(),
            domain.clone(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(skipped.push_page(&pages[1]).is_err());

        // A truncated walk never reaches the baseline commitment.
        let mut truncated = RelationConflictMaterialVerifier::new(
            realm.clone(),
            domain.clone(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        truncated.push_page(&pages[0]).unwrap();
        assert!(truncated.finish(&baseline).is_err());

        // A tampered member set breaks its own page digest.
        let mut tampered_pages = pages.clone();
        tampered_pages[1].member_event_ids.pop();
        let mut tampered = RelationConflictMaterialVerifier::new(
            realm.clone(),
            domain.clone(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        tampered.push_page(&tampered_pages[0]).unwrap();
        assert!(tampered.push_page(&tampered_pages[1]).is_err());

        // The same pages under a different domain reproduce nothing.
        let other_domain = RelationConflictDomain::try_new(
            RelationConflictDomainKind::Tuple,
            RelationKind::AssignedTo,
            "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                .to_owned()
                .into(),
            Some(account_endpoint("station-b.example")),
        )
        .unwrap();
        let mut foreign = RelationConflictMaterialVerifier::new(
            realm,
            other_domain,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(foreign.push_page(&pages[0]).is_err());
    }

    #[test]
    fn candidates_outcome_pairs_the_diagnostic_with_a_bounded_baseline() {
        let realm = conflict_realm();
        let domain = tuple_domain();
        let small = conflict_members(3);
        let (pages, baseline) = verified_baseline(&realm, &domain, &small);
        let request = RelationConflictCandidatesRequestBody {
            realm_id: realm.clone(),
            conflict_domain: domain.clone(),
            cursor: None,
        };
        let diagnostic = RelationConflictDiagnostic::try_new(
            domain.clone(),
            small
                .iter()
                .map(|event_id| RelationConflictCandidate {
                    event_id: event_id.clone(),
                    reason: None,
                })
                .collect(),
        )
        .unwrap();
        let outcome = RelationConflictCandidatesOutcome {
            realm_id: realm.clone(),
            conflict_domain: domain.clone(),
            baseline: baseline.clone(),
            page: pages[0].clone(),
            diagnostic: Some(diagnostic),
        };
        outcome.validate_for_request(&request).unwrap();

        // A 2..=16 group without its diagnostic, and a 17+ group with one, are
        // both refused: the presence of the display shortcut is exact.
        let mut missing = outcome.clone();
        missing.diagnostic = None;
        assert!(missing.validate_for_request(&request).is_err());

        let large = conflict_members(300);
        let (large_pages, large_baseline) = verified_baseline(&realm, &domain, &large);
        let large_request = RelationConflictCandidatesRequestBody {
            realm_id: realm.clone(),
            conflict_domain: domain.clone(),
            cursor: None,
        };
        let large_outcome = RelationConflictCandidatesOutcome {
            realm_id: realm,
            conflict_domain: domain,
            baseline: large_baseline,
            page: large_pages[0].clone(),
            diagnostic: None,
        };
        large_outcome.validate_for_request(&large_request).unwrap();
    }
}
