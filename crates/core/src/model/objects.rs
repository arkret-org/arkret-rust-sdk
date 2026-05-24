use super::*;

// Realm/Space inversion (spec 59ac1d4): the existing `Space` struct (below)
// represents the **security boundary**, which is now renamed to **Realm**.
// `Realm` is exposed as a type alias so downstream code can migrate
// gradually. The container that used to be `Place` is the new `Space` —
// see the `Place` struct further down (kept under its old name for
// transitional compile-only compatibility; new code should refer to it
// as Space via the alias `pub type Space = ...`). TODO(realm-rework):
// invert the struct names once the rename is propagated through all
// reducers / resolvers / API call sites.
pub type Realm = Space;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Space {
    pub schema: String,
    pub id: SpaceId,
    pub title: String,
    /// Round 4 (2026-05-20, spec a77b995) — REQUIRED trust domain binding.
    /// Captured at create time (`cx.realm.create`) and immutable; any
    /// later event whose `trust_domain` mismatches MUST be rejected with
    /// `cross_domain_replay_rejected`. Mixed into the canonical signing
    /// transcript of high-risk proofs (cross-signing reset,
    /// audit_policy_version_digest). This field is `Realm`-scoped because
    /// `Space` is the security-boundary type (Realm/Space inversion);
    /// the container surface is `Place`.
    pub trust_domain: TypedTrustDomainId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_class: Option<SecurityClass>,
    pub created_by_principal: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organizations: Vec<Did>,
    pub schema_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<PolicyId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub encryption_profile: EncryptionProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_ref: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    /// Per-relation_kind cardinality declarations enforced by the resolver.
    /// Empty means every relation kind is many-to-many.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_profiles: Vec<RelationProfile>,
    /// Anchor profile (data-structures.md §4 — Move/Anchor/Lattice). Hub /
    /// threshold / open-set / mixed deployment shape. `None` means "use the
    /// `anchorer` cell value's runtime shape" (recommended default; the
    /// `anchorer` cell is the source of truth — this hint is purely
    /// advertisement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_profile: Option<AnchorProfile>,
    /// Initial anchorer cell value (data-structures.md §4). Reducer-derived
    /// after Space creation; this field is the **create-time hint** so
    /// servers can populate the anchorer cell without an extra round-trip.
    /// Subsequent anchorer changes flow through Move on the
    /// `cx:cell:cx.component.anchorer.v1:<space_id>` cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchorer: Option<crate::anchorer::AnchorerValue>,
    /// Soft cap on how stale the latest Anchor leaf may be before clients
    /// SHOULD warn / re-fetch. `None` means "implementation default" (spec
    /// suggests 30s for hub, longer for threshold). Reducer-derived field;
    /// passing a value at create time is a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_anchor_staleness_ms: Option<u64>,
    /// Lattice declarations per cell_family used in this Space. Reducer-
    /// derived; this field exists so clients can render bottom diagnostics
    /// before observing any Move. Empty means "use the cell registry
    /// defaults from contract-catalog".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cell_lattices: Vec<CellLatticeDeclaration>,
    /// Co-write policy (data-structures.md §4 — Move/Anchor/Lattice). How
    /// the server orders concurrent Moves before they reach an Anchor.
    /// `None` means "implementation default" (spec suggests
    /// `deterministic_order` for hub, `causal_only` for threshold).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_write_policy: Option<CoWritePolicy>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Anchor deployment profile for a Space (data-structures.md §4 —
/// Move/Anchor/Lattice).
///
/// This is a **hint field on `Space`** — the live anchorer identity always
/// lives in the `cx:cell:cx.component.anchorer.v1:<space_id>` cell. The
/// hint exists so clients can pre-allocate state before observing the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AnchorProfile {
    /// Single DID anchorer signs every Anchor. Lowest latency, single
    /// point of failure / governance.
    Hub,
    /// k-of-n threshold signature on each Anchor. Higher governance,
    /// higher latency.
    Threshold,
    /// Any member of an open set may sign; subsequent signers can replace
    /// or extend prior commitments via the anchorer cell or-set semantics.
    OpenSet,
    /// Primary single anchorer with a fallback recovery quorum that can
    /// rotate the primary via a recovery Move.
    Mixed,
}

/// Per-cell-family lattice declaration carried on `Space` (Move/Anchor/Lattice
/// data-structures.md §4). Maps a cell family used in this Space to its
/// declared lattice + bottom shape. Reducer-derived in practice; this is a
/// **hint** so clients can set up bottom diagnostics surfaces upfront.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CellLatticeDeclaration {
    /// `cx.component.<...>.v<N>` cell family identifier.
    pub cell_family: String,
    /// One of `or_set` / `mv_register` / `cas_register` / `fsm` / `counter` /
    /// `ordered_log` per spec event-auth-state-resolution.md §5.3.
    pub lattice: String,
    /// `reject` (default) or `expose` per spec §5.3 bottom semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom: Option<String>,
}

/// Co-write policy declaration on `Space` (Move/Anchor/Lattice). Governs
/// how concurrent Moves are ordered before reaching an Anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CoWritePolicy {
    /// Anchorer applies a deterministic order (HLC → issuer → id) before
    /// folding into the next Anchor. Best for hub deployments.
    DeterministicOrder,
    /// Causal-only order; concurrent Moves on the same cell may produce
    /// `bottom`. Suitable for threshold / open-set deployments.
    CausalOnly,
}

impl Space {
    /// Round 4 (2026-05-20, spec a77b995) — wire-breaking: `trust_domain`
    /// is REQUIRED. Constructors MUST now pass the deployment-scope
    /// trust domain captured at `cx.realm.create` time.
    pub fn new(
        id: SpaceId,
        title: impl Into<String>,
        created_by_principal: Did,
        trust_domain: TypedTrustDomainId,
    ) -> Self {
        Self {
            schema: SPACE_SCHEMA.to_owned(),
            id,
            title: title.into(),
            trust_domain,
            summary: None,
            security_class: None,
            created_by_principal,
            owning_organizations: Vec::new(),
            schema_refs: vec![CORE_SCHEMA_PROFILE.to_owned()],
            policy_ref: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            encryption_profile: EncryptionProfile::None,
            federation_policy: None,
            retention_policy_ref: None,
            avatar_blob_ref: None,
            created_at: Utc::now(),
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            relation_profiles: Vec::new(),
            anchor_profile: None,
            anchorer: None,
            max_anchor_staleness_ms: None,
            cell_lattices: Vec::new(),
            co_write_policy: None,
            extra: BTreeMap::new(),
        }
    }

    /// Builder: declare the Anchor deployment profile (data-structures.md §4).
    /// `Hub` uses a single-DID anchorer; `Threshold` / `OpenSet` / `Mixed`
    /// introduce multi-signer governance.
    pub fn with_anchor_profile(mut self, profile: AnchorProfile) -> Self {
        self.anchor_profile = Some(profile);
        self
    }

    /// Builder: declare the initial anchorer cell value. Servers seed the
    /// `cx:cell:cx.component.anchorer.v1:<space_id>` cell from this hint at
    /// Space creation time. Subsequent rotations flow through Move.
    pub fn with_anchorer(mut self, anchorer: crate::anchorer::AnchorerValue) -> Self {
        self.anchorer = Some(anchorer);
        self
    }

    /// Builder: cap how stale the latest Anchor leaf may be before clients
    /// SHOULD warn / re-fetch.
    pub fn with_max_anchor_staleness(mut self, max_ms: u64) -> Self {
        self.max_anchor_staleness_ms = Some(max_ms);
        self
    }

    /// Builder: declare a per-cell-family lattice hint. Append-only; call
    /// once per (cell_family, lattice) pair.
    pub fn with_cell_lattice(
        mut self,
        cell_family: impl Into<String>,
        lattice: impl Into<String>,
        bottom: Option<String>,
    ) -> Self {
        self.cell_lattices.push(CellLatticeDeclaration {
            cell_family: cell_family.into(),
            lattice: lattice.into(),
            bottom,
        });
        self
    }

    /// Builder: declare the Move co-write policy (deterministic vs causal).
    pub fn with_co_write_policy(mut self, policy: CoWritePolicy) -> Self {
        self.co_write_policy = Some(policy);
        self
    }

    /// Look up the active [`RelationProfile`] for a given `relation_kind`.
    pub fn relation_profile(&self, relation_kind: &str) -> Option<&RelationProfile> {
        self.relation_profiles.iter().find(|profile| profile.relation_kind == relation_kind)
    }

    /// Validate spec-level Space invariants.
    pub fn validate_kind_invariants(&self) -> Result<()> {
        if matches!(self.security_class, Some(SecurityClass::HighAssurance))
            && matches!(self.federation_policy, Some(FederationPolicy::Open))
        {
            return Err(Error::Protocol(
                "space.security_class=high_assurance forbids federation_policy=open".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Place {
    pub schema: String,
    pub id: SpaceId,
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_ref: Option<String>,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<PlaceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Place {
    pub fn new(
        id: SpaceId,
        space_id: SpaceId,
        kind: impl Into<String>,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            schema: SPACE_SCHEMA.to_owned(),
            id,
            space_id,
            parent_ref: None,
            kind: kind.into(),
            title: title.into(),
            summary: None,
            rank: None,
            schema_refs: Vec::new(),
            fields: BTreeMap::new(),
            labels: Vec::new(),
            avatar_blob_ref: None,
            state: Some(PlaceState::Active),
            state_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind.trim().is_empty() {
            return Err(Error::Protocol("place kind must not be empty".to_owned()));
        }
        if self.title.trim().is_empty() {
            return Err(Error::Protocol("place title must not be empty".to_owned()));
        }
        if let Some(parent_ref) = &self.parent_ref
            && !parent_ref.starts_with("cx:space:")
        {
            return Err(Error::Protocol("place parent_ref must be a Space ref".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorProfile {
    pub schema: String,
    pub id: ActorProfileId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub principal_id: Did,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ActorStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_to: Vec<Did>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Flow {
    pub schema: String,
    pub id: String,
    pub space_id: SpaceId,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<Value>,
    /// Active Flow tracks keyed by canonical track name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tracks: BTreeMap<String, FlowTrackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discussion_realm_ref: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Flow {
    pub fn new(
        id: impl Into<String>,
        space_id: SpaceId,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        let mut tracks = BTreeMap::new();
        tracks.insert(FLOW_TRACK_NAME_SYNTHESIS.to_owned(), FlowTrackConfig::synthesis());
        Self {
            schema: FLOW_SCHEMA.to_owned(),
            id: id.into(),
            space_id,
            title: title.into(),
            summary: None,
            body: None,
            encrypted_payload: None,
            tracks,
            discussion_realm_ref: None,
            fields: BTreeMap::new(),
            state: Some(ObjectState::Active),
            state_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    /// Construct a Flow whose primary entry point is the `discussion` track.
    pub fn discussion(
        id: impl Into<String>,
        space_id: SpaceId,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        let mut flow = Self::new(id, space_id, title, created_by);
        let mut tracks = BTreeMap::new();
        tracks.insert(FLOW_TRACK_NAME_SYNTHESIS.to_owned(), FlowTrackConfig::synthesis());
        tracks.insert(FLOW_TRACK_NAME_DISCUSSION.to_owned(), FlowTrackConfig::discussion_primary());
        flow.tracks = tracks;
        flow
    }

    pub fn is_conversational(&self) -> bool {
        resolve_primary_track(&self.tracks, None)
            .ok()
            .flatten()
            .is_some_and(|(name, _)| name == FLOW_TRACK_NAME_DISCUSSION)
    }

    pub fn validate_title(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(Error::Protocol("flow title must not be empty".to_owned()));
        }
        if self.tracks.is_empty() {
            return Err(Error::Protocol("flow tracks must not be empty".to_owned()));
        }
        for track_name in self.tracks.keys() {
            validate_flow_track_name(track_name)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Relation {
    pub schema: String,
    pub id: RelationId,
    pub space_id: SpaceId,
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
}

/// Relation cardinality declared by a `RelationProfile` (data-structures.md
/// §relation-profile).
///
/// Resolvers MUST refuse a `cx.relation.create` event whose
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

/// Enforce the cardinality declared by the matching `RelationProfile`.
///
/// `existing` is the set of currently-active edges with the same
/// `relation_kind`. The function returns `Err(Error::Protocol("relation_cardinality_violation"))`
/// when the candidate edge would breach the cardinality rule.
///
/// Cardinality rules:
/// - `OneToOne` — a Space MAY contain at most one edge per `from` and
///   per `to` for the given `relation_kind`.
/// - `OneToMany` — many `to` per `from` are fine, but each `to` MUST
///   have at most one `from`.
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
            Err(Error::Protocol("relation requires non-empty from_ref and to_ref".to_owned()))
        } else {
            Ok(())
        }
    }
}
