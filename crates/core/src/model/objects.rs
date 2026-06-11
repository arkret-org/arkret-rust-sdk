use super::*;

// Realm carries the security-boundary fields (`trust_domain` /
// `security_class` / `federation_policy` / `history_visibility`; spec
// realm.schema.json). Space carries the product container fields (`kind` /
// `parent_space_id` / `rank`; spec space.schema.json).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
// Field declaration order mirrors `realm.schema.json` properties order
// (`id, schema, title, summary, security_class, trust_domain, …`); local
// non-schema fields (`labels` / `metadata` / `extra`) trail the cluster.
pub struct Realm {
    pub id: RealmId,
    pub schema: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_class: Option<SecurityClass>,
    /// Round 4 (2026-05-20, spec a77b995) — REQUIRED trust domain binding.
    /// Captured at create time (`ck.realm.create`) and immutable; any
    /// later event whose `trust_domain` mismatches MUST be rejected with
    /// `cross_domain_replay_rejected`. Mixed into the canonical signing
    /// transcript of high-risk proofs (cross-signing reset,
    /// audit_policy_version_digest). This field is `Realm`-scoped because
    /// `Realm` is the security-boundary type; the container surface is
    /// `Space`.
    pub trust_domain: TypedTrustDomainId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organizations: Vec<Did>,
    pub schema_refs: Vec<String>,
    /// Per-relation_kind cardinality declarations enforced by the resolver.
    /// Empty means every relation kind is many-to-many.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_profiles: Vec<RelationProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub encryption_profile: EncryptionProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    /// Seal profile (data-structures.md §4 — Move/Seal/Lattice). Hub /
    /// threshold / open-set / mixed deployment shape. `None` means "use the
    /// `notary` cell value's runtime shape" (recommended default; the
    /// `notary` cell is the source of truth — this hint is purely
    /// advertisement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notary_profile: Option<NotaryProfile>,
    /// Initial notary cell value (data-structures.md §4). Reducer-derived
    /// after Realm creation; this field is the **create-time hint** so
    /// servers can populate the notary cell without an extra round-trip.
    /// Subsequent notary changes flow through Move on the
    /// `ck:cell:ck.component.notary.v1:<realm_id>` cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notary: Option<crate::notary::NotaryValue>,
    /// Soft cap on how stale the latest Seal leaf may be before clients
    /// SHOULD warn / re-fetch. `None` means "implementation default" (spec
    /// suggests 30s for hub, longer for threshold). Reducer-derived field;
    /// passing a value at create time is a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_window_ms: Option<u64>,
    /// Lattice declarations per cell_family used in this Realm. Reducer-
    /// derived; this field exists so clients can render bottom diagnostics
    /// before observing any Move. Empty means "use the cell registry
    /// defaults from contract-catalog".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cell_lattices: Vec<CellLatticeDeclaration>,
    /// Co-write policy (data-structures.md §4 — Move/Seal/Lattice). How
    /// the server orders concurrent Moves before they reach an Seal.
    /// `None` means "implementation default" (spec suggests
    /// `deterministic_order` for hub, `causal_only` for threshold).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_write_policy: Option<CoWritePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    /// Spec rename (head 37ce729): `created_by_principal` → `created_by`.
    ///
    /// Declaration order mirrors `spec/v1/artifacts/schemas/realm.schema.json`
    /// (common-fields §3.2): `created_by` lives in the trailing audit cluster
    /// `… avatar_blob_ref, created_by, created_at, updated_by, updated_at`.
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Seal deployment profile for a Realm (data-structures.md §4 —
/// Move/Seal/Lattice).
///
/// This is a **hint field on `Realm`** — the live notary identity always
/// lives in the `ck:cell:ck.component.notary.v1:<realm_id>` cell. The
/// hint exists so clients can pre-allocate state before observing the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotaryProfile {
    /// Single DID notary signs every Seal. Lowest latency, single
    /// point of failure / governance.
    Hub,
    /// k-of-n threshold signature on each Seal. Higher governance,
    /// higher latency.
    Threshold,
    /// Any member of an open set may sign; subsequent signers can replace
    /// or extend prior commitments via the notary cell or-set semantics.
    OpenSet,
    /// Primary single notary with a fallback recovery quorum that can
    /// rotate the primary via a recovery Move.
    Mixed,
}

/// Per-cell-family lattice declaration carried on `Realm` (Move/Seal/Lattice
/// data-structures.md §4). Maps a cell family used in this Realm to its
/// declared lattice + bottom shape. Reducer-derived in practice; this is a
/// **hint** so clients can set up bottom diagnostics surfaces upfront.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CellLatticeDeclaration {
    /// `ck.component.<...>.v<N>` cell family identifier.
    pub cell_family: String,
    /// One of `or_set` / `mv_register` / `cas_register` / `fsm` / `counter` /
    /// `ordered_log` per spec event-auth-state-resolution.md §5.3.
    pub lattice: String,
    /// `reject` (default) or `expose` per spec §5.3 bottom semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom: Option<String>,
}

/// Co-write policy declaration on `Realm` (Move/Seal/Lattice). Governs
/// how concurrent Moves are ordered before reaching an Seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CoWritePolicy {
    /// Notary applies a deterministic order (HLC → issuer → id) before
    /// folding into the next Seal. Best for hub deployments.
    DeterministicOrder,
    /// Causal-only order; concurrent Moves on the same cell may produce
    /// `bottom`. Suitable for threshold / open-set deployments.
    CausalOnly,
}

impl Realm {
    /// Round 4 (2026-05-20, spec a77b995) — wire-breaking: `trust_domain`
    /// is REQUIRED. Constructors MUST now pass the deployment-scope
    /// trust domain captured at `ck.realm.create` time.
    pub fn new(
        id: RealmId,
        title: impl Into<String>,
        created_by: Did,
        trust_domain: TypedTrustDomainId,
    ) -> Self {
        Self {
            id,
            // `Realm` is the security-boundary type, so it serializes the
            // Realm schema id, not the container Space id.
            schema: REALM_SCHEMA_ID.to_owned(),
            title: title.into(),
            summary: None,
            security_class: None,
            trust_domain,
            owning_organizations: Vec::new(),
            schema_refs: vec![CORE_SCHEMA_PROFILE.to_owned()],
            relation_profiles: Vec::new(),
            policy_id: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            encryption_profile: EncryptionProfile::None,
            content_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            metadata_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            federation_policy: None,
            notary_profile: None,
            notary: None,
            revocation_freshness_window_ms: None,
            cell_lattices: Vec::new(),
            co_write_policy: None,
            retention_policy_id: None,
            avatar_blob_ref: None,
            created_by,
            created_at: Utc::now(),
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Builder: declare the Seal deployment profile (data-structures.md §4).
    /// `Hub` uses a single-DID notary; `Threshold` / `OpenSet` / `Mixed`
    /// introduce multi-signer governance.
    pub fn with_notary_profile(mut self, profile: NotaryProfile) -> Self {
        self.notary_profile = Some(profile);
        self
    }

    /// Builder: declare the initial notary cell value. Servers seed the
    /// `ck:cell:ck.component.notary.v1:<realm_id>` cell from this hint at
    /// Realm creation time. Subsequent rotations flow through Move.
    pub fn with_notary(mut self, notary: crate::notary::NotaryValue) -> Self {
        self.notary = Some(notary);
        self
    }

    /// Builder: cap how stale the latest Seal leaf may be before clients
    /// SHOULD warn / re-fetch.
    pub fn with_revocation_freshness_window(mut self, max_ms: u64) -> Self {
        self.revocation_freshness_window_ms = Some(max_ms);
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
        self.relation_profiles
            .iter()
            .find(|profile| profile.relation_kind == relation_kind)
    }

    /// Validate spec-level Realm invariants.
    pub fn validate_kind_invariants(&self) -> Result<()> {
        if matches!(self.security_class, Some(SecurityClass::HighAssurance))
            && matches!(self.federation_policy, Some(FederationPolicy::Open))
        {
            return Err(Error::Protocol(
                "realm.security_class=high_assurance forbids federation_policy=open".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Space {
    pub id: SpaceId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    // Declaration order mirrors `spec/v1/artifacts/schemas/space.schema.json`
    // (common-fields §3.2): the discriminator cluster `kind, rank, schema_refs`
    // precedes `title, summary`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SpaceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// CKP-0007 (spec b7d35be) — optional Circle scope binding on the Space
    /// (container). Authorization-transparent: never carries its own
    /// membership/policy/E2EE group; this field places the Space's metadata
    /// inside an existing Circle encryption scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    /// CKP-0007 — optional default Circle scope for newly created child
    /// resources. Creation hint only; reducer enforcement uses
    /// [`ChildScopePolicy`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_scope_circle_id: Option<CircleId>,
    /// CKP-0007 — reducer-enforced constraint on how child resources may
    /// pick their scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_scope_policy: Option<ChildScopePolicy>,
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

/// CKP-0007 (spec b7d35be) — Space `child_scope_policy` discriminator.
///
/// Mirrors `spec/v1/artifacts/schemas/space.schema.json` `$defs.child_scope_policy`.
/// The `require_scope_circle_id` variant carries the required Circle id.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChildScopePolicy {
    /// Any scope is accepted, including unscoped.
    AllowAny {
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
    /// Child resources MUST live in an E2EE scope (any Circle or the
    /// Realm-default E2EE scope).
    RequireE2ee {
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
    /// Child resources MUST share the parent Space's `scope_circle_id`.
    RequireSameScope {
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
    /// Child resources MUST set `scope_circle_id` to the named Circle.
    RequireScopeCircleId {
        scope_circle_id: CircleId,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
}

impl Space {
    pub fn new(
        id: SpaceId,
        realm_id: RealmId,
        kind: impl Into<String>,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: SPACE_SCHEMA.to_owned(),
            realm_id,
            default_realm_id: None,
            parent_space_id: None,
            kind: kind.into(),
            rank: None,
            schema_refs: Vec::new(),
            title: title.into(),
            summary: None,
            fields: BTreeMap::new(),
            labels: Vec::new(),
            avatar_blob_ref: None,
            state: Some(SpaceState::Active),
            state_changed_at: None,
            scope_circle_id: None,
            default_scope_circle_id: None,
            child_scope_policy: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind.trim().is_empty() {
            return Err(Error::Protocol("space kind must not be empty".to_owned()));
        }
        if self.title.trim().is_empty() {
            return Err(Error::Protocol("space title must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ActorProfile {
    pub id: ActorProfileId,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
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
    pub accountable_principal_ids: Vec<Did>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Shared `metadata` shape for materialised objects that carry
/// `metadata.title` / `metadata.summary` (Flow, Morph). Field set matches
/// `flow.schema.json#/$defs/metadata` (common-fields §3): `title`, `summary`,
/// `fields`, plus a `#[serde(flatten)]` `extra` catch-all. Empty `fields` is
/// omitted from the wire (`skip_serializing_if`), so objects that do not use
/// `metadata.fields` (e.g. Morph, which carries top-level `fields`) serialise
/// identically to a metadata object without a `fields` member.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ObjectMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ObjectMetadata {
    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Self::default()
        }
    }
}

/// Flow `metadata` shape — see [`ObjectMetadata`].
pub type FlowMetadata = ObjectMetadata;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageMetadata {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Flow {
    pub id: FlowId,
    pub schema: String,
    pub realm_id: RealmId,
    /// CKP-0007 (spec b7d35be) — optional Circle scope binding. When set, all
    /// Flow tracks share the referenced Circle's MLS group, membership and
    /// history visibility; when unset the Flow lives in the Realm-default
    /// scope. Rebinding `scope_circle_id` is forbidden by default (reducer
    /// reason `scope_rebind_forbidden`). The Circle's parent Realm MUST
    /// equal the Flow's Realm.
    ///
    /// Declaration order mirrors `spec/v1/artifacts/schemas/flow.schema.json`
    /// (common-fields §3.2): `id, schema, realm_id, scope_circle_id, …`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FlowMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(rename = "content", skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    /// Active Flow tracks keyed by canonical track name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tracks: BTreeMap<String, FlowTrackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Business-progression stage (spec `flow.schema.json` required `stage`).
    /// Orthogonal to lifecycle `state`. Mutated only via `ck.flow.stage.set`;
    /// constructors default to [`ObjectStage::Draft`], consistent with Morph.
    pub stage: ObjectStage,
    /// Reducer-derived timestamp of the most recent `stage` transition;
    /// preserved on deserialize, omitted by producers (servers populate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_changed_at: Option<DateTime<Utc>>,
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
    pub fn new(id: FlowId, realm_id: RealmId, title: impl Into<String>, created_by: Did) -> Self {
        let mut tracks = BTreeMap::new();
        tracks.insert(
            FLOW_TRACK_NAME_SYNTHESIS.to_owned(),
            FlowTrackConfig::synthesis(),
        );
        Self {
            id,
            schema: FLOW_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            metadata: Some(FlowMetadata::with_title(title)),
            encrypted_metadata: None,
            body: None,
            encrypted_content: None,
            tracks,
            state: Some(ObjectState::Active),
            state_changed_at: None,
            stage: ObjectStage::Draft,
            stage_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_metadata_title(mut self, title: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(FlowMetadata::default)
            .title = Some(title.into());
        self
    }

    pub fn metadata_title(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.title.as_deref())
    }

    pub fn metadata_summary(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.summary.as_deref())
    }

    pub fn metadata_fields(&self) -> Option<&BTreeMap<String, Value>> {
        self.metadata.as_ref().map(|metadata| &metadata.fields)
    }

    /// Construct a Flow whose primary entry point is the `discussion` track.
    pub fn discussion(
        id: FlowId,
        realm_id: RealmId,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        let mut flow = Self::new(id, realm_id, title, created_by);
        let mut tracks = BTreeMap::new();
        tracks.insert(
            FLOW_TRACK_NAME_SYNTHESIS.to_owned(),
            FlowTrackConfig::synthesis(),
        );
        tracks.insert(
            FLOW_TRACK_NAME_DISCUSSION.to_owned(),
            FlowTrackConfig::discussion_primary(),
        );
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
        if self
            .metadata_title()
            .is_none_or(|title| title.trim().is_empty())
        {
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
