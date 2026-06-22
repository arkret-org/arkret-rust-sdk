//! Realm security-boundary model.

use super::*;

// Realm carries the security-boundary fields (`trust_domain` /
// `security_class` / `federation_policy` / `history_visibility`; spec
// realm.schema.json). Product container fields live on `Space`.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_policy_id: Option<PolicyId>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_endpoints: Vec<SyncEndpoint>,
    /// Seal profile (data-structures.md §4 — Move/Seal/Lattice). Single-DID /
    /// threshold / open-set / mixed deployment shape. This create-locked
    /// discriminator must match the genesis `notary` cell value.
    pub notary_profile: NotaryProfile,
    #[serde(default)]
    pub digest_algorithm: canonical::DigestSuite,
    /// Initial notary cell value (data-structures.md §4). Reducers seed the
    /// authoritative notary cell from this genesis value at Realm creation.
    /// Subsequent notary changes strand through Move on the
    /// `ck:cell:ck.component.notary.v1:<realm_id>` cell.
    pub notary: crate::notary::NotaryValue,
    /// Soft cap on how stale the latest Seal leaf may be before clients
    /// SHOULD warn / re-fetch. `None` means "implementation default" (spec
    /// suggests 30s for single-DID, longer for threshold). Reducer-derived
    /// field; passing a value at create time is a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_window_ms: Option<u64>,
    #[serde(default = "default_max_delegation_lifetime_ms")]
    pub max_delegation_lifetime_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom_escalation_after_ms: Option<u64>,
    /// Lattice declarations per cell_family used in this Realm. Reducer-
    /// derived; this field exists so clients can render bottom diagnostics
    /// before observing any Move. Empty means "use the cell registry
    /// defaults from contract-catalog".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cell_lattices: Vec<CellLatticeDeclaration>,
    /// Co-write policy (data-structures.md §4 — Move/Seal/Lattice). How
    /// the server orders concurrent Moves before they reach an Seal.
    /// `None` means "implementation default" (spec suggests
    /// `deterministic_order` for single-DID, `causal_only` for threshold).
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
    pub updated_by: Option<Did>,
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
    SingleDid,
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
    /// folding into the next Seal. Best for single-DID deployments.
    DeterministicOrder,
    /// Causal-only order; concurrent Moves on the same cell may produce
    /// `bottom`. Suitable for threshold / open-set deployments.
    CausalOnly,
}

fn default_max_delegation_lifetime_ms() -> u64 {
    86_400_000
}

impl Realm {
    /// Build a materialized Realm object. The deployment-scope trust domain
    /// and genesis notary value are required because `ck.realm.create`
    /// validates the full Realm object schema.
    pub fn new(
        id: RealmId,
        title: impl Into<String>,
        created_by: Did,
        trust_domain: TypedTrustDomainId,
        notary_profile: NotaryProfile,
        notary: crate::notary::NotaryValue,
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
            preview_policy_id: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            encryption_profile: EncryptionProfile::None,
            content_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            metadata_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            federation_policy: None,
            sync_endpoints: Vec::new(),
            notary_profile,
            digest_algorithm: canonical::DigestSuite::Sha256,
            notary,
            revocation_freshness_window_ms: None,
            max_delegation_lifetime_ms: default_max_delegation_lifetime_ms(),
            bottom_escalation_after_ms: None,
            cell_lattices: Vec::new(),
            co_write_policy: None,
            retention_policy_id: None,
            avatar_blob_ref: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Builder: declare the Seal deployment profile (data-structures.md §4).
    /// `SingleDid` uses a single-DID notary; `Threshold` / `OpenSet` / `Mixed`
    /// introduce multi-signer governance.
    pub fn with_notary_profile(mut self, profile: NotaryProfile) -> Self {
        self.notary_profile = profile;
        self
    }

    /// Builder: declare the initial notary cell value. Servers seed the
    /// `ck:cell:ck.component.notary.v1:<realm_id>` cell from this hint at
    /// Realm creation time. Subsequent rotations strand through Move.
    pub fn with_notary(mut self, notary: crate::notary::NotaryValue) -> Self {
        self.notary = notary;
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
        self.notary.validate()?;
        if !matches!(
            (&self.notary_profile, &self.notary),
            (NotaryProfile::SingleDid, crate::notary::NotaryValue::SingleDid { .. })
                | (NotaryProfile::Threshold, crate::notary::NotaryValue::Threshold { .. })
                | (NotaryProfile::OpenSet, crate::notary::NotaryValue::OpenSet { .. })
                | (NotaryProfile::Mixed, crate::notary::NotaryValue::Mixed { .. })
        ) {
            return Err(Error::Protocol(
                "Realm notary_profile must match notary.type".to_owned(),
            ));
        }
        Ok(())
    }
}
