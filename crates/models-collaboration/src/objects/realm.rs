//! Realm security-boundary model.

use std::collections::BTreeMap;

use arkret_wire::constants::{CORE_SCHEMA_PROFILE, REALM_SCHEMA_ID};
use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    BlobRef, ControlProposalDecisionPolicy, Did, Discoverability, EncryptionProfile, Error,
    FederationPolicy, HistoryVisibility, JoinRule, PolicyId, RealmId, Result, SecurityClass,
    StrandId, TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::agent_participation::AgentParticipationPolicy;
use crate::governance::circle::EncryptionFloor;
use crate::objects::relation::RelationProfile;

/// Principal Control Realm role markers (`models/realm-and-space.md` §2.8.1).
///
/// `realm.schema.json` binds the two discriminators bidirectionally: a
/// `fields.purpose = "principal_control"` object MUST carry the profile ref and
/// vice versa, so a half-marked object is already schema-rejected. Sibling of
/// the Direct Conversation role constants in
/// [`crate::objects::direct_conversation`]; both Realm roles spell their
/// profile id exactly once here so no consumer re-types the string.
pub const PRINCIPAL_CONTROL_REALM_PROFILE: &str = "ak.profile.principal_control_realm.v1";
pub const PRINCIPAL_CONTROL_PURPOSE_FIELD: &str = "purpose";
pub const PRINCIPAL_CONTROL_PURPOSE: &str = "principal_control";

/// Whether an `ak.realm.create` Realm object declares the Principal Control
/// Realm role.
///
/// BOTH markers are required. This is deliberately the fail-closed reading for
/// a gate that hands a PCR something an ordinary Realm does not get (the
/// profile-fixed history-sharing baseline, exemption from the same-batch policy
/// requirement): a half-marked object MUST NOT collect the exemption, and it
/// cannot be conformant anyway.
pub fn realm_object_is_principal_control(object: &Value) -> bool {
    let purpose_marker = object
        .get("fields")
        .and_then(Value::as_object)
        .and_then(|fields| fields.get(PRINCIPAL_CONTROL_PURPOSE_FIELD))
        .and_then(Value::as_str)
        == Some(PRINCIPAL_CONTROL_PURPOSE);
    let profile_marker = object
        .get("schema_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .any(|schema_ref| schema_ref.as_str() == Some(PRINCIPAL_CONTROL_REALM_PROFILE))
        });
    purpose_marker && profile_marker
}

/// Counterpart for `spec/v1/artifacts/schemas/realm.schema.json#/$defs/sync_endpoint`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEndpoint {
    pub did: Did,
    pub endpoint: String,
    pub role: String,
    pub service_kind: String,
    pub plaintext_visible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

// Realm carries the security-boundary fields (`trust_domain` /
// `security_class` / `federation_policy` / `history_visibility`; spec
// realm.schema.json). Product container fields live on `Space`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order mirrors `realm.schema.json` properties order
// (`id, schema, title, summary, security_class, trust_domain, …`); local
// fields trail the cluster.
pub struct Realm {
    pub id: RealmId,
    pub schema: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_class: Option<SecurityClass>,
    /// Round 4 (2026-05-20, spec a77b995) — REQUIRED trust domain binding.
    /// Captured at create time (`ak.realm.create`) and immutable; any
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
    /// Product/profile fields carried by `realm.schema.json`. Security
    /// discriminators such as `purpose=principal_control` are validated by
    /// the profile-specific admission path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    /// Per-relation_kind cardinality declarations enforced by the resolver.
    /// Empty means every relation kind is many-to-many.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_profiles: Vec<RelationProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_strand_id: Option<StrandId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub encryption_profile: EncryptionProfile,
    /// Content AEAD scheme selector. `Some("mls_exporter_aead_v1")` opts the
    /// Realm into exporter-derived history-shareable content encryption;
    /// `None` keeps the legacy per-epoch `mls_rfc9420` PrivateMessage path.
    /// Additive — absent in existing genesis payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    /// Optional deployment-capped native-agent participation policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    /// Realm Recovery Key (RRK) durability policy (realm-and-space.md §2.3.1,
    /// encryption-and-audit.md §2.10.8). Declares who can recover Realm history
    /// after all member devices are lost or all members leave. Confidentiality-
    /// axis durability, orthogonal to `notary` / `notary.recovery_*` (finality
    /// axis). Only effective (`mode != none`) when
    /// `content_scheme == "mls_exporter_aead_v1"`. Reducer-derived (written via
    /// `ak.realm.policy_bundle`); a value at create time is a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability_policy: Option<DurabilityPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_endpoints: Vec<SyncEndpoint>,
    /// Seal profile (data-structures.md §4 — Move/Seal/Lattice). Single-DID /
    /// threshold / open-set / mixed deployment shape. This create-locked
    /// discriminator must match the genesis `notary` cell value.
    pub notary_profile: NotaryProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_policy: Option<RealmAvailabilityPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_policy: Option<RealmAuditPolicy>,
    #[serde(default)]
    pub digest_algorithm: canonical::DigestSuite,
    /// Initial notary cell value (data-structures.md §4). Reducers seed the
    /// authoritative notary cell from this genesis value at Realm creation.
    /// Subsequent notary changes strand through Move on the
    /// `ak:cell:ak.component.notary.v1:<realm_id>` cell.
    pub notary: NotaryValue,
    /// Soft cap on how stale the latest Seal leaf may be before clients
    /// SHOULD warn / re-fetch. `None` means "implementation default" (spec
    /// suggests 30s for single-DID, longer for threshold). Reducer-derived
    /// field; passing a value at create time is a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_witness_freshness_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_sla_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_decision_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_absolute_deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_proposal_defers: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_compaction_max_interval_ms: Option<u64>,
    #[serde(default = "default_max_delegation_lifetime_ms")]
    pub max_delegation_lifetime_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom_escalation_after_ms: Option<u64>,
    /// Lattice declarations per cell_family used in this Realm. Reducer-
    /// derived; this field exists so clients can render bottom diagnostics
    /// before observing any Move. Empty means "use the cell registry
    /// defaults from contract-registry".
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Realm Recovery Key (RRK) durability policy (realm-and-space.md §2.3.1,
/// encryption-and-audit.md §2.10.8). Recovery recipients are offline HPKE
/// public keys, NOT MLS members; granularity is expressed by organization
/// composition, not a per-Realm knob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityPolicy {
    pub mode: DurabilityMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_recipients: Vec<RealmRecoveryRecipient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<DurabilityThreshold>,
}

/// Durability mode selector. `None` = no organizational recovery path (total
/// member loss = permanent loss); `OrgRecoveryKey` = single org RRK;
/// `Threshold` = k-of-n recovery recipients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityMode {
    None,
    OrgRecoveryKey,
    Threshold,
}

/// k-of-n threshold parameters for `DurabilityMode::Threshold`. `k <= n` and
/// `n` MUST equal `recovery_recipients.len()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DurabilityThreshold {
    pub k: u32,
    pub n: u32,
}

/// One Realm Recovery Key holder. `verification_method` MUST point to a
/// verification method designated by an active `ArkretRealmHistoryRecoveryKey`
/// service entry published by `principal_id` (identity-did.md §8.3),
/// domain-separated from the principal's `did_recovery` key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmRecoveryRecipient {
    pub recipient_id: String,
    pub principal_id: Did,
    pub verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_organization: Option<Did>,
}

/// Seal deployment profile for a Realm (data-structures.md §4 —
/// Move/Seal/Lattice).
///
/// This is a **hint field on `Realm`** — the live notary identity always
/// lives in the `ak:cell:ak.component.notary.v1:<realm_id>` cell. The
/// hint exists so clients can pre-allocate state before observing the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct CellLatticeDeclaration {
    /// `ak.component.<...>.v<N>` cell family identifier.
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
#[serde(rename_all = "snake_case")]
pub enum CoWritePolicy {
    /// Notary applies a deterministic order (HLC → issuer → id) before
    /// folding into the next Seal. Best for single-DID deployments.
    DeterministicOrder,
    /// Causal-only order; concurrent Moves on the same cell may produce
    /// `bottom`. Suitable for threshold / open-set deployments.
    CausalOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityHolderRole {
    Notary,
    IndependentWitness,
    SyncMirror,
    ArchiveNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityEvidenceScope {
    SealInclude,
    Snapshot,
    Backfill,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAvailabilityPolicy {
    pub min_holders: u8,
    pub holder_roles: Vec<AvailabilityHolderRole>,
    pub applies_to: Vec<AvailabilityEvidenceScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_retention_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditWitnessIndependence {
    DistinctDid,
    DistinctControllingOrganization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuditPolicy {
    pub range_completeness_witnesses: Vec<Did>,
    pub witnessed_min_attestations: u8,
    pub witness_independence: AuditWitnessIndependence,
}

fn default_max_delegation_lifetime_ms() -> u64 {
    86_400_000
}

impl Realm {
    /// Build a materialized Realm object. The deployment-scope trust domain
    /// and genesis notary value are required because `ak.realm.create`
    /// validates the full Realm object schema.
    pub fn new(
        id: RealmId,
        title: impl Into<String>,
        created_by: Did,
        trust_domain: TypedTrustDomainId,
        notary_profile: NotaryProfile,
        notary: NotaryValue,
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
            fields: BTreeMap::new(),
            relation_profiles: Vec::new(),
            policy_id: None,
            preview_policy_id: None,
            default_strand_id: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            encryption_profile: EncryptionProfile::None,
            content_scheme: None,
            content_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            metadata_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            agent_participation: None,
            durability_policy: None,
            federation_policy: None,
            sync_endpoints: Vec::new(),
            notary_profile,
            availability_policy: None,
            audit_policy: None,
            digest_algorithm: canonical::DigestSuite::Sha256,
            notary,
            revocation_freshness_window_ms: None,
            recovery_witness_freshness_window_ms: None,
            receipt_sla_ms: None,
            proposal_decision_window_ms: None,
            proposal_absolute_deadline_ms: None,
            max_proposal_defers: None,
            seal_compaction_max_interval_ms: None,
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
    /// `ak:cell:ak.component.notary.v1:<realm_id>` cell from this hint at
    /// Realm creation time. Subsequent rotations strand through Move.
    pub fn with_notary(mut self, notary: NotaryValue) -> Self {
        self.notary = notary;
        self
    }

    /// Builder: cap how stale the latest Seal leaf may be before clients
    /// SHOULD warn / re-fetch.
    pub fn with_revocation_freshness_window(mut self, max_ms: u64) -> Self {
        self.revocation_freshness_window_ms = Some(max_ms);
        self
    }

    pub fn control_proposal_decision_policy(&self) -> Result<ControlProposalDecisionPolicy> {
        let duration_from_ms = |value: u64, field: &str| {
            i64::try_from(value)
                .map(Duration::milliseconds)
                .map_err(|_| Error::Protocol(format!("{field} exceeds the signed duration range")))
        };
        let policy = ControlProposalDecisionPolicy {
            receipt_sla: duration_from_ms(
                self.receipt_sla_ms.unwrap_or(86_400_000),
                "receipt_sla_ms",
            )?,
            decision_window: duration_from_ms(
                self.proposal_decision_window_ms.unwrap_or(30_000),
                "proposal_decision_window_ms",
            )?,
            absolute_horizon: duration_from_ms(
                self.proposal_absolute_deadline_ms.unwrap_or(90_000),
                "proposal_absolute_deadline_ms",
            )?,
            max_defers: self.max_proposal_defers.unwrap_or(2),
        };
        policy.validate()?;
        Ok(policy)
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
            (NotaryProfile::SingleDid, NotaryValue::SingleDid { .. })
                | (NotaryProfile::Threshold, NotaryValue::Threshold { .. })
                | (NotaryProfile::OpenSet, NotaryValue::OpenSet { .. })
                | (NotaryProfile::Mixed, NotaryValue::Mixed { .. })
        ) {
            return Err(Error::Protocol(
                "Realm notary_profile must match notary.kind".to_owned(),
            ));
        }
        self.control_proposal_decision_policy()?;
        if self
            .recovery_witness_freshness_window_ms
            .is_some_and(|value| value > 604_800_000)
        {
            return Err(Error::Protocol(
                "recovery_witness_freshness_window_ms exceeds 7 days".to_owned(),
            ));
        }
        if self
            .seal_compaction_max_interval_ms
            .is_some_and(|value| !(300_000..=604_800_000).contains(&value))
        {
            return Err(Error::Protocol(
                "seal_compaction_max_interval_ms must be within 5 minutes..=7 days".to_owned(),
            ));
        }
        if let Some(policy) = &self.availability_policy {
            if !(1..=16).contains(&policy.min_holders)
                || policy.holder_roles.is_empty()
                || policy.applies_to.is_empty()
                || policy
                    .holder_roles
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != policy.holder_roles.len()
                || policy
                    .applies_to
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != policy.applies_to.len()
            {
                return Err(Error::Protocol(
                    "Realm availability_policy violates its bounded unique-set contract".to_owned(),
                ));
            }
        }
        if let Some(policy) = &self.audit_policy {
            let witness_count = policy.range_completeness_witnesses.len();
            if !(1..=64).contains(&witness_count)
                || !(1..=16).contains(&policy.witnessed_min_attestations)
                || usize::from(policy.witnessed_min_attestations) > witness_count
                || policy
                    .range_completeness_witnesses
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != witness_count
            {
                return Err(Error::Protocol(
                    "Realm audit_policy violates its bounded witness contract".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> Realm {
        let notary = Did::new("did:web:notary.example").unwrap();
        Realm::new(
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            "Policy Realm",
            notary.clone(),
            TypedTrustDomainId::new("ak:trust_domain:example.net".to_owned()).unwrap(),
            NotaryProfile::SingleDid,
            NotaryValue::single_did(notary),
        )
    }

    #[test]
    fn proposal_policy_uses_realm_overrides_within_protocol_ceilings() {
        let mut realm = realm();
        realm.proposal_decision_window_ms = Some(3_600_000);
        realm.proposal_absolute_deadline_ms = Some(7_200_000);
        realm.max_proposal_defers = Some(1);
        let policy = realm.control_proposal_decision_policy().unwrap();
        assert_eq!(policy.decision_window, Duration::hours(1));
        assert_eq!(policy.absolute_horizon, Duration::hours(2));
        assert_eq!(policy.max_defers, 1);
    }

    #[test]
    fn proposal_policy_rejects_an_absolute_window_shorter_than_the_first_window() {
        let mut realm = realm();
        realm.proposal_decision_window_ms = Some(60_000);
        realm.proposal_absolute_deadline_ms = Some(30_000);
        assert!(realm.control_proposal_decision_policy().is_err());
    }

    #[test]
    fn proposal_policy_only_allows_equal_windows_without_defers() {
        let mut realm = realm();
        realm.proposal_decision_window_ms = Some(60_000);
        realm.proposal_absolute_deadline_ms = Some(60_000);
        realm.max_proposal_defers = Some(0);
        realm.control_proposal_decision_policy().unwrap();

        realm.max_proposal_defers = Some(1);
        assert!(realm.control_proposal_decision_policy().is_err());

        let serialized = serde_json::to_value(&realm).unwrap();
        let decoded: Realm = serde_json::from_value(serialized).unwrap();
        assert!(decoded.control_proposal_decision_policy().is_err());
    }

    /// Both PCR markers are required. `realm.schema.json` binds them
    /// bidirectionally, so a half-marked object is non-conformant; a gate that
    /// grants a PCR-only exemption MUST NOT accept one.
    #[test]
    fn principal_control_role_needs_both_pinned_discriminators() {
        assert!(realm_object_is_principal_control(&serde_json::json!({
            "fields": {"purpose": PRINCIPAL_CONTROL_PURPOSE},
            "schema_refs": ["ak.schema.realm.v1", PRINCIPAL_CONTROL_REALM_PROFILE]
        })));
        // Purpose without the profile ref.
        assert!(!realm_object_is_principal_control(&serde_json::json!({
            "fields": {"purpose": PRINCIPAL_CONTROL_PURPOSE},
            "schema_refs": ["ak.schema.realm.v1"]
        })));
        // Profile ref without the purpose discriminator.
        assert!(!realm_object_is_principal_control(&serde_json::json!({
            "schema_refs": ["ak.schema.realm.v1", PRINCIPAL_CONTROL_REALM_PROFILE]
        })));
        // A Direct Conversation Realm is the sibling role, never a PCR.
        assert!(!realm_object_is_principal_control(&serde_json::json!({
            "fields": {"collaboration_role": "direct_conversation"},
            "schema_refs": [
                "ak.schema.realm.v1",
                "ak.profile.direct_conversation_realm.v1"
            ]
        })));
    }
}
