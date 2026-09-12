//! Realm security-boundary model.

use std::collections::BTreeMap;

use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    ActorId, BlobRef, CORE_REDUCER_PROFILE, ContentScheme, ControlProposalDecisionPolicy,
    DidCoreId, Discoverability, DurabilityPolicy, EncryptionProfile, FederationPolicy,
    HistoryAccess, JoinRule, PolicyId, RealmId, Result, SchemaId, SecurityClass, StrandId,
    TrustDomainId, WireError, canonical,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::agent_participation::AgentParticipationPolicy;
use crate::governance::circle::EncryptionFloor;

pub const PRINCIPAL_CONTROL_PURPOSE: &str = "principal_control";

// Realm carries the security-boundary fields (`trust_domain` /
// `security_class` / `federation_policy` / `history_access`; spec
// realm.schema.json). Product container fields live on `Space`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order mirrors `realm.schema.json` properties order
// (`id, schema, title, summary, security_class, trust_domain, …`); local
// fields trail the cluster.
pub struct Realm {
    /// Present on the materialised object; absent from the create payload.
    ///
    /// Spec `zh/models/realm-and-space.md` section 2.5.0: `ak.realm.create`
    /// MUST omit it — the Realm id is derived from the genesis Event, so a
    /// payload copy would be a second, forgeable truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<RealmId>,
    pub schema: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_class: Option<SecurityClass>,
    /// REQUIRED trust domain binding.
    /// Captured at create time (`ak.realm.create`) and immutable; any
    /// later event whose `trust_domain` mismatches MUST be rejected with
    /// `cross_domain_replay_rejected`. Mixed into the canonical signing
    /// transcript of high-risk proofs (PCR-policy recovery,
    /// audit_policy_version_digest). This field is `Realm`-scoped because
    /// `Realm` is the security-boundary type; the container surface is
    /// `Space`.
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organization_ids: Vec<DidCoreId>,
    pub schema_refs: Vec<String>,
    /// Product/profile fields carried by `realm.schema.json`. Security
    /// discriminators such as `purpose=principal_control` and
    /// `purpose=agent_control` are validated by
    /// the profile-specific admission path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_strand_id: Option<StrandId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_access: HistoryAccess,
    /// Materialized value of the Realm reducer-profile singleton cell.
    /// `ak.realm.create` supplies the genesis value; only
    /// `ak.realm.upgrade` can change it.
    pub reducer_profile: String,
    pub encryption_profile: EncryptionProfile,
    /// Content AEAD scheme selector (realm-and-space.md §2, encryption-and-audit.md
    /// §2.10). Applies only when `encryption_profile = mls_rfc9420`. Absent means
    /// `mls_rfc9420`: MLS PrivateMessage, pre-join history undecryptable, so the
    /// Realm must use `history_access=since_join`.
    /// `Some("mls_exporter_aead_v1")` selects per-epoch `history_secret`, which
    /// structurally permits either history-access state and a
    /// `durability_policy` with `mode != none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_scheme: Option<ContentScheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    /// Optional deployment-capped Agent participation policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    /// Realm History Recovery Key (RHRK) durability policy (realm-and-space.md §2.3.1,
    /// encryption-and-audit.md §2.10.8). Declares whether an organization
    /// recovery key can recover Realm history after all member devices are lost
    /// or all members leave. Confidentiality-axis durability, orthogonal to
    /// `notary` / `notary.recovery_*` (finality axis). Required exactly on
    /// `content_scheme = mls_exporter_aead_v1`, and frozen together with it by
    /// the accepted MLS group Genesis — never mutable policy state. Custody
    /// topology (replica count, HSM, Shamir, k-of-n threshold, recipient list)
    /// is deliberately absent: section 2.3.1 keeps it off the Realm wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability_policy: Option<DurabilityPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_witness_freshness_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_intake_sla_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_decision_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_absolute_deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_proposal_defers: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_compaction_max_interval_ms: Option<u64>,
    #[serde(default = "default_max_delegation_lifetime_ms")]
    pub max_authority_lifetime_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom_escalation_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    /// Spec rename (head 37ce729): `created_by_principal` → `created_by`.
    ///
    /// Declaration order mirrors `spec/v1/artifacts/schemas/realm.schema.json`
    /// (common-fields §3.2): `created_by` lives in the trailing audit cluster
    /// `… avatar_blob_ref, created_by, created_at, updated_by, updated_at`.
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
    pub applies_to: Vec<AvailabilityEvidenceScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_retention_ms: Option<u64>,
}

impl Default for RealmAvailabilityPolicy {
    fn default() -> Self {
        Self {
            min_holders: 1,
            applies_to: vec![AvailabilityEvidenceScope::SealInclude],
            minimum_retention_ms: Some(86_400_000),
        }
    }
}

impl RealmAvailabilityPolicy {
    pub fn validate(&self) -> Result<()> {
        if !(1..=16).contains(&self.min_holders)
            || self.applies_to.is_empty()
            || self
                .applies_to
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.applies_to.len()
        {
            return Err(WireError::Protocol(
                "Realm availability_policy violates its bounded unique-set contract".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealTransparencyAuditorIndependence {
    DistinctDid,
    DistinctControllingOrganization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuditPolicy {
    pub seal_transparency_auditor_ids: Vec<DidCoreId>,
    pub seal_transparency_min_attestations: u8,
    pub seal_transparency_auditor_independence: SealTransparencyAuditorIndependence,
}

fn default_max_delegation_lifetime_ms() -> u64 {
    86_400_000
}

impl Realm {
    pub const SCHEMA: &'static str = SchemaId::REALM_V1;
    /// Build a materialized Realm object. The deployment-scope trust domain,
    /// genesis notary value are required because `ak.realm.create` validates
    /// the full Realm object schema.
    ///
    /// Every argument is a value `ak.realm.create` validates against the full
    /// Realm object schema, so none of them can be defaulted away into a
    /// smaller constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: RealmId,
        title: impl Into<String>,
        created_by: ActorId,
        trust_domain: TrustDomainId,
        reducer_profile: impl Into<String>,
        notary: NotaryValue,
    ) -> Self {
        Self {
            id: Some(id),
            // `Realm` is the security-boundary type, so it serializes the
            // Realm schema id, not the container Space id.
            schema: SchemaId::REALM_V1.to_owned(),
            title: title.into(),
            summary: None,
            security_class: None,
            trust_domain,
            owning_organization_ids: Vec::new(),
            schema_refs: Vec::new(),
            fields: BTreeMap::new(),
            policy_id: None,
            preview_policy_id: None,
            default_strand_id: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_access: HistoryAccess::SinceJoin,
            reducer_profile: reducer_profile.into(),
            encryption_profile: EncryptionProfile::None,
            content_scheme: None,
            content_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            metadata_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
            agent_participation: None,
            durability_policy: None,
            federation_policy: None,
            availability_policy: None,
            audit_policy: None,
            digest_algorithm: canonical::DigestSuite::Sha256,
            notary,
            recovery_witness_freshness_window_ms: None,
            proposal_intake_sla_ms: None,
            proposal_decision_window_ms: None,
            proposal_absolute_deadline_ms: None,
            max_proposal_defers: None,
            seal_compaction_max_interval_ms: None,
            max_authority_lifetime_ms: default_max_delegation_lifetime_ms(),
            bottom_escalation_after_ms: None,
            retention_policy_id: None,
            avatar_blob_ref: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }

    pub fn control_proposal_decision_policy(&self) -> Result<ControlProposalDecisionPolicy> {
        let duration_from_ms = |value: u64, field: &str| {
            i64::try_from(value)
                .map(Duration::milliseconds)
                .map_err(|_| {
                    WireError::Protocol(format!("{field} exceeds the signed duration range"))
                })
        };
        let policy = ControlProposalDecisionPolicy {
            proposal_intake_sla: duration_from_ms(
                self.proposal_intake_sla_ms.unwrap_or(86_400_000),
                "proposal_intake_sla_ms",
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

    /// Validate spec-level Realm invariants.
    pub fn validate_kind_invariants(&self) -> Result<()> {
        if self.reducer_profile != CORE_REDUCER_PROFILE {
            return Err(WireError::Protocol("unsupported_profile".to_owned()));
        }
        if matches!(self.security_class, Some(SecurityClass::HighAssurance))
            && matches!(self.federation_policy, Some(FederationPolicy::Open))
        {
            return Err(WireError::Protocol(
                "realm.security_class=high_assurance forbids federation_policy=open".to_owned(),
            ));
        }
        self.notary.validate()?;
        self.control_proposal_decision_policy()?;
        if self
            .recovery_witness_freshness_window_ms
            .is_some_and(|value| value > 604_800_000)
        {
            return Err(WireError::Protocol(
                "recovery_witness_freshness_window_ms exceeds 7 days".to_owned(),
            ));
        }
        if self
            .seal_compaction_max_interval_ms
            .is_some_and(|value| !(300_000..=604_800_000).contains(&value))
        {
            return Err(WireError::Protocol(
                "seal_compaction_max_interval_ms must be within 5 minutes..=7 days".to_owned(),
            ));
        }
        if let Some(policy) = &self.availability_policy {
            policy.validate()?;
        }
        if let Some(policy) = &self.audit_policy {
            let auditor_count = policy.seal_transparency_auditor_ids.len();
            if !(1..=64).contains(&auditor_count)
                || !(1..=16).contains(&policy.seal_transparency_min_attestations)
                || usize::from(policy.seal_transparency_min_attestations) > auditor_count
                || policy
                    .seal_transparency_auditor_ids
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != auditor_count
            {
                return Err(WireError::Protocol(
                    "Realm audit_policy violates its bounded seal-transparency auditor contract"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::notary::{NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor};
    use arkret_wire::{DidCoreId, DidUrl, Hash};

    use super::*;

    fn realm() -> Realm {
        let notary_actor = DidCoreId::new("ak:did_core:web:notary.example").unwrap();
        Realm::new(
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            "Policy Realm",
            ActorId::service(notary_actor.clone()),
            TrustDomainId::new("ak:trust_domain:example.net".to_owned()).unwrap(),
            CORE_REDUCER_PROFILE,
            NotaryValue::new(
                vec![NotarySignerDescriptor {
                    actor_id: ActorId::service(notary_actor),
                    verification_method: DidUrl::new("did:web:notary.example#key-1").unwrap(),
                    key_kind: NotaryKeyKind::Ed25519Raw32,
                    jose_algorithm: NotaryJoseAlgorithm::Ed25519,
                    frozen_public_key_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        .to_owned(),
                    frozen_public_key_digest: Hash::new(
                        "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
                    )
                    .unwrap(),
                }],
                0,
                0,
            )
            .unwrap(),
        )
    }

    #[test]
    fn realm_rejects_removed_relation_profiles() {
        let mut serialized = serde_json::to_value(realm()).unwrap();
        assert!(serialized.get("relation_profiles").is_none());
        serialized["relation_profiles"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Realm>(serialized).is_err());
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
}
