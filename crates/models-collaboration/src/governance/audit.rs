use std::collections::BTreeMap;

use arkret_wire::constants::{PROFILE_ATTESTED_AUDIT_E2EE, PROFILE_DISCLOSED_AUDIT_E2EE};
use arkret_wire::{
    Did, Error, EventId, Hash, Proof, RealmId, ReasonCode, Result, TypedTrustDomainId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Plaintext,
    Audit,
    Erasure,
    Backup,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AuditPolicyAccessPayload {
    pub realm_id: RealmId,
    pub actor: Did,
    pub access_kind: AccessKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    pub observed_at: DateTime<Utc>,
}

impl AuditPolicyAccessPayload {
    pub fn validate_minimal(&self) -> Result<()> {
        match (self.access_kind, &self.late_recovery_original_event_id) {
            (AccessKind::E2EELateRecovery, None) => Err(Error::Protocol("ak.audit.policy_access access_kind=e2ee_late_recovery requires late_recovery_original_event_id (schema_violation)".to_owned())),
            (kind, Some(_)) if !matches!(kind, AccessKind::E2EELateRecovery) => {
                Err(Error::Protocol("ak.audit.policy_access late_recovery_original_event_id is only valid for access_kind=e2ee_late_recovery (schema_violation)".to_owned()))
            }
            _ => Ok(()),
        }
    }
}

/// Audit assurance class (encryption-and-audit.md §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuditAssurance {
    AttestedHardware,
    DisclosedPolicy,
}

/// Round R2/R3 (2026-05-20) — `ak.profile.e2ee_relaxed.v1`.
///
/// Profile that permits temporarily widening the MLS send-pause window
/// for advisory reasons. Round R2/R3 introduces an **absolute hard
/// ceiling** of 5 minutes (300_000 ms) on the relaxed window.
pub const PROFILE_E2EE_RELAXED: &str = "ak.profile.e2ee_relaxed.v1";

/// Compliance profiles that MUST NOT coexist with
/// [`PROFILE_E2EE_RELAXED`]. Round R2/R3 — declaring both is rejected as
/// `e2ee_relaxed_disallowed_in_compliance_profile`.
pub const E2EE_RELAXED_INCOMPATIBLE_COMPLIANCE_PROFILES: &[&str] =
    &[PROFILE_ATTESTED_AUDIT_E2EE, PROFILE_DISCLOSED_AUDIT_E2EE];

/// Absolute hard ceiling on the `ak.profile.e2ee_relaxed.v1` send-pause
/// relaxation window, in milliseconds. Round R2/R3 (2026-05-20).
/// Implementations MUST reject any `relaxed_window_ms` exceeding this
/// value with `relaxed_window_exceeds_ceiling`.
pub const ABSOLUTE_HARD_CEILING_MS: u32 = 300_000;

/// Round R2/R3 — true when `active_profiles` is compatible with
/// `ak.profile.e2ee_relaxed.v1`. False if any of the compliance audit
/// profiles is present (the two are mutually exclusive — declaring both
/// MUST be rejected with
/// `ErrorCode::E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE`).
pub fn is_e2ee_relaxed_compatible_with_compliance<S: AsRef<str>>(active_profiles: &[S]) -> bool {
    !active_profiles
        .iter()
        .any(|p| E2EE_RELAXED_INCOMPATIBLE_COMPLIANCE_PROFILES.contains(&p.as_ref()))
}

/// Round R2/R3 — validate a relaxed-window value against the absolute hard
/// ceiling. Returns `Err(ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING)` when
/// `ms > ABSOLUTE_HARD_CEILING_MS`.
pub fn validate_relaxed_window_ms(ms: u32) -> std::result::Result<(), &'static str> {
    if ms > ABSOLUTE_HARD_CEILING_MS {
        return Err(ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING);
    }
    Ok(())
}

impl AuditAssurance {
    pub fn profile_id(self) -> &'static str {
        match self {
            AuditAssurance::AttestedHardware => PROFILE_ATTESTED_AUDIT_E2EE,
            AuditAssurance::DisclosedPolicy => PROFILE_DISCLOSED_AUDIT_E2EE,
        }
    }

    pub fn from_profile_id(profile: &str) -> Option<Self> {
        match profile {
            PROFILE_ATTESTED_AUDIT_E2EE => Some(AuditAssurance::AttestedHardware),
            PROFILE_DISCLOSED_AUDIT_E2EE => Some(AuditAssurance::DisclosedPolicy),
            _ => None,
        }
    }

    /// Words that MUST NOT appear in user-facing materials in disclosed
    /// audit mode (encryption-and-audit.md §3.1).
    pub fn forbidden_marketing_terms(self) -> &'static [&'static str] {
        match self {
            AuditAssurance::AttestedHardware => &[],
            AuditAssurance::DisclosedPolicy => &[
                "cryptographically enforced",
                "tee-equivalent",
                "attested",
                "hardware-enforced",
            ],
        }
    }
}

/// Issuer role for a Read-Your-Writes audit receipt
/// (`audit-ryw-receipt.schema.json`).
///
/// `events_api` is the originating Events API node; `witness` is an
/// independent log; `peer_node` is another Principal Server replica.
/// Combine with [`ReceiptIndependence`] to detect single-source receipts
/// that don't satisfy the attested-mode independence requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RywIssuerRole {
    EventsApi,
    Witness,
    PeerNode,
}

/// Whether the RYW receipt was issued by an issuer independent of the
/// Events API node that accepted the audit envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReceiptIndependence {
    /// At least one issuer is distinct from the originating Events API.
    Independent,
    /// All proofs come from the same node — not durable in attested mode.
    SingleSource,
}

/// Per-actor frontier entry referenced by the RYW receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct RywActorFrontierEntry {
    pub actor_seq: u64,
    pub event_id: EventId,
}

/// Frontier reference inside an RYW receipt
/// (`audit-ryw-receipt.schema.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct RywFrontier {
    pub realm_frontier: Vec<EventId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor_frontier: BTreeMap<Did, RywActorFrontierEntry>,
}

/// `ak.audit.ryw_receipt` event payload
/// (`audit-ryw-receipt.schema.json`).
///
/// Issued by an Events API node, witness, or peer Principal Server to
/// confirm a `ak.audit.accessed` envelope reached `accepted`. The Audit
/// Agent MUST gate plaintext release on receiving a receipt that meets
/// the Realm's declared `audit_assurance`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AuditRywReceipt {
    pub receipt_id: String,
    pub schema: String,
    pub issuer: Did,
    pub issuer_role: RywIssuerRole,
    pub audit_event_id: EventId,
    pub audit_event_digest: Hash,
    pub realm_id: RealmId,
    /// Round 4 (2026-05-20, spec a77b995) — REQUIRED trust domain
    /// binding. Mixed into the canonical `audit_policy_version_digest`
    /// 4-tuple so receipts cannot be replayed across deployments.
    pub trust_domain: TypedTrustDomainId,
    pub audit_actor_id: Did,
    pub frontier: RywFrontier,
    pub observed_at: DateTime<Utc>,
    pub receipt_independence: ReceiptIndependence,
    pub audit_assurance_class: AuditAssurance,
    pub proofs: Vec<Proof>,
}

impl AuditRywReceipt {
    /// Canonical schema id and event-kind constant for `ak.audit.ryw_receipt`.
    pub const SCHEMA: &'static str = "ak.schema.audit_ryw_receipt.v1";
    pub const EVENT_KIND: &'static str = "ak.audit.ryw_receipt";

    /// Validate independence vs the declared assurance class. Returns
    /// `Err` when an attested-mode receipt is single-source (which fails
    /// closed per `encryption-and-audit.md` §3.3.1).
    pub fn validate_independence(&self) -> Result<()> {
        if matches!(self.audit_assurance_class, AuditAssurance::AttestedHardware)
            && matches!(self.receipt_independence, ReceiptIndependence::SingleSource)
        {
            return Err(Error::Protocol(
                "attested audit profile requires independent RYW receipts".to_owned(),
            ));
        }
        Ok(())
    }
}
