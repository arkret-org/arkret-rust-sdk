use super::*;
use crate::binding_contexts;

fn now_utc_seconds() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0).unwrap_or_else(Utc::now)
}

/// Standard track profile names.
pub const STRAND_TRACK_NAME_SYNTHESIS: &str = "synthesis";
pub const STRAND_TRACK_NAME_DISCUSSION: &str = "discussion";

/// Per-track configuration carried as the value side of the `Strand.tracks` map.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandTrackConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

impl StrandTrackConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Standard `synthesis` track config.
    pub fn synthesis() -> Self {
        Self::default()
    }

    /// Standard `discussion` track config.
    pub fn discussion() -> Self {
        Self {
            profile: Some("discussion".to_owned()),
            ..Self::default()
        }
    }

    /// Standard `discussion` track config marked as the Strand's primary entry point.
    pub fn discussion_primary() -> Self {
        Self {
            is_primary: Some(true),
            ..Self::discussion()
        }
    }

    /// Set the track as the Strand's primary entry point.
    pub fn primary(mut self) -> Self {
        self.is_primary = Some(true);
        self
    }

    /// Set a profile string.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Add one track-local UI metadata field.
    pub fn with_metadata_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Validate a `StrandTrack` map key against `^[a-z][a-z0-9_]{0,63}$`.
pub fn validate_strand_track_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(Error::Protocol(
            "StrandTrack name must be 1..=64 chars".to_owned(),
        ));
    }
    let mut chars = name.chars();
    let first = chars
        .next()
        .ok_or_else(|| Error::Protocol("StrandTrack name must not be empty".to_owned()))?;
    if !first.is_ascii_lowercase() {
        return Err(Error::Protocol(
            "StrandTrack name must start with [a-z]".to_owned(),
        ));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(Error::Protocol(format!(
                "StrandTrack name contains invalid character '{c}'"
            )));
        }
    }
    Ok(())
}

/// Resolve the primary track of a Strand.
pub fn resolve_primary_track<'a>(
    tracks: &'a BTreeMap<String, StrandTrackConfig>,
    profile_default: Option<&str>,
) -> Result<Option<(&'a String, &'a StrandTrackConfig)>> {
    let explicit: Vec<(&String, &StrandTrackConfig)> = tracks
        .iter()
        .filter(|(_, cfg)| cfg.is_primary == Some(true))
        .collect();
    match explicit.len() {
        0 => {}
        1 => return Ok(Some(explicit[0])),
        _ => {
            return Err(Error::Protocol(
                "Strand has more than one track with is_primary=true".to_owned(),
            ));
        }
    }
    if let Some((k, v)) = tracks.get_key_value(STRAND_TRACK_NAME_SYNTHESIS) {
        return Ok(Some((k, v)));
    }
    if tracks.len() == 1 {
        return Ok(tracks.iter().next());
    }
    if let Some(default_name) = profile_default
        && let Some((k, v)) = tracks.get_key_value(default_name)
    {
        return Ok(Some((k, v)));
    }
    Ok(None)
}

/// Morph `metadata` shape — shares [`ObjectMetadata`] with Strand. Morph carries
/// its data in the top-level `Morph.fields`, so `metadata.fields` stays empty
/// and is omitted from the wire (preserving the prior `MorphMetadata` shape of
/// `{title?, summary?, ...extra}`).
pub type MorphMetadata = ObjectMetadata;

fn serialize_non_empty_schema_refs<S>(
    schema_refs: &[String],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if schema_refs.is_empty() {
        return Err(serde::ser::Error::custom(
            "Morph.schema_refs must contain at least one schema ref",
        ));
    }
    schema_refs.serialize(serializer)
}

fn deserialize_non_empty_schema_refs<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let schema_refs = Vec::<String>::deserialize(deserializer)?;
    if schema_refs.is_empty() {
        return Err(serde::de::Error::custom(
            "Morph.schema_refs must contain at least one schema ref",
        ));
    }
    let mut seen = BTreeSet::new();
    for schema_ref in &schema_refs {
        if !seen.insert(schema_ref) {
            return Err(serde::de::Error::custom(format!(
                "Morph.schema_refs contains duplicate schema ref `{schema_ref}`"
            )));
        }
    }
    Ok(schema_refs)
}

/// Morph object (data-structures.md §7).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Morph {
    pub id: MorphId,
    pub schema: String,
    pub realm_id: RealmId,
    /// AKP-0007 (spec b7d35be) — optional Circle scope binding. Morphs that
    /// carry confidential synthesis fields can be bound to a Circle so their
    /// payload is encrypted inside that Circle's MLS group.
    ///
    /// Declaration order mirrors `morph.schema.json`: `realm_id`,
    /// `scope_circle_id`, `schema_refs`, …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    /// Round C47 (spec e10b6ad): authoritative schema set for Morph fields and
    /// transition validation. Reducers MUST validate Morph fields against
    /// exactly these refs (set-equal compare on `ak.morph.schema_migrate`);
    /// `morph_type` / `facets` are not a replacement.
    #[serde(
        serialize_with = "serialize_non_empty_schema_refs",
        deserialize_with = "deserialize_non_empty_schema_refs"
    )]
    pub schema_refs: Vec<String>,
    pub morph_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facets: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MorphMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Option<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    /// Reducer-derived timestamp of the most recent `state` transition;
    /// preserved on deserialize, omitted by producers (servers populate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Business progress axis (spec `morph.schema.json` required `stage`).
    /// Only Strand/Morph carry a `stage`. Distinct from `state` (lifecycle).
    pub stage: ObjectStage,
    /// Reducer-derived timestamp of the last `stage` transition; preserved on
    /// deserialize, omitted by producers (servers populate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Morph {
    pub fn new(
        id: MorphId,
        realm_id: RealmId,
        morph_type: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: MORPH_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            schema_refs: vec![MORPH_SCHEMA.to_owned()],
            morph_type: morph_type.into(),
            facets: BTreeMap::new(),
            metadata: None,
            encrypted_metadata: None,
            content: None,
            encrypted_content: None,
            fields: BTreeMap::new(),
            state: Some(ObjectState::Active),
            state_changed_at: None,
            stage: ObjectStage::Draft,
            stage_changed_at: None,
            created_by,
            created_at: now_utc_seconds(),
            updated_by: None,
            updated_at: None,
        }
    }

    pub fn with_metadata_title(mut self, title: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(MorphMetadata::default)
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

    /// Validate that `morph_type` does not use the reserved `ak.` prefix
    /// for unregistered types (morph.md §3 / data-structures.md §7).
    pub fn validate_morph_type(&self, registered_ak_types: &[&str]) -> Result<()> {
        if self.morph_type.starts_with("ak.")
            && !registered_ak_types.contains(&self.morph_type.as_str())
        {
            return Err(Error::Protocol(format!(
                "morph_type '{}' uses reserved ak. prefix without registration",
                self.morph_type
            )));
        }
        if self.morph_type.trim().is_empty() {
            return Err(Error::Protocol("morph_type must not be empty".to_owned()));
        }
        Ok(())
    }
}

/// Account lifecycle status (account-lifecycle.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::SoftLoggedOut => "soft_logged_out",
            AccountStatus::Locked => "locked",
            AccountStatus::Suspended => "suspended",
            AccountStatus::Deactivated => "deactivated",
            AccountStatus::ErasurePending => "erasure_pending",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "active" => Some(AccountStatus::Active),
            "soft_logged_out" => Some(AccountStatus::SoftLoggedOut),
            "locked" => Some(AccountStatus::Locked),
            "suspended" => Some(AccountStatus::Suspended),
            "deactivated" => Some(AccountStatus::Deactivated),
            "erasure_pending" => Some(AccountStatus::ErasurePending),
            _ => None,
        }
    }

    /// Strictness order from account-lifecycle.md §3.
    pub fn severity_rank(self) -> u8 {
        match self {
            AccountStatus::Active => 0,
            AccountStatus::SoftLoggedOut => 1,
            AccountStatus::Locked => 2,
            AccountStatus::Suspended => 3,
            AccountStatus::Deactivated => 4,
            AccountStatus::ErasurePending => 5,
        }
    }

    pub fn is_stricter_than(self, other: Self) -> bool {
        self.severity_rank() > other.severity_rank()
    }

    pub fn is_less_strict_than(self, other: Self) -> bool {
        self.severity_rank() < other.severity_rank()
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, AccountStatus::ErasurePending)
    }

    pub fn can_transition_to(self, to: Self) -> bool {
        use AccountStatus::{
            Active, Deactivated, ErasurePending, Locked, SoftLoggedOut, Suspended,
        };

        if self == to {
            return true;
        }

        match (self, to) {
            (Active, SoftLoggedOut | Locked | Suspended | Deactivated | ErasurePending)
            | (SoftLoggedOut, Active | Locked | Suspended | Deactivated | ErasurePending)
            | (Locked, Active | SoftLoggedOut | Suspended | Deactivated | ErasurePending)
            | (Suspended, Active | SoftLoggedOut | Locked | Deactivated | ErasurePending)
            | (Deactivated, ErasurePending) => true,
            (Deactivated, Active | SoftLoggedOut | Locked | Suspended)
            | (ErasurePending, Active | SoftLoggedOut | Locked | Suspended | Deactivated) => false,
            _ => false,
        }
    }

    pub fn validate_transition_to(
        self,
        to: Self,
        supersedes_status_event_visible: bool,
    ) -> std::result::Result<(), AccountStatusTransitionRejection> {
        if self == AccountStatus::ErasurePending && to != AccountStatus::ErasurePending {
            return Err(AccountStatusTransitionRejection::ErasurePendingIsTerminal);
        }

        if !self.can_transition_to(to) {
            return Err(AccountStatusTransitionRejection::TransitionInvalid);
        }

        if to.is_less_strict_than(self) && !supersedes_status_event_visible {
            return Err(AccountStatusTransitionRejection::TransitionInvalid);
        }

        Ok(())
    }

    /// Return whether new writes are allowed in this state.
    pub fn allows_writes(self) -> bool {
        matches!(self, AccountStatus::Active)
    }

    /// Return whether refresh / re-auth is the only allowed transition.
    pub fn requires_reauth(self) -> bool {
        matches!(self, AccountStatus::SoftLoggedOut | AccountStatus::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatusTransitionRejection {
    ErasurePendingIsTerminal,
    TransitionInvalid,
}

impl AccountStatusTransitionRejection {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::ErasurePendingIsTerminal => crate::ReasonCode::ERASURE_PENDING_IS_TERMINAL,
            Self::TransitionInvalid => crate::ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjectionCandidate {
    pub event_id: EventId,
    pub status: AccountStatus,
    pub effective_at: DateTime<Utc>,
    pub event_digest: Hash,
    pub supersedes_status_event_id: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjection<'a> {
    pub current: Option<&'a AccountStatusProjectionCandidate>,
    pub rejected: Vec<AccountStatusProjectionRejected>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusProjectionRejected {
    pub event_id: EventId,
    pub reason_code: &'static str,
}

pub fn project_account_status_heads<'a>(
    heads: &'a [AccountStatusProjectionCandidate],
    visible_status_event_ids: &BTreeSet<EventId>,
) -> AccountStatusProjection<'a> {
    let mut rejected = Vec::new();
    let mut suppressed = BTreeSet::new();

    for candidate in heads {
        if let Some(superseded_id) = candidate.supersedes_status_event_id.as_ref() {
            if !visible_status_event_ids.contains(superseded_id) {
                continue;
            }

            if let Some(superseded) = heads.iter().find(|head| &head.event_id == superseded_id)
                && candidate.status.is_less_strict_than(superseded.status)
            {
                match superseded
                    .status
                    .validate_transition_to(candidate.status, true)
                {
                    Ok(()) => {
                        suppressed.insert(superseded.event_id.clone());
                    }
                    Err(rejection) => rejected.push(AccountStatusProjectionRejected {
                        event_id: candidate.event_id.clone(),
                        reason_code: rejection.reason_code(),
                    }),
                }
            }
        }
    }

    let current = heads
        .iter()
        .filter(|candidate| !suppressed.contains(&candidate.event_id))
        .filter(|candidate| {
            !rejected
                .iter()
                .any(|rejection| rejection.event_id == candidate.event_id)
        })
        .max_by(|left, right| {
            left.status
                .severity_rank()
                .cmp(&right.status.severity_rank())
                .then_with(|| left.effective_at.cmp(&right.effective_at))
                .then_with(|| left.event_digest.as_str().cmp(right.event_digest.as_str()))
        });

    AccountStatusProjection { current, rejected }
}

/// Audit assurance class (encryption-and-audit.md §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
/// ceiling. Returns `Err(crate::ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING)` when
/// `ms > ABSOLUTE_HARD_CEILING_MS`.
pub fn validate_relaxed_window_ms(ms: u32) -> std::result::Result<(), &'static str> {
    if ms > ABSOLUTE_HARD_CEILING_MS {
        return Err(crate::ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING);
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RywIssuerRole {
    EventsApi,
    Witness,
    PeerNode,
}

/// Whether the RYW receipt was issued by an issuer independent of the
/// Events API node that accepted the audit envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReceiptIndependence {
    /// At least one issuer is distinct from the originating Events API.
    Independent,
    /// All proofs come from the same node — not durable in attested mode.
    SingleSource,
}

/// Per-actor frontier entry referenced by the RYW receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RywActorFrontierEntry {
    pub actor_seq: u64,
    pub event_id: EventId,
}

/// Frontier reference inside an RYW receipt
/// (`audit-ryw-receipt.schema.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

/// Constraint evaluation class (constraint-schema.md §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IdentityLinkStatus {
    Active,
    Revoked,
}

fn identity_link_default_status() -> IdentityLinkStatus {
    IdentityLinkStatus::Active
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLinkProof {
    pub verification_method: String,
    pub signature_algorithm: String,
    pub payload_digest: Hash,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLink {
    pub schema: String,
    #[serde(default = "identity_link_default_status")]
    pub status: IdentityLinkStatus,
    pub pairwise_did: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub trust_domain: TypedTrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(
        rename = "track_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub track: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    pub mls_leaf_index: u64,
    pub mls_epoch: u64,
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_policy_id: Option<PolicyId>,
    pub proof: IdentityLinkProof,
}

impl IdentityLink {
    pub const SCHEMA: &'static str = "ak.schema.identity_link.v1";

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(
                "identity_link schema must be ak.schema.identity_link.v1".to_owned(),
            ));
        }
        if self.strand_id.is_some() && self.track.as_deref().is_none_or(str::is_empty) {
            return Err(Error::Protocol(
                "identity_link strand_id requires track_name".to_owned(),
            ));
        }
        if let Some(track_name) = self.track.as_deref() {
            validate_strand_track_name(track_name)?;
        }
        if self.proof.verification_method.trim().is_empty()
            || self.proof.signature_algorithm.trim().is_empty()
            || self.proof.signature.trim().is_empty()
        {
            return Err(Error::Protocol(
                "identity_link proof requires verification_method, signature_algorithm, and signature"
                    .to_owned(),
            ));
        }
        let expected = self.canonical_payload_digest()?;
        if self.proof.payload_digest != expected {
            return Err(Error::Protocol(
                "identity_link proof payload_digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_proof_input(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self).map_err(|error| {
            Error::Protocol(format!("identity_link serialization failed: {error}"))
        })?;
        if let Value::Object(object) = &mut value
            && let Some(Value::Object(proof)) = object.get_mut("proof")
        {
            proof.remove("payload_digest");
            proof.remove("signature");
        }
        let canonical = canonical::canonical_json_bytes(&value)?;
        let mut input =
            Vec::with_capacity(binding_contexts::IDENTITY_LINK_PREFIX.len() + canonical.len());
        input.extend_from_slice(binding_contexts::IDENTITY_LINK_PREFIX);
        input.extend_from_slice(&canonical);
        Ok(input)
    }

    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        let input = self.canonical_proof_input()?;
        Hash::new(canonical::sha256_digest(&input)).map_err(|error| {
            Error::Protocol(format!("identity_link payload hash invalid: {error}"))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureSubjectKind {
    Principal,
    Space,
    Event,
    Blob,
    Device,
    AccountPrivateState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureStorageBoundary {
    CanonicalLogMinimization,
    BlobStore,
    ProjectionStore,
    AccountPrivateStore,
    SearchIndex,
    PushRoutes,
    DeviceSecretStore,
    MediaDerivatives,
    ServiceDefined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureOutcome {
    Completed,
    PartiallyCompleted,
    BlockedByLegalHold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasedClass {
    CanonicalPayloadBytes,
    BlobBytes,
    ProjectionRows,
    AccountPrivateState,
    PushRoutes,
    DeviceSecrets,
    SearchIndexEntries,
    DerivedPlaintext,
    MediaDerivatives,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureSubject {
    pub kind: ErasureSubjectKind,
    pub subject_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureScope {
    pub storage_boundary: ErasureStorageBoundary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureReceiptProof {
    pub verification_method: String,
    pub payload_digest: Hash,
    pub signature: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Cross-Principal-Server erasure-receipt fanout aggregate status tracked by
/// the issuing server (mirrors `erasure-receipt.schema.json` `fanout_status`;
/// models/realm-and-space.md §2.6.2). Replaces the dropped point-dotted pseudo
/// kind `ak.audit.erasure_receipt.fanout_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasureFanoutStatus {
    /// Peers still within `erasure_propagation_window_ms` and not all
    /// acknowledged.
    Pending,
    /// Every peer that ever held this Realm's content returned a receipt.
    Complete,
    /// At least one peer failed to acknowledge within
    /// `erasure_propagation_window_ms`. The issuing server MUST surface this
    /// to audit/UI and MUST NOT silently swallow it.
    Incomplete,
}

/// Per-peer fanout acknowledgement status (mirrors `erasure-receipt.schema.json`
/// `peer_receipts[].status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErasurePeerStatus {
    /// Awaiting this peer's feedback receipt.
    Pending,
    /// Peer returned a receipt (regardless of its outcome).
    Acknowledged,
    /// Peer reported a non-completed feedback outcome
    /// (`partially_completed` / `blocked_by_legal_hold`).
    Failed,
    /// No feedback within `erasure_propagation_window_ms`.
    TimedOut,
}

/// One per-peer fanout acknowledgement record maintained by the issuing server
/// (mirrors `erasure-receipt.schema.json` `peer_receipts[]`). One entry per peer
/// Principal Server that ever held this Realm's content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasurePeerReceipt {
    /// Peer Principal Server DID.
    pub peer: Did,
    pub status: ErasurePeerStatus,
    /// The peer's own feedback receipt id, when received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErasureReceipt {
    pub receipt_id: String,
    pub schema: String,
    pub issuer: Did,
    pub subject: ErasureSubject,
    pub scope: ErasureScope,
    pub outcome: ErasureOutcome,
    pub erased_classes: Vec<ErasedClass>,
    pub retained_stub_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub retained_stub: Option<VerificationStub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<String>,
    pub completed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    pub proofs: Vec<ErasureReceiptProof>,
    /// Cross-Principal-Server erasure fanout aggregate status. Absent on
    /// receipts that do not drive fanout tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_status: Option<ErasureFanoutStatus>,
    /// Per-peer fanout acknowledgement records backing `fanout_status`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_receipts: Vec<ErasurePeerReceipt>,
}

impl ErasureReceipt {
    pub const SCHEMA: &'static str = "ak.schema.erasure_receipt.v1";
    pub const EVENT_KIND: &'static str = "ak.audit.erasure_receipt";

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(
                "erasure receipt schema mismatch".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "erasure receipt proofs must not be empty".to_owned(),
            ));
        }
        if matches!(self.outcome, ErasureOutcome::BlockedByLegalHold)
            && self.legal_hold_ref.is_none()
        {
            return Err(Error::Protocol(
                "blocked erasure receipt requires legal_hold_ref".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical bytes signed by every receipt proof. The `proofs` array is
    /// excluded so proof payload digests cannot recursively depend on their
    /// own signatures.
    pub fn canonical_proof_input(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            Error::Protocol("erasure receipt must serialize as an object".to_owned())
        })?;
        object.remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        let input = self.canonical_proof_input()?;
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn validate_proof_payload_digests(&self) -> Result<()> {
        self.validate_minimal()?;
        let expected = self.canonical_payload_digest()?;
        for proof in &self.proofs {
            if proof.payload_digest != expected {
                return Err(Error::Protocol(
                    "erasure receipt proof payload_digest mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Validate a received receipt against the retained verification stub.
    pub fn validate_with_retained_stub(&self, retained_stub: &VerificationStub) -> Result<()> {
        self.validate_minimal()?;
        let retained_stub_digest = Hash::new(canonical::canonical_sha256(retained_stub)?)?;
        if retained_stub_digest != self.retained_stub_digest {
            return Err(Error::Protocol(
                "erasure_receipt_stub_digest_mismatch".to_owned(),
            ));
        }
        self.validate_proof_payload_digests()?;
        Ok(())
    }

    /// Validate a receipt that carries its verification stub inline.
    pub fn validate_with_inline_retained_stub(&self) -> Result<()> {
        let retained_stub = self.retained_stub.as_ref().ok_or_else(|| {
            Error::Protocol("erasure receipt retained_stub is required".to_owned())
        })?;
        self.validate_with_retained_stub(retained_stub)?;
        Ok(())
    }
}

#[cfg(test)]
mod erasure_receipt_tests {
    use super::*;

    fn receipt(stub: &VerificationStub) -> ErasureReceipt {
        let mut receipt = ErasureReceipt {
            receipt_id: "ak:receipt:01970e58-0004-7000-8000-000000000010".to_owned(),
            schema: ErasureReceipt::SCHEMA.to_owned(),
            issuer: Did::new("did:webvh:z6mkfixture:erasure.example".to_owned()).unwrap(),
            subject: ErasureSubject {
                kind: ErasureSubjectKind::Event,
                subject_ref: "ak:event:01970e58-0004-7000-8000-000000000004".to_owned(),
            },
            scope: ErasureScope {
                storage_boundary: ErasureStorageBoundary::CanonicalLogMinimization,
                realm_id: None,
                target_refs: Vec::new(),
                retention_policy_id: None,
                service_scope: None,
            },
            outcome: ErasureOutcome::Completed,
            erased_classes: vec![ErasedClass::CanonicalPayloadBytes],
            retained_stub_digest: Hash::new(canonical::canonical_sha256(stub).unwrap()).unwrap(),
            retained_stub: Some(stub.clone()),
            legal_hold_ref: None,
            completed_at: Utc::now(),
            issued_at: None,
            proofs: vec![ErasureReceiptProof {
                verification_method: "did:webvh:z6mkfixture:erasure.example#key-1".to_owned(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                signature: "zplaceholder".to_owned(),
                extra: BTreeMap::new(),
            }],
            fanout_status: None,
            peer_receipts: Vec::new(),
        };
        receipt.proofs[0].payload_digest = receipt.canonical_payload_digest().unwrap();
        receipt
    }

    #[test]
    fn retained_stub_digest_mismatch_fails_closed() {
        let stub = VerificationStub {
            stub_schema: "ak.schema.erasure_verification_stub.v1".to_owned(),
            subject: VerificationStubSubject {
                kind: "event".to_owned(),
                subject_ref: "ak:event:01970e58-0004-7000-8000-000000000004".to_owned(),
            },
            scope: VerificationStubScope {
                storage_boundary: "canonical_log_minimization".to_owned(),
                realm_id: None,
                target_refs: None,
                retention_policy_id: None,
                service_scope: None,
            },
            event_digest: None,
            retained_digests: None,
            seal_inclusion: None,
            redaction_authorization_ref: None,
            legal_hold_ref: None,
            receipt_id: "ak:receipt:01970e58-0004-7000-8000-000000000010".to_owned(),
            completed_at: Utc::now(),
        };
        let receipt = receipt(&stub);
        assert!(receipt.validate_with_retained_stub(&stub).is_ok());

        let mut tampered = stub;
        tampered.subject.subject_ref = "ak:event:01970e58-0004-7000-8000-ffffffffffff".to_owned();
        assert!(receipt.validate_with_retained_stub(&tampered).is_err());
    }
}

/// Backup class for key backup envelopes (key-management.md §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
}

impl BackupClass {
    /// Canonical snake_case wire token used by `ak.schema.key_backup.v1`.
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupClass::DidRecovery => "did_recovery",
            BackupClass::SecretStorage => "secret_storage",
            BackupClass::MlsHistory => "mls_history",
        }
    }

    /// HKDF info string per key-management.md §7.2.
    pub fn hkdf_info(self, subdomain: &str) -> String {
        let class = match self {
            BackupClass::DidRecovery => "did_recovery",
            BackupClass::SecretStorage => "secret_storage",
            BackupClass::MlsHistory => "mls_history",
        };
        format!("arkret-key-backup/{class}/{subdomain}/v1")
    }
}

/// Parse a `ak.schema.key_backup.v1` backup_class wire token.
impl TryFrom<&str> for BackupClass {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "did_recovery" => Ok(Self::DidRecovery),
            "secret_storage" => Ok(Self::SecretStorage),
            "mls_history" => Ok(Self::MlsHistory),
            other => Err(format!("unsupported backup_class {other}")),
        }
    }
}

/// Approval workflow mode (constraint-schema.md §9.1–§9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ApprovalWorkflowMode {
    BeforeCommit,
    AfterCommitReview,
    ProposalThenApprove,
}

/// Moderation action (moderation.md §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    DenyJoin,
    DenyInvite,
    DenyWrite,
    QuarantineMessage,
    RequireReview,
    RedactOnAccept,
    ShadowCollapse,
}

/// Moderation report (moderation.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub report_id: String,
    pub realm_id: RealmId,
    pub target_ref: String,
    pub report_reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<ModerationFrankingProof>,
    pub created_at: DateTime<Utc>,
}

impl ModerationReport {
    pub fn new(
        id: impl Into<String>,
        realm_id: RealmId,
        target_ref: impl Into<String>,
        report_reason_code: impl Into<String>,
        reporter: Did,
    ) -> Self {
        Self {
            schema: Some(MODERATION_REPORT_SCHEMA.to_owned()),
            report_id: id.into(),
            realm_id,
            target_ref: target_ref.into(),
            report_reason_code: report_reason_code.into(),
            description: None,
            reporter,
            evidence_refs: Vec::new(),
            franking_proof: None,
            created_at: now_utc_seconds(),
        }
    }
}

/// Moderation franking proof for E2EE content (moderation.md §3.4).
///
/// `franking_tag` MUST be a key-bound MAC of the reported ciphertext that
/// only the reporter could have produced; spec leaves the algorithm open
/// per profile — this struct just carries the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationFrankingProof {
    pub algorithm: String,
    pub franking_tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

/// Verification class returned by federation `verify_actor` (M-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FederationActorValidationClass {
    Valid,
    Stale,
    Unknown,
    Invalid,
}
