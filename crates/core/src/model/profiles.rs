use super::*;

/// Standard track profile names.
pub const FLOW_TRACK_NAME_SYNTHESIS: &str = "synthesis";
pub const FLOW_TRACK_NAME_DISCUSSION: &str = "discussion";

/// Per-track configuration carried as the value side of the `Flow.tracks` map.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FlowTrackConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
}

impl FlowTrackConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Standard `synthesis` track config.
    pub fn synthesis() -> Self {
        Self::default()
    }

    /// Standard `discussion` track config.
    pub fn discussion() -> Self {
        Self { profile: Some("discussion".to_owned()), ..Self::default() }
    }

    /// Standard `discussion` track config marked as the Flow's primary entry point.
    pub fn discussion_primary() -> Self {
        Self { is_primary: Some(true), ..Self::discussion() }
    }

    /// Set the track as the Flow's primary entry point.
    pub fn primary(mut self) -> Self {
        self.is_primary = Some(true);
        self
    }

    /// Set a profile string.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }
}

/// Validate a `FlowTrack` map key against `^[a-z][a-z0-9_]{0,63}$`.
pub fn validate_flow_track_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(Error::Protocol("FlowTrack name must be 1..=64 chars".to_owned()));
    }
    let mut chars = name.chars();
    let first = chars
        .next()
        .ok_or_else(|| Error::Protocol("FlowTrack name must not be empty".to_owned()))?;
    if !first.is_ascii_lowercase() {
        return Err(Error::Protocol("FlowTrack name must start with [a-z]".to_owned()));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(Error::Protocol(format!(
                "FlowTrack name contains invalid character '{c}'"
            )));
        }
    }
    Ok(())
}

/// Resolve the primary track of a Flow.
pub fn resolve_primary_track<'a>(
    tracks: &'a BTreeMap<String, FlowTrackConfig>,
    profile_default: Option<&str>,
) -> Result<Option<(&'a String, &'a FlowTrackConfig)>> {
    let explicit: Vec<(&String, &FlowTrackConfig)> =
        tracks.iter().filter(|(_, cfg)| cfg.is_primary == Some(true)).collect();
    match explicit.len() {
        0 => {}
        1 => return Ok(Some(explicit[0])),
        _ => {
            return Err(Error::Protocol(
                "Flow has more than one track with is_primary=true".to_owned(),
            ));
        }
    }
    if let Some((k, v)) = tracks.get_key_value(FLOW_TRACK_NAME_SYNTHESIS) {
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

/// Morph object (data-structures.md §7).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Morph {
    pub schema: String,
    pub id: String,
    pub space_id: SpaceId,
    /// Round C47 (spec e10b6ad): authoritative schema set for Morph fields and
    /// transition validation. Reducers MUST validate Morph fields against
    /// exactly these refs (set-equal compare on `cx.morph.schema_migrate`);
    /// `morph_type` / `facets` are not a replacement. Defaults to empty on
    /// the wire while existing fixtures are migrated; new producers MUST
    /// populate at least one entry. TODO(C47 Lane A4 / B-soland-deep): make
    /// this non-empty + enforce set-equal compare.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    pub morph_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facets: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
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

impl Morph {
    pub fn new(
        id: impl Into<String>,
        space_id: SpaceId,
        morph_type: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            schema: MORPH_SCHEMA.to_owned(),
            id: id.into(),
            space_id,
            schema_refs: Vec::new(),
            morph_type: morph_type.into(),
            facets: BTreeMap::new(),
            title: None,
            summary: None,
            content: None,
            fields: BTreeMap::new(),
            state: Some(ObjectState::Active),
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Validate that `morph_type` does not use the reserved `cx.` prefix
    /// for unregistered types (data-structures.md §7).
    pub fn validate_morph_type(&self, registered_cx_types: &[&str]) -> Result<()> {
        if self.morph_type.starts_with("cx.")
            && !registered_cx_types.contains(&self.morph_type.as_str())
        {
            return Err(Error::Protocol(format!(
                "morph_type '{}' uses reserved cx. prefix without registration",
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
    /// Return whether new writes are allowed in this state.
    pub fn allows_writes(self) -> bool {
        matches!(self, AccountStatus::Active)
    }

    /// Return whether refresh / re-auth is the only allowed transition.
    pub fn requires_reauth(self) -> bool {
        matches!(self, AccountStatus::SoftLoggedOut | AccountStatus::Locked)
    }
}

/// Service implementation profile IDs surfaced by discovery / requirements.
pub const PROFILE_DIRECTORY_SERVICE: &str = "cx.profile.directory_service.v1";

/// Audit assurance class (encryption-and-audit.md §3.1; spec _todos A1–A9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuditAssurance {
    AttestedHardware,
    DisclosedPolicy,
}

/// Profile id constants for audit profiles (spec _todos A1).
pub const PROFILE_ATTESTED_AUDIT_E2EE: &str = "cx.profile.attested_audit.e2ee.v1";
pub const PROFILE_DISCLOSED_AUDIT_E2EE: &str = "cx.profile.disclosed_audit.e2ee.v1";

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
    /// audit mode (spec _todos A7).
    pub fn forbidden_marketing_terms(self) -> &'static [&'static str] {
        match self {
            AuditAssurance::AttestedHardware => &[],
            AuditAssurance::DisclosedPolicy => {
                &["cryptographically enforced", "tee-equivalent", "attested", "hardware-enforced"]
            }
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
    pub space_frontier: Vec<EventId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor_frontier: BTreeMap<Did, RywActorFrontierEntry>,
}

/// `cx.audit.ryw_receipt` event payload
/// (`audit-ryw-receipt.schema.json`, spec _todos A10).
///
/// Issued by an Events API node, witness, or peer Principal Server to
/// confirm a `cx.audit.accessed` envelope reached `accepted`. The Audit
/// Agent MUST gate plaintext release on receiving a receipt that meets
/// the Space's declared `audit_assurance`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuditRywReceipt {
    pub receipt_id: String,
    pub schema: String,
    pub issuer: Did,
    pub issuer_role: RywIssuerRole,
    pub audit_event_id: EventId,
    pub audit_event_digest: Hash,
    pub space_id: SpaceId,
    pub audit_actor_id: Did,
    pub frontier: RywFrontier,
    pub observed_at: DateTime<Utc>,
    pub receipt_independence: ReceiptIndependence,
    pub audit_assurance_class: AuditAssurance,
    pub proofs: Vec<Proof>,
}

impl AuditRywReceipt {
    /// Canonical schema id and event-kind constant for `cx.audit.ryw_receipt`.
    pub const SCHEMA: &'static str = "cx.schema.audit_ryw_receipt.v1";
    pub const EVENT_KIND: &'static str = "cx.audit.ryw_receipt";

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

/// Backup class for key backup envelopes (key-management.md §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
    External,
}

impl BackupClass {
    /// HKDF info string per key-management.md §7.2.
    pub fn hkdf_info(self, subdomain: &str) -> String {
        let class = match self {
            BackupClass::DidRecovery => "did_recovery",
            BackupClass::SecretStorage => "secret_storage",
            BackupClass::MlsHistory => "mls_history",
            BackupClass::External => "external",
        };
        format!("contrix-key-backup/{class}/{subdomain}/v1")
    }
}

/// Constraint evaluation class (constraint-schema.md §2.1, spec _todos B4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EvaluationClass {
    Stateless,
    GrantLocal,
    SpaceState,
    External,
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
    pub schema: String,
    pub id: String,
    pub space_id: SpaceId,
    pub target_ref: String,
    pub reason: String,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub franking: Option<ModerationFrank>,
    pub created_at: DateTime<Utc>,
}

impl ModerationReport {
    pub fn new(
        id: impl Into<String>,
        space_id: SpaceId,
        target_ref: impl Into<String>,
        reason: impl Into<String>,
        reporter: Did,
    ) -> Self {
        Self {
            schema: MODERATION_REPORT_SCHEMA.to_owned(),
            id: id.into(),
            space_id,
            target_ref: target_ref.into(),
            reason: reason.into(),
            reporter,
            evidence_refs: Vec::new(),
            franking: None,
            created_at: Utc::now(),
        }
    }
}

/// Moderation frank for E2EE content (moderation.md §3.4).
///
/// `franking_tag` MUST be a key-bound MAC of the reported ciphertext that
/// only the reporter could have produced; spec leaves the algorithm open
/// per profile — this struct just carries the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationFrank {
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
