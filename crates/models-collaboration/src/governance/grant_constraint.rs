//! Grant constraint governance family, capability subject / grant wire
//! records, and the approval workflow mode vocabulary
//! (`grant-constraint.schema.json` / `capability.schema.json`).

use std::collections::BTreeMap;

use arkret_wire::serde_helpers::{canonical_timestamp, optional_canonical_timestamp};
use arkret_wire::{
    AppletId, CircleId, Did, EncryptionProfile, Error, EvaluationClass, Facet, GrantId, Hash,
    HistoryVisibility, PayloadProof, ProofContextId, RealmId, Result, WireError, XExtensionMap,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::resource_selector::WireResourceSelector;

/// Approval workflow mode (`grant-constraint.schema.json` /
/// `moderation.md`): when the approval gate runs relative to commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalWorkflowMode {
    BeforeCommit,
    AfterCommitReview,
    ProposalThenApprove,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CapabilitySubject {
    Did(Did),
    Selector(Value),
}

/// Grant constraint family discriminator from `grant-constraint.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintKind {
    Temporal,
    FieldAccess,
    KindRestriction,
    ScopeLimitation,
    AuthorityControl,
    Quota,
    ClaimBased,
    Confidentiality,
}

/// Grant constraint effect from `grant-constraint.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// Optional specialization discriminator inside a grant constraint family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintSubkind {
    Claim,
    Approval,
    Accountability,
    Rate,
    Resource,
    Encryption,
    Visibility,
    Window,
    EditWindow,
    RedactWindow,
    Session,
    AppletAuthority,
}

/// Quota counting scope from `grant-constraint.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintScope {
    PerActor,
    PerSpace,
    PerRealm,
    Global,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintRecurrenceFrequency {
    Daily,
    Weekly,
    Monthly,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintRecurrenceDay {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// Recurrence rule for temporal grant constraints.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraintRecurrence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency: Option<GrantConstraintRecurrenceFrequency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<GrantConstraintRecurrenceDay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Named condition predicate for grant constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintConditionKind {
    ObjectIsOwnedByActor,
    ActorIsAssignee,
    ActorIsResponsible,
    ActorIsGuardian,
    ActorIsController,
    ObjectInActorContainer,
    ObjectIsUnencrypted,
    ObjectIsEncrypted,
    Always,
    Never,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraintCondition {
    pub kind: GrantConstraintConditionKind,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintSensitiveHandling {
    Redact,
    Hash,
    Omit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantApprovalRelation {
    Responsible,
    Controller,
    Guardian,
    RealmAdmin,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantApprovalThreshold {
    Majority,
    Unanimous,
    Quorum,
    Custom,
}

/// Conditional claim requirement in a grant constraint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraintClaimRequirement {
    pub claim_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_matches_actor: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub value_constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobPresignPurpose {
    MediaInline,
    Thumbnail,
    Download,
}

/// Scope limiter for blob presign grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPresignScope {
    pub allowed_purposes: Vec<BlobPresignPurpose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_ref_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
}

/// Schema extension key for grant constraints.
///
/// `grant-constraint.schema.json` only allows top-level extension fields
/// matching `^x_[a-z][a-z0-9_]{0,63}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantConstraintExtensionKey(String);

impl GrantConstraintExtensionKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if grant_constraint_extension_key_is_valid(&value) {
            Ok(Self(value))
        } else {
            Err(Error::Protocol(format!(
                "invalid grant constraint extension key '{value}'"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Serialize for GrantConstraintExtensionKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GrantConstraintExtensionKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if grant_constraint_extension_key_is_valid(&value) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid grant constraint extension key '{value}'"
            )))
        }
    }
}

fn grant_constraint_extension_key_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 3 || bytes.len() > 66 || bytes[0] != b'x' || bytes[1] != b'_' {
        return false;
    }
    if !bytes[2].is_ascii_lowercase() {
        return false;
    }
    bytes[3..]
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Strong wire DTO for `grant-constraint.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_id: Option<String>,
    pub constraint_kind: GrantConstraintKind,
    pub effect: GrantConstraintEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_class: Option<EvaluationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_subkind: Option<GrantConstraintSubkind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<GrantConstraintRecurrence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_edit_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_redact_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redact_after_window_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<GrantConstraintCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_write_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_write_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_read_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_read_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive_handling: Option<GrantConstraintSensitiveHandling>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_object_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_object_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_morph_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_morph_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_space_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_space_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_strand_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_strand_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_space_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_space_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_circle_ids: Vec<CircleId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_session_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_renderers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_view_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_view_renderers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_relation_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_from_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_to_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_limit_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tracks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_tracks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_presign_scope: Option<BlobPresignScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_data_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_authority_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_path: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_regrant_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_expansion_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_reference_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_epoch: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_presign_max_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_blob_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_artifact_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operations: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_scope: Option<GrantConstraintScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_resources: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalWorkflowMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_actor_ids: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_relation: Option<GrantApprovalRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reject_on_timeout: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_morph_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_threshold: Option<GrantApprovalThreshold>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_claims: Vec<GrantConstraintClaimRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_claim_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_refresh_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_max_age: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_history_visibility_values: Vec<HistoryVisibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_history_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_encryption_level: Option<EncryptionProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_fallback_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_trail_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rotation_period: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_key_age: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_backup_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_key_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends_on_moderation_state: Option<bool>,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extensions: XExtensionMap,
}

impl GrantConstraint {
    pub fn new(constraint_kind: GrantConstraintKind, effect: GrantConstraintEffect) -> Self {
        Self {
            constraint_id: None,
            constraint_kind,
            effect,
            evaluation_class: None,
            constraint_subkind: None,
            applies_to_actions: Vec::new(),
            not_before: None,
            expires_at: None,
            recurrence: None,
            max_duration: None,
            max_session_duration: None,
            inactivity_timeout: None,
            expires_after: None,
            message_edit_window: None,
            message_redact_window: None,
            redact_after_window_allowed: None,
            condition: None,
            allowed_write_fields: Vec::new(),
            denied_write_fields: Vec::new(),
            allowed_read_fields: Vec::new(),
            denied_read_fields: Vec::new(),
            sensitive_fields: Vec::new(),
            sensitive_handling: None,
            allowed_object_kinds: Vec::new(),
            denied_object_kinds: Vec::new(),
            allowed_morph_kinds: Vec::new(),
            denied_morph_kinds: Vec::new(),
            allowed_space_kinds: Vec::new(),
            denied_space_kinds: Vec::new(),
            allowed_facets: Vec::new(),
            denied_facets: Vec::new(),
            allowed_view_ids: Vec::new(),
            allowed_strand_ids: Vec::new(),
            denied_strand_ids: Vec::new(),
            allowed_space_ids: Vec::new(),
            denied_space_ids: Vec::new(),
            allowed_circle_ids: Vec::new(),
            allowed_session_ids: Vec::new(),
            allowed_view_kinds: Vec::new(),
            allowed_view_renderers: Vec::new(),
            denied_view_kinds: Vec::new(),
            denied_view_renderers: Vec::new(),
            allowed_relation_kinds: Vec::new(),
            allowed_from_container_refs: Vec::new(),
            allowed_to_container_refs: Vec::new(),
            wip_limit_override: None,
            allowed_tracks: Vec::new(),
            denied_tracks: Vec::new(),
            blob_presign_scope: None,
            allowed_data_labels: Vec::new(),
            allowed_endpoints: Vec::new(),
            max_authority_depth: None,
            authority_path: Vec::new(),
            authority_regrant_allowed: None,
            authority_scope: None,
            scope_expansion_allowed: None,
            parent_reference_required: None,
            applet_id: None,
            executed_by: None,
            registration_epoch: None,
            blob_max_bytes: None,
            blob_presign_max_ttl_seconds: None,
            max_total_blob_bytes: None,
            max_artifact_bytes: None,
            max_operations: None,
            period: None,
            burst: None,
            constraint_scope: None,
            max_resources: None,
            resource_kind: None,
            approval_required: None,
            approval_mode: None,
            approval_actor_ids: Vec::new(),
            approval_relation: None,
            timeout: None,
            auto_reject_on_timeout: None,
            proposal_morph_kind: None,
            approval_threshold: None,
            approvers: Vec::new(),
            accountability_required: None,
            guardian_approval_required: None,
            controller_approval_required: None,
            required_claims: Vec::new(),
            trusted_claim_issuers: Vec::new(),
            claim_refresh_required: None,
            claim_max_age: None,
            allowed_history_visibility_values: Vec::new(),
            redacted_history_allowed: None,
            encryption_required: None,
            min_encryption_level: None,
            plaintext_fallback_allowed: None,
            audit_trail_required: None,
            key_rotation_period: None,
            max_key_age: None,
            key_backup_required: None,
            approved_key_issuers: Vec::new(),
            depends_on_moderation_state: None,
            extensions: XExtensionMap::default(),
        }
    }

    pub fn authority_control(max_authority_depth: u64, authority_regrant_allowed: bool) -> Self {
        let mut constraint = Self::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        constraint.max_authority_depth = Some(max_authority_depth);
        constraint.authority_regrant_allowed = Some(authority_regrant_allowed);
        constraint
    }

    /// Build the canonical Applet install grant binding from
    /// `constraint-schema.md` §7.3.
    pub fn applet_authority(
        applet_id: AppletId,
        executed_by: Did,
        registration_epoch: Hash,
    ) -> Self {
        let mut constraint = Self::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        constraint.evaluation_class = Some(EvaluationClass::GrantLocal);
        constraint.constraint_subkind = Some(GrantConstraintSubkind::AppletAuthority);
        constraint.applet_id = Some(applet_id);
        constraint.executed_by = Some(executed_by);
        constraint.registration_epoch = Some(registration_epoch);
        constraint
    }

    /// Schema-aligned scaffold examples for approval, claim, and container-move constraints.
    pub fn scaffold_examples() -> Vec<Self> {
        let mut approval = Self::new(
            GrantConstraintKind::ClaimBased,
            GrantConstraintEffect::RequireReview,
        );
        approval.constraint_subkind = Some(GrantConstraintSubkind::Approval);
        approval.denied_write_fields = vec!["assignee".to_owned(), "status".to_owned()];
        approval.allowed_object_kinds = vec!["strand".to_owned()];
        approval.allowed_view_ids = vec!["ak:view:01904100-0000-7000-8000-b74ef68eeddf".to_owned()];
        approval.allowed_relation_kinds = vec!["responsible".to_owned()];
        approval.wip_limit_override = Some(false);
        approval.denied_view_kinds = vec!["public_board".to_owned()];
        approval.allowed_tracks = vec!["discussion".to_owned()];
        approval.max_authority_depth = Some(1);
        approval.approval_required = Some(true);
        approval.approval_mode = Some(ApprovalWorkflowMode::BeforeCommit);
        approval.approval_actor_ids = vec![
            Did::new("did:webvh:z6mkfixture:controller.example").expect("scaffold DID is valid"),
            Did::new("did:webvh:z6mkfixture:guardian.example").expect("scaffold DID is valid"),
        ];
        approval.approval_relation = Some(GrantApprovalRelation::Controller);

        let mut claim = Self::new(
            GrantConstraintKind::ClaimBased,
            GrantConstraintEffect::Allow,
        );
        claim.constraint_subkind = Some(GrantConstraintSubkind::Claim);
        claim.allowed_object_kinds = vec!["key_backup".to_owned()];
        claim.allowed_facets = vec![Facet::Reviewable];
        claim.max_authority_depth = Some(0);
        claim.approval_required = Some(false);
        claim.required_claims = vec![GrantConstraintClaimRequirement {
            claim_kind: "recovery_operator".to_owned(),
            issuer: Some(
                Did::new("did:webvh:z6mkfixture:coauth.example").expect("scaffold DID is valid"),
            ),
            trusted_issuers: Vec::new(),
            subject_matches_actor: None,
            value_constraints: BTreeMap::new(),
            organization: Some(
                Did::new("did:webvh:z6mkfixture:example-org").expect("scaffold DID is valid"),
            ),
            status: Some("active".to_owned()),
            roles: vec!["backup_admin".to_owned()],
            extra: BTreeMap::new(),
        }];

        let mut container_move = Self::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Deny,
        );
        container_move.allowed_object_kinds = vec!["strand".to_owned()];
        container_move.allowed_from_container_refs = vec!["ak:list:triage".to_owned()];
        container_move.allowed_to_container_refs = vec!["ak:list:ready".to_owned()];
        container_move.wip_limit_override = Some(false);
        container_move.allowed_tracks = vec!["synthesis".to_owned()];
        container_move.denied_tracks = vec!["discussion".to_owned()];
        container_move.max_authority_depth = Some(0);
        container_move.approval_required = Some(true);
        container_move.approval_mode = Some(ApprovalWorkflowMode::ProposalThenApprove);
        container_move.approval_actor_ids =
            vec![Did::new("did:webvh:z6mkfixture:ops.example").expect("scaffold DID is valid")];
        container_move.approval_relation = Some(GrantApprovalRelation::Responsible);

        vec![approval, claim, container_move]
    }
}

/// One entry of a grant's `issuer_authority_refs[]`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IssuerAuthorityRef {
    /// A grant the issuer holds. The issuer MUST be its subject and the ref
    /// MUST be active when the child is evaluated.
    Grant { grant_id: GrantId },
    /// The Realm authority-root cell — a rooted terminal, never a graph edge.
    ///
    /// `controller_epoch_at_issuance` is issuance audit only: comparing it to
    /// the current epoch would make an owner transfer invalidate every grant
    /// the previous controller ever signed. `authority_generation` is the field
    /// that IS compared, because an authority reset advances it precisely so a
    /// whole tree stops resolving.
    RealmRoot {
        realm_id: RealmId,
        cell_ref: String,
        controller_epoch_at_issuance: u64,
        authority_generation: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: GrantId,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer: Did,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_action_registry_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    /// The authority this grant was issued under (`capabilities.md` §10).
    /// A `realm_root` entry is a rooted terminal; a `grant` entry is an edge.
    /// v1 has one grant shape, so this is the only thing that distinguishes a
    /// root controller's grant from a member re-granting what it holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_authority_refs: Vec<IssuerAuthorityRef>,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    pub proofs: Vec<PayloadProof>,
}

impl CapabilityGrant {
    /// RFC 8785 canonical bytes of the grant body covered by
    /// `proof.payload_digest`. The `proofs` carrier is excluded so adding the
    /// detached proof cannot recursively change the signed digest.
    pub fn canonical_payload_without_proofs(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("CapabilityGrant serializes as an object")
            .remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    /// `sha256:` digest committed by every capability-grant payload proof.
    pub fn payload_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            &self.canonical_payload_without_proofs()?,
        ))?)
    }

    /// Canonical `ak.capability-grant-proof-v1` transcript for one proof.
    pub fn canonical_proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest {
            return Err(WireError::Protocol(
                "capability grant proof payload_digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::from_iter([
            (
                "context".to_owned(),
                Value::String(ProofContextId::CAPABILITY_GRANT_PROOF_V1.to_owned()),
            ),
            (
                "payload_digest".to_owned(),
                serde_json::to_value(&payload_digest)?,
            ),
            ("issuer".to_owned(), serde_json::to_value(&self.issuer)?),
            ("subject".to_owned(), serde_json::to_value(&self.subject)?),
            (
                "verification_method".to_owned(),
                Value::String(proof.verification_method.as_str().to_owned()),
            ),
            (
                "created_at".to_owned(),
                Value::String(canonical::format_timestamp_canonical(proof.created_at)),
            ),
        ]);
        if let Some(domain) = &proof.domain {
            binding.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &proof.audience {
            binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(binding))?)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, PayloadProofPurpose};
    use serde_json::json;

    use super::*;

    #[test]
    fn capability_grant_accepts_omitted_optional_constraints() {
        let grant: CapabilityGrant = serde_json::from_value(json!({
            "id": "ak:grant:01904100-0000-7000-8000-000000000001",
            "schema": "ak.schema.capability.v1",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "issuer": "did:web:issuer.example",
            "subject": "did:web:subject.example",
            "actions": ["ak.event.read"],
            "resources": [{"kind": "realm"}],
            "issued_at": "2026-07-14T12:34:56.789Z",
            "proofs": []
        }))
        .expect("constraints are optional in capability-grant.schema.json");

        assert!(grant.constraints.is_empty());
    }

    #[test]
    fn applet_delegation_uses_registered_delegation_control_shape() {
        let constraint = GrantConstraint::applet_authority(
            AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            Did::new("did:web:calendar.example").unwrap(),
            Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        );
        let wire = serde_json::to_value(constraint).unwrap();

        assert_eq!(wire["constraint_kind"], "authority_control");
        assert_eq!(wire["constraint_subkind"], "applet_authority");
        assert_eq!(wire["evaluation_class"], "grant_local");
        assert_eq!(wire["executed_by"], "did:web:calendar.example");
        assert!(wire.get("applet_delegation_binding").is_none());
    }

    #[test]
    fn capability_grant_serializes_all_timestamps_canonically() {
        let fractional = DateTime::parse_from_rfc3339("2026-07-14T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut grant = CapabilityGrant {
            id: GrantId::new("ak:grant:01904100-0000-7000-8000-000000000001").unwrap(),
            schema: "ak.schema.capability.v1".to_owned(),
            realm_id: Some(RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()),
            issuer: Did::new("did:web:issuer.example").unwrap(),
            subject: CapabilitySubject::Did(Did::new("did:web:subject.example").unwrap()),
            actions: vec!["ak.event.read".to_owned()],
            resources: vec![serde_json::from_value(json!({"kind": "realm"})).unwrap()],
            capability_action_registry_digest: None,
            constraints: Vec::new(),
            issuer_authority_refs: Vec::new(),
            issued_at: fractional,
            not_before: Some(fractional),
            expires_at: Some(fractional),
            updated_by: None,
            updated_at: Some(fractional),
            revoked_by: None,
            revoked_at: Some(fractional),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: DidUrl::new("did:web:issuer.example#key-1").unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: fractional,
                domain: None,
                audience: None,
                proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
                jws: "header..signature".to_owned(),
            }],
        };

        let wire = serde_json::to_value(&grant).unwrap();
        for pointer in [
            "/issued_at",
            "/not_before",
            "/expires_at",
            "/updated_at",
            "/revoked_at",
            "/proofs/0/created_at",
        ] {
            assert_eq!(
                wire.pointer(pointer).and_then(Value::as_str),
                Some("2026-07-14T12:34:56.789Z")
            );
        }

        grant.proofs[0].created_at = DateTime::parse_from_rfc3339("2026-07-14T12:34:56.000Z")
            .unwrap()
            .with_timezone(&Utc);
        grant.proofs[0].payload_digest = grant.payload_digest().unwrap();
        let binding: Value = serde_json::from_slice(
            &grant
                .canonical_proof_binding_bytes(&grant.proofs[0])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(binding["created_at"], "2026-07-14T12:34:56.000Z");
    }
}
