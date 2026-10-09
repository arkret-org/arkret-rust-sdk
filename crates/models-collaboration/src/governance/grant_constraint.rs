//! Grant constraint governance family, capability subject / grant wire
//! records, and the approval workflow mode vocabulary
//! (`grant-constraint.schema.json` / `capability.schema.json`).

use std::collections::BTreeMap;

use arkret_wire::serde_helpers::{canonical_timestamp, optional_canonical_timestamp};
use arkret_wire::{
    AccountId, ActorId, AppletId, CircleId, DidCoreId, EncryptionProfile, EvaluationClass, EventId,
    Facet, GrantId, Hash, HistoryAccess, RealmId, Result, SchemaId, WireError,
    WireResourceSelector, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    Actor(ActorId),
    Condition(ConditionSubjectSelector),
}

/// Claim-based subject predicate from `capability-grant.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionSubjectSelector {
    pub kind: ConditionSubjectSelectorKind,
    pub required_claims: Vec<GrantConstraintClaimRequirement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionSubjectSelectorKind {
    Condition,
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

impl GrantConstraintKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Temporal => "temporal",
            Self::FieldAccess => "field_access",
            Self::KindRestriction => "kind_restriction",
            Self::ScopeLimitation => "scope_limitation",
            Self::AuthorityControl => "authority_control",
            Self::Quota => "quota",
            Self::ClaimBased => "claim_based",
            Self::Confidentiality => "confidentiality",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantApprovalThreshold {
    Majority,
    Unanimous,
    Count(std::num::NonZeroU64),
}

impl Default for GrantApprovalThreshold {
    fn default() -> Self {
        Self::Unanimous
    }
}

impl GrantApprovalThreshold {
    pub fn required_votes(self, eligible_approvers: u64) -> Option<u64> {
        if eligible_approvers == 0 {
            return None;
        }
        let required = match self {
            Self::Majority => eligible_approvers / 2 + 1,
            Self::Unanimous => eligible_approvers,
            Self::Count(count) => count.get(),
        };
        (required <= eligible_approvers).then_some(required)
    }
}

impl Serialize for GrantApprovalThreshold {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Majority => serializer.serialize_str("majority"),
            Self::Unanimous => serializer.serialize_str("unanimous"),
            Self::Count(count) => serializer.serialize_u64(count.get()),
        }
    }
}

impl<'de> Deserialize<'de> for GrantApprovalThreshold {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::String(value) if value == "majority" => Ok(Self::Majority),
            Value::String(value) if value == "unanimous" => Ok(Self::Unanimous),
            Value::Number(value) => value
                .as_u64()
                .and_then(std::num::NonZeroU64::new)
                .map(Self::Count)
                .ok_or_else(|| {
                    serde::de::Error::custom("approval threshold must be a positive integer")
                }),
            _ => Err(serde::de::Error::custom(
                "approval threshold must be majority, unanimous or a positive integer",
            )),
        }
    }
}

/// Conditional claim requirement in a grant constraint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraintClaimRequirement {
    pub claim_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuer_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_matches_actor: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub value_constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<DidCoreId>,
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
            Err(WireError::Protocol(format!(
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
    pub authority_path_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_regrant_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_managed_actor_roles: Vec<ManagedActorRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<ActorId>,
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
    pub approval_actor_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_relation: Option<GrantApprovalRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_threshold: Option<GrantApprovalThreshold>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_claims: Vec<GrantConstraintClaimRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_claim_issuer_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_refresh_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_max_age: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_history_access_values: Vec<HistoryAccess>,
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
    pub approved_key_issuer_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends_on_moderation_state: Option<bool>,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extensions: XExtensionMap,
}

impl GrantConstraint {
    pub const SCHEMA: &'static str = SchemaId::GRANT_CONSTRAINT_V1;
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
            authority_path_ids: Vec::new(),
            authority_regrant_allowed: None,
            allowed_managed_actor_roles: Vec::new(),
            authority_scope: None,
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
            approval_threshold: None,
            accountability_required: None,
            guardian_approval_required: None,
            controller_approval_required: None,
            required_claims: Vec::new(),
            trusted_claim_issuer_ids: Vec::new(),
            claim_refresh_required: None,
            claim_max_age: None,
            allowed_history_access_values: Vec::new(),
            redacted_history_allowed: None,
            encryption_required: None,
            min_encryption_level: None,
            plaintext_fallback_allowed: None,
            audit_trail_required: None,
            key_rotation_period: None,
            max_key_age: None,
            key_backup_required: None,
            approved_key_issuer_ids: Vec::new(),
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
        executed_by: ActorId,
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
}

/// One entry of a grant's `issuer_authority_refs[]`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IssuerAuthorityRef {
    /// Controller-bounded execution source. It requires current ownership and
    /// exact join generations and must never be used as a regrant parent.
    OwnedAgent {
        realm_id: RealmId,
        controller_account_id: AccountId,
        controller_join_event_id: EventId,
        agent_join_event_id: EventId,
    },
    /// A grant the issuer holds. The issuer MUST be its subject and the ref
    /// MUST be active when the child is evaluated.
    Grant { grant_id: GrantId },
    /// A Realm authority root accepted by the governing Station. The current
    /// result revision used at acceptance is Station-local state, not wire.
    RealmRoot {
        realm_id: RealmId,
        authority_event_ref: EventId,
        authority_generation: u64,
    },
}

/// Identity of one committed authority source reached by a grant.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityRootRef {
    OwnedAgent {
        realm_id: RealmId,
        controller_account_id: AccountId,
        controller_join_event_id: EventId,
        agent_join_event_id: EventId,
    },
    RealmRoot {
        realm_id: RealmId,
        authority_event_ref: EventId,
        authority_generation: u64,
    },
}

/// Reducer-derived lifecycle state of one capability grant current result.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityGrantStatus {
    Active,
    Revoked,
    Relinquished,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    pub id: GrantId,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer_id: ActorId,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    /// The authority this grant was issued under (`capabilities.md` §10).
    /// A `realm_root` entry is a rooted terminal; a `grant` entry is an edge.
    /// v1 has one grant shape, so this is the only thing that distinguishes a
    /// root controller's grant from a member re-granting what it holds.
    // Required by capability-grant.schema.json.  Do not add `default` or
    // `skip_serializing_if`: doing so lets a strongly typed grant silently
    // deserialize or serialize without its authority root/parent edge.
    pub issuer_authority_refs: Vec<IssuerAuthorityRef>,
    /// Absolute distance from a committed authority source. An owned Agent
    /// execution source has depth one and grants no Realm root control.
    pub authority_depth: u64,
    /// Canonically sorted, deduplicated authority sources reached through
    /// `issuer_authority_refs`. This is reducer-derived and never authored in
    /// the create body.
    pub authority_root_refs: Vec<AuthorityRootRef>,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    /// Station-derived lifecycle state. Producers cannot author this member;
    /// it is present on the materialized capability-grant current result.
    pub status: CapabilityGrantStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl CapabilityGrant {
    /// Original signer of this dedicated source, independent of current
    /// membership, lifecycle effectiveness or the controller's action rights.
    pub fn owned_agent_issuer(&self) -> Option<&AccountId> {
        let [
            IssuerAuthorityRef::OwnedAgent {
                realm_id,
                controller_account_id,
                ..
            },
        ] = self.issuer_authority_refs.as_slice()
        else {
            return None;
        };
        (self.realm_id.as_ref() == Some(realm_id)
            && self.issuer_id.as_account_id() == Some(controller_account_id))
        .then_some(controller_account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_approval_threshold_uses_the_eligible_roster() {
        assert_eq!(GrantApprovalThreshold::default().required_votes(3), Some(3));
        assert_eq!(GrantApprovalThreshold::Majority.required_votes(4), Some(3));
        assert_eq!(GrantApprovalThreshold::Majority.required_votes(0), None);
        let count: GrantApprovalThreshold = serde_json::from_value(serde_json::json!(2)).unwrap();
        assert_eq!(count.required_votes(3), Some(2));
        assert_eq!(count.required_votes(1), None);
        assert_eq!(serde_json::to_value(count).unwrap(), serde_json::json!(2));
        for value in [
            serde_json::json!("quorum"),
            serde_json::json!("custom"),
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            Value::Null,
        ] {
            assert!(serde_json::from_value::<GrantApprovalThreshold>(value).is_err());
        }
    }

    #[test]
    fn grant_constraint_rejects_retired_proposal_morph_kind() {
        let mut constraint = GrantConstraint::new(
            GrantConstraintKind::ClaimBased,
            GrantConstraintEffect::RequireReview,
        );
        constraint
            .extensions
            .insert("x_review_note", Value::Bool(true))
            .unwrap();
        let wire = serde_json::to_value(&constraint).unwrap();
        assert!(wire.get("proposal_morph_kind").is_none());
        assert_eq!(wire["x_review_note"], true);
        assert!(serde_json::from_value::<GrantConstraint>(wire.clone()).is_ok());

        let mut retired = wire;
        retired["proposal_morph_kind"] = Value::String("old_proposal".to_owned());
        assert!(serde_json::from_value::<GrantConstraint>(retired).is_err());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedActorRole {
    Bot,
    Ghost,
}
