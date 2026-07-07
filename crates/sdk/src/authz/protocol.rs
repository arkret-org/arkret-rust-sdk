use super::*;

/// Schema-aligned constraint family from `ck.schema.grant_constraint.v1`.
///
/// v1 uses 8 stable families plus the optional `subtype` field on
/// [`ProtocolGrantConstraint`] for evaluator-specific refinements:
///
/// - `temporal` with subtype `window`, `edit_window`, `redact_window`, or `session`
/// - `scope_limitation.container_move`
/// - `quota` with subtype `rate` or `resource`
/// - `claim_based` with subtype `claim`, `approval`, or `accountability`
/// - `confidentiality` with subtype `encryption` or `visibility`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantConstraintType {
    Temporal,
    FieldAccess,
    TypeRestriction,
    ScopeLimitation,
    DelegationControl,
    Quota,
    ClaimBased,
    Confidentiality,
}

/// Schema-aligned constraint effect from `ck.schema.grant_constraint.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantConstraintEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// Schema-aligned track selector inside grant constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantConstraintTrack {
    Synthesis,
    Discussion,
}

/// Schema-aligned approval relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantApprovalRelation {
    Responsible,
    Controller,
    Guardian,
    RealmAdmin,
    Custom,
}

/// Schema-aligned approval timing mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolGrantApprovalMode {
    BeforeCommit,
    ProposalThenApprove,
    AfterCommitReview,
}

/// Schema extension key for grant constraints.
///
/// `grant-constraint.schema.json` only allows top-level extension fields
/// matching `^x_[a-z][a-z0-9_]{0,63}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolGrantExtensionKey(String);

impl ProtocolGrantExtensionKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if protocol_extension_key_is_valid(&value) {
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

impl Serialize for ProtocolGrantExtensionKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProtocolGrantExtensionKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if protocol_extension_key_is_valid(&value) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid grant constraint extension key '{value}'"
            )))
        }
    }
}

fn protocol_extension_key_is_valid(value: &str) -> bool {
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

/// Schema-aligned claim requirement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGrantClaimRequirement {
    pub claim_kind: String,
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Schema-aligned grant-constraint facade used by REST/OpenAPI/scaffold surfaces.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGrantConstraint {
    pub constraint_type: ProtocolGrantConstraintType,
    /// Optional discriminator within a family. Standard values:
    /// `claim`, `approval`, `accountability`, `rate`, `resource`,
    /// `encryption`, `visibility`, `window`, `edit_window`, `redact_window`,
    /// or `session`. Implementations
    /// MAY require subtype for these families and fail closed on unknown
    /// values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    pub effect: ProtocolGrantConstraintEffect,
    /// Evaluation class per `constraint-schema.md` §2.1 / §2.3 — gates how
    /// aggressively the result may be cached. `Stateless` and `GrantLocal`
    /// constraints are safe for fast-path caching; `RealmState` requires
    /// re-evaluation on every frontier change; `External` (claim, policy
    /// server) MUST NOT be cached without an explicit TTL bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_class: Option<crate::EvaluationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_write_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_write_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_facets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_facets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_relation_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_from_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_to_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_limit_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_view_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tracks: Vec<ProtocolGrantConstraintTrack>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_tracks: Vec<ProtocolGrantConstraintTrack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ProtocolGrantApprovalMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_actor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_relation: Option<ProtocolGrantApprovalRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_claims: Vec<ProtocolGrantClaimRequirement>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<ProtocolGrantExtensionKey, Value>,
}

impl ProtocolGrantConstraint {
    /// Schema-aligned scaffold examples for approval/claim/container-move
    /// constraints introduced or expanded by the 2026-05-04 protocol delta.
    pub fn scaffold_examples() -> Vec<Self> {
        vec![
            Self {
                constraint_type: ProtocolGrantConstraintType::ClaimBased,
                subtype: Some("approval".to_owned()),
                effect: ProtocolGrantConstraintEffect::RequireReview,
                not_before: None,
                expires_at: None,
                allowed_write_fields: Vec::new(),
                denied_write_fields: vec!["assignee".to_owned(), "status".to_owned()],
                allowed_object_types: vec!["strand".to_owned()],
                denied_object_types: Vec::new(),
                allowed_morph_types: Vec::new(),
                denied_morph_types: Vec::new(),
                allowed_facets: Vec::new(),
                denied_facets: Vec::new(),
                allowed_view_ids: vec!["ck:view:01904100-0000-7000-8000-b74ef68eeddf".to_owned()],
                allowed_relation_kinds: vec!["responsible".to_owned()],
                allowed_from_container_refs: Vec::new(),
                allowed_to_container_refs: Vec::new(),
                wip_limit_override: Some(false),
                denied_view_kinds: vec!["public_board".to_owned()],
                allowed_tracks: vec![ProtocolGrantConstraintTrack::Discussion],
                denied_tracks: Vec::new(),
                max_delegation_depth: Some(1),
                approval_required: Some(true),
                approval_mode: Some(ProtocolGrantApprovalMode::BeforeCommit),
                approval_actor_ids: vec![
                    "did:webvh:z6mkfixture:controller.example".to_owned(),
                    "did:webvh:z6mkfixture:guardian.example".to_owned(),
                ],
                approval_relation: Some(ProtocolGrantApprovalRelation::Controller),
                requires_claims: Vec::new(),
                evaluation_class: None,
                extensions: BTreeMap::new(),
            },
            Self {
                constraint_type: ProtocolGrantConstraintType::ClaimBased,
                subtype: Some("claim".to_owned()),
                effect: ProtocolGrantConstraintEffect::Allow,
                not_before: None,
                expires_at: None,
                allowed_write_fields: Vec::new(),
                denied_write_fields: Vec::new(),
                allowed_object_types: vec!["key_backup".to_owned()],
                denied_object_types: Vec::new(),
                allowed_morph_types: Vec::new(),
                denied_morph_types: Vec::new(),
                allowed_facets: vec!["recovery".to_owned()],
                denied_facets: Vec::new(),
                allowed_view_ids: Vec::new(),
                allowed_relation_kinds: Vec::new(),
                allowed_from_container_refs: Vec::new(),
                allowed_to_container_refs: Vec::new(),
                wip_limit_override: None,
                denied_view_kinds: Vec::new(),
                allowed_tracks: Vec::new(),
                denied_tracks: Vec::new(),
                max_delegation_depth: Some(0),
                approval_required: Some(false),
                approval_mode: None,
                approval_actor_ids: Vec::new(),
                approval_relation: None,
                requires_claims: vec![ProtocolGrantClaimRequirement {
                    claim_kind: "recovery_operator".to_owned(),
                    issuer: "did:webvh:z6mkfixture:coauth.example".to_owned(),
                    organization: Some("example-org".to_owned()),
                    status: Some("active".to_owned()),
                    roles: vec!["backup_admin".to_owned()],
                    extra: BTreeMap::new(),
                }],
                evaluation_class: None,
                extensions: BTreeMap::new(),
            },
            Self {
                constraint_type: ProtocolGrantConstraintType::ScopeLimitation,
                subtype: None,
                effect: ProtocolGrantConstraintEffect::Deny,
                not_before: None,
                expires_at: None,
                allowed_write_fields: Vec::new(),
                denied_write_fields: Vec::new(),
                allowed_object_types: vec!["strand".to_owned()],
                denied_object_types: Vec::new(),
                allowed_morph_types: Vec::new(),
                denied_morph_types: Vec::new(),
                allowed_facets: Vec::new(),
                denied_facets: Vec::new(),
                allowed_view_ids: Vec::new(),
                allowed_relation_kinds: Vec::new(),
                allowed_from_container_refs: vec!["ck:list:triage".to_owned()],
                allowed_to_container_refs: vec!["ck:list:ready".to_owned()],
                wip_limit_override: Some(false),
                denied_view_kinds: Vec::new(),
                allowed_tracks: vec![ProtocolGrantConstraintTrack::Synthesis],
                denied_tracks: vec![ProtocolGrantConstraintTrack::Discussion],
                max_delegation_depth: Some(0),
                approval_required: Some(true),
                approval_mode: Some(ProtocolGrantApprovalMode::ProposalThenApprove),
                approval_actor_ids: vec!["did:webvh:z6mkfixture:ops.example".to_owned()],
                approval_relation: Some(ProtocolGrantApprovalRelation::Responsible),
                requires_claims: Vec::new(),
                evaluation_class: None,
                extensions: BTreeMap::new(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn approval_relation_uses_realm_admin_wire_value() {
        assert_eq!(
            serde_json::to_string(&ProtocolGrantApprovalRelation::RealmAdmin).unwrap(),
            "\"realm_admin\""
        );
        assert!(serde_json::from_str::<ProtocolGrantApprovalRelation>("\"space_admin\"").is_err());
    }

    #[test]
    fn grant_constraint_rejects_non_schema_extension_keys() {
        let value = json!({
            "constraint_type": "claim_based",
            "subtype": "approval",
            "effect": "require_review",
            "priority": 10
        });
        assert!(serde_json::from_value::<ProtocolGrantConstraint>(value).is_err());

        let value = json!({
            "constraint_type": "claim_based",
            "subtype": "approval",
            "effect": "require_review",
            "x_approval_profile": {"name": "ops"}
        });
        let parsed: ProtocolGrantConstraint = serde_json::from_value(value).unwrap();
        assert!(
            parsed
                .extensions
                .contains_key(&ProtocolGrantExtensionKey::new("x_approval_profile").unwrap())
        );
    }

    #[test]
    fn scaffold_examples_emit_schema_approval_modes() {
        let examples = ProtocolGrantConstraint::scaffold_examples();
        let serialized = serde_json::to_value(examples).unwrap();
        assert!(!serialized.to_string().contains("two_man_rule"));
        assert!(!serialized.to_string().contains("move_gate"));
    }
}
