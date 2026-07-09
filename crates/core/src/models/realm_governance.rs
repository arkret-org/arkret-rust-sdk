//! Realm governance typed payloads introduced by the R1.2 Realm/Space
//! boundary split (spec rounds R2 / R3).
//!
//! These types model the three new wire payloads that compose the
//! cross-Realm governance surface:
//!
//! - [`RealmLink`] — `ck.realm.link` payload. Typed link between two Realm boundaries, one of eight
//!   canonical [`RealmLinkKind`] values.
//! - [`RealmInheritancePolicy`] — `ck.realm.inheritance_policy` payload. Declares which policy
//!   names + capability bundles a child Realm inherits from a parent Realm, capped by `max_depth`.
//! - [`CapabilityDerived`] — `ck.capability.derived` payload. Records a capability that was derived
//!   by composing a parent Realm's grant with a child Realm's inheritance declaration.
//!
//! All three are wire-shape-only typed structs at this stage; the full
//! derive evaluation lives in the reducer's audit pipeline.

use super::*;

/// Wire field names used by effective moderation policy payloads.
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_REALM_ID: &str = "realm_id";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_INHERITANCE_MODE: &str = "inheritance_mode";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_INHERITANCE_CHAIN: &str = "inheritance_chain";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_LAYERS: &str =
    "organization_policy_layers";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_REALM_POLICY: &str = "realm_policy";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_EFFECTIVE_RULES: &str = "effective_rules";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_EFFECTIVE_RULES: &str =
    "organization_effective_rules";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL: &str =
    "override_requires_organization_approval";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_POLICY_MERGE_STRATEGY: &str =
    "policy_merge_strategy";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY: &str =
    "organization_policy_merge_strategy";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_FANOUT: &str = "fanout";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_FANOUT: &str =
    "organization_policy_fanout";

/// Canonical moderation policy merge strategy value for organization inheritance.
pub const REALM_MODERATION_POLICY_MERGE_STRATEGY_MOST_RESTRICTIVE: &str = "most_restrictive";

/// Canonical fanout source value for organization moderation policy projection.
pub const REALM_MODERATION_POLICY_FANOUT_SOURCE_ORGANIZATION_POLICY: &str = "organization_policy";

/// Wire code returned when a Realm moderation policy override needs organization approval.
pub const REALM_MODERATION_POLICY_WIRE_CODE_REQUIRES_ORGANIZATION_APPROVAL: &str =
    "requires_organization_approval";

/// Canonical link_kind values for `ck.realm.link`. The eight values
/// enumerate the typed cross-Realm relations the spec recognises after the
/// Realm/Space boundary split; link payloads MUST carry exactly one of
/// these. Wire form is snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkKind {
    /// Target Realm is the governing authority for source Realm.
    GovernedBy,
    /// Source Realm may be discovered by members of target Realm.
    DiscoverableFrom,
    /// Source Realm accepts join requests from target Realm's
    /// authenticated members.
    JoinGateFrom,
    /// Source Realm inherits policy from target Realm (paired with a
    /// `ck.realm.inheritance_policy` declaration).
    InheritsPolicyFrom,
    /// Source Realm is a confidential extension (sub-Realm with stricter
    /// confidentiality envelope) of the target Realm.
    ConfidentialExtensionOf,
    /// Source Realm mirrors target Realm's content for replication /
    /// disaster-recovery purposes.
    MirrorOf,
    /// Source Realm was split off from target Realm (governance fork).
    SplitFrom,
    /// Source Realm fully replaces target Realm (terminal: target is
    /// tombstoned in favour of source).
    Replaces,
}

impl RealmLinkKind {
    /// Stable string form used in cell_subject keys and wire payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GovernedBy => "governed_by",
            Self::DiscoverableFrom => "discoverable_from",
            Self::JoinGateFrom => "join_gate_from",
            Self::InheritsPolicyFrom => "inherits_policy_from",
            Self::ConfidentialExtensionOf => "confidential_extension_of",
            Self::MirrorOf => "mirror_of",
            Self::SplitFrom => "split_from",
            Self::Replaces => "replaces",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "governed_by" => Self::GovernedBy,
            "discoverable_from" => Self::DiscoverableFrom,
            "join_gate_from" => Self::JoinGateFrom,
            "inherits_policy_from" => Self::InheritsPolicyFrom,
            "confidential_extension_of" => Self::ConfidentialExtensionOf,
            "mirror_of" => Self::MirrorOf,
            "split_from" => Self::SplitFrom,
            "replaces" => Self::Replaces,
            _ => return None,
        })
    }

    /// The full enumeration of canonical kinds; useful for tests and
    /// admin tooling.
    pub fn all() -> &'static [RealmLinkKind] {
        &[
            Self::GovernedBy,
            Self::DiscoverableFrom,
            Self::JoinGateFrom,
            Self::InheritsPolicyFrom,
            Self::ConfidentialExtensionOf,
            Self::MirrorOf,
            Self::SplitFrom,
            Self::Replaces,
        ]
    }
}

/// Lifecycle status of a `ck.realm.link`. The link cell is `or_set`-keyed
/// by `(source_realm_id, target_realm_id, link_kind)`; status flips this
/// triple from `active` to `rejected` or `tombstoned` without producing
/// a new key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkStatus {
    Active,
    Rejected,
    Tombstoned,
}

impl RealmLinkStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rejected => "rejected",
            Self::Tombstoned => "tombstoned",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "active" => Self::Active,
            "rejected" => Self::Rejected,
            "tombstoned" => Self::Tombstoned,
            _ => return None,
        })
    }
}

/// Typed payload for the `ck.realm.link` event.
///
/// Cell family: `ck.component.realm.link.v1` (or_set lattice). Cell
/// subject key: `(realm_id, target_realm_id, link_kind)`. The reducer
/// resolves status flips by retaining the latest status per triple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmLinkPayload {
    /// Target Realm id (the link's "to" side). `source_realm_id` is the
    /// envelope `realm_id` and is therefore implicit.
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    #[serde(default = "default_link_status")]
    pub status: RealmLinkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional opaque commitment / proof reference linking this edge to
    /// an external attestation (e.g. governance approval, sub-Realm split
    /// transcript). Free-form per spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

fn default_link_status() -> RealmLinkStatus {
    RealmLinkStatus::Active
}

/// Direction filter used by the realm-link query API to scope the
/// returned edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkDirection {
    /// Edges where this Realm is the source — `realm_id == realm_id`.
    Outbound,
    /// Edges where this Realm is the target — `target_realm_id == realm_id`.
    Inbound,
    /// Both directions concatenated.
    #[default]
    Both,
}

impl RealmLinkDirection {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "outbound" => Self::Outbound,
            "inbound" => Self::Inbound,
            "both" => Self::Both,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkEntry {
    pub realm_id: RealmId,
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    pub status: RealmLinkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub type RealmLinkCreateRequestBody = RealmLinkPayload;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkList {
    pub realm_id: RealmId,
    pub direction: RealmLinkDirection,
    #[serde(default)]
    pub links: Vec<RealmLinkEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkMutationOutcome {
    pub realm_id: RealmId,
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    pub status: RealmLinkStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmEffectivePolicyInheritanceMode {
    Explicit,
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmEffectivePolicyOutcome {
    pub realm_id: RealmId,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub effective_policy: BTreeMap<String, Value>,
    #[serde(default)]
    pub inheritance_chain: Vec<RealmId>,
    pub inheritance_mode: RealmEffectivePolicyInheritanceMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLifecycleView {
    pub ok: bool,
    pub realm_id: RealmId,
    pub owner: Did,
    #[serde(default)]
    pub members: Vec<Did>,
    pub deleted: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmExport {
    pub schema: String,
    pub realm_id: RealmId,
    pub generated_at: DateTime<Utc>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub operations: Vec<BTreeMap<String, Value>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub events: Vec<BTreeMap<String, Value>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmModerationInheritanceMode {
    None,
    Organization,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmEffectiveModerationPolicy {
    pub realm_id: RealmId,
    pub inheritance_mode: RealmModerationInheritanceMode,
    #[serde(default)]
    pub inheritance_chain: Vec<Did>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub organization_policy_layers: Vec<BTreeMap<String, Value>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_policy: Option<BTreeMap<String, Value>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub effective_rules: Vec<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_requires_organization_approval: Option<bool>,
    /// content-moderation.md §7 — how the owning organizations' policy layers
    /// combine. A Realm that names more than one owning organization merges
    /// their layers most-restrictively (`most_restrictive`): a join / write is
    /// denied if ANY owning organization denies it, and a Realm override of an
    /// organization deny requires approval from every organization that denies
    /// the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_merge_strategy: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmModerationPolicyReplaceRequestBody {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub policy: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmModerationPolicyDocument {
    pub kind: String,
    pub realm_id: RealmId,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub policy: BTreeMap<String, Value>,
    pub updated_by: Did,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmPolicyServerOnTimeout {
    FailClosed,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmPolicyServerView {
    pub realm_id: RealmId,
    pub policy_server_did: Did,
    pub policy_server_url: String,
    pub cache_ttl_seconds: u64,
    pub timeout_ms: u64,
    pub on_timeout: RealmPolicyServerOnTimeout,
    pub updated_at: DateTime<Utc>,
    pub from_org_fallback: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmPolicyServerReplaceRequestBody {
    pub policy_server_did: Did,
    pub policy_server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<RealmPolicyServerOnTimeout>,
}

/// `lifecycle_phase` discriminator for a projected `ck.realm.organization`
/// relationship row
/// (`realm-organization-operations.schema.json#/$defs/lifecycle_phase`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationLifecyclePhase {
    /// Latest accepted statement for `(organization_id, relationship)` is
    /// `status=active` and within its validity window.
    VerifiedActive,
    /// The relationship has been revoked or is outside its validity window.
    RevokedOrExpired,
}

/// One projected `ck.realm.organization` relationship row surfaced by
/// `ck.self.realm_organization.query.list`. Mirrors the canonical
/// `realm_organization_payload` field order; `lifecycle_phase` is
/// reducer-derived. A row here is a projection only: an organization
/// relationship is only verified when `lifecycle_phase=verified_active`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipRow {
    pub statement_id: String,
    pub organization_id: Did,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_frontier_digest: Option<Hash>,
    pub issuer_role: RealmOrganizationIssuerRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
    pub lifecycle_phase: RealmOrganizationLifecyclePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Response DTO for `ck.self.realm_organization.query.list`
/// (`realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub relationships: Vec<RealmOrganizationRelationshipRow>,
    /// `owning_organizations` declared hints with no verified statement. These
    /// are unverified claims and MUST NOT be rendered as official / governed /
    /// endorsed.
    #[serde(default)]
    pub declared_organization_hints: Vec<Did>,
}

/// Typed payload for the `ck.realm.inheritance_policy` event.
///
/// Cell family: `ck.component.realm.inheritance_policy.v1` (cas-register).
/// Declares which policy names and capability bundles a Realm inherits
/// from a parent (source) Realm. The reducer rejects payloads with
/// `max_depth > 1` (the wire spec currently caps inheritance at depth 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmInheritancePolicy {
    /// Parent Realm whose policies / capabilities are being inherited.
    pub source_realm_id: RealmId,
    /// List of policy names (free-form strings per spec; reducer does no
    /// enum enforcement) inherited from `source_realm_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_policies: Vec<String>,
    /// Capability bundle identifiers inherited from `source_realm_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_capability_bundles: Vec<String>,
    /// Maximum inheritance depth. Wire spec currently caps this at 1;
    /// the reducer rejects payloads with `max_depth > 1`.
    #[serde(default = "default_inheritance_max_depth")]
    pub max_depth: u32,
}

fn default_inheritance_max_depth() -> u32 {
    1
}

impl RealmInheritancePolicy {
    /// Cap on `max_depth` enforced by the wire validator + soland
    /// reducer at this stage. Composite inheritance (depth > 1) is outside
    /// the current v1 cap.
    pub const MAX_DEPTH_CAP: u32 = 1;

    pub fn validate(&self) -> Result<()> {
        if self.max_depth == 0 {
            return Err(Error::Protocol(
                "realm.inheritance_policy.max_depth MUST be >= 1".to_owned(),
            ));
        }
        if self.max_depth > Self::MAX_DEPTH_CAP {
            return Err(Error::Protocol(format!(
                "realm.inheritance_policy.max_depth must be <= {} (current wire cap)",
                Self::MAX_DEPTH_CAP
            )));
        }
        Ok(())
    }
}

/// Typed payload for the `ck.capability.derived` event.
///
/// Cell family: `ck.component.capability.derived.v1` (cas-register keyed
/// by `capability_id`). Records a capability that was derived from
/// composing a parent Realm grant (`source_grant_ref`) with a child
/// Realm's inheritance declaration (`source_realm_inheritance_policy_ref`).
///
/// The full derive evaluation (verify the source grant, replay the
/// inheritance policy, project the resulting bundle) lives in the
/// reducer's audit pipeline. At schema level the soland reducer accepts
/// the payload + projects the cell so downstream consumers can introspect it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityDerived {
    pub capability_id: CapabilityId,
    pub source_grant_ref: EventRef,
    pub source_realm_inheritance_policy_ref: EventRef,
    /// Causal frontier (free-form string per spec event-kind-registry)
    /// that the derived capability is sealed against. Reducer treats
    /// this opaquely.
    pub causal_frontier: String,
    /// Optional declarative shape of the derived capability bundle.
    /// Reducer projects it through but doesn't introspect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_link_kind_roundtrip_covers_all_eight() {
        for kind in RealmLinkKind::all() {
            let s = kind.as_str();
            let parsed = RealmLinkKind::parse(s).unwrap_or_else(|| panic!("parse {s}"));
            assert_eq!(parsed, *kind);
        }
        // Total count: spec pins exactly eight canonical kinds.
        assert_eq!(RealmLinkKind::all().len(), 8);
    }

    #[test]
    fn realm_link_status_default_is_active() {
        let payload: RealmLinkPayload = serde_json::from_value(serde_json::json!({
            "target_realm_id": "ak:realm:01904100-0000-7000-8000-cfc039892036",
            "link_kind": "governed_by",
        }))
        .unwrap();
        assert_eq!(payload.status, RealmLinkStatus::Active);
    }

    #[test]
    fn realm_link_payload_serde_roundtrip() {
        let payload = RealmLinkPayload {
            target_realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            link_kind: RealmLinkKind::JoinGateFrom,
            status: RealmLinkStatus::Active,
            label: Some("compliance gate".to_owned()),
            commitment: Some("ak:event:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned()),
        };
        let v = serde_json::to_value(&payload).unwrap();
        let back: RealmLinkPayload = serde_json::from_value(v).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn realm_inheritance_policy_validate_rejects_excessive_depth() {
        let bad = RealmInheritancePolicy {
            source_realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 2,
        };
        assert!(bad.validate().is_err());

        let good = RealmInheritancePolicy {
            source_realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 1,
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn capability_derived_serde_roundtrip() {
        let cap = CapabilityDerived {
            capability_id: CapabilityId::new("ak:capability:01904100-0000-7000-8000-bbbbbbbbbbbb")
                .unwrap(),
            source_grant_ref: EventRef::new(
                "ak:event:01904100-0000-7000-8000-cccccccccccc".to_owned(),
                "authorized_by".to_owned(),
            ),
            source_realm_inheritance_policy_ref: EventRef::new(
                "ak:event:01904100-0000-7000-8000-dddddddddddd".to_owned(),
                "inherits_from".to_owned(),
            ),
            causal_frontier: "ak:frontier:02000000".to_owned(),
            bundle: Some(serde_json::json!({"capabilities": ["read", "write"]})),
        };
        let v = serde_json::to_value(&cap).unwrap();
        let back: CapabilityDerived = serde_json::from_value(v).unwrap();
        assert_eq!(back, cap);
    }
}

// ── SDK-ORG-06 — ck.realm.organization statement verifier ──────────────
//
// Stateless, injectable verification of a [`RealmOrganizationPayload`]
// relationship statement. This is the canonical organization-side check
// shared across soland / teabay / cotest so none of them re-implements the
// issuer-role / delegation / proof / validity-window / scope / revocation
// invariants. The helper performs NO product-side DB queries; the DID /
// delegation resolution it needs is injected via
// [`RealmOrganizationDelegationResolver`].
//
// `DateTime`/`Utc`/`Did`/`ObjectRef`/`RealmId`/`SignatureMaterial` and the
// `RealmOrganization*` payload enums are all in scope via `use super::*`.

/// Outcome of resolving an `authorization.delegation_ref` for a delegated
/// organization statement (`issuer_role` ∈ {governance_service,
/// account_authority}).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmOrganizationDelegation {
    /// Organization DID the delegation is anchored to. MUST equal the
    /// statement's `organization_id`; the helper rejects otherwise.
    pub organization_id: Did,
    /// Whether the delegation is currently live (not expired / not revoked).
    pub is_live: bool,
    /// Relationships the delegation's purpose authorizes. The statement's
    /// `relationship` MUST be covered.
    pub covered_relationships: Vec<RealmOrganizationRelationship>,
    /// Control scopes the delegation's purpose authorizes. The statement's
    /// `control_scopes` MUST be a subset.
    pub covered_control_scopes: Vec<RealmOrganizationControlScope>,
}

/// Injection hook resolving `authorization.delegation_ref` to a live
/// organization DID delegation. Production callers wire this to their DID /
/// delegation store; offline callers use [`NoDelegationResolver`] (which
/// fails closed for any delegated statement).
pub trait RealmOrganizationDelegationResolver {
    /// Resolve `delegation_ref`. Return `Ok(None)` when the reference does
    /// not resolve to any delegation (verification then fails closed).
    fn resolve_delegation(
        &self,
        delegation_ref: &ObjectRef,
        organization_id: &Did,
    ) -> Result<Option<RealmOrganizationDelegation>>;
}

/// Offline / test resolver: never resolves a delegation. Any statement whose
/// `issuer_role` requires a delegation fails closed when verified with this
/// resolver, so production callers MUST inject a real resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDelegationResolver;

impl RealmOrganizationDelegationResolver for NoDelegationResolver {
    fn resolve_delegation(
        &self,
        _delegation_ref: &ObjectRef,
        _organization_id: &Did,
    ) -> Result<Option<RealmOrganizationDelegation>> {
        Ok(None)
    }
}

/// Verify a [`RealmOrganizationPayload`] organization-side relationship
/// statement.
///
/// This checks, fail-closed:
/// 1. `realm_id` matches the enclosing `Event.realm_id` (`expected_realm_id`).
/// 2. issuer-role / delegation coupling: delegated roles (governance_service / account_authority)
///    MUST carry a `delegation_ref` that resolves (via `resolver`) to a live delegation anchored to
///    `organization_id` and covering the requested relationship + scopes; non-delegated roles MUST
///    NOT carry one.
/// 3. proof presence / structure (non-empty signature material).
/// 4. validity window: `not_before <= now < expires_at`.
/// 5. status / revocation consistency (`revoked` requires `revokes_statement_id`; `active` must not
///    carry it).
///
/// It does NOT verify the cryptographic signature bytes themselves (the
/// caller's crypto layer does that against `verification_method`); it
/// guarantees the statement is structurally and semantically authorized to
/// be evaluated. Error messages embed the spec wire error-code constant.
pub fn verify_realm_organization_statement<R>(
    payload: &RealmOrganizationPayload,
    expected_realm_id: &RealmId,
    now: DateTime<Utc>,
    resolver: &R,
) -> Result<()>
where
    R: RealmOrganizationDelegationResolver,
{
    // 1. realm binding.
    if &payload.realm_id != expected_realm_id {
        return Err(Error::Protocol(format!(
            "ak.realm.organization realm_id must equal Event.realm_id ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        )));
    }

    // 3. proof presence / structure (checked early; cheap and pure).
    let proof_ok = match &payload.authorization.proof {
        SignatureMaterial::NonEmptyString(s) => !s.trim().is_empty(),
        SignatureMaterial::Variant1(map) => !map.is_empty(),
    };
    if !proof_ok {
        return Err(Error::Protocol(format!(
            "ak.realm.organization authorization.proof must be present ({})",
            crate::ERROR_CODE_INVALID_SIGNATURE
        )));
    }

    // 2. issuer-role / delegation coupling.
    let role = payload.authorization.issuer_role;
    match (
        role.requires_delegation_ref(),
        &payload.authorization.delegation_ref,
    ) {
        (true, None) => {
            return Err(Error::Protocol(format!(
                "ak.realm.organization issuer_role requires delegation_ref ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }
        (false, Some(_)) => {
            return Err(Error::Protocol(format!(
                "ak.realm.organization delegation_ref only valid for delegated issuer_role ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }
        (true, Some(delegation_ref)) => {
            let delegation = resolver
                .resolve_delegation(delegation_ref, &payload.organization_id)?
                .ok_or_else(|| {
                    Error::Protocol(format!(
                        "ak.realm.organization delegation_ref did not resolve ({})",
                        crate::REASON_GRANT_REVOKED_UPSTREAM
                    ))
                })?;
            if !delegation.is_live {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation is not live ({})",
                    crate::REASON_GRANT_REVOKED_UPSTREAM
                )));
            }
            if delegation.organization_id != payload.organization_id {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation anchored to a different organization ({})",
                    crate::REASON_GRANT_EXCEEDS_ISSUER_AUTHORITY
                )));
            }
            if !delegation
                .covered_relationships
                .contains(&payload.relationship)
            {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation does not cover relationship ({})",
                    crate::REASON_GRANT_EXCEEDS_ISSUER_AUTHORITY
                )));
            }
            if !payload
                .control_scopes
                .iter()
                .all(|scope| delegation.covered_control_scopes.contains(scope))
            {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation does not cover all control_scopes ({})",
                    crate::REASON_GRANT_EXCEEDS_ISSUER_AUTHORITY
                )));
            }
        }
        (false, None) => {}
    }

    // 4. validity window.
    if payload.is_not_yet_valid(now) {
        return Err(Error::Protocol(format!(
            "ak.realm.organization statement is not yet valid ({})",
            crate::ERROR_CODE_FAILED_PRECONDITION
        )));
    }
    if payload.is_expired(now) {
        return Err(Error::Protocol(format!(
            "ak.realm.organization statement is expired ({})",
            crate::REASON_TTL_EXPIRED
        )));
    }

    // 5. status / revocation consistency.
    match payload.status {
        RealmOrganizationStatus::Revoked if payload.revokes_statement_id.is_none() => {
            Err(Error::Protocol(format!(
                "ak.realm.organization revoked status requires revokes_statement_id ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )))
        }
        RealmOrganizationStatus::Active if payload.revokes_statement_id.is_some() => {
            Err(Error::Protocol(format!(
                "ak.realm.organization active status must not carry revokes_statement_id ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )))
        }
        _ => Ok(()),
    }
}

/// Transcript discriminator for the bytes an organization-side proof signs over.
pub const ORGANIZATION_STATEMENT_TRANSCRIPT_KIND: &str = "ak.realm.organization.statement.v1";

/// Canonical transcript the organization-side proof signs over. Every statement
/// field except `authorization.proof` (the signature itself) and the redundant
/// `signed_at` is included, so a verifier can rebuild the exact bytes from the
/// wire statement. Optional fields are omitted when absent so the bytes are
/// stable.
#[derive(Debug, Serialize)]
struct OrganizationStatementTranscript<'a> {
    kind: &'a str,
    statement_id: &'a str,
    realm_id: &'a RealmId,
    organization_id: &'a Did,
    relationship: &'a RealmOrganizationRelationship,
    status: &'a RealmOrganizationStatus,
    control_scopes: &'a [RealmOrganizationControlScope],
    issued_at: &'a DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<&'a DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revokes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm_frontier_digest: Option<&'a Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_policy_ref: Option<&'a ObjectRef>,
    issuer: &'a Did,
    issuer_role: &'a RealmOrganizationIssuerRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_ref: Option<&'a ObjectRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_by: Option<&'a Did>,
}

/// Canonical bytes the organization-side `authorization.proof` signs over.
///
/// Both the issuing side (coauth) and the verifying side (soland) MUST derive
/// the signing input from this one function so the bytes are byte-identical.
/// The transcript binds every semantic field of the statement except the proof
/// itself, so a detached signature over these bytes authenticates the whole
/// statement. The signing key MUST be a verification method in the
/// `organization_id` DID document (`authorization.verification_method`); the
/// verifier resolves that document and checks the signature.
pub fn realm_organization_statement_signing_bytes(
    payload: &RealmOrganizationPayload,
) -> Result<Vec<u8>> {
    let authorization = &payload.authorization;
    let transcript = OrganizationStatementTranscript {
        kind: ORGANIZATION_STATEMENT_TRANSCRIPT_KIND,
        statement_id: &payload.statement_id,
        realm_id: &payload.realm_id,
        organization_id: &payload.organization_id,
        relationship: &payload.relationship,
        status: &payload.status,
        control_scopes: &payload.control_scopes,
        issued_at: &payload.issued_at,
        not_before: payload.not_before.as_ref(),
        expires_at: payload.expires_at.as_ref(),
        supersedes_statement_id: payload.supersedes_statement_id.as_ref(),
        revokes_statement_id: payload.revokes_statement_id.as_ref(),
        realm_frontier_digest: payload.realm_frontier_digest.as_ref(),
        organization_policy_ref: payload.organization_policy_ref.as_ref(),
        issuer: &authorization.issuer,
        issuer_role: &authorization.issuer_role,
        delegation_ref: authorization.delegation_ref.as_ref(),
        executed_by: authorization.executed_by.as_ref(),
    };
    canonical::canonical_json_bytes(&transcript)
}

#[cfg(test)]
mod realm_organization_verifier_tests {
    use chrono::TimeZone;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000010").unwrap()
    }

    fn org_did() -> Did {
        Did::new("did:webvh:example.test:orgs:org1".to_owned()).unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn active_payload() -> RealmOrganizationPayload {
        RealmOrganizationPayload {
            statement_id: "org-stmt-1".to_owned(),
            realm_id: realm_id(),
            organization_id: org_did(),
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Active,
            control_scopes: vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin,
            ],
            issued_at: now(),
            not_before: None,
            expires_at: None,
            supersedes_statement_id: None,
            revokes_statement_id: None,
            realm_frontier_digest: None,
            organization_policy_ref: None,
            authorization: RealmOrganizationAuthorization {
                issuer: org_did(),
                issuer_role: RealmOrganizationIssuerRole::OrganizationDid,
                verification_method: "did:webvh:example.test:orgs:org1#k1".to_owned(),
                delegation_ref: None,
                executed_by: None,
                signed_at: now(),
                proof: SignatureMaterial::NonEmptyString("c2ln".to_owned()),
            },
        }
    }

    fn live_delegation() -> RealmOrganizationDelegation {
        RealmOrganizationDelegation {
            organization_id: org_did(),
            is_live: true,
            covered_relationships: vec![RealmOrganizationRelationship::Owner],
            covered_control_scopes: vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin,
            ],
        }
    }

    struct FixedResolver(Option<RealmOrganizationDelegation>);
    impl RealmOrganizationDelegationResolver for FixedResolver {
        fn resolve_delegation(
            &self,
            _delegation_ref: &ObjectRef,
            _organization_id: &Did,
        ) -> Result<Option<RealmOrganizationDelegation>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn active_organization_did_statement_passes() {
        verify_realm_organization_statement(
            &active_payload(),
            &realm_id(),
            now(),
            &NoDelegationResolver,
        )
        .unwrap();
    }

    #[test]
    fn realm_id_mismatch_fails() {
        let other = RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000099").unwrap();
        assert!(
            verify_realm_organization_statement(
                &active_payload(),
                &other,
                now(),
                &NoDelegationResolver
            )
            .is_err()
        );
    }

    #[test]
    fn delegated_role_without_delegation_ref_fails() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn delegated_role_with_unresolvable_delegation_fails_closed() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::AccountAuthority;
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn delegated_role_with_live_covering_delegation_passes() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        verify_realm_organization_statement(
            &p,
            &realm_id(),
            now(),
            &FixedResolver(Some(live_delegation())),
        )
        .unwrap();
    }

    #[test]
    fn non_delegated_role_with_delegation_ref_fails() {
        let mut p = active_payload();
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn delegation_not_covering_scopes_fails() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        let mut delegation = live_delegation();
        delegation.covered_control_scopes = vec![RealmOrganizationControlScope::OfficialBadge];
        assert!(
            verify_realm_organization_statement(
                &p,
                &realm_id(),
                now(),
                &FixedResolver(Some(delegation))
            )
            .is_err()
        );
    }

    #[test]
    fn empty_proof_fails() {
        let mut p = active_payload();
        p.authorization.proof = SignatureMaterial::NonEmptyString("   ".to_owned());
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn expired_and_not_yet_valid_fail() {
        let mut expired = active_payload();
        expired.expires_at = Some(Utc.with_ymd_and_hms(2026, 6, 25, 6, 0, 0).unwrap());
        assert!(
            verify_realm_organization_statement(
                &expired,
                &realm_id(),
                now(),
                &NoDelegationResolver
            )
            .is_err()
        );

        let mut future = active_payload();
        future.not_before = Some(Utc.with_ymd_and_hms(2026, 6, 26, 0, 0, 0).unwrap());
        assert!(
            verify_realm_organization_statement(&future, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn revoked_requires_revokes_statement_id() {
        let mut p = active_payload();
        p.status = RealmOrganizationStatus::Revoked;
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
        p.revokes_statement_id = Some("org-stmt-0".to_owned());
        verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver).unwrap();
    }
}
