//! Realm governance typed payloads introduced by the R1.2 Realm/Space
//! boundary split (spec rounds R2 / R3).
//!
//! These types model the three new wire payloads that compose the
//! cross-Realm governance surface:
//!
//! - `RealmLink` — `ak.realm.link` payload. Typed link between two Realm boundaries, one of eight
//!   canonical [`RealmLinkKind`] values.
//! - [`RealmInheritancePolicy`] — `ak.realm.inheritance_policy` payload. Declares which policy
//!   names + capability bundles a child Realm inherits from a parent Realm, capped by `max_depth`.
//! - [`CapabilityDerived`] — `ak.capability.derived` payload. Records a capability that was derived
//!   by composing a parent Realm's grant with a child Realm's inheritance declaration.
//!
//! All three are wire-shape-only typed structs at this stage; the full
//! derive evaluation lives in the reducer's audit pipeline.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, DidCoreId, ErrorCode, GrantId, Hash, RealmId, ReasonCode, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
    RealmOrganizationStatus,
};
use crate::governance::grant_constraint::CapabilityGrant;
use crate::objects::realm_alias::RealmAlias;

pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_LAYERS: &str =
    "organization_policy_layers";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_EFFECTIVE_RULES: &str = "effective_rules";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_EFFECTIVE_RULES: &str =
    "organization_effective_rules";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_POLICY_MERGE_STRATEGY: &str =
    "policy_merge_strategy";
pub const REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY: &str =
    "organization_policy_merge_strategy";
/// Canonical link_kind values for `ak.realm.link`. The eight values
/// enumerate the typed cross-Realm relations the spec recognises after the
/// Realm/Space boundary split; link payloads MUST carry exactly one of
/// these. Wire form is snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmLinkKind {
    /// Target Realm is the governing authority for source Realm.
    GovernedBy,
    /// Source Realm may be discovered by member_ids of target Realm.
    DiscoverableFrom,
    /// Source Realm accepts join requests from target Realm's
    /// authenticated member_ids.
    JoinGateFrom,
    /// Source Realm inherits policy from target Realm (paired with a
    /// `ak.realm.inheritance_policy` declaration).
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

/// Lifecycle status of an `ak.realm.link` FSM cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

    /// Whether this status can be the first value written to an absent cell.
    pub fn is_initial(self) -> bool {
        REALM_LINK_INITIAL_STATES.contains(&self)
    }

    /// Whether this status is terminal under the canonical Realm Link FSM.
    pub fn is_terminal(self) -> bool {
        REALM_LINK_TERMINAL_STATES.contains(&self)
    }

    /// Whether the canonical transition matrix contains `self -> next`.
    pub fn can_transition_to(self, next: Self) -> bool {
        REALM_LINK_ALLOWED_TRANSITIONS.contains(&(self, next))
    }
}

/// States that may initialize an absent Realm Link cell.
pub const REALM_LINK_INITIAL_STATES: &[RealmLinkStatus] = &[
    RealmLinkStatus::Active,
    RealmLinkStatus::Rejected,
    RealmLinkStatus::Tombstoned,
];

/// Terminal states in the canonical Realm Link FSM.
pub const REALM_LINK_TERMINAL_STATES: &[RealmLinkStatus] = &[RealmLinkStatus::Tombstoned];

/// The complete canonical Realm Link transition matrix.
pub const REALM_LINK_ALLOWED_TRANSITIONS: &[(RealmLinkStatus, RealmLinkStatus)] = &[
    (RealmLinkStatus::Active, RealmLinkStatus::Active),
    (RealmLinkStatus::Active, RealmLinkStatus::Rejected),
    (RealmLinkStatus::Active, RealmLinkStatus::Tombstoned),
    (RealmLinkStatus::Rejected, RealmLinkStatus::Rejected),
    (RealmLinkStatus::Rejected, RealmLinkStatus::Active),
    (RealmLinkStatus::Rejected, RealmLinkStatus::Tombstoned),
    (RealmLinkStatus::Tombstoned, RealmLinkStatus::Tombstoned),
];

/// Typed payload for the `ak.realm.link` event.
///
/// Cell family: `ak.component.realm.link.v1` (`fsm` / `reject`). Cell
/// subject key: `(target_realm_id, link_kind)` inside the envelope Realm.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmLinkPayload {
    /// Target Realm id (the link's "to" side). `source_realm_id` is the
    /// envelope `realm_id` and is therefore implicit.
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    pub status: RealmLinkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional opaque commitment / proof reference linking this edge to
    /// an external attestation (e.g. governance approval, sub-Realm split
    /// transcript). Free-form per spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

/// A sealed Realm Link write and the canonical bytes needed to distinguish an
/// exact replay from a conflicting sibling at the same basis.
#[derive(Clone, Copy, Debug)]
pub struct RealmLinkTransitionCandidate<'a> {
    pub payload: &'a RealmLinkPayload,
    pub canonical_move_bytes: &'a [u8],
    pub canonical_basis_bytes: &'a [u8],
}

/// Canonical outcome of evaluating a Realm Link write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealmLinkTransitionOutcome {
    Apply,
    IdempotentReplay,
    Bottom,
}

/// Canonical admission errors for Realm Link writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealmLinkTransitionError {
    #[error("Realm Link target must differ from its enclosing Realm")]
    SelfReference,
    #[error("Realm Link transition from {from:?} to {to:?} is not allowed")]
    InvalidTransition {
        from: RealmLinkStatus,
        to: RealmLinkStatus,
    },
}

impl RealmLinkTransitionError {
    /// Top-level error code required by the protocol error mapping.
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::SelfReference => ErrorCode::SchemaViolation,
            Self::InvalidTransition { .. } => ErrorCode::FailedPrecondition,
        }
    }

    /// Stable reason code required by the protocol error mapping.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::SelfReference => ReasonCode::REALM_LINK_SELF_REFERENCE,
            Self::InvalidTransition { .. } => ReasonCode::REALM_LINK_INVALID_TRANSITION,
        }
    }
}

/// Evaluate a Realm Link write against its currently accepted head.
///
/// Exact move-byte replay at the same canonical basis is idempotent. Any other
/// same-basis sibling is Bottom. A write on a later basis must follow the
/// canonical FSM; terminal tombstones cannot be rewritten.
pub fn evaluate_realm_link_transition(
    source_realm_id: &RealmId,
    current: Option<RealmLinkTransitionCandidate<'_>>,
    candidate: RealmLinkTransitionCandidate<'_>,
) -> std::result::Result<RealmLinkTransitionOutcome, RealmLinkTransitionError> {
    if source_realm_id == &candidate.payload.target_realm_id {
        return Err(RealmLinkTransitionError::SelfReference);
    }

    let Some(current) = current else {
        debug_assert!(candidate.payload.status.is_initial());
        return Ok(RealmLinkTransitionOutcome::Apply);
    };

    if current.canonical_basis_bytes == candidate.canonical_basis_bytes {
        return if current.canonical_move_bytes == candidate.canonical_move_bytes {
            Ok(RealmLinkTransitionOutcome::IdempotentReplay)
        } else {
            Ok(RealmLinkTransitionOutcome::Bottom)
        };
    }

    let from = current.payload.status;
    let to = candidate.payload.status;
    if from.is_terminal() || !from.can_transition_to(to) {
        return Err(RealmLinkTransitionError::InvalidTransition { from, to });
    }

    Ok(RealmLinkTransitionOutcome::Apply)
}

/// Direction filter used by the realm-link query API to scope the
/// returned edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// `realm-link-operations.schema.json#/$defs/realm_link_list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkList {
    pub realm_id: RealmId,
    pub direction: RealmLinkDirection,
    #[serde(default)]
    pub links: Vec<RealmLinkEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmEffectivePolicyInheritanceMode {
    Explicit,
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmEffectivePolicyOutcome {
    pub realm_id: RealmId,
    pub effective_policy: BTreeMap<String, Value>,
    #[serde(default)]
    pub inheritance_chain_ids: Vec<RealmId>,
    pub inheritance_mode: RealmEffectivePolicyInheritanceMode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmLifecycleView {
    pub realm_id: RealmId,
    pub owner_id: DidCoreId,
    #[serde(default)]
    pub member_ids: Vec<ActorId>,
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
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub freeze_expires_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmExport {
    pub schema: RealmExportSchema,
    pub realm_id: RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub generated_at: DateTime<Utc>,
    pub operations: Vec<BTreeMap<String, Value>>,
    pub events: Vec<BTreeMap<String, Value>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum RealmExportSchema {
    #[serde(rename = "ak.export.realm.v1")]
    V1,
}

/// Wire counterpart:
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_alias_declaration`.
///
/// `ak.realm.alias` declaration — the ONLY wire carrier of a Realm alias.
///
/// `realm.schema.json` is a closed object with no `alias` property, and
/// Realm genesis/profile payloads MUST NOT carry one
/// (`discovery/object-addressing.md` §3.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAliasDeclarationPayload {
    pub alias: RealmAlias,
}

/// `ak.realm.alias` durable value tombstone: releases the alias without
/// erasing cell history. Effective resolution then treats the Realm as
/// addressable only by `realm_id`.
/// Wire counterpart:
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_alias_tombstone`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAliasTombstonePayload {
    pub tombstone: bool,
}

impl RealmAliasTombstonePayload {
    pub const VALUE: Self = Self { tombstone: true };

    pub fn validate(self) -> Result<Self> {
        if self.tombstone {
            Ok(self)
        } else {
            Err(WireError::Protocol(
                "realm alias tombstone MUST be true".to_owned(),
            ))
        }
    }
}

/// Closed `ak.realm.alias` payload: declaration or exact value tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmAliasPayload {
    Declaration(RealmAliasDeclarationPayload),
    Tombstone(RealmAliasTombstonePayload),
}

impl RealmAliasPayload {
    pub fn declaration(alias: RealmAlias) -> Self {
        Self::Declaration(RealmAliasDeclarationPayload { alias })
    }

    pub const fn tombstone() -> Self {
        Self::Tombstone(RealmAliasTombstonePayload::VALUE)
    }

    /// Effective alias carried by this payload; `None` for a tombstone.
    pub fn alias(&self) -> Option<&RealmAlias> {
        match self {
            Self::Declaration(declaration) => Some(&declaration.alias),
            Self::Tombstone(_) => None,
        }
    }

    /// Reject a `{"tombstone": false}` shape, which is neither form.
    pub fn validate(self) -> Result<Self> {
        match self {
            Self::Declaration(_) => Ok(self),
            Self::Tombstone(tombstone) => tombstone.validate().map(Self::Tombstone),
        }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm alias payload serialize: {err}")))
    }
}

/// `lifecycle_phase` discriminator for a projected `ak.realm.organization`
/// relationship row
/// (`realm-organization-operations.schema.json#/$defs/lifecycle_phase`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationLifecyclePhase {
    /// Latest accepted statement for `(organization_id, relationship)` is
    /// `status=active` and within its validity window.
    VerifiedActive,
    /// The relationship has been revoked or is outside its validity window.
    RevokedOrExpired,
}

/// Typed payload for the `ak.realm.inheritance_policy` event.
///
/// Cell family: `ak.component.realm.inheritance_policy.v1` (cas-register).
/// Declares which policy names and capability bundles a Realm inherits
/// from a parent (source) Realm. The reducer rejects payloads with
/// `max_depth > 1` (the wire spec currently caps inheritance at depth 1).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            return Err(WireError::Protocol(
                "realm.inheritance_policy.max_depth MUST be >= 1".to_owned(),
            ));
        }
        if self.max_depth > Self::MAX_DEPTH_CAP {
            return Err(WireError::Protocol(format!(
                "realm.inheritance_policy.max_depth must be <= {} (current wire cap)",
                Self::MAX_DEPTH_CAP
            )));
        }
        Ok(())
    }
}

/// Typed payload for the `ak.capability.derived` event.
///
/// Cell family: `ak.component.capability.derived.v1` (OR-set keyed by
/// `grant_id`). The complete projected grant preserves its exact issuer and
/// subject identities and names its source grant through
/// `grant.issuer_authority_refs`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDerived {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub grant: CapabilityGrant,
    pub grant_id: GrantId,
}

/// One projected `ak.realm.organization` relationship row surfaced by
/// `ak.self.realm_organization.read.list.v1`. Mirrors the canonical
/// `realm_organization_payload` field order; `lifecycle_phase` is
/// reducer-derived. A row here is a projection only: an organization
/// relationship is only verified when `lifecycle_phase=verified_active`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipRow {
    pub statement_id: String,
    pub organization_id: DidCoreId,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Response DTO for `ak.self.realm_organization.read.list.v1`
/// (`realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub relationships: Vec<RealmOrganizationRelationshipRow>,
    /// `owning_organization_ids` declared hints with no verified statement. These
    /// are unverified claims and MUST NOT be rendered as official / governed /
    /// endorsed.
    #[serde(default)]
    pub declared_organization_hint_ids: Vec<DidCoreId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(byte: char) -> RealmId {
        RealmId::from_event_id(
            &arkret_wire::EventId::from_event_digest(
                &Hash::new(arkret_canonical::sha256_digest(byte.to_string())).unwrap(),
            )
            .unwrap(),
        )
    }

    fn link_payload(target_realm_id: RealmId, status: RealmLinkStatus) -> RealmLinkPayload {
        RealmLinkPayload {
            target_realm_id,
            link_kind: RealmLinkKind::GovernedBy,
            status,
            label: None,
            commitment: None,
        }
    }

    #[test]
    fn realm_organization_relationship_list_uses_canonical_relationships_field() {
        let value = serde_json::to_value(RealmOrganizationRelationshipList {
            realm_id: realm('o'),
            relationships: Vec::new(),
            declared_organization_hint_ids: Vec::new(),
        })
        .unwrap();

        assert!(value.get("relationships").is_some());
        assert!(value.get("realm_organization_relationship_rows").is_none());
        serde_json::from_value::<RealmOrganizationRelationshipList>(value).unwrap();
    }

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
    fn realm_link_status_is_required_in_the_signed_payload() {
        assert!(
            serde_json::from_value::<RealmLinkPayload>(serde_json::json!({
                "target_realm_id": "ak:realm:AUIDHR-4MyDvxQx3OgxqW_dIB1bGA6V3G5iIYL3wd8A9",
                "link_kind": "governed_by",
            }))
            .is_err()
        );
    }

    #[test]
    fn realm_link_fsm_matrix_matches_the_normative_vector() {
        assert_eq!(
            REALM_LINK_INITIAL_STATES,
            &[
                RealmLinkStatus::Active,
                RealmLinkStatus::Rejected,
                RealmLinkStatus::Tombstoned,
            ]
        );
        assert_eq!(REALM_LINK_ALLOWED_TRANSITIONS.len(), 7);
        assert_eq!(REALM_LINK_TERMINAL_STATES, &[RealmLinkStatus::Tombstoned]);
        assert!(
            REALM_LINK_INITIAL_STATES
                .iter()
                .all(|state| state.is_initial())
        );
        assert!(
            REALM_LINK_ALLOWED_TRANSITIONS
                .iter()
                .all(|(from, to)| from.can_transition_to(*to))
        );
    }

    #[test]
    fn realm_link_fsm_accepts_all_initial_states_and_non_terminal_transitions() {
        let source = realm('1');
        let target = realm('2');

        for status in REALM_LINK_INITIAL_STATES {
            let payload = link_payload(target.clone(), *status);
            let outcome = evaluate_realm_link_transition(
                &source,
                None,
                RealmLinkTransitionCandidate {
                    payload: &payload,
                    canonical_move_bytes: b"initial",
                    canonical_basis_bytes: b"basis-0",
                },
            )
            .unwrap();
            assert_eq!(outcome, RealmLinkTransitionOutcome::Apply);
        }

        for (from, to) in REALM_LINK_ALLOWED_TRANSITIONS {
            if from.is_terminal() {
                continue;
            }
            let current_payload = link_payload(target.clone(), *from);
            let candidate_payload = link_payload(target.clone(), *to);
            let outcome = evaluate_realm_link_transition(
                &source,
                Some(RealmLinkTransitionCandidate {
                    payload: &current_payload,
                    canonical_move_bytes: b"current",
                    canonical_basis_bytes: b"basis-1",
                }),
                RealmLinkTransitionCandidate {
                    payload: &candidate_payload,
                    canonical_move_bytes: b"candidate",
                    canonical_basis_bytes: b"basis-2",
                },
            )
            .unwrap();
            assert_eq!(outcome, RealmLinkTransitionOutcome::Apply);
        }
    }

    #[test]
    fn realm_link_replay_and_same_basis_siblings_are_deterministic() {
        let source = realm('1');
        let target = realm('2');
        let current_payload = link_payload(target.clone(), RealmLinkStatus::Active);
        let replay_payload = current_payload.clone();
        let sibling_payload = link_payload(target, RealmLinkStatus::Rejected);
        let current = RealmLinkTransitionCandidate {
            payload: &current_payload,
            canonical_move_bytes: b"same-move",
            canonical_basis_bytes: b"same-basis",
        };

        assert_eq!(
            evaluate_realm_link_transition(
                &source,
                Some(current),
                RealmLinkTransitionCandidate {
                    payload: &replay_payload,
                    canonical_move_bytes: b"same-move",
                    canonical_basis_bytes: b"same-basis",
                },
            )
            .unwrap(),
            RealmLinkTransitionOutcome::IdempotentReplay
        );
        assert_eq!(
            evaluate_realm_link_transition(
                &source,
                Some(current),
                RealmLinkTransitionCandidate {
                    payload: &sibling_payload,
                    canonical_move_bytes: b"different-move",
                    canonical_basis_bytes: b"same-basis",
                },
            )
            .unwrap(),
            RealmLinkTransitionOutcome::Bottom
        );
    }

    #[test]
    fn realm_link_tombstone_is_terminal_except_exact_replay() {
        let source = realm('1');
        let target = realm('2');
        let current_payload = link_payload(target, RealmLinkStatus::Tombstoned);
        let next_payload = current_payload.clone();
        let current = RealmLinkTransitionCandidate {
            payload: &current_payload,
            canonical_move_bytes: b"tombstone",
            canonical_basis_bytes: b"basis-1",
        };

        assert_eq!(
            evaluate_realm_link_transition(
                &source,
                Some(current),
                RealmLinkTransitionCandidate {
                    payload: &next_payload,
                    canonical_move_bytes: b"tombstone",
                    canonical_basis_bytes: b"basis-1",
                },
            )
            .unwrap(),
            RealmLinkTransitionOutcome::IdempotentReplay
        );

        let error = evaluate_realm_link_transition(
            &source,
            Some(current),
            RealmLinkTransitionCandidate {
                payload: &next_payload,
                canonical_move_bytes: b"new-tombstone",
                canonical_basis_bytes: b"basis-2",
            },
        )
        .unwrap_err();
        assert_eq!(error.error_code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            error.reason_code(),
            ReasonCode::REALM_LINK_INVALID_TRANSITION
        );
    }

    #[test]
    fn realm_link_rejects_only_self_reference_not_general_graph_cycles() {
        let source = realm('1');
        let target = realm('2');
        let valid_payload = link_payload(target, RealmLinkStatus::Active);
        assert_eq!(
            evaluate_realm_link_transition(
                &source,
                None,
                RealmLinkTransitionCandidate {
                    payload: &valid_payload,
                    canonical_move_bytes: b"cycle-edge-is-allowed",
                    canonical_basis_bytes: b"basis",
                },
            )
            .unwrap(),
            RealmLinkTransitionOutcome::Apply
        );

        let self_link = link_payload(source.clone(), RealmLinkStatus::Active);
        let error = evaluate_realm_link_transition(
            &source,
            None,
            RealmLinkTransitionCandidate {
                payload: &self_link,
                canonical_move_bytes: b"self-link",
                canonical_basis_bytes: b"basis",
            },
        )
        .unwrap_err();
        assert_eq!(error.error_code(), ErrorCode::SchemaViolation);
        assert_eq!(error.reason_code(), ReasonCode::REALM_LINK_SELF_REFERENCE);
    }

    #[test]
    fn realm_link_payload_serde_roundtrip() {
        let payload = RealmLinkPayload {
            target_realm_id: RealmId::new("ak:realm:AUIDHR-4MyDvxQx3OgxqW_dIB1bGA6V3G5iIYL3wd8A9")
                .unwrap(),
            link_kind: RealmLinkKind::JoinGateFrom,
            status: RealmLinkStatus::Active,
            label: Some("compliance gate".to_owned()),
            commitment: Some("ak:event:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned()),
        };
        let v = serde_json::to_value(&payload).unwrap();
        let back: RealmLinkPayload = serde_json::from_value(v).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn realm_inheritance_policy_validate_rejects_excessive_depth() {
        let bad = RealmInheritancePolicy {
            source_realm_id: RealmId::new("ak:realm:AUIDHR-4MyDvxQx3OgxqW_dIB1bGA6V3G5iIYL3wd8A9")
                .unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 2,
        };
        assert!(bad.validate().is_err());

        let good = RealmInheritancePolicy {
            source_realm_id: RealmId::new("ak:realm:AUIDHR-4MyDvxQx3OgxqW_dIB1bGA6V3G5iIYL3wd8A9")
                .unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 1,
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn capability_derived_serde_roundtrip() {
        let value = serde_json::json!({
            "grant": {
                "id": "ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
                "schema": "ak.schema.capability.v1",
                "realm_id": "ak:realm:AUIDHR-4MyDvxQx3OgxqW_dIB1bGA6V3G5iIYL3wd8A9",
                "issuer_id": {
                    "kind": "service",
                    "service_id": "ak:did_core:web:reducer.example"
                },
                "subject": {
                    "kind": "service",
                    "service_id": "ak:did_core:web:subject.example"
                },
                "actions": ["ak.event.read"],
                "resources": [{"kind": "realm"}],
                "issuer_authority_refs": [{
                    "kind": "grant",
                    "grant_id": "ak:grant:ARle858WIq1Q6tyqPUeacCaK06rWbVcvzG37T12U0-yi"
                }],
                "issued_at": "2026-09-03T00:00:00.000Z"
            },
            "grant_id": "ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM"
        });
        let decoded: CapabilityDerived = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    }

    #[test]
    fn realm_alias_payload_is_closed_to_declaration_or_tombstone() {
        let declaration =
            RealmAliasPayload::declaration(RealmAlias::parse("general:acme.example").unwrap());
        assert_eq!(
            declaration.to_value().unwrap(),
            serde_json::json!({"alias": "general:acme.example"})
        );
        assert_eq!(
            RealmAliasPayload::tombstone().to_value().unwrap(),
            serde_json::json!({"tombstone": true})
        );
        assert!(RealmAliasPayload::tombstone().alias().is_none());

        // Both shapes at once matches neither arm.
        assert!(
            serde_json::from_value::<RealmAliasPayload>(serde_json::json!({
                "alias": "general:acme.example",
                "tombstone": true
            }))
            .is_err()
        );
        // The `#` share sigil is display-only and never reaches the wire.
        assert!(
            serde_json::from_value::<RealmAliasPayload>(
                serde_json::json!({"alias": "#general:acme.example"})
            )
            .is_err()
        );
        // A bare localpart is not a canonical alias.
        assert!(
            serde_json::from_value::<RealmAliasPayload>(serde_json::json!({"alias": "general"}))
                .is_err()
        );
        // `{"tombstone": false}` is neither form.
        assert!(
            serde_json::from_value::<RealmAliasPayload>(serde_json::json!({"tombstone": false}))
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
