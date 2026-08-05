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

use arkret_wire::event_envelope::EventRef;
use arkret_wire::{
    CapabilityId, Did, DidUrl, Error, ErrorCode, Hash, NonEmptyString, ProtocolKind, RealmId,
    ReasonCode, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
    RealmOrganizationStatus,
};
use crate::objects::realm_alias::RealmAlias;

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
    "override_organization_approval_required";
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

/// `failed_precondition` reason returned when a Realm moderation policy
/// override needs organization approval.
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
    /// Source Realm may be discovered by members of target Realm.
    DiscoverableFrom,
    /// Source Realm accepts join requests from target Realm's
    /// authenticated members.
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

fn default_link_status() -> RealmLinkStatus {
    RealmLinkStatus::Active
}

/// Operation DTO for creating a Realm Link. The HTTP default is materialized
/// when this value is converted into the strict durable payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkCreateRequestBody {
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    #[serde(default = "default_link_status")]
    pub status: RealmLinkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

impl From<RealmLinkCreateRequestBody> for RealmLinkPayload {
    fn from(request: RealmLinkCreateRequestBody) -> Self {
        Self {
            target_realm_id: request.target_realm_id,
            link_kind: request.link_kind,
            status: request.status,
            label: request.label,
            commitment: request.commitment,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkList {
    pub realm_id: RealmId,
    pub direction: RealmLinkDirection,
    #[serde(default)]
    pub links: Vec<RealmLinkEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmLinkMutationOutcome {
    pub realm_id: RealmId,
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    pub status: RealmLinkStatus,
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
    pub inheritance_chain: Vec<RealmId>,
    pub inheritance_mode: RealmEffectivePolicyInheritanceMode,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmModerationInheritanceMode {
    None,
    Organization,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmEffectiveModerationPolicy {
    pub realm_id: RealmId,
    pub inheritance_mode: RealmModerationInheritanceMode,
    #[serde(default)]
    pub inheritance_chain: Vec<Did>,
    pub organization_policy_layers: Vec<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_policy: Option<BTreeMap<String, Value>>,
    pub effective_rules: Vec<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_organization_approval_required: Option<bool>,
    /// content-moderation.md §7 — how the owning organizations' policy layers
    /// combine. A Realm that names more than one owning organization merges
    /// their layers most-restrictively (`most_restrictive`): a join / write is
    /// denied if ANY owning organization denies it, and a Realm override of an
    /// organization deny requires approval from every organization that denies
    /// the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_merge_strategy: Option<String>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RealmModerationPolicyReplaceRequestBody {
    #[serde(flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub policy: BTreeMap<String, Value>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmModerationPolicyDocument {
    pub kind: String,
    pub realm_id: RealmId,
    pub policy: BTreeMap<String, Value>,
    pub updated_by: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmPolicyServerOnTimeout {
    FailClosed,
    Deny,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmPolicyServerFailMode {
    Open,
    SoftDeny,
    Quarantine,
    Closed,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmPolicyServerAppliesTo {
    Join,
    Invite,
    Message,
    Media,
    Applet,
    Directory,
    Call,
    Federation,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPolicyServerPolicySource {
    pub kind: ProtocolKind,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPolicyServerDeclarationPayload {
    pub policy_server_did: Did,
    pub policy_server_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_keys: Vec<DidUrl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<RealmPolicyServerAppliesTo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_sources: Vec<RealmPolicyServerPolicySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_profile_ref: Option<NonEmptyString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_mode: Option<RealmPolicyServerFailMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<RealmPolicyServerOnTimeout>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPolicyServerTombstonePayload {
    pub tombstone: bool,
}

impl RealmPolicyServerTombstonePayload {
    pub const VALUE: Self = Self { tombstone: true };

    pub fn validate(self) -> Result<Self> {
        if self.tombstone {
            Ok(self)
        } else {
            Err(Error::Protocol(
                "realm policy server tombstone MUST be true".to_owned(),
            ))
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmPolicyServerPayload {
    Declaration(RealmPolicyServerDeclarationPayload),
    Tombstone(RealmPolicyServerTombstonePayload),
}

/// `ak.realm.alias` declaration — the ONLY wire carrier of a Realm alias.
///
/// `realm.schema.json` is a closed object with no `alias` property, and
/// `ak.realm.create` / `ak.realm.update` payloads MUST NOT carry one
/// (`discovery/object-addressing.md` §3.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAliasDeclarationPayload {
    pub alias: RealmAlias,
}

/// `ak.realm.alias` durable value tombstone: releases the alias without
/// erasing cell history. Effective resolution then treats the Realm as
/// addressable only by `realm_id`.
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
            Err(Error::Protocol(
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
            .map_err(|err| Error::Protocol(format!("realm alias payload serialize: {err}")))
    }

    /// The alias `<domain>` is the issuing authority; a Realm's own notary
    /// signature is not evidence that a foreign domain authorized the claim.
    /// Declarations under any other authority fail closed.
    pub fn validate_issuing_authority(self, authority_domain: &str) -> Result<Self> {
        let validated = self.validate()?;
        if let Self::Declaration(declaration) = &validated
            && declaration.alias.domain() != authority_domain
        {
            return Err(Error::Protocol(format!(
                "{}: realm alias domain {} is not the issuing authority domain {authority_domain}",
                ReasonCode::REALM_ALIAS_AUTHORITY_MISMATCH,
                declaration.alias.domain(),
            )));
        }
        Ok(validated)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPolicyServerView {
    pub realm_id: RealmId,
    pub policy_server_did: Did,
    pub policy_server_url: String,
    pub cache_ttl_seconds: u64,
    pub timeout_ms: u64,
    pub on_timeout: RealmPolicyServerOnTimeout,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub from_org_fallback: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Typed payload for the `ak.capability.derived` event.
///
/// Cell family: `ak.component.capability.derived.v1` (cas-register keyed
/// by `capability_id`). Records a capability that was derived from
/// composing a parent Realm grant (`source_grant_ref`) with a child
/// Realm's inheritance declaration (`source_realm_inheritance_policy_ref`).
///
/// The full derive evaluation (verify the source grant, replay the
/// inheritance policy, project the resulting bundle) lives in the
/// reducer's audit pipeline. At schema level the soland reducer accepts
/// the payload + projects the cell so downstream consumers can introspect it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDerived {
    pub capability_id: CapabilityId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub source_grant_ref: EventRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
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

/// One projected `ak.realm.organization` relationship row surfaced by
/// `ak.self.realm_organization.query.list`. Mirrors the canonical
/// `realm_organization_payload` field order; `lifecycle_phase` is
/// reducer-derived. A row here is a projection only: an organization
/// relationship is only verified when `lifecycle_phase=verified_active`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipRow {
    pub statement_id: String,
    pub organization_id: Did,
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

/// Response DTO for `ak.self.realm_organization.query.list`
/// (`realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(byte: char) -> RealmId {
        RealmId::new(format!(
            "ak:realm:01904100-0000-8000-8000-0000000000{byte}{byte}"
        ))
        .unwrap()
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
    fn realm_link_request_default_materializes_but_durable_payload_is_strict() {
        let request: RealmLinkCreateRequestBody = serde_json::from_value(serde_json::json!({
            "target_realm_id": "ak:realm:01904100-0000-8000-8000-cfc039892036",
            "link_kind": "governed_by",
        }))
        .unwrap();
        assert_eq!(request.status, RealmLinkStatus::Active);

        let payload: RealmLinkPayload = request.into();
        assert_eq!(payload.status, RealmLinkStatus::Active);
        assert_eq!(
            serde_json::to_value(payload).unwrap()["status"],
            serde_json::json!("active")
        );
        assert!(
            serde_json::from_value::<RealmLinkPayload>(serde_json::json!({
                "target_realm_id": "ak:realm:01904100-0000-8000-8000-cfc039892036",
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
            target_realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-cfc039892036").unwrap(),
            link_kind: RealmLinkKind::JoinGateFrom,
            status: RealmLinkStatus::Active,
            label: Some("compliance gate".to_owned()),
            commitment: Some("ak:event:01904100-0000-8000-8000-aaaaaaaaaaaa".to_owned()),
        };
        let v = serde_json::to_value(&payload).unwrap();
        let back: RealmLinkPayload = serde_json::from_value(v).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn realm_inheritance_policy_validate_rejects_excessive_depth() {
        let bad = RealmInheritancePolicy {
            source_realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-cfc039892036").unwrap(),
            allowed_policies: vec!["join_policy.v1".to_owned()],
            allowed_capability_bundles: vec!["bundle.admin.v1".to_owned()],
            max_depth: 2,
        };
        assert!(bad.validate().is_err());

        let good = RealmInheritancePolicy {
            source_realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-cfc039892036").unwrap(),
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
                "ak:event:01904100-0000-8000-8000-cccccccccccc".to_owned(),
                "authorized_by".to_owned(),
            ),
            source_realm_inheritance_policy_ref: EventRef::new(
                "ak:event:01904100-0000-8000-8000-dddddddddddd".to_owned(),
                "inherits_from".to_owned(),
            ),
            causal_frontier: "ak:frontier:02000000".to_owned(),
            bundle: Some(serde_json::json!({"capabilities": ["read", "write"]})),
        };
        let v = serde_json::to_value(&cap).unwrap();
        let back: CapabilityDerived = serde_json::from_value(v).unwrap();
        assert_eq!(back, cap);
    }

    #[test]
    fn realm_policy_server_tombstone_is_closed_and_true() {
        let value = serde_json::to_value(RealmPolicyServerTombstonePayload::VALUE).unwrap();
        assert_eq!(value, serde_json::json!({"tombstone": true}));
        assert!(
            serde_json::from_value::<RealmPolicyServerPayload>(serde_json::json!({
                "tombstone": true,
                "policy_server_did": "did:web:policy.example"
            }))
            .is_err()
        );
        let false_tombstone = serde_json::from_value::<RealmPolicyServerTombstonePayload>(
            serde_json::json!({"tombstone": false}),
        )
        .unwrap();
        assert!(false_tombstone.validate().is_err());
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

    #[test]
    fn realm_alias_declaration_binds_the_issuing_authority_domain() {
        let declaration =
            RealmAliasPayload::declaration(RealmAlias::parse("general:acme.example").unwrap());
        assert!(
            declaration
                .clone()
                .validate_issuing_authority("acme.example")
                .is_ok()
        );
        let error = declaration
            .validate_issuing_authority("other.example")
            .unwrap_err()
            .to_string();
        assert!(error.contains(ReasonCode::REALM_ALIAS_AUTHORITY_MISMATCH));
        // A tombstone releases the Realm's own alias and carries no authority.
        assert!(
            RealmAliasPayload::tombstone()
                .validate_issuing_authority("other.example")
                .is_ok()
        );
    }
}
