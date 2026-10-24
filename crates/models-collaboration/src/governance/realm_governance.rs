//! Realm governance typed payloads introduced by the R1.2 Realm/Space
//! boundary split (spec rounds R2 / R3).
//!
//! These types model the Realm-link wire payloads that compose the
//! cross-Realm governance surface:
//!
//! - `RealmLink` — `ak.realm.link` payload. Typed link between two Realm boundaries, one of seven
//!   canonical [`RealmLinkKind`] values.
//!
//! Realm links do not propagate membership, policy, or capability state.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, DidCoreId, ErrorCode, RealmCommitId, RealmId, ReasonCode, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
    RealmOrganizationStatus,
};
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
/// Canonical link_kind values for `ak.realm.link`. The seven values
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
    /// Source Realm accepts join requests using target Realm membership only
    /// when both Realms have the same current governing Station. The Station
    /// resolves authoritative current state during final admission.
    JoinGateFrom,
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
/// Projection family: `ak.component.realm.link.v1`. Authority-committed
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterpart_event_ref: Option<arkret_wire::EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_digest_commitment: Option<arkret_wire::Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<arkret_wire::EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A Realm Link write and the canonical bytes needed to distinguish an exact
/// replay from a conflicting write on the same basis.
#[derive(Clone, Copy, Debug)]
pub struct RealmLinkTransitionCandidate<'a> {
    pub payload: &'a RealmLinkPayload,
    pub canonical_event_bytes: &'a [u8],
    pub canonical_basis_bytes: &'a [u8],
}

/// Canonical outcome of evaluating a Realm Link write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealmLinkTransitionDecision {
    Apply,
    IdempotentReplay,
    Rejected,
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
/// Exact event-byte replay at the same canonical basis is idempotent. Any other
/// write on that basis is rejected. A write on a later basis must follow the
/// canonical FSM; terminal tombstones cannot be rewritten.
pub fn evaluate_realm_link_transition(
    source_realm_id: &RealmId,
    current: Option<RealmLinkTransitionCandidate<'_>>,
    candidate: RealmLinkTransitionCandidate<'_>,
) -> std::result::Result<RealmLinkTransitionDecision, RealmLinkTransitionError> {
    if source_realm_id == &candidate.payload.target_realm_id {
        return Err(RealmLinkTransitionError::SelfReference);
    }

    let Some(current) = current else {
        debug_assert!(candidate.payload.status.is_initial());
        return Ok(RealmLinkTransitionDecision::Apply);
    };

    if current.canonical_basis_bytes == candidate.canonical_basis_bytes {
        return if current.canonical_event_bytes == candidate.canonical_event_bytes {
            Ok(RealmLinkTransitionDecision::IdempotentReplay)
        } else {
            Ok(RealmLinkTransitionDecision::Rejected)
        };
    }

    let from = current.payload.status;
    let to = candidate.payload.status;
    if from.is_terminal() || !from.can_transition_to(to) {
        return Err(RealmLinkTransitionError::InvalidTransition { from, to });
    }

    Ok(RealmLinkTransitionDecision::Apply)
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
pub struct RealmLinkView {
    pub realm_id: RealmId,
    pub target_realm_id: RealmId,
    pub link_kind: RealmLinkKind,
    pub status: RealmLinkStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub commitment: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmLifecycleView {
    pub realm_id: RealmId,
    pub owner_id: DidCoreId,
    pub member_ids: Vec<ActorId>,
    pub deleted: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub terminal_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub successor_realm_id: Option<RealmId>,
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

impl RealmLifecycleView {
    pub fn validate_for_realm(&self, realm: &RealmId) -> Result<()> {
        if &self.realm_id != realm
            || self
                .member_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.member_ids.len()
            || self
                .terminal_state
                .as_deref()
                .is_some_and(|state| !matches!(state, "tombstoned" | "destroyed"))
        {
            return Err(WireError::Protocol(
                "Realm lifecycle response binding differs".into(),
            ));
        }
        Ok(())
    }
}

impl RealmExport {
    pub fn validate_for_realm(&self, realm: &RealmId) -> Result<()> {
        if &self.realm_id != realm {
            return Err(WireError::Protocol(
                "Realm export response binding differs".into(),
            ));
        }
        Ok(())
    }
}

impl RealmLinkList {
    pub fn validate_for_request(
        &self,
        realm: &RealmId,
        direction: RealmLinkDirection,
        allow: Option<&[RealmLinkKind]>,
    ) -> Result<()> {
        if self.realm_id != *realm || self.direction != direction {
            return Err(WireError::Protocol(
                "Realm link response binding differs".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for link in &self.links {
            if let Some(label) = &link.label {
                arkret_wire::validate_single_line_display_text(label, 256)?;
            }
            let related = match direction {
                RealmLinkDirection::Outbound => &link.realm_id == realm,
                RealmLinkDirection::Inbound => &link.target_realm_id == realm,
                RealmLinkDirection::Both => {
                    &link.realm_id == realm || &link.target_realm_id == realm
                }
            };
            if !related
                || link.realm_id == link.target_realm_id
                || allow.is_some_and(|allow| !allow.contains(&link.link_kind))
                || !seen.insert((
                    link.realm_id.clone(),
                    link.target_realm_id.clone(),
                    link.link_kind,
                ))
            {
                return Err(WireError::Protocol(
                    "Realm link response edge differs".into(),
                ));
            }
        }
        Ok(())
    }
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

/// One projected `ak.realm.organization` relationship row surfaced by
/// `ak.self.realm_organization.read.list.v1`. Mirrors the canonical
/// `realm_organization_payload` field order; `lifecycle_phase` is
/// reducer-derived. A row here is a projection only: an organization
/// relationship is only verified when `lifecycle_phase=verified_active`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipView {
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
    pub realm_commit_ref: Option<RealmCommitId>,
    pub issuer_role: RealmOrganizationIssuerRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
    pub lifecycle_phase: RealmOrganizationLifecyclePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

include!("generated/realm_governance_contracts.rs");
