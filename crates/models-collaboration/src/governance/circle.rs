//! Circle primitive (AKP-0007, spec b7d35be..2b0d70d).
//!
//! A `Circle` is an intra-Realm scoped event/message boundary. It hosts
//! its own membership (which MUST be a strict subset of the parent
//! Realm's membership), history access and delivery/query/projection
//! boundary. A Circle is plaintext delivery-only until its own
//! `ak.mls.genesis` is accepted, which irreversibly activates standard
//! RFC 9420 for that Circle scope.
//!
//! Wire/serde shape mirrors spec
//! `spec/v1/artifacts/schemas/circle.schema.json`. The struct is
//! intentionally tolerant of unknown fields (`extra: BTreeMap<String, Value>`)
//! so forward-compatible non-critical extensions round-trip.

use std::collections::BTreeSet;

/// Canonical schema id for `Circle`.
///
/// Re-export of [`arkret_wire::SchemaId::CIRCLE_V1`] for code that imports
/// types from this module.
pub use arkret_wire::CircleId;
use arkret_wire::event_envelope::Event;
use arkret_wire::{ActorId, EventCommitSubmission, HistoryAccess, RealmId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::agent_participation::{
    AgentParticipationError, AgentParticipationPolicy, ParticipationBits,
    validate_agent_participation_ceiling_tightens,
};
use crate::objects::space::ChildScopePolicy;

/// Top-level Circle directory visibility (spec circle.schema.json
/// `directory_visibility` enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleDirectoryVisibility {
    /// Only Circle member_ids see this Circle in any directory listing.
    Members,
    /// Any active parent-Realm member sees the directory entry (title,
    /// short_name, member_count) but does NOT gain history or event
    /// access.
    RealmMembers,
}

/// How an actor becomes a Circle member (spec circle.schema.json
/// `join_rule` enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleJoinRule {
    /// Admin must invite or add.
    Invite,
    /// Profile-defined apply/approve strand.
    Knock,
    /// Any active parent-Realm member self-joins.
    Public,
}

/// Color tokens accepted on `Circle.display.color_token` (spec
/// circle.schema.json `$defs.display.color_token` enum). Mapping
/// token → theme color is a client responsibility; clients MUST NOT
/// reassign tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleColorToken {
    Slate,
    Red,
    Orange,
    Amber,
    Yellow,
    Lime,
    Green,
    Emerald,
    Teal,
    Cyan,
    Sky,
    Blue,
    Indigo,
    Violet,
    Fuchsia,
    Pink,
    GrayHighContrast,
}

/// Symbol on `Circle.display.symbol` (spec circle.schema.json
/// `$defs.display.symbol` oneOf). Exactly one of `emoji` / `glyph` is
/// populated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleSymbol {
    Emoji { emoji: String },
    Glyph { glyph: CircleGlyph },
}

/// Closed enum of glyph symbols accepted on `Circle.display.symbol.glyph`
/// (spec circle.schema.json).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleGlyph {
    Lock,
    Shield,
    Eye,
    EyeOff,
    UserShield,
    Fingerprint,
    Key,
    Diamond,
    Flame,
    Leaf,
    Stamp,
    Compass,
    Atom,
    Bolt,
    Moon,
    Sun,
    Star,
    Globe,
    Satellite,
    Ring,
    Chain,
    Tag,
    Flag,
    Scroll,
    Scale,
    Hourglass,
    Spark,
}

/// Display-only nameplate (spec circle.schema.json `$defs.display`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleDisplay {
    pub short_name: String,
    pub color_token: CircleColorToken,
    pub symbol: CircleSymbol,
}

/// Canonical Circle object — `ak.schema.circle.v1` (AKP-0007).
///
/// Field order/shape mirrors `spec/v1/artifacts/schemas/circle.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct Circle {
    /// The object id.
    ///
    /// Absent on the create payload: `ak.circle.create`'s registry `id_source`
    /// is `event_derived`, so the id is `CircleId::from_event_id(&event_id)`
    /// and a payload copy would be a second, forgeable truth (spec
    /// `zh/models/common-fields.md` section 6.0). Present on every projected
    /// snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<CircleId>,
    pub schema: String,
    /// Parent Realm — create-locked. Circle never re-binds to another Realm.
    pub realm_id: RealmId,
    /// Optional create-locked semantic profile discriminator. Ordinary
    /// Circles omit it; profile-specific Circles persist the registered
    /// `ak.profile.*.v1` identifier so projections can filter them safely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub display: CircleDisplay,
    pub directory_visibility: CircleDirectoryVisibility,
    pub join_rule: CircleJoinRule,
    pub history_access: HistoryAccess,
    /// Optional Agent participation ceiling. Omitted bits inherit
    /// the parent Realm ceiling independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    /// Governance-committed binding of this Circle to its independent MLS
    /// group. It is set by the accepted `ak.mls.genesis` for this Circle scope
    /// and is the single indicator that the scope has irreversibly activated
    /// standard RFC 9420; it is never actor-supplied on create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    pub state: CircleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleView {
    pub circle_id: CircleId,
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub display: CircleDisplay,
    pub directory_visibility: CircleDirectoryVisibility,
    pub join_rule: CircleJoinRule,
    pub history_access: HistoryAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    pub state: CircleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_membership: Option<CircleMembership>,
    #[serde(default)]
    pub member_ids: Vec<ActorId>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleCreateRequestBody {
    /// Initial publication of the caller-signed `ak.circle.create` Event.
    ///
    /// The body carries nothing else: every actor-supplied Circle field lives in
    /// `create_event.event.payload.object`, the parent Realm is
    /// `create_event.event.realm_id`, and the Circle id is
    /// `retype(create_event.event.event_id)`. A service MUST submit these exact
    /// bytes through ordinary Event admission and MUST NOT co-sign, rebuild or
    /// synthesize the Event.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub create_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub circle_views: Vec<CircleView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleMembership {
    Join,
    Knock,
    Leave,
    Ban,
}

impl CircleMembership {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Knock => "knock",
            Self::Leave => "leave",
            Self::Ban => "ban",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleMemberRequestBody {
    /// Initial publication of the caller-signed `ak.circle.member.state` Event.
    ///
    /// The target actor and the membership value live in
    /// `member_event.event.payload`, and the Circle is `payload.circle_id`, which
    /// must equal the path `circle_id`. Nothing else belongs here: the payload is
    /// closed, and the `ak.circle.member.manage` decision is the admission path's,
    /// evaluated against projected grants rather than asserted by the request.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub member_event: EventCommitSubmission,
}

/// Request body for `ak.self.circle.member.resource.delete.v1`.
///
/// The signed Event is the sole source of the durable leave transition. The
/// service verifies its Circle and target actor against the DELETE path and
/// forwards the exact submission through ordinary Event admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleMemberDeleteRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub member_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleMembershipOutcome {
    pub circle_id: CircleId,
    pub member_id: ActorId,
    pub membership: CircleMembership,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleScopeRotateRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleScopeRotateOutcome {
    pub circle_id: CircleId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Circle lifecycle state. Mirrors spec circle.schema.json `state` enum.
///
/// This enum is intentionally **distinct** from `ObjectState`. Both happen
/// to be 3-value enums today, but the value spaces are not compatible and
/// MUST NOT be cross-mapped:
///
/// | enum            | variants                              | terminal state |
/// |-----------------|---------------------------------------|----------------|
/// | [`CircleState`] | `active`, `archived`, `tombstoned`    | `tombstoned`   |
/// | `ObjectState` | `active`, `archived`, `redacted`      | `redacted`     |
///
/// * `CircleState::Tombstoned` is the Circle-container terminal state (AKP-0007 §3.5): the Circle
///   directory entry remains, but its MLS group is sealed and no further writes (or member changes)
///   are accepted.
/// * `ObjectState::Redacted` is the object-payload terminal state (round C47, spec e10b6ad): the
///   object's content is wiped via a `ak.redaction` event, but the object id and lifecycle history
///   remain.
///
/// Reducers MUST keep these enums separate. In particular: never silently
/// translate `Tombstoned ↔ Redacted` — Circle lifecycle events
/// (`ak.circle.tombstone`) and per-object redaction events (`ak.redaction`)
/// run on independent state machines.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleState {
    Active,
    Archived,
    Tombstoned,
}

/// Per-actor Circle membership state. Mirrors AKP-0007 §3.6
/// `ak.circle.member.state` `membership` enum.
///
/// The transition table is encoded in [`validate_member_transition`];
/// Circle membership reuses the Realm `membership_state` enum exactly:
/// `join`, `knock`, `leave`, and `ban`. Invite is an independent workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleMemberState {
    Join,
    Knock,
    Leave,
    Ban,
}

impl CircleMemberState {
    /// Wire identifier (snake_case) for this membership state. Mirrors the
    /// canonical strings in `ak.circle.member.state` payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            CircleMemberState::Join => "join",
            CircleMemberState::Knock => "knock",
            CircleMemberState::Leave => "leave",
            CircleMemberState::Ban => "ban",
        }
    }
}

/// Reducer-pure validator: returns `Ok(())` iff `prev → next` is a legal
/// `ak.circle.member.state` transition under the parent Circle's
/// [`CircleJoinRule`] (AKP-0007 §3.6).
///
/// `prev = None` denotes the `none` pseudo-state — an actor who has never
/// had a Circle membership row. The full transition table:
///
/// ```text
///   none / leave                         → knock (join_rule=knock only)
///   none / leave                         → join
///   join                                 → leave
///   none / knock / join / leave          → ban
///   ban                                  → leave
/// ```
///
/// Everything else — in particular `ban → join`, `join → invite`, and
/// self-loops — is illegal. Writer/capability constraints are enforced by the
/// caller; this helper validates the state topology and join-rule-dependent
/// `knock` edge.
pub fn validate_member_transition(
    prev: Option<CircleMemberState>,
    next: CircleMemberState,
    join_rule: CircleJoinRule,
) -> Result<(), CircleScopeError> {
    use CircleMemberState::*;
    // ban -> join is a hard wall (admin MUST un-ban via ban -> leave first).
    if prev == Some(Ban) && next == Join {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: Some(Ban),
            to: next,
            reason: "ban -> join forbidden; admin MUST un-ban via ban -> leave first",
        });
    }
    // knock is only available on request-rule Circles.
    if matches!((prev, next), (None, Knock) | (Some(Leave), Knock))
        && join_rule != CircleJoinRule::Knock
    {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: prev,
            to: next,
            reason: "knock is only legal when join_rule=knock",
        });
    }
    // Self-loops are not transitions.
    if prev == Some(next) {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: prev,
            to: next,
            reason: "self-loop is not a member.state transition",
        });
    }
    // Catalogue legal (prev, next) tuples. Anything not here is illegal.
    let legal: &[(Option<CircleMemberState>, CircleMemberState)] = &[
        (None, Knock),
        (Some(Leave), Knock),
        (Some(Knock), Join),
        (Some(Knock), Leave),
        (None, Join),
        (Some(Leave), Join),
        (Some(Join), Leave),
        (None, Ban),
        (Some(Knock), Ban),
        (Some(Join), Ban),
        (Some(Leave), Ban),
        (Some(Ban), Leave),
    ];
    if legal.iter().any(|&(f, t)| f == prev && t == next) {
        return Ok(());
    }
    Err(CircleScopeError::IllegalMemberTransition {
        from: prev,
        to: next,
        reason: "transition not present in AKP-0007 §3.6 table",
    })
}

/// Reducer-pure validator: a Strand / Space / Morph object's
/// `scope_circle_id` MUST NOT change between two sequential states
/// (`prev`, `next`). AKP-0007 §3.4 — default profile rejects all scope
/// rebinds with `failed_precondition` reason
/// [`arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN`].
///
/// Cases (legal):
///   * `None → None`         — Realm-default stays Realm-default.
///   * `Some(C) → Some(C)`   — same Circle, identity-equal.
///
/// Cases (rejected):
///   * `None → Some(C)`      — rebind to a Circle scope.
///   * `Some(C) → None`      — rebind to Realm-default.
///   * `Some(A) → Some(B)`   — rebind across Circles.
pub fn validate_no_scope_rebind(
    prev: Option<&CircleId>,
    next: Option<&CircleId>,
) -> Result<(), CircleScopeError> {
    match (prev, next) {
        (None, None) => Ok(()),
        (Some(a), Some(b)) if a.as_str() == b.as_str() => Ok(()),
        (None, Some(b)) => Err(CircleScopeError::ScopeRebindForbidden {
            from: None,
            to: Some(b.clone()),
        }),
        (Some(a), None) => Err(CircleScopeError::ScopeRebindForbidden {
            from: Some(a.clone()),
            to: None,
        }),
        (Some(a), Some(b)) => Err(CircleScopeError::ScopeRebindForbidden {
            from: Some(a.clone()),
            to: Some(b.clone()),
        }),
    }
}

/// Reducer-pure validator: a content or metadata write into a scope whose
/// `ak.mls.genesis` is already accepted MUST carry RFC 9420 application
/// ciphertext. Wire reason
/// [`arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED`].
pub fn validate_scope_mls_activation(
    scope_mls_group_id: Option<&str>,
    write_is_encrypted: bool,
) -> Result<(), CircleScopeError> {
    if scope_mls_group_id.is_some() && !write_is_encrypted {
        return Err(CircleScopeError::MlsActivationRequired);
    }
    Ok(())
}

/// Reducer-pure validator: an accepted MLS activation is irreversible. A second
/// `ak.mls.genesis` for the same scope, or any transition that would clear the
/// committed `mls_group_id`, is rejected with wire reason
/// [`arkret_wire::ReasonCode::MLS_ACTIVATION_IRREVERSIBLE`].
pub fn validate_mls_activation_is_irreversible(
    previous_mls_group_id: Option<&str>,
    next_mls_group_id: Option<&str>,
) -> Result<(), CircleScopeError> {
    match (previous_mls_group_id, next_mls_group_id) {
        (None, _) => Ok(()),
        (Some(previous), Some(next)) if previous == next => Ok(()),
        _ => Err(CircleScopeError::MlsActivationIrreversible),
    }
}

/// Error returned by [`Circle::assert_member_ids_strict_subset`] and the
/// AKP-0007 reducer-pure validators in this module.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CircleScopeError {
    #[error("invalid Circle MLS configuration: {0}")]
    InvalidMlsConfiguration(&'static str),
    #[error(
        "circle member {circle_member} is not an active parent-Realm member \
         (reducer reason=circle_member_must_be_realm_member, AKP-0007)"
    )]
    MemberNotInRealm { circle_member: ActorId },
    #[error(
        "circle membership is not a strict subset of realm membership \
         (reducer reason=circle_member_must_be_realm_member, AKP-0007)"
    )]
    NotStrictSubset,
    /// `ak.circle.member.state` transition rejected by the
    /// [AKP-0007 §3.6 table][validate_member_transition].
    #[error(
        "illegal ak.circle.member.state transition {from:?} → {to:?}: {reason} \
         (AKP-0007 §3.6)"
    )]
    IllegalMemberTransition {
        from: Option<CircleMemberState>,
        to: CircleMemberState,
        reason: &'static str,
    },
    /// `scope_circle_id` rebind rejected by default profile.
    /// Wire reason: [`arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN`].
    #[error(
        "reason=scope_rebind_forbidden: scope_circle_id rebind from {from:?} to \
         {to:?} forbidden (AKP-0007 §3.4)"
    )]
    ScopeRebindForbidden {
        from: Option<CircleId>,
        to: Option<CircleId>,
    },
    /// Plaintext write into a scope whose `ak.mls.genesis` is accepted.
    #[error(
        "reason=mls_activation_required: content write into an activated scope is not MLS-backed"
    )]
    MlsActivationRequired,
    /// An attempt to re-run or undo an accepted MLS activation.
    #[error(
        "reason=mls_activation_irreversible: an accepted MLS activation cannot be replaced or cleared"
    )]
    MlsActivationIrreversible,
    /// `Space.child_scope_policy` rejected the child's scope.
    #[error("child_scope_policy={policy_kind} violated: {detail} (AKP-0007 §3.4.2)")]
    ChildScopePolicyViolated {
        policy_kind: &'static str,
        detail: &'static str,
    },
}

impl Circle {
    pub const SCHEMA: &'static str = SchemaId::CIRCLE_V1;

    /// Create a Circle struct with required defaults filled in.
    ///
    /// Reducer-derived fields (`mls_group_id`, `state_changed_at`,
    /// `updated_*`) start unset and are populated by the spec-defined
    /// reducer; callers that want a fully-formed snapshot can mutate
    /// the struct after construction.
    pub fn new(
        id: CircleId,
        realm_id: RealmId,
        title: impl Into<String>,
        display: CircleDisplay,
        created_by: ActorId,
    ) -> Self {
        Self {
            id: Some(id),
            schema: SchemaId::CIRCLE_V1.to_owned(),
            realm_id,
            profile_ref: None,
            title: title.into(),
            summary: None,
            display,
            directory_visibility: CircleDirectoryVisibility::Members,
            join_rule: CircleJoinRule::Invite,
            history_access: HistoryAccess::SinceJoin,
            agent_participation: None,
            mls_group_id: None,
            state: CircleState::Active,
            state_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }

    /// Build the Circle body of an `ak.circle.create` payload.
    ///
    /// [`Circle::new`] takes an id because it also describes a projected Circle.
    /// A create payload carries none: `ak.circle.create` is
    /// `id_source: event_derived`, so the id is `retype(create.event_id)` and a
    /// payload copy would be a second, forgeable truth (spec
    /// `zh/models/common-fields.md` section 6.0). Use this constructor to author
    /// one instead of minting a placeholder id and clearing it afterwards.
    pub fn create_object(
        realm_id: RealmId,
        title: impl Into<String>,
        display: CircleDisplay,
        created_by: ActorId,
    ) -> Self {
        Self {
            id: None,
            schema: SchemaId::CIRCLE_V1.to_owned(),
            realm_id,
            profile_ref: None,
            title: title.into(),
            summary: None,
            display,
            directory_visibility: CircleDirectoryVisibility::Members,
            join_rule: CircleJoinRule::Invite,
            history_access: HistoryAccess::SinceJoin,
            agent_participation: None,
            mls_group_id: None,
            state: CircleState::Active,
            state_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }

    /// Validate this Circle's optional agent-participation ceiling against
    /// its parent Realm ceiling and return the materialized effective ceiling.
    pub fn validate_agent_participation_ceiling(
        &self,
        parent: ParticipationBits,
    ) -> Result<ParticipationBits, AgentParticipationError> {
        match self.agent_participation.and_then(|policy| policy.agent) {
            Some(child) => validate_agent_participation_ceiling_tightens(parent, child),
            None => Ok(parent),
        }
    }

    /// Validate that `circle_member_ids` is a strict subset of
    /// `realm_member_ids` (AKP-0007 invariant: every Circle member MUST be
    /// an active parent-Realm member; reducer reason
    /// `circle_member_must_be_realm_member`).
    ///
    /// Returns `Ok(())` when the relation holds (Circle MAY equal Realm in
    /// the empty-Realm degenerate case — strict subset here is "no
    /// member outside the Realm set"), otherwise the first offending
    /// Circle member.
    pub fn assert_member_ids_strict_subset(
        circle_member_ids: &[ActorId],
        realm_member_ids: &[ActorId],
    ) -> Result<(), CircleScopeError> {
        let realm: BTreeSet<&ActorId> = realm_member_ids.iter().collect();
        for member in circle_member_ids {
            if !realm.contains(member) {
                return Err(CircleScopeError::MemberNotInRealm {
                    circle_member: member.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Reducer-pure predicate for `Space.child_scope_policy` enforcement
/// (AKP-0007 §3.4.2).
///
/// * `AllowAny` — accepts any scope.
/// * `RequireE2ee` — child MUST live in a scope whose committed MLS binding is active.
/// * `RequireSameScope` — child's `scope_circle_id` MUST equal the parent Space's `scope_circle_id`
///   (both `None` counts as "same").
/// * `RequireScopeCircleId` — child's `scope_circle_id` MUST equal the named Circle.
pub fn enforce_child_scope_policy(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    scope_mls_active: bool,
) -> Result<(), CircleScopeError> {
    enforce_child_scope_policy_with_mls_state(
        policy,
        child_scope,
        parent_space_scope,
        scope_mls_active,
    )
}

/// Variant of [`enforce_child_scope_policy`] for callers that have resolved
/// whether the selected scope has an active committed MLS binding.
pub fn enforce_child_scope_policy_with_mls_state(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    scope_mls_active: bool,
) -> Result<(), CircleScopeError> {
    match policy {
        ChildScopePolicy::AllowAny {} => Ok(()),
        ChildScopePolicy::RequireE2ee {} if scope_mls_active => Ok(()),
        ChildScopePolicy::RequireE2ee {} => Err(CircleScopeError::ChildScopePolicyViolated {
            policy_kind: "require_e2ee",
            detail: "child scope requires an active governance-committed MLS binding",
        }),
        ChildScopePolicy::RequireSameScope {} => {
            let child_s = child_scope.map(|c| c.as_str());
            let parent_s = parent_space_scope.map(|c| c.as_str());
            if child_s == parent_s {
                Ok(())
            } else {
                Err(CircleScopeError::ChildScopePolicyViolated {
                    policy_kind: "require_same_scope",
                    detail: "child scope_circle_id differs from parent Space scope_circle_id",
                })
            }
        }
        ChildScopePolicy::RequireScopeCircleId {
            scope_circle_id, ..
        } => match child_scope {
            Some(child) if child.as_str() == scope_circle_id.as_str() => Ok(()),
            _ => Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_scope_circle_id",
                detail: "child scope_circle_id does not match the policy's required circle",
            }),
        },
    }
}
