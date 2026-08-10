//! Circle primitive (AKP-0007, spec b7d35be..2b0d70d).
//!
//! A `Circle` is an intra-Realm scoped event/message boundary. It hosts
//! its own membership (which MUST be a strict subset of the parent
//! Realm's membership), history visibility and delivery/query/projection
//! boundary. A Circle may be plaintext delivery-only
//! (`encryption_profile=none`) or MLS-backed (`mls_rfc9420`) depending on
//! the parent Realm policy floor.
//!
//! Wire/serde shape mirrors spec
//! `spec/v1/artifacts/schemas/circle.schema.json`. The struct is
//! intentionally tolerant of unknown fields (`extra: BTreeMap<String, Value>`)
//! so forward-compatible non-critical extensions round-trip.

use std::collections::BTreeSet;

pub use arkret_wire::CircleId;
/// Canonical schema id for `Circle`.
///
/// Re-export of [`arkret_wire::SchemaId::CIRCLE_V1`] for code that imports
/// types from this module.
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    DidCoreId, EncryptionProfile, EventId, EventInitialSubmission, HistoryVisibility, RealmId,
    SchemaId,
};
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
    /// Only Circle members see this Circle in any directory listing.
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

/// Binary encryption floor, shared by `content_encryption_floor` and
/// `metadata_encryption_floor` on both Realm and Circle (spec
/// realm.schema.json / circle.schema.json). `allow_plaintext` lets the
/// covered field stay wire-plaintext; `e2ee_required` forces it into
/// E2EE — `encrypted_metadata` for the metadata floor, MLS-backed
/// `effective_scope` for the content floor. Comparison order
/// `allow_plaintext < e2ee_required`; the effective floor MAY only
/// tighten, never widen, and is a one-way ratchet (reducer enforces).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum EncryptionFloor {
    AllowPlaintext,
    E2eeRequired,
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
    Seal,
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
    pub history_visibility: HistoryVisibility,
    /// Optional Circle-local content-encryption floor. When omitted the
    /// Circle inherits the parent Realm `content_encryption_floor`; effective
    /// floor = max(parent Realm, Circle). MAY only tighten parent Realm floor
    /// and the effective floor is a one-way ratchet; `e2ee_required` is only
    /// valid when `encryption_profile = mls_rfc9420`. Reducer enforces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    /// Optional tightening of metadata-encryption floor inherited from
    /// parent Realm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    /// Optional native-agent participation ceiling. Omitted bits inherit
    /// the parent Realm ceiling independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    pub encryption_profile: EncryptionProfile,
    /// Reducer-derived; populated by `ak.circle.create` reducer once the
    /// independent MLS group is bound. NOT actor-supplied on wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_ref: Option<String>,
    pub state: CircleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CirclePendingMlsRemoval {
    pub principal_id: DidCoreId,
    /// Exact membership/device-trust frontier that caused this MLS-backed
    /// Circle scope to require a Remove commit. For device revocation this
    /// MUST name the accepted `ak.device.revoke` or the Realm governance
    /// Control Move that imported that revocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub membership_frontier: Vec<EventId>,
}

impl CirclePendingMlsRemoval {
    pub fn principal_id(&self) -> &DidCoreId {
        &self.principal_id
    }

    pub fn membership_frontier(&self) -> &[EventId] {
        &self.membership_frontier
    }
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
    pub history_visibility: HistoryVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    pub encryption_profile: EncryptionProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_mls_removals: Vec<CirclePendingMlsRemoval>,
    pub state: CircleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_membership: Option<CircleMembership>,
    #[serde(default)]
    pub members: Vec<DidCoreId>,
    pub created_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<DidCoreId>,
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
    pub create_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub circles: Vec<CircleView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CircleMembership {
    Join,
    Invite,
    Knock,
    Leave,
    Ban,
}

impl CircleMembership {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Invite => "invite",
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
    pub member_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleMembershipOutcome {
    pub circle_id: CircleId,
    pub actor_id: DidCoreId,
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
    pub mls_group_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// The three Circle lifecycle operations take separate request types because each
// pins its own Event kind. The body shape is identical: one caller-signed Event,
// whose `payload.target_ref` single-sources the target Circle and must equal the
// path `circle_id`. An optional human-readable reason is `payload.reason`.

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleArchiveRequestBody {
    /// Closed `ak.circle.archive` Event authored and signed by the caller.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleRestoreRequestBody {
    /// Closed `ak.circle.restore` Event authored and signed by the caller.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleTombstoneRequestBody {
    /// Closed `ak.circle.tombstone` Event authored and signed by the caller.
    ///
    /// Tombstone is terminal: the lifecycle transition matrix admits no transition
    /// out, so this Event is the whole record of who ended the Circle.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub lifecycle_event: EventInitialSubmission,
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
/// `invite`, `join`, `knock`, `leave`, and `ban`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleMemberState {
    Invite,
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
            CircleMemberState::Invite => "invite",
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
///   none / leave                         → invite
///   none / leave                         → knock (join_rule=knock only)
///   knock                                → invite / join / leave
///   invite                               → join
///   none / leave                         → join
///   join                                 → leave
///   none / invite / knock / join / leave → ban
///   ban                                  → leave / invite
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
    // ban -> join is a hard wall (admin MUST un-ban via ban -> {leave, invite} first).
    if prev == Some(Ban) && next == Join {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: Some(Ban),
            to: next,
            reason: "ban -> join forbidden; admin MUST un-ban via ban -> {leave, invite} first",
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
    // join -> invite is a regression not in the spec table.
    if prev == Some(Join) && next == Invite {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: Some(Join),
            to: next,
            reason: "join -> invite regression not in AKP-0007 §9.1 transition table",
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
        (None, Invite),
        (Some(Leave), Invite),
        (None, Knock),
        (Some(Leave), Knock),
        (Some(Knock), Invite),
        (Some(Knock), Join),
        (Some(Knock), Leave),
        (Some(Invite), Join),
        (None, Join),
        (Some(Leave), Join),
        (Some(Join), Leave),
        (None, Ban),
        (Some(Invite), Ban),
        (Some(Knock), Ban),
        (Some(Join), Ban),
        (Some(Leave), Ban),
        (Some(Ban), Leave),
        (Some(Ban), Invite),
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

/// Strictness rank for [`HistoryVisibility`] on the linear floor lattice.
/// Returns `None` for `Restricted`, which is a profile-evaluated overlay
/// rather than a point on the linear ordering.
fn history_visibility_rank(v: &HistoryVisibility) -> Option<u8> {
    match v {
        HistoryVisibility::WorldReadable => Some(0),
        HistoryVisibility::Shared => Some(1),
        HistoryVisibility::Invited => Some(2),
        HistoryVisibility::Joined => Some(3),
        HistoryVisibility::Restricted => None,
    }
}

/// Reducer-pure helper: a Circle's effective history visibility is the
/// stricter of `(realm_floor, circle_setting)` (AKP-0007 §3.4). Returns
/// `Err` when either input is `Restricted` (which lives off the linear
/// floor lattice).
///
/// Strictness order (least → most strict):
///   `world_readable < shared < invited < joined`.
pub fn compute_effective_history_visibility(
    realm_floor: HistoryVisibility,
    circle_setting: HistoryVisibility,
) -> Result<HistoryVisibility, CircleScopeError> {
    let r = history_visibility_rank(&realm_floor).ok_or(
        CircleScopeError::RestrictedNotInLinearFloor {
            side: "realm_floor",
        },
    )?;
    let c = history_visibility_rank(&circle_setting).ok_or(
        CircleScopeError::RestrictedNotInLinearFloor {
            side: "circle_setting",
        },
    )?;
    Ok(if r >= c { realm_floor } else { circle_setting })
}

/// Strictness rank for [`EncryptionFloor`]: stricter →
/// larger rank.
fn metadata_floor_rank(floor: EncryptionFloor) -> u8 {
    match floor {
        EncryptionFloor::AllowPlaintext => 0,
        EncryptionFloor::E2eeRequired => 1,
    }
}

/// Reducer-pure validator: a Circle MAY only tighten its parent Realm's
/// `metadata_encryption_floor` floor, never loosen it
/// (AKP-0007 §3.4.1). Returns `Ok(())` when
/// `rank(circle_floor) >= rank(realm_floor)`; otherwise
/// [`CircleScopeError::MetadataEncryptionFloorViolation`] (wire reason
/// [`arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_VIOLATION`]).
pub fn validate_metadata_floor_tightens(
    realm_floor: EncryptionFloor,
    circle_floor: EncryptionFloor,
) -> Result<(), CircleScopeError> {
    if metadata_floor_rank(circle_floor) >= metadata_floor_rank(realm_floor) {
        Ok(())
    } else {
        Err(CircleScopeError::MetadataEncryptionFloorViolation {
            realm_floor,
            circle_floor,
        })
    }
}

/// Reducer-pure validator for the one-way content encryption floor ratchet.
/// Tightening or preserving the floor is accepted; lowering it returns
/// [`CircleScopeError::ContentEncryptionFloorDowngrade`].
pub fn validate_content_encryption_floor_ratchet(
    previous: EncryptionFloor,
    next: EncryptionFloor,
) -> Result<(), CircleScopeError> {
    if metadata_floor_rank(next) >= metadata_floor_rank(previous) {
        Ok(())
    } else {
        Err(CircleScopeError::ContentEncryptionFloorDowngrade { previous, next })
    }
}

/// Reducer-pure validator for the one-way metadata encryption floor ratchet.
/// Tightening or preserving the floor is accepted; lowering it returns
/// [`CircleScopeError::MetadataEncryptionFloorDowngrade`].
pub fn validate_metadata_encryption_floor_ratchet(
    previous: EncryptionFloor,
    next: EncryptionFloor,
) -> Result<(), CircleScopeError> {
    if metadata_floor_rank(next) >= metadata_floor_rank(previous) {
        Ok(())
    } else {
        Err(CircleScopeError::MetadataEncryptionFloorDowngrade { previous, next })
    }
}

/// Reducer-pure validator: Circle encryption MUST NOT fall below the
/// parent Realm or effective content encryption floor.
pub fn validate_circle_encryption_floor(
    realm_encryption_profile: &EncryptionProfile,
    content_encryption_floor: EncryptionFloor,
    circle_encryption_profile: &EncryptionProfile,
) -> Result<(), CircleScopeError> {
    let requires_mls = matches!(realm_encryption_profile, EncryptionProfile::MlsRfc9420)
        || matches!(content_encryption_floor, EncryptionFloor::E2eeRequired);
    if requires_mls && !matches!(circle_encryption_profile, EncryptionProfile::MlsRfc9420) {
        Err(CircleScopeError::CircleEncryptionBelowRealmFloor {
            realm_encryption_profile: realm_encryption_profile.clone(),
            content_encryption_floor,
            circle_encryption_profile: circle_encryption_profile.clone(),
        })
    } else {
        Ok(())
    }
}

/// Reducer-pure validator for Strand / Message / Morph / Blob content writes
/// under `Realm.content_encryption_floor`.
pub fn validate_content_encryption_floor(
    content_encryption_floor: EncryptionFloor,
    realm_encryption_profile: &EncryptionProfile,
    circle_encryption_profile: Option<&EncryptionProfile>,
) -> Result<(), CircleScopeError> {
    if !matches!(content_encryption_floor, EncryptionFloor::E2eeRequired) {
        return Ok(());
    }
    let mls_backed = match circle_encryption_profile {
        Some(profile) => matches!(profile, EncryptionProfile::MlsRfc9420),
        None => matches!(realm_encryption_profile, EncryptionProfile::MlsRfc9420),
    };
    if mls_backed {
        Ok(())
    } else {
        Err(CircleScopeError::ContentEncryptionFloorViolation)
    }
}

/// Error returned by [`Circle::assert_members_strict_subset`] and the
/// AKP-0007 reducer-pure validators in this module.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CircleScopeError {
    #[error(
        "circle member {circle_member} is not an active parent-Realm member \
         (reducer reason=circle_member_must_be_realm_member, AKP-0007)"
    )]
    MemberNotInRealm { circle_member: DidCoreId },
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
    /// `Restricted` history visibility cannot participate in the linear
    /// floor lattice (AKP-0007 §3.4).
    #[error(
        "history_visibility=restricted is not on the linear floor lattice \
         (side={side}, AKP-0007 §3.4)"
    )]
    RestrictedNotInLinearFloor { side: &'static str },
    /// Circle's `metadata_encryption_floor` is laxer than the parent
    /// Realm's. Wire reason:
    /// [`arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_VIOLATION`].
    #[error(
        "reason=metadata_encryption_floor_violation: circle_floor={circle_floor:?} is \
         laxer than realm_floor={realm_floor:?} (AKP-0007 §3.4.1)"
    )]
    MetadataEncryptionFloorViolation {
        realm_floor: EncryptionFloor,
        circle_floor: EncryptionFloor,
    },
    /// A content encryption floor update lowered the effective floor.
    #[error(
        "reason=content_encryption_floor_downgrade: content_encryption_floor ratchet \
         attempted to lower from {previous:?} to {next:?}"
    )]
    ContentEncryptionFloorDowngrade {
        previous: EncryptionFloor,
        next: EncryptionFloor,
    },
    /// A metadata encryption floor update lowered the effective floor.
    #[error(
        "reason=metadata_encryption_floor_downgrade: metadata_encryption_floor ratchet \
         attempted to lower from {previous:?} to {next:?}"
    )]
    MetadataEncryptionFloorDowngrade {
        previous: EncryptionFloor,
        next: EncryptionFloor,
    },
    /// Circle encryption profile would be weaker than the Realm content floor.
    #[error(
        "reason=circle_encryption_below_realm_floor: circle_encryption_profile={circle_encryption_profile:?} is below realm_encryption_profile={realm_encryption_profile:?} / content_encryption_floor={content_encryption_floor:?}"
    )]
    CircleEncryptionBelowRealmFloor {
        realm_encryption_profile: EncryptionProfile,
        content_encryption_floor: EncryptionFloor,
        circle_encryption_profile: EncryptionProfile,
    },
    /// Plaintext content write under `content_encryption_floor=e2ee_required`.
    #[error("reason=content_encryption_floor_violation: content write is not MLS-backed")]
    ContentEncryptionFloorViolation,
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
    /// Reducer-derived fields (`mls_group_ref`, `state_changed_at`,
    /// `updated_*`) start unset and are populated by the spec-defined
    /// reducer; callers that want a fully-formed snapshot can mutate
    /// the struct after construction.
    pub fn new(
        id: CircleId,
        realm_id: RealmId,
        title: impl Into<String>,
        display: CircleDisplay,
        created_by: DidCoreId,
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
            history_visibility: HistoryVisibility::Joined,
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            agent_participation: None,
            encryption_profile: EncryptionProfile::None,
            mls_group_ref: None,
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
        created_by: DidCoreId,
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
            history_visibility: HistoryVisibility::Joined,
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            agent_participation: None,
            encryption_profile: EncryptionProfile::None,
            mls_group_ref: None,
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
        match self
            .agent_participation
            .and_then(|policy| policy.native_agent)
        {
            Some(child) => validate_agent_participation_ceiling_tightens(parent, child),
            None => Ok(parent),
        }
    }

    /// Validate that `circle_members` is a strict subset of
    /// `realm_members` (AKP-0007 invariant: every Circle member MUST be
    /// an active parent-Realm member; reducer reason
    /// `circle_member_must_be_realm_member`).
    ///
    /// Returns `Ok(())` when the relation holds (Circle MAY equal Realm in
    /// the empty-Realm degenerate case — strict subset here is "no
    /// member outside the Realm set"), otherwise the first offending
    /// Circle member.
    pub fn assert_members_strict_subset(
        circle_members: &[DidCoreId],
        realm_members: &[DidCoreId],
    ) -> Result<(), CircleScopeError> {
        let realm: BTreeSet<&DidCoreId> = realm_members.iter().collect();
        for member in circle_members {
            if !realm.contains(member) {
                return Err(CircleScopeError::MemberNotInRealm {
                    circle_member: member.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_display() -> CircleDisplay {
        CircleDisplay {
            short_name: "Ops".to_owned(),
            color_token: CircleColorToken::Indigo,
            symbol: CircleSymbol::Glyph {
                glyph: CircleGlyph::Shield,
            },
        }
    }

    #[test]
    fn circle_round_trips_json() {
        let id = CircleId::new("ak:circle:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned())
            .unwrap();
        let realm_id =
            RealmId::new("ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned())
                .unwrap();
        let actor: DidCoreId = "ak:did_core:webvh:z6mkfixturealice".parse().unwrap();
        let circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        let json = serde_json::to_value(&circle).unwrap();
        let parsed: Circle = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.schema, SchemaId::CIRCLE_V1);
        assert_eq!(parsed.title, "Ops Circle");
        assert_eq!(parsed.profile_ref, circle.profile_ref);
        assert_eq!(parsed.state, CircleState::Active);
    }

    #[test]
    fn circle_agent_participation_round_trips_complete_ceiling() {
        let id = CircleId::new("ak:circle:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg".to_owned())
            .unwrap();
        let realm_id =
            RealmId::new("ak:realm:AZiQUXWgexBvj0pdmSuNERtMTAFCjqds5-eP8K9OsgEo".to_owned())
                .unwrap();
        let actor: DidCoreId = "ak:did_core:webvh:z6mkfixturealice".parse().unwrap();
        let mut circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        circle.agent_participation = Some(AgentParticipationPolicy {
            native_agent: Some(ParticipationBits {
                reply_message: true,
                reaction_add: true,
                reaction_remove: true,
                accept_third_party_mention: false,
                act_on_behalf: false,
            }),
        });

        let value = serde_json::to_value(&circle).unwrap();
        assert_eq!(
            value.get("agent_participation"),
            Some(&serde_json::json!({
                "native_agent": {
                    "reply_message": true,
                    "reaction_add": true,
                    "reaction_remove": true,
                    "accept_third_party_mention": false,
                    "act_on_behalf": false
                }
            }))
        );
        let parsed: Circle = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.agent_participation, circle.agent_participation);
    }

    #[test]
    fn pending_mls_removal_carries_precise_membership_frontier() {
        let value = serde_json::json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "membership_frontier": [
                "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
            ]
        });
        let parsed: CirclePendingMlsRemoval = serde_json::from_value(value).unwrap();

        assert_eq!(
            parsed.principal_id().as_str(),
            "ak:did_core:webvh:z6mkfixture"
        );
        assert_eq!(
            parsed.membership_frontier()[0].as_str(),
            "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        );
    }

    #[test]
    fn pending_mls_removal_rejects_legacy_string() {
        assert!(
            serde_json::from_value::<CirclePendingMlsRemoval>(serde_json::json!(
                "did:webvh:z6mkfixture:bob.example"
            ))
            .is_err()
        );
    }

    #[test]
    fn circle_agent_participation_validates_tighten_only() {
        let id = CircleId::new("ak:circle:AYdzR-cxE5CaMt7Xeab7lJ6oTMVcXRDFIfPqcXOahgQ4".to_owned())
            .unwrap();
        let realm_id =
            RealmId::new("ak:realm:AYkxMogpjqRFcRiejZN897KN1bjKnAjkbNCCRbsgxeHR".to_owned())
                .unwrap();
        let actor: DidCoreId = "ak:did_core:webvh:z6mkfixturealice".parse().unwrap();
        let mut circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        let parent = ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: true,
            accept_third_party_mention: false,
            act_on_behalf: true,
        };

        assert_eq!(
            circle.validate_agent_participation_ceiling(parent).unwrap(),
            parent
        );

        circle.agent_participation = Some(AgentParticipationPolicy {
            native_agent: Some(ParticipationBits {
                reply_message: false,
                reaction_add: false,
                reaction_remove: false,
                accept_third_party_mention: false,
                act_on_behalf: true,
            }),
        });
        assert_eq!(
            circle.validate_agent_participation_ceiling(parent).unwrap(),
            ParticipationBits {
                reply_message: false,
                reaction_add: false,
                reaction_remove: false,
                accept_third_party_mention: false,
                act_on_behalf: true,
            }
        );

        circle.agent_participation = Some(AgentParticipationPolicy {
            native_agent: Some(ParticipationBits {
                reply_message: true,
                reaction_add: true,
                reaction_remove: true,
                accept_third_party_mention: true,
                act_on_behalf: true,
            }),
        });
        assert!(matches!(
            circle.validate_agent_participation_ceiling(parent),
            Err(AgentParticipationError::CeilingWiden { .. })
        ));
    }

    #[test]
    fn strict_subset_accepts_empty_circle() {
        let realm: Vec<DidCoreId> = vec!["ak:did_core:webvh:z6mkfixturealice".parse().unwrap()];
        Circle::assert_members_strict_subset(&[], &realm).unwrap();
    }

    #[test]
    fn strict_subset_rejects_outsider() {
        let alice: DidCoreId = "ak:did_core:webvh:z6mkfixturealice".parse().unwrap();
        let bob: DidCoreId = "ak:did_core:webvh:z6mkfixturebob".parse().unwrap();
        let realm = vec![alice];
        let err =
            Circle::assert_members_strict_subset(std::slice::from_ref(&bob), &realm).unwrap_err();
        match err {
            CircleScopeError::MemberNotInRealm { circle_member } => {
                assert_eq!(circle_member, bob);
            }
            _ => panic!("unexpected variant"),
        }
    }

    // ── validate_member_transition ─────────────────────────────────────────

    #[test]
    fn member_transition_accepts_legal_invite_path() {
        use CircleMemberState::*;
        // none -> invite -> join -> leave -> invite -> join under join_rule=invite.
        validate_member_transition(None, Invite, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Invite), Join, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Join), Leave, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Leave), Invite, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Join), Ban, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Ban), Leave, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Ban), Invite, CircleJoinRule::Invite).unwrap();
        validate_member_transition(None, Ban, CircleJoinRule::Invite).unwrap();
    }

    #[test]
    fn member_transition_knock_requires_request_join_rule() {
        use CircleMemberState::*;
        validate_member_transition(None, Knock, CircleJoinRule::Knock).unwrap();
        validate_member_transition(Some(Leave), Knock, CircleJoinRule::Knock).unwrap();
        for jr in [CircleJoinRule::Invite, CircleJoinRule::Public] {
            let err = validate_member_transition(None, Knock, jr).unwrap_err();
            match err {
                CircleScopeError::IllegalMemberTransition { from, to, .. } => {
                    assert_eq!(from, None);
                    assert_eq!(to, Knock);
                }
                _ => panic!("expected IllegalMemberTransition, got {err:?}"),
            }
        }
    }

    #[test]
    fn member_transition_ban_to_join_is_hard_wall() {
        use CircleMemberState::*;
        for jr in [
            CircleJoinRule::Invite,
            CircleJoinRule::Public,
            CircleJoinRule::Knock,
        ] {
            assert!(validate_member_transition(Some(Ban), Join, jr).is_err());
        }
    }

    #[test]
    fn member_transition_rejects_self_loops_and_join_to_invite() {
        use CircleMemberState::*;
        for s in [Invite, Join, Knock, Leave, Ban] {
            assert!(
                validate_member_transition(Some(s), s, CircleJoinRule::Invite).is_err(),
                "self-loop {s:?} → {s:?} MUST be illegal"
            );
        }
        assert!(validate_member_transition(Some(Join), Invite, CircleJoinRule::Invite).is_err());
    }

    // ── validate_no_scope_rebind ───────────────────────────────────────────

    fn circle_a() -> CircleId {
        CircleId::new("ak:circle:AfbuccJDrS3BsS8P0aU9BrlGUaJIhhDcLOcyloeyFzvK".to_owned()).unwrap()
    }
    fn circle_b() -> CircleId {
        CircleId::new("ak:circle:AQGn4ahivUviiVFvRY8dK3cbp__YLN2_Kbe8Ibm8t1ay".to_owned()).unwrap()
    }

    #[test]
    fn scope_rebind_accepts_identity_pairs() {
        validate_no_scope_rebind(None, None).unwrap();
        let a = circle_a();
        validate_no_scope_rebind(Some(&a), Some(&a)).unwrap();
    }

    #[test]
    fn scope_rebind_rejects_all_changes() {
        let a = circle_a();
        let b = circle_b();
        // None → Some
        assert!(matches!(
            validate_no_scope_rebind(None, Some(&a)),
            Err(CircleScopeError::ScopeRebindForbidden { .. })
        ));
        // Some → None
        assert!(matches!(
            validate_no_scope_rebind(Some(&a), None),
            Err(CircleScopeError::ScopeRebindForbidden { .. })
        ));
        // Some(A) → Some(B)
        assert!(matches!(
            validate_no_scope_rebind(Some(&a), Some(&b)),
            Err(CircleScopeError::ScopeRebindForbidden { .. })
        ));
    }

    // ── compute_effective_history_visibility ───────────────────────────────

    #[test]
    fn effective_history_visibility_takes_stricter() {
        use HistoryVisibility::*;
        // Realm stricter than Circle.
        assert_eq!(
            compute_effective_history_visibility(Joined, WorldReadable).unwrap(),
            Joined
        );
        // Circle stricter than Realm.
        assert_eq!(
            compute_effective_history_visibility(WorldReadable, Invited).unwrap(),
            Invited
        );
        // Equal levels.
        assert_eq!(
            compute_effective_history_visibility(Shared, Shared).unwrap(),
            Shared
        );
    }

    #[test]
    fn effective_history_visibility_rejects_restricted_on_either_side() {
        use HistoryVisibility::*;
        assert!(matches!(
            compute_effective_history_visibility(Restricted, Joined),
            Err(CircleScopeError::RestrictedNotInLinearFloor {
                side: "realm_floor"
            })
        ));
        assert!(matches!(
            compute_effective_history_visibility(Joined, Restricted),
            Err(CircleScopeError::RestrictedNotInLinearFloor {
                side: "circle_setting"
            })
        ));
    }

    // ── validate_metadata_floor_tightens ───────────────────────────────────

    #[test]
    fn metadata_floor_accepts_tightening() {
        use EncryptionFloor::*;
        validate_metadata_floor_tightens(AllowPlaintext, AllowPlaintext).unwrap();
        validate_metadata_floor_tightens(AllowPlaintext, E2eeRequired).unwrap();
        validate_metadata_floor_tightens(E2eeRequired, E2eeRequired).unwrap();
    }

    #[test]
    fn metadata_floor_rejects_loosening() {
        use EncryptionFloor::*;
        assert!(matches!(
            validate_metadata_floor_tightens(E2eeRequired, AllowPlaintext),
            Err(CircleScopeError::MetadataEncryptionFloorViolation { .. })
        ));
    }

    #[test]
    fn encryption_floor_ratchets_reject_downgrade() {
        use EncryptionFloor::*;
        validate_content_encryption_floor_ratchet(AllowPlaintext, AllowPlaintext).unwrap();
        validate_content_encryption_floor_ratchet(AllowPlaintext, E2eeRequired).unwrap();
        validate_content_encryption_floor_ratchet(E2eeRequired, E2eeRequired).unwrap();
        assert!(matches!(
            validate_content_encryption_floor_ratchet(E2eeRequired, AllowPlaintext),
            Err(CircleScopeError::ContentEncryptionFloorDowngrade { .. })
        ));

        validate_metadata_encryption_floor_ratchet(AllowPlaintext, AllowPlaintext).unwrap();
        validate_metadata_encryption_floor_ratchet(AllowPlaintext, E2eeRequired).unwrap();
        validate_metadata_encryption_floor_ratchet(E2eeRequired, E2eeRequired).unwrap();
        assert!(matches!(
            validate_metadata_encryption_floor_ratchet(E2eeRequired, AllowPlaintext),
            Err(CircleScopeError::MetadataEncryptionFloorDowngrade { .. })
        ));
    }

    // ── CircleMemberState wire shape ───────────────────────────────────────

    #[test]
    fn member_state_serialises_as_snake_case() {
        for (variant, expected) in [
            (CircleMemberState::Invite, "invite"),
            (CircleMemberState::Join, "join"),
            (CircleMemberState::Knock, "knock"),
            (CircleMemberState::Leave, "leave"),
            (CircleMemberState::Ban, "ban"),
        ] {
            assert_eq!(variant.as_str(), expected);
            let v = serde_json::to_value(variant).unwrap();
            assert_eq!(v.as_str().unwrap(), expected);
            let parsed: CircleMemberState =
                serde_json::from_str(&format!("\"{expected}\"")).unwrap();
            assert_eq!(parsed, variant);
        }
    }
}

/// Reducer-pure predicate for `Space.child_scope_policy` enforcement
/// (AKP-0007 §3.4.2).
///
/// * `AllowAny` — accepts any scope.
/// * `RequireE2ee` — child MUST live in an MLS-backed scope: a Circle scope, or the Realm-default
///   scope when `realm_encryption_profile = MlsRfc9420`.
/// * `RequireSameScope` — child's `scope_circle_id` MUST equal the parent Space's `scope_circle_id`
///   (both `None` counts as "same").
/// * `RequireScopeCircleId` — child's `scope_circle_id` MUST equal the named Circle.
pub fn enforce_child_scope_policy(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    realm_encryption_profile: &EncryptionProfile,
) -> Result<(), CircleScopeError> {
    enforce_child_scope_policy_with_circle_profile(
        policy,
        child_scope,
        parent_space_scope,
        realm_encryption_profile,
        None,
    )
}

/// Variant of [`enforce_child_scope_policy`] for reducers that have already
/// resolved the child Circle and can distinguish plaintext delivery-only
/// Circles from MLS-backed Circles.
pub fn enforce_child_scope_policy_with_circle_profile(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    realm_encryption_profile: &EncryptionProfile,
    child_circle_encryption_profile: Option<&EncryptionProfile>,
) -> Result<(), CircleScopeError> {
    match policy {
        ChildScopePolicy::AllowAny {} => Ok(()),
        ChildScopePolicy::RequireE2ee {} => match child_scope {
            Some(_)
                if matches!(
                    child_circle_encryption_profile,
                    Some(EncryptionProfile::MlsRfc9420)
                ) =>
            {
                Ok(())
            }
            Some(_) => Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_e2ee",
                detail: "Circle-scoped child requires circle.encryption_profile = mls_rfc9420",
            }),
            None => match realm_encryption_profile {
                EncryptionProfile::MlsRfc9420 => Ok(()),
                _ => Err(CircleScopeError::ChildScopePolicyViolated {
                    policy_kind: "require_e2ee",
                    detail: "Realm-default child requires realm.encryption_profile = mls_rfc9420",
                }),
            },
        },
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

#[cfg(test)]
mod child_scope_tests {
    use super::*;

    fn circle_a() -> CircleId {
        CircleId::new("ak:circle:AfbuccJDrS3BsS8P0aU9BrlGUaJIhhDcLOcyloeyFzvK".to_owned()).unwrap()
    }
    fn circle_b() -> CircleId {
        CircleId::new("ak:circle:AQGn4ahivUviiVFvRY8dK3cbp__YLN2_Kbe8Ibm8t1ay".to_owned()).unwrap()
    }

    // ── enforce_child_scope_policy ─────────────────────────────────────────

    #[test]
    fn child_scope_allow_any_accepts_everything() {
        let policy = ChildScopePolicy::AllowAny {};
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None).unwrap();
        enforce_child_scope_policy(&policy, Some(&circle_a()), None, &EncryptionProfile::None)
            .unwrap();
    }

    #[test]
    fn child_scope_require_e2ee_needs_circle_or_mls_realm() {
        let policy = ChildScopePolicy::RequireE2ee {};
        // Circle-scoped child requires the reducer to resolve the Circle's
        // encryption profile; plaintext delivery-only Circles do not satisfy
        // require_e2ee.
        enforce_child_scope_policy_with_circle_profile(
            &policy,
            Some(&circle_a()),
            None,
            &EncryptionProfile::None,
            Some(&EncryptionProfile::MlsRfc9420),
        )
        .unwrap();
        assert!(matches!(
            enforce_child_scope_policy_with_circle_profile(
                &policy,
                Some(&circle_a()),
                None,
                &EncryptionProfile::None,
                Some(&EncryptionProfile::None),
            ),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_e2ee",
                ..
            })
        ));
        // Realm-default child + MLS realm → accept.
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::MlsRfc9420).unwrap();
        // Realm-default child + non-MLS realm → reject.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_e2ee",
                ..
            })
        ));
    }

    #[test]
    fn child_scope_require_same_scope_matches_parent() {
        let policy = ChildScopePolicy::RequireSameScope {};
        let a = circle_a();
        enforce_child_scope_policy(&policy, Some(&a), Some(&a), &EncryptionProfile::None).unwrap();
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None).unwrap();
        // Mismatch.
        let b = circle_b();
        assert!(matches!(
            enforce_child_scope_policy(&policy, Some(&b), Some(&a), &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_same_scope",
                ..
            })
        ));
        // Asymmetric None/Some.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, Some(&a), &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated { .. })
        ));
    }

    #[test]
    fn child_scope_require_circle_id_matches_named() {
        let a = circle_a();
        let policy = ChildScopePolicy::RequireScopeCircleId {
            scope_circle_id: a.clone(),
        };
        enforce_child_scope_policy(&policy, Some(&a), None, &EncryptionProfile::None).unwrap();
        // Wrong circle.
        let b = circle_b();
        assert!(matches!(
            enforce_child_scope_policy(&policy, Some(&b), None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_scope_circle_id",
                ..
            })
        ));
        // No scope at all.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated { .. })
        ));
    }
}
