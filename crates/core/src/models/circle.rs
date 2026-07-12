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

pub use arkret_identifiers::CircleId;

/// Canonical schema id for `Circle`.
///
/// Re-export of [`crate::models::CIRCLE_SCHEMA_ID`] for code that imports
/// types from this module.
pub use super::CIRCLE_SCHEMA_ID as CIRCLE_SCHEMA;
use super::*;

/// Top-level Circle directory visibility (spec circle.schema.json
/// `directory_visibility` enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CircleJoinRule {
    /// Admin must invite or add.
    Invite,
    /// Profile-defined apply/approve strand.
    Request,
    /// Any active parent-Realm member self-joins.
    Open,
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EncryptionFloor {
    AllowPlaintext,
    E2eeRequired,
}

/// Color tokens accepted on `Circle.display.color_token` (spec
/// circle.schema.json `$defs.display.color_token` enum). Mapping
/// token → theme color is a client responsibility; clients MUST NOT
/// reassign tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum CircleSymbol {
    Emoji { emoji: String },
    Glyph { glyph: CircleGlyph },
}

/// Closed enum of glyph symbols accepted on `Circle.display.symbol.glyph`
/// (spec circle.schema.json).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CircleDisplay {
    pub short_name: String,
    pub color_token: CircleColorToken,
    pub symbol: CircleSymbol,
}

/// Canonical Circle object — `ak.schema.circle.v1` (AKP-0007).
///
/// Field order/shape mirrors `spec/v1/artifacts/schemas/circle.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circle {
    pub id: CircleId,
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
    pub agent_participation: Option<AgentParticipationCeiling>,
    pub encryption_profile: EncryptionProfile,
    /// Reducer-derived; populated by `ak.circle.create` reducer once the
    /// independent MLS group is bound. NOT actor-supplied on wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_ref: Option<String>,
    pub state: CircleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CirclePendingMlsRemoval {
    pub principal_id: Did,
    /// Exact membership/device-trust frontier that caused this MLS-backed
    /// Circle scope to require a Remove commit. For device revocation this
    /// MUST name the accepted `ak.device.revoke` or the Realm governance
    /// Control Move that imported that revocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub membership_frontier: Vec<EventId>,
}

impl CirclePendingMlsRemoval {
    pub fn principal_id(&self) -> &Did {
        &self.principal_id
    }

    pub fn membership_frontier(&self) -> &[EventId] {
        &self.membership_frontier
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
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
    pub agent_participation: Option<AgentParticipationCeiling>,
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
    pub members: Vec<Did>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleCreateRequestBody {
    pub realm_id: RealmId,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_visibility: Option<CircleDirectoryVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<CircleJoinRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationCeiling>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_profile: Option<EncryptionProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub circles: Vec<CircleView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleMemberRequestBody {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership: Option<CircleMembership>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleMembershipOutcome {
    pub circle_id: CircleId,
    pub actor_id: Did,
    pub membership: CircleMembership,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleScopeRotateRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleScopeRotateOutcome {
    pub circle_id: CircleId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleared_pending_removals: Vec<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CircleLifecycleRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// Circle lifecycle state. Mirrors spec circle.schema.json `state` enum.
///
/// This enum is intentionally **distinct** from [`ObjectState`]. Both happen
/// to be 3-value enums today, but the value spaces are not compatible and
/// MUST NOT be cross-mapped:
///
/// | enum            | variants                              | terminal state |
/// |-----------------|---------------------------------------|----------------|
/// | [`CircleState`] | `active`, `archived`, `tombstoned`    | `tombstoned`   |
/// | [`ObjectState`] | `active`, `archived`, `redacted`      | `redacted`     |
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
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
///   none / leave                         → knock (join_rule=request only)
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
) -> std::result::Result<(), CircleScopeError> {
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
        && join_rule != CircleJoinRule::Request
    {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: prev,
            to: next,
            reason: "knock is only legal when join_rule=request",
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
/// [`crate::error::REASON_SCOPE_REBIND_FORBIDDEN`].
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
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<HistoryVisibility, CircleScopeError> {
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
/// [`crate::error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION`]).
pub fn validate_metadata_floor_tightens(
    realm_floor: EncryptionFloor,
    circle_floor: EncryptionFloor,
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<(), CircleScopeError> {
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
) -> std::result::Result<(), CircleScopeError> {
    match policy {
        ChildScopePolicy::AllowAny { .. } => Ok(()),
        ChildScopePolicy::RequireE2ee { .. } => match child_scope {
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
        ChildScopePolicy::RequireSameScope { .. } => {
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

/// Error returned by [`Circle::assert_members_strict_subset`] and the
/// AKP-0007 reducer-pure validators in this module.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CircleScopeError {
    #[error(
        "circle member {circle_member} is not an active parent-Realm member \
         (reducer reason=circle_member_must_be_realm_member, AKP-0007)"
    )]
    MemberNotInRealm { circle_member: Did },
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
    /// Wire reason: [`crate::error::REASON_SCOPE_REBIND_FORBIDDEN`].
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
    /// [`crate::error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION`].
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
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: CIRCLE_SCHEMA.to_owned(),
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
            extra: BTreeMap::new(),
        }
    }

    /// Validate this Circle's optional agent-participation ceiling against
    /// its parent Realm ceiling and return the materialized effective ceiling.
    pub fn validate_agent_participation_ceiling(
        &self,
        parent: AgentParticipation,
    ) -> std::result::Result<AgentParticipation, AgentParticipationError> {
        match self.agent_participation {
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
        circle_members: &[Did],
        realm_members: &[Did],
    ) -> std::result::Result<(), CircleScopeError> {
        let realm: BTreeSet<&Did> = realm_members.iter().collect();
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
        let id =
            CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000001".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000002".to_owned()).unwrap();
        let actor: Did = "did:webvh:z6mkfixture:alice.example".parse().unwrap();
        let mut circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        circle.profile_ref = Some("ak.profile.agent_sidecar_thread.v1".to_owned());
        let json = serde_json::to_value(&circle).unwrap();
        let parsed: Circle = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.schema, CIRCLE_SCHEMA);
        assert_eq!(parsed.title, "Ops Circle");
        assert_eq!(parsed.profile_ref, circle.profile_ref);
        assert_eq!(parsed.state, CircleState::Active);
    }

    #[test]
    fn circle_agent_participation_round_trips_partial_ceiling() {
        let id =
            CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000011".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000012".to_owned()).unwrap();
        let actor: Did = "did:webvh:z6mkfixture:alice.example".parse().unwrap();
        let mut circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        circle.agent_participation = Some(AgentParticipationCeiling {
            reply: Some(true),
            accept_third_party_mention: None,
            act_on_behalf: Some(false),
        });

        let value = serde_json::to_value(&circle).unwrap();
        assert_eq!(
            value.get("agent_participation"),
            Some(&serde_json::json!({
                "reply": true,
                "act_on_behalf": false
            }))
        );
        let parsed: Circle = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.agent_participation, circle.agent_participation);
    }

    #[test]
    fn pending_mls_removal_carries_precise_membership_frontier() {
        let value = serde_json::json!({
            "principal_id": "did:webvh:z6mkfixture:bob.example",
            "membership_frontier": [
                "ak:event:0196419b-0000-7000-8000-000000000001"
            ]
        });
        let parsed: CirclePendingMlsRemoval = serde_json::from_value(value).unwrap();

        assert_eq!(
            parsed.principal_id().as_str(),
            "did:webvh:z6mkfixture:bob.example"
        );
        assert_eq!(
            parsed.membership_frontier()[0].as_str(),
            "ak:event:0196419b-0000-7000-8000-000000000001"
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
        let id =
            CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000021".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000022".to_owned()).unwrap();
        let actor: Did = "did:webvh:z6mkfixture:alice.example".parse().unwrap();
        let mut circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        let parent = AgentParticipation {
            reply: true,
            accept_third_party_mention: false,
            act_on_behalf: true,
        };

        assert_eq!(
            circle.validate_agent_participation_ceiling(parent).unwrap(),
            parent
        );

        circle.agent_participation = Some(AgentParticipationCeiling {
            reply: Some(false),
            accept_third_party_mention: None,
            act_on_behalf: None,
        });
        assert_eq!(
            circle.validate_agent_participation_ceiling(parent).unwrap(),
            AgentParticipation {
                reply: false,
                accept_third_party_mention: false,
                act_on_behalf: true,
            }
        );

        circle.agent_participation = Some(AgentParticipationCeiling {
            reply: None,
            accept_third_party_mention: Some(true),
            act_on_behalf: None,
        });
        assert!(matches!(
            circle.validate_agent_participation_ceiling(parent),
            Err(AgentParticipationError::CeilingWiden { .. })
        ));
    }

    #[test]
    fn strict_subset_accepts_empty_circle() {
        let realm: Vec<Did> = vec!["did:webvh:z6mkfixture:alice.example".parse().unwrap()];
        Circle::assert_members_strict_subset(&[], &realm).unwrap();
    }

    #[test]
    fn strict_subset_rejects_outsider() {
        let alice: Did = "did:webvh:z6mkfixture:alice.example".parse().unwrap();
        let bob: Did = "did:webvh:z6mkfixture:bob.example".parse().unwrap();
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
        validate_member_transition(None, Knock, CircleJoinRule::Request).unwrap();
        validate_member_transition(Some(Leave), Knock, CircleJoinRule::Request).unwrap();
        for jr in [CircleJoinRule::Invite, CircleJoinRule::Open] {
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
            CircleJoinRule::Open,
            CircleJoinRule::Request,
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
        CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000a01".to_owned()).unwrap()
    }
    fn circle_b() -> CircleId {
        CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000a02".to_owned()).unwrap()
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

    // ── enforce_child_scope_policy ─────────────────────────────────────────

    #[test]
    fn child_scope_allow_any_accepts_everything() {
        let policy = ChildScopePolicy::AllowAny {
            metadata_encryption_floor: None,
        };
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None).unwrap();
        enforce_child_scope_policy(&policy, Some(&circle_a()), None, &EncryptionProfile::None)
            .unwrap();
    }

    #[test]
    fn child_scope_require_e2ee_needs_circle_or_mls_realm() {
        let policy = ChildScopePolicy::RequireE2ee {
            metadata_encryption_floor: None,
        };
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
        let policy = ChildScopePolicy::RequireSameScope {
            metadata_encryption_floor: None,
        };
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
            metadata_encryption_floor: None,
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
