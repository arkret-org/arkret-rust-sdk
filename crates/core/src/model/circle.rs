//! Circle primitive (CKP-0007, spec b7d35be..2b0d70d).
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

use super::*;
pub use cokret_identifiers::CircleId;

/// Canonical schema id for `Circle`.
///
/// Re-export of [`crate::model::CIRCLE_SCHEMA_ID`] for code that imports
/// types from this module.
pub use super::CIRCLE_SCHEMA_ID as CIRCLE_SCHEMA;

/// Top-level Circle directory visibility (spec circle.schema.json
/// `directory_visibility` enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[serde(rename_all = "snake_case")]
pub enum CircleJoinRule {
    /// Admin must invite or add.
    Invite,
    /// Profile-defined apply/approve flow.
    Request,
    /// Any active parent-Realm member self-joins.
    Open,
}

/// Optional Circle-local metadata encryption floor (spec
/// circle.schema.json `metadata_encryption_floor` enum). Binary and
/// symmetric with `content_encryption_floor`: `allow_plaintext` means
/// metadata MAY be wire-plaintext, `e2ee_required` means user-readable
/// metadata MUST move into `encrypted_metadata`. MAY only tighten parent
/// Realm floor; reducer enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CircleMetadataEncryptionFloor {
    AllowPlaintext,
    E2eeRequired,
}

/// Realm-wide content encryption floor (spec realm.schema.json
/// `content_encryption_floor`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContentEncryptionFloor {
    AllowPlaintext,
    E2eeRequired,
}

/// Color tokens accepted on `Circle.display.color_token` (spec
/// circle.schema.json `$defs.display.color_token` enum). Mapping
/// token → theme color is a client responsibility; clients MUST NOT
/// reassign tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[serde(untagged)]
pub enum CircleSymbol {
    Emoji { emoji: String },
    Glyph { glyph: CircleGlyph },
}

/// Closed enum of glyph symbols accepted on `Circle.display.symbol.glyph`
/// (spec circle.schema.json).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    Anchor,
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
pub struct CircleDisplay {
    pub short_name: String,
    pub color_token: CircleColorToken,
    pub symbol: CircleSymbol,
}

/// Canonical Circle object — `ck.schema.circle.v1` (CKP-0007).
///
/// Field order/shape mirrors `spec/v1/artifacts/schemas/circle.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circle {
    pub id: CircleId,
    pub schema: String,
    /// Parent Realm — create-locked. Circle never re-binds to another Realm.
    pub realm_id: RealmId,
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
    pub content_encryption_floor: Option<ContentEncryptionFloor>,
    /// Optional tightening of metadata-encryption floor inherited from
    /// parent Realm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<CircleMetadataEncryptionFloor>,
    pub encryption_profile: EncryptionProfile,
    /// Reducer-derived; populated by `ck.circle.create` reducer once the
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
/// * `CircleState::Tombstoned` is the Circle-container terminal state
///   (CKP-0007 §3.5): the Circle directory entry remains, but its MLS group
///   is sealed and no further writes (or member changes) are accepted.
/// * `ObjectState::Redacted` is the object-payload terminal state
///   (round C47, spec e10b6ad): the object's content is wiped via a
///   `ck.redaction` event, but the object id and lifecycle history remain.
///
/// Reducers MUST keep these enums separate. In particular: never silently
/// translate `Tombstoned ↔ Redacted` — Circle lifecycle events
/// (`ck.circle.tombstone`) and per-object redaction events (`ck.redaction`)
/// run on independent state machines.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleState {
    Active,
    Archived,
    Tombstoned,
}

/// Per-actor Circle membership state. Mirrors CKP-0007 §3.6
/// `ck.circle.member.state` `membership` enum.
///
/// The transition table is encoded in [`validate_member_transition`];
/// `Active` is the steady-state "this actor is currently in the Circle",
/// `Invited` is the pending-acceptance bucket, `Left` covers both
/// self-departures and admin-removals (re-invitation is allowed), and
/// `Banned` is the admin-blocked bucket (un-ban only via
/// `member.manage`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleMemberState {
    Active,
    Invited,
    Left,
    Banned,
}

impl CircleMemberState {
    /// Wire identifier (snake_case) for this membership state. Mirrors the
    /// canonical strings in `ck.circle.member.state` payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            CircleMemberState::Active => "active",
            CircleMemberState::Invited => "invited",
            CircleMemberState::Left => "left",
            CircleMemberState::Banned => "banned",
        }
    }
}

/// Reducer-pure validator: returns `Ok(())` iff `prev → next` is a legal
/// `ck.circle.member.state` transition under the parent Circle's
/// [`CircleJoinRule`] (CKP-0007 §3.6).
///
/// `prev = None` denotes the `none` pseudo-state — an actor who has never
/// had a Circle membership row. The full transition table:
///
/// ```text
///   none    → invited
///   left    → invited                    (re-invitation)
///   banned  → invited                    (admin un-ban + re-invite)
///   invited → active
///   none    → active   (only when join_rule = open; else MUST transit invited)
///   active  → left
///   invited → left
///   banned  → left                       (admin un-ban via member.manage)
///   active  → banned
///   invited → banned
///   left    → banned
///   none    → banned                     (admin bans before invite)
/// ```
///
/// Everything else — in particular `banned → active`, `active → invited`,
/// `left → active` (under non-open join_rule), and self-loops — is illegal.
pub fn validate_member_transition(
    prev: Option<CircleMemberState>,
    next: CircleMemberState,
    join_rule: CircleJoinRule,
) -> std::result::Result<(), CircleScopeError> {
    use CircleMemberState::*;
    // banned → active is a hard wall (admin MUST un-ban via banned → {left, invited} first).
    if prev == Some(Banned) && next == Active {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: Some(Banned),
            to: next,
            reason: "banned → active forbidden; admin MUST un-ban via banned → {left, invited} first",
        });
    }
    // none → active requires join_rule=open; otherwise MUST pass through invited.
    if prev.is_none() && next == Active && join_rule != CircleJoinRule::Open {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: None,
            to: next,
            reason: "none → active requires join_rule=open; otherwise MUST transit `invited`",
        });
    }
    // active → invited is a regression not in the spec table.
    if prev == Some(Active) && next == Invited {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: Some(Active),
            to: next,
            reason: "active → invited regression not in CKP-0007 §3.6 transition table",
        });
    }
    // left → active directly is illegal unless join_rule=open.
    if prev == Some(Left) && next == Active && join_rule != CircleJoinRule::Open {
        return Err(CircleScopeError::IllegalMemberTransition {
            from: Some(Left),
            to: next,
            reason: "left → active requires re-invite first (left → invited → active)",
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
        (None, Invited),
        (Some(Left), Invited),
        (Some(Banned), Invited),
        (Some(Invited), Active),
        (None, Active), // join_rule=open guarded above
        (Some(Active), Left),
        (Some(Invited), Left),
        (Some(Banned), Left),
        (Some(Active), Banned),
        (Some(Invited), Banned),
        (Some(Left), Banned),
        (None, Banned),
    ];
    if legal.iter().any(|&(f, t)| f == prev && t == next) {
        return Ok(());
    }
    Err(CircleScopeError::IllegalMemberTransition {
        from: prev,
        to: next,
        reason: "transition not present in CKP-0007 §3.6 table",
    })
}

/// Reducer-pure validator: a Flow / Space / Morph object's
/// `scope_circle_id` MUST NOT change between two sequential states
/// (`prev`, `next`). CKP-0007 §3.4 — default profile rejects all scope
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
        (None, Some(b)) => {
            Err(CircleScopeError::ScopeRebindForbidden { from: None, to: Some(b.clone()) })
        }
        (Some(a), None) => {
            Err(CircleScopeError::ScopeRebindForbidden { from: Some(a.clone()), to: None })
        }
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
/// stricter of `(realm_floor, circle_setting)` (CKP-0007 §3.4). Returns
/// `Err` when either input is `Restricted` (which lives off the linear
/// floor lattice).
///
/// Strictness order (least → most strict):
///   `world_readable < shared < invited < joined`.
pub fn compute_effective_history_visibility(
    realm_floor: HistoryVisibility,
    circle_setting: HistoryVisibility,
) -> std::result::Result<HistoryVisibility, CircleScopeError> {
    let r = history_visibility_rank(&realm_floor)
        .ok_or(CircleScopeError::RestrictedNotInLinearFloor { side: "realm_floor" })?;
    let c = history_visibility_rank(&circle_setting)
        .ok_or(CircleScopeError::RestrictedNotInLinearFloor { side: "circle_setting" })?;
    Ok(if r >= c { realm_floor } else { circle_setting })
}

/// Strictness rank for [`CircleMetadataEncryptionFloor`]: stricter →
/// larger rank.
fn metadata_floor_rank(floor: CircleMetadataEncryptionFloor) -> u8 {
    match floor {
        CircleMetadataEncryptionFloor::AllowPlaintext => 0,
        CircleMetadataEncryptionFloor::E2eeRequired => 1,
    }
}

/// Reducer-pure validator: a Circle MAY only tighten its parent Realm's
/// `metadata_encryption_floor` floor, never loosen it
/// (CKP-0007 §3.4.1). Returns `Ok(())` when
/// `rank(circle_floor) >= rank(realm_floor)`; otherwise
/// [`CircleScopeError::MetadataEncryptionFloorViolation`] (wire reason
/// [`crate::error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION`]).
pub fn validate_metadata_floor_tightens(
    realm_floor: CircleMetadataEncryptionFloor,
    circle_floor: CircleMetadataEncryptionFloor,
) -> std::result::Result<(), CircleScopeError> {
    if metadata_floor_rank(circle_floor) >= metadata_floor_rank(realm_floor) {
        Ok(())
    } else {
        Err(CircleScopeError::MetadataEncryptionFloorViolation { realm_floor, circle_floor })
    }
}

/// Reducer-pure validator: Circle encryption MUST NOT fall below the
/// parent Realm or effective content encryption floor.
pub fn validate_circle_encryption_floor(
    realm_encryption_profile: &EncryptionProfile,
    content_encryption_floor: ContentEncryptionFloor,
    circle_encryption_profile: &EncryptionProfile,
) -> std::result::Result<(), CircleScopeError> {
    let requires_mls = matches!(realm_encryption_profile, EncryptionProfile::MlsRfc9420)
        || matches!(content_encryption_floor, ContentEncryptionFloor::E2eeRequired);
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

/// Reducer-pure validator for Flow / Message / Morph / Blob content writes
/// under `Realm.content_encryption_floor`.
pub fn validate_content_encryption_floor(
    content_encryption_floor: ContentEncryptionFloor,
    realm_encryption_profile: &EncryptionProfile,
    circle_encryption_profile: Option<&EncryptionProfile>,
) -> std::result::Result<(), CircleScopeError> {
    if !matches!(content_encryption_floor, ContentEncryptionFloor::E2eeRequired) {
        return Ok(());
    }
    let mls_backed = match circle_encryption_profile {
        Some(profile) => matches!(profile, EncryptionProfile::MlsRfc9420),
        None => matches!(realm_encryption_profile, EncryptionProfile::MlsRfc9420),
    };
    if mls_backed { Ok(()) } else { Err(CircleScopeError::ContentEncryptionFloorViolation) }
}

/// Reducer-pure predicate for `Space.child_scope_policy` enforcement
/// (CKP-0007 §3.4.2).
///
/// * `AllowAny` — accepts any scope.
/// * `RequireE2ee` — child MUST live in an MLS-backed scope: a Circle scope,
///   or the Realm-default scope when `realm_encryption_profile = MlsRfc9420`.
/// * `RequireSameScope` — child's `scope_circle_id` MUST equal the parent
///   Space's `scope_circle_id` (both `None` counts as "same").
/// * `RequireScopeCircleId` — child's `scope_circle_id` MUST equal the named
///   Circle.
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
        ChildScopePolicy::RequireScopeCircleId { scope_circle_id, .. } => match child_scope {
            Some(child) if child.as_str() == scope_circle_id.as_str() => Ok(()),
            _ => Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_scope_circle_id",
                detail: "child scope_circle_id does not match the policy's required circle",
            }),
        },
    }
}

/// Error returned by [`Circle::assert_members_strict_subset`] and the
/// CKP-0007 reducer-pure validators in this module.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CircleScopeError {
    #[error(
        "circle member {circle_member} is not an active parent-Realm member \
         (reducer reason=circle_member_must_be_realm_member, CKP-0007)"
    )]
    MemberNotInRealm { circle_member: Did },
    #[error(
        "circle membership is not a strict subset of realm membership \
         (reducer reason=circle_member_must_be_realm_member, CKP-0007)"
    )]
    NotStrictSubset,
    /// `ck.circle.member.state` transition rejected by the
    /// [CKP-0007 §3.6 table][validate_member_transition].
    #[error(
        "illegal ck.circle.member.state transition {from:?} → {to:?}: {reason} \
         (CKP-0007 §3.6)"
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
         {to:?} forbidden (CKP-0007 §3.4)"
    )]
    ScopeRebindForbidden { from: Option<CircleId>, to: Option<CircleId> },
    /// `Restricted` history visibility cannot participate in the linear
    /// floor lattice (CKP-0007 §3.4).
    #[error(
        "history_visibility=restricted is not on the linear floor lattice \
         (side={side}, CKP-0007 §3.4)"
    )]
    RestrictedNotInLinearFloor { side: &'static str },
    /// Circle's `metadata_encryption_floor` is laxer than the parent
    /// Realm's. Wire reason:
    /// [`crate::error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION`].
    #[error(
        "reason=metadata_encryption_floor_violation: circle_floor={circle_floor:?} is \
         laxer than realm_floor={realm_floor:?} (CKP-0007 §3.4.1)"
    )]
    MetadataEncryptionFloorViolation {
        realm_floor: CircleMetadataEncryptionFloor,
        circle_floor: CircleMetadataEncryptionFloor,
    },
    /// Circle encryption profile would be weaker than the Realm content floor.
    #[error(
        "reason=circle_encryption_below_realm_floor: circle_encryption_profile={circle_encryption_profile:?} is below realm_encryption_profile={realm_encryption_profile:?} / content_encryption_floor={content_encryption_floor:?}"
    )]
    CircleEncryptionBelowRealmFloor {
        realm_encryption_profile: EncryptionProfile,
        content_encryption_floor: ContentEncryptionFloor,
        circle_encryption_profile: EncryptionProfile,
    },
    /// Plaintext content write under `content_encryption_floor=e2ee_required`.
    #[error("reason=content_encryption_floor_violation: content write is not MLS-backed")]
    ContentEncryptionFloorViolation,
    /// `Space.child_scope_policy` rejected the child's scope.
    #[error("child_scope_policy={policy_kind} violated: {detail} (CKP-0007 §3.4.2)")]
    ChildScopePolicyViolated { policy_kind: &'static str, detail: &'static str },
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
            title: title.into(),
            summary: None,
            display,
            directory_visibility: CircleDirectoryVisibility::Members,
            join_rule: CircleJoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            content_encryption_floor: None,
            metadata_encryption_floor: None,
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

    /// Validate that `circle_members` is a strict subset of
    /// `realm_members` (CKP-0007 invariant: every Circle member MUST be
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
                return Err(CircleScopeError::MemberNotInRealm { circle_member: member.clone() });
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
            symbol: CircleSymbol::Glyph { glyph: CircleGlyph::Shield },
        }
    }

    #[test]
    fn circle_round_trips_json() {
        let id =
            CircleId::new("ck:circle:0196419b-0000-7000-8000-000000000001".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000002".to_owned()).unwrap();
        let actor: Did = "did:web:alice.example".parse().unwrap();
        let circle = Circle::new(id, realm_id, "Ops Circle", sample_display(), actor);
        let json = serde_json::to_value(&circle).unwrap();
        let parsed: Circle = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.schema, CIRCLE_SCHEMA);
        assert_eq!(parsed.title, "Ops Circle");
        assert_eq!(parsed.state, CircleState::Active);
    }

    #[test]
    fn strict_subset_accepts_empty_circle() {
        let realm: Vec<Did> = vec!["did:web:alice.example".parse().unwrap()];
        Circle::assert_members_strict_subset(&[], &realm).unwrap();
    }

    #[test]
    fn strict_subset_rejects_outsider() {
        let alice: Did = "did:web:alice.example".parse().unwrap();
        let bob: Did = "did:web:bob.example".parse().unwrap();
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
        // none → invited → active → left → invited → active under join_rule=invite.
        validate_member_transition(None, Invited, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Invited), Active, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Active), Left, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Left), Invited, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Active), Banned, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Banned), Left, CircleJoinRule::Invite).unwrap();
        validate_member_transition(Some(Banned), Invited, CircleJoinRule::Invite).unwrap();
        validate_member_transition(None, Banned, CircleJoinRule::Invite).unwrap();
    }

    #[test]
    fn member_transition_none_to_active_requires_open_join_rule() {
        use CircleMemberState::*;
        // Open join rule: none → active is legal.
        validate_member_transition(None, Active, CircleJoinRule::Open).unwrap();
        // Invite / Request: none → active rejected.
        for jr in [CircleJoinRule::Invite, CircleJoinRule::Request] {
            let err = validate_member_transition(None, Active, jr).unwrap_err();
            match err {
                CircleScopeError::IllegalMemberTransition { from, to, .. } => {
                    assert_eq!(from, None);
                    assert_eq!(to, Active);
                }
                _ => panic!("expected IllegalMemberTransition, got {err:?}"),
            }
        }
    }

    #[test]
    fn member_transition_banned_to_active_is_hard_wall() {
        use CircleMemberState::*;
        for jr in [CircleJoinRule::Invite, CircleJoinRule::Open, CircleJoinRule::Request] {
            assert!(validate_member_transition(Some(Banned), Active, jr).is_err());
        }
    }

    #[test]
    fn member_transition_rejects_self_loops_and_active_to_invited() {
        use CircleMemberState::*;
        for s in [Active, Invited, Left, Banned] {
            assert!(
                validate_member_transition(Some(s), s, CircleJoinRule::Invite).is_err(),
                "self-loop {s:?} → {s:?} MUST be illegal"
            );
        }
        assert!(validate_member_transition(Some(Active), Invited, CircleJoinRule::Invite).is_err());
        // left → active under invite MUST be illegal (re-invite required).
        assert!(validate_member_transition(Some(Left), Active, CircleJoinRule::Invite).is_err());
    }

    // ── validate_no_scope_rebind ───────────────────────────────────────────

    fn circle_a() -> CircleId {
        CircleId::new("ck:circle:0196419b-0000-7000-8000-000000000a01".to_owned()).unwrap()
    }
    fn circle_b() -> CircleId {
        CircleId::new("ck:circle:0196419b-0000-7000-8000-000000000a02".to_owned()).unwrap()
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
        assert_eq!(compute_effective_history_visibility(Joined, WorldReadable).unwrap(), Joined);
        // Circle stricter than Realm.
        assert_eq!(compute_effective_history_visibility(WorldReadable, Invited).unwrap(), Invited);
        // Equal levels.
        assert_eq!(compute_effective_history_visibility(Shared, Shared).unwrap(), Shared);
    }

    #[test]
    fn effective_history_visibility_rejects_restricted_on_either_side() {
        use HistoryVisibility::*;
        assert!(matches!(
            compute_effective_history_visibility(Restricted, Joined),
            Err(CircleScopeError::RestrictedNotInLinearFloor { side: "realm_floor" })
        ));
        assert!(matches!(
            compute_effective_history_visibility(Joined, Restricted),
            Err(CircleScopeError::RestrictedNotInLinearFloor { side: "circle_setting" })
        ));
    }

    // ── validate_metadata_floor_tightens ───────────────────────────────────

    #[test]
    fn metadata_floor_accepts_tightening() {
        use CircleMetadataEncryptionFloor::*;
        validate_metadata_floor_tightens(AllowPlaintext, AllowPlaintext).unwrap();
        validate_metadata_floor_tightens(AllowPlaintext, E2eeRequired).unwrap();
        validate_metadata_floor_tightens(E2eeRequired, E2eeRequired).unwrap();
    }

    #[test]
    fn metadata_floor_rejects_loosening() {
        use CircleMetadataEncryptionFloor::*;
        assert!(matches!(
            validate_metadata_floor_tightens(E2eeRequired, AllowPlaintext),
            Err(CircleScopeError::MetadataEncryptionFloorViolation { .. })
        ));
    }

    // ── enforce_child_scope_policy ─────────────────────────────────────────

    #[test]
    fn child_scope_allow_any_accepts_everything() {
        let policy = ChildScopePolicy::AllowAny { metadata_encryption_floor: None };
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None).unwrap();
        enforce_child_scope_policy(&policy, Some(&circle_a()), None, &EncryptionProfile::None)
            .unwrap();
    }

    #[test]
    fn child_scope_require_e2ee_needs_circle_or_mls_realm() {
        let policy = ChildScopePolicy::RequireE2ee { metadata_encryption_floor: None };
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
            Err(CircleScopeError::ChildScopePolicyViolated { policy_kind: "require_e2ee", .. })
        ));
        // Realm-default child + MLS realm → accept.
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::MlsRfc9420).unwrap();
        // Realm-default child + non-MLS realm → reject.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated { policy_kind: "require_e2ee", .. })
        ));
    }

    #[test]
    fn child_scope_require_same_scope_matches_parent() {
        let policy = ChildScopePolicy::RequireSameScope { metadata_encryption_floor: None };
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
            (CircleMemberState::Active, "active"),
            (CircleMemberState::Invited, "invited"),
            (CircleMemberState::Left, "left"),
            (CircleMemberState::Banned, "banned"),
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
