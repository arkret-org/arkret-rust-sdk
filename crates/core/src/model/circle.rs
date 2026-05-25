//! Circle primitive (CXP-0007, spec b7d35be..2b0d70d).
//!
//! A `Circle` is an intra-Realm cryptographic sub-boundary. It hosts its
//! own MLS group, its own membership (which MUST be a strict subset of
//! the parent Realm's membership), and its own history visibility. It
//! does NOT carry federation identity, policy server, or capability
//! registry — those remain on the parent Realm.
//!
//! Wire/serde shape mirrors spec
//! `spec/v1/artifacts/schemas/circle.schema.json`. The struct is
//! intentionally tolerant of unknown fields (`extra: BTreeMap<String, Value>`)
//! so forward-compatible non-critical extensions round-trip.

use super::*;
pub use contrix_identifiers::CircleId;

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
/// circle.schema.json `metadata_encryption_floor` enum). MAY only
/// tighten parent Realm floor; reducer enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleMetadataEncryptionFloor {
    BodyOnly,
    MinimalEncrypted,
    FullEncrypted,
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
    Diamond,
    Flame,
    Leaf,
    Anchor,
    Compass,
    Key,
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

/// Canonical Circle object — `cx.schema.circle.v1` (CXP-0007).
///
/// Field order/shape mirrors `spec/v1/artifacts/schemas/circle.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circle {
    pub schema: String,
    pub id: CircleId,
    /// Parent Realm — create-locked. Circle never re-binds to another Realm.
    pub realm_id: RealmId,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub display: CircleDisplay,
    pub directory_visibility: CircleDirectoryVisibility,
    pub join_rule: CircleJoinRule,
    pub history_visibility: HistoryVisibility,
    /// Optional tightening of metadata-encryption floor inherited from
    /// parent Realm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<CircleMetadataEncryptionFloor>,
    pub encryption_profile: EncryptionProfile,
    /// Reducer-derived; populated by `cx.circle.create` reducer once the
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
/// Note this is intentionally a Circle-local 3-value enum (active /
/// archived / tombstoned) and is distinct from [`ObjectState`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleState {
    Active,
    Archived,
    Tombstoned,
}

/// Error returned by [`Circle::assert_members_strict_subset`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CircleScopeError {
    #[error(
        "circle member {circle_member} is not an active parent-Realm member \
         (reducer reason=circle_member_must_be_realm_member, CXP-0007)"
    )]
    MemberNotInRealm { circle_member: Did },
    #[error(
        "circle membership is not a strict subset of realm membership \
         (reducer reason=circle_member_must_be_realm_member, CXP-0007)"
    )]
    NotStrictSubset,
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
            schema: CIRCLE_SCHEMA.to_owned(),
            id,
            realm_id,
            title: title.into(),
            summary: None,
            display,
            directory_visibility: CircleDirectoryVisibility::Members,
            join_rule: CircleJoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            metadata_encryption_floor: None,
            encryption_profile: EncryptionProfile::MlsRfc9420,
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
    /// `realm_members` (CXP-0007 invariant: every Circle member MUST be
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
            symbol: CircleSymbol::Glyph { glyph: CircleGlyph::Shield },
        }
    }

    #[test]
    fn circle_round_trips_json() {
        let id =
            CircleId::new("cx:circle:0196419b-0000-7000-8000-000000000001".to_owned()).unwrap();
        let realm_id =
            RealmId::new("cx:realm:0196419b-0000-7000-8000-000000000002".to_owned()).unwrap();
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
        let realm = vec![alice.clone()];
        let err = Circle::assert_members_strict_subset(&[bob.clone()], &realm).unwrap_err();
        match err {
            CircleScopeError::MemberNotInRealm { circle_member } => {
                assert_eq!(circle_member, bob);
            }
            _ => panic!("unexpected variant"),
        }
    }
}
