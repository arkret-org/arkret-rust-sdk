//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/reducer-profile-registry.json; version=2026-08-25.1;
//! sha256=0fde5d1bda803d7e4600b2f7386f957fa933e7f37b3a1eb912d042127b9dd632
//! Entries: reducer_profiles=1, upgrade_edges=0

/// Active Realm reducer profiles. A Realm selects exactly one through
/// its reducer-profile singleton control cell; ordinary Events and
/// federation service bindings do not declare one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReducerProfileId {
    CoreV1,
}

impl ReducerProfileId {
    pub const ALL: &'static [Self] = &[Self::CoreV1];

    pub const CORE_V1: &'static str = "ak.reducer.core.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoreV1 => Self::CORE_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::CORE_V1 => Some(Self::CoreV1),
            _ => None,
        }
    }

    /// Whether this profile registers a direct upgrade to `target`.
    /// An upgrade the source does not declare is never valid.
    pub fn can_upgrade_to(self, target: Self) -> bool {
        REDUCER_PROFILE_UPGRADE_EDGES.contains(&(self, target))
    }
}

/// Directed reducer-profile upgrades registered by the source profile.
pub const REDUCER_PROFILE_UPGRADE_EDGES: &[(ReducerProfileId, ReducerProfileId)] = &[];

/// Whether `value` names an active Realm reducer profile.
pub fn is_reducer_profile_id(value: &str) -> bool {
    ReducerProfileId::from_wire(value).is_some()
}

/// Whether `source` registers a direct upgrade to `target`. Ids that are
/// unknown or no longer active never upgrade.
pub fn can_upgrade_reducer_profile(source: &str, target: &str) -> bool {
    match (
        ReducerProfileId::from_wire(source),
        ReducerProfileId::from_wire(target),
    ) {
        (Some(source), Some(target)) => source.can_upgrade_to(target),
        _ => false,
    }
}
