//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/reducer-profile-registry.json; version=2026-09-12.6;
//! sha256=47c52cb7e71715820789b14d2fbeeff50bba5d42caed2b4014dfbe3a5289bafd Input: registry/
//! contract-registry.json; version=2026-09-15.15;
//! sha256=8218f3529eda55ef988ec0711d4a30ac6d055e044c0b7b4bb51cadad1bf1477e
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
    pub fn can_upgrade_to(self, target: Self) -> bool {
        REDUCER_PROFILE_UPGRADE_EDGES.contains(&(self, target))
    }
}

/// SHA-256 of the JCS encoding of the complete canonical contract registry.
pub const CANONICAL_REDUCER_CONTRACT_DIGEST: &str =
    "sha256:d91dc724559574fd89cf751b433bbeb021fde606f22296d58cefce5d22d5bbf2";

/// Directed reducer-profile upgrades registered by the source profile.
pub const REDUCER_PROFILE_UPGRADE_EDGES: &[(ReducerProfileId, ReducerProfileId)] = &[];

pub fn is_reducer_profile_id(value: &str) -> bool {
    ReducerProfileId::from_wire(value).is_some()
}

pub fn can_upgrade_reducer_profile(source: &str, target: &str) -> bool {
    match (
        ReducerProfileId::from_wire(source),
        ReducerProfileId::from_wire(target),
    ) {
        (Some(source), Some(target)) => source.can_upgrade_to(target),
        _ => false,
    }
}
