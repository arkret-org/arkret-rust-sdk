//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/reducer-profile-registry.json; version=2026-09-12.6;
//! sha256=6320b77b67f33df5cf8a8afed6b9b2e5d007f32f4eb942326b226a13f70ada75
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
    "sha256:50f21e37d682df67a5ea9bdc79d49dd270f4a82ac3b876d5981da1d95eac8178";

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
