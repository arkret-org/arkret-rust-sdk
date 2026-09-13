//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/reducer-profile-registry.json; version=2026-09-12.6;
//! sha256=47c52cb7e71715820789b14d2fbeeff50bba5d42caed2b4014dfbe3a5289bafd Input: registry/
//! contract-registry.json; version=2026-09-13.12;
//! sha256=ee2619e668e507fc333447b65115a895bea39574fb8e4d37a97341f70307e3e8
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
    "sha256:6db9fd5e9749ec6c2575060aa18bd1d4b9f21db91b868a6f8baea8bb097f87cb";

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
