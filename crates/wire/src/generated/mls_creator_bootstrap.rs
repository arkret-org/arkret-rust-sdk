//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/mls-creator-bootstrap-transaction-registry.json; version=2026-09-16.11;
//! sha256=cc72f80e47b1e31e5d5c5564c831182b73cc117864ad7113e25122ef494a7b40 Entries: states=11,
//! transitions=9, state_kinds=4

use serde::{Deserialize, Serialize};

/// Lifecycle class of one creator MLS Genesis bootstrap state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MlsCreatorBootstrapStateKind {
    Progress,
    TerminalAttempt,
    TerminalFailure,
    TerminalSuccess,
}

impl MlsCreatorBootstrapStateKind {
    pub const ALL: &'static [Self] = &[
        Self::Progress,
        Self::TerminalAttempt,
        Self::TerminalFailure,
        Self::TerminalSuccess,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Progress => "progress",
            Self::TerminalAttempt => "terminal_attempt",
            Self::TerminalFailure => "terminal_failure",
            Self::TerminalSuccess => "terminal_success",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "progress" => Some(Self::Progress),
            "terminal_attempt" => Some(Self::TerminalAttempt),
            "terminal_failure" => Some(Self::TerminalFailure),
            "terminal_success" => Some(Self::TerminalSuccess),
            _ => None,
        }
    }
}

/// Durable state of the single client-local creator MLS Genesis bootstrap
/// transaction, keyed by `(owner_actor_id, effective_scope, operation)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MlsCreatorBootstrapState {
    GenesisIntentPersisted,
    RealmAccepted,
    GovernanceResultPinned,
    Epoch0StatePersisted,
    GenesisQueued,
    GenesisAccepted,
    ArtifactsConverged,
    Ready,
    Rejected,
    Superseded,
    Quarantined,
}

impl MlsCreatorBootstrapState {
    /// Registry order, which is the ordinal order of the state machine.
    pub const ALL: &'static [Self] = &[
        Self::GenesisIntentPersisted,
        Self::RealmAccepted,
        Self::GovernanceResultPinned,
        Self::Epoch0StatePersisted,
        Self::GenesisQueued,
        Self::GenesisAccepted,
        Self::ArtifactsConverged,
        Self::Ready,
        Self::Rejected,
        Self::Superseded,
        Self::Quarantined,
    ];

    pub const GENESIS_INTENT_PERSISTED: &'static str = "genesis_intent_persisted";
    pub const REALM_ACCEPTED: &'static str = "realm_accepted";
    pub const GOVERNANCE_RESULT_PINNED: &'static str = "governance_result_pinned";
    pub const EPOCH0_STATE_PERSISTED: &'static str = "epoch0_state_persisted";
    pub const GENESIS_QUEUED: &'static str = "genesis_queued";
    pub const GENESIS_ACCEPTED: &'static str = "genesis_accepted";
    pub const ARTIFACTS_CONVERGED: &'static str = "artifacts_converged";
    pub const READY: &'static str = "ready";
    pub const REJECTED: &'static str = "rejected";
    pub const SUPERSEDED: &'static str = "superseded";
    pub const QUARANTINED: &'static str = "quarantined";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GenesisIntentPersisted => Self::GENESIS_INTENT_PERSISTED,
            Self::RealmAccepted => Self::REALM_ACCEPTED,
            Self::GovernanceResultPinned => Self::GOVERNANCE_RESULT_PINNED,
            Self::Epoch0StatePersisted => Self::EPOCH0_STATE_PERSISTED,
            Self::GenesisQueued => Self::GENESIS_QUEUED,
            Self::GenesisAccepted => Self::GENESIS_ACCEPTED,
            Self::ArtifactsConverged => Self::ARTIFACTS_CONVERGED,
            Self::Ready => Self::READY,
            Self::Rejected => Self::REJECTED,
            Self::Superseded => Self::SUPERSEDED,
            Self::Quarantined => Self::QUARANTINED,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::GENESIS_INTENT_PERSISTED => Some(Self::GenesisIntentPersisted),
            Self::REALM_ACCEPTED => Some(Self::RealmAccepted),
            Self::GOVERNANCE_RESULT_PINNED => Some(Self::GovernanceResultPinned),
            Self::EPOCH0_STATE_PERSISTED => Some(Self::Epoch0StatePersisted),
            Self::GENESIS_QUEUED => Some(Self::GenesisQueued),
            Self::GENESIS_ACCEPTED => Some(Self::GenesisAccepted),
            Self::ARTIFACTS_CONVERGED => Some(Self::ArtifactsConverged),
            Self::READY => Some(Self::Ready),
            Self::REJECTED => Some(Self::Rejected),
            Self::SUPERSEDED => Some(Self::Superseded),
            Self::QUARANTINED => Some(Self::Quarantined),
            _ => None,
        }
    }

    pub fn descriptor(self) -> &'static MlsCreatorBootstrapStateDescriptor {
        &MLS_CREATOR_BOOTSTRAP_STATES[self as usize]
    }

    pub fn ordinal(self) -> u32 {
        self.descriptor().ordinal
    }

    pub fn kind(self) -> MlsCreatorBootstrapStateKind {
        self.descriptor().kind
    }

    /// States a recoverer may move to from here. A terminal state has none.
    pub fn allowed_exits(self) -> &'static [MlsCreatorBootstrapState] {
        self.descriptor().allowed_exits
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsCreatorBootstrapStateDescriptor {
    pub state: MlsCreatorBootstrapState,
    pub ordinal: u32,
    pub kind: MlsCreatorBootstrapStateKind,
    pub allowed_exits: &'static [MlsCreatorBootstrapState],
}

pub const MLS_CREATOR_BOOTSTRAP_STATES: &[MlsCreatorBootstrapStateDescriptor] = &[
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::GenesisIntentPersisted,
        ordinal: 1,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::GenesisIntentPersisted,
            MlsCreatorBootstrapState::RealmAccepted,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::RealmAccepted,
        ordinal: 2,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::GovernanceResultPinned,
            MlsCreatorBootstrapState::Superseded,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::GovernanceResultPinned,
        ordinal: 3,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::Epoch0StatePersisted,
            MlsCreatorBootstrapState::Superseded,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::Epoch0StatePersisted,
        ordinal: 4,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::GenesisQueued,
            MlsCreatorBootstrapState::Superseded,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::GenesisQueued,
        ordinal: 5,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::GenesisAccepted,
            MlsCreatorBootstrapState::Rejected,
            MlsCreatorBootstrapState::Superseded,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::GenesisAccepted,
        ordinal: 6,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::ArtifactsConverged,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::ArtifactsConverged,
        ordinal: 7,
        kind: MlsCreatorBootstrapStateKind::Progress,
        allowed_exits: &[
            MlsCreatorBootstrapState::Ready,
            MlsCreatorBootstrapState::Quarantined,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::Ready,
        ordinal: 8,
        kind: MlsCreatorBootstrapStateKind::TerminalSuccess,
        allowed_exits: &[],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::Rejected,
        ordinal: 9,
        kind: MlsCreatorBootstrapStateKind::TerminalAttempt,
        allowed_exits: &[
            MlsCreatorBootstrapState::RealmAccepted,
            MlsCreatorBootstrapState::Superseded,
        ],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::Superseded,
        ordinal: 10,
        kind: MlsCreatorBootstrapStateKind::TerminalFailure,
        allowed_exits: &[],
    },
    MlsCreatorBootstrapStateDescriptor {
        state: MlsCreatorBootstrapState::Quarantined,
        ordinal: 11,
        kind: MlsCreatorBootstrapStateKind::TerminalFailure,
        allowed_exits: &[],
    },
];

/// The single arrows a recoverer may execute. `from_state` is `None` for
/// the one arrow that creates the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MlsCreatorBootstrapTransition {
    AbsentToGenesisIntentPersisted,
    GenesisIntentPersistedToGenesisIntentPersisted,
    GenesisIntentPersistedToRealmAccepted,
    RealmAcceptedToGovernanceResultPinned,
    GovernanceResultPinnedToEpoch0StatePersisted,
    Epoch0StatePersistedToGenesisQueued,
    GenesisQueuedToGenesisAccepted,
    GenesisAcceptedToArtifactsConverged,
    ArtifactsConvergedToReady,
}

impl MlsCreatorBootstrapTransition {
    pub const ALL: &'static [Self] = &[
        Self::AbsentToGenesisIntentPersisted,
        Self::GenesisIntentPersistedToGenesisIntentPersisted,
        Self::GenesisIntentPersistedToRealmAccepted,
        Self::RealmAcceptedToGovernanceResultPinned,
        Self::GovernanceResultPinnedToEpoch0StatePersisted,
        Self::Epoch0StatePersistedToGenesisQueued,
        Self::GenesisQueuedToGenesisAccepted,
        Self::GenesisAcceptedToArtifactsConverged,
        Self::ArtifactsConvergedToReady,
    ];

    pub const ABSENT_TO_GENESIS_INTENT_PERSISTED: &'static str =
        "absent_to_genesis_intent_persisted";
    pub const GENESIS_INTENT_PERSISTED_TO_GENESIS_INTENT_PERSISTED: &'static str =
        "genesis_intent_persisted_to_genesis_intent_persisted";
    pub const GENESIS_INTENT_PERSISTED_TO_REALM_ACCEPTED: &'static str =
        "genesis_intent_persisted_to_realm_accepted";
    pub const REALM_ACCEPTED_TO_GOVERNANCE_RESULT_PINNED: &'static str =
        "realm_accepted_to_governance_result_pinned";
    pub const GOVERNANCE_RESULT_PINNED_TO_EPOCH0_STATE_PERSISTED: &'static str =
        "governance_result_pinned_to_epoch0_state_persisted";
    pub const EPOCH0_STATE_PERSISTED_TO_GENESIS_QUEUED: &'static str =
        "epoch0_state_persisted_to_genesis_queued";
    pub const GENESIS_QUEUED_TO_GENESIS_ACCEPTED: &'static str =
        "genesis_queued_to_genesis_accepted";
    pub const GENESIS_ACCEPTED_TO_ARTIFACTS_CONVERGED: &'static str =
        "genesis_accepted_to_artifacts_converged";
    pub const ARTIFACTS_CONVERGED_TO_READY: &'static str = "artifacts_converged_to_ready";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AbsentToGenesisIntentPersisted => Self::ABSENT_TO_GENESIS_INTENT_PERSISTED,
            Self::GenesisIntentPersistedToGenesisIntentPersisted => {
                Self::GENESIS_INTENT_PERSISTED_TO_GENESIS_INTENT_PERSISTED
            }
            Self::GenesisIntentPersistedToRealmAccepted => {
                Self::GENESIS_INTENT_PERSISTED_TO_REALM_ACCEPTED
            }
            Self::RealmAcceptedToGovernanceResultPinned => {
                Self::REALM_ACCEPTED_TO_GOVERNANCE_RESULT_PINNED
            }
            Self::GovernanceResultPinnedToEpoch0StatePersisted => {
                Self::GOVERNANCE_RESULT_PINNED_TO_EPOCH0_STATE_PERSISTED
            }
            Self::Epoch0StatePersistedToGenesisQueued => {
                Self::EPOCH0_STATE_PERSISTED_TO_GENESIS_QUEUED
            }
            Self::GenesisQueuedToGenesisAccepted => Self::GENESIS_QUEUED_TO_GENESIS_ACCEPTED,
            Self::GenesisAcceptedToArtifactsConverged => {
                Self::GENESIS_ACCEPTED_TO_ARTIFACTS_CONVERGED
            }
            Self::ArtifactsConvergedToReady => Self::ARTIFACTS_CONVERGED_TO_READY,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ABSENT_TO_GENESIS_INTENT_PERSISTED => Some(Self::AbsentToGenesisIntentPersisted),
            Self::GENESIS_INTENT_PERSISTED_TO_GENESIS_INTENT_PERSISTED => {
                Some(Self::GenesisIntentPersistedToGenesisIntentPersisted)
            }
            Self::GENESIS_INTENT_PERSISTED_TO_REALM_ACCEPTED => {
                Some(Self::GenesisIntentPersistedToRealmAccepted)
            }
            Self::REALM_ACCEPTED_TO_GOVERNANCE_RESULT_PINNED => {
                Some(Self::RealmAcceptedToGovernanceResultPinned)
            }
            Self::GOVERNANCE_RESULT_PINNED_TO_EPOCH0_STATE_PERSISTED => {
                Some(Self::GovernanceResultPinnedToEpoch0StatePersisted)
            }
            Self::EPOCH0_STATE_PERSISTED_TO_GENESIS_QUEUED => {
                Some(Self::Epoch0StatePersistedToGenesisQueued)
            }
            Self::GENESIS_QUEUED_TO_GENESIS_ACCEPTED => Some(Self::GenesisQueuedToGenesisAccepted),
            Self::GENESIS_ACCEPTED_TO_ARTIFACTS_CONVERGED => {
                Some(Self::GenesisAcceptedToArtifactsConverged)
            }
            Self::ARTIFACTS_CONVERGED_TO_READY => Some(Self::ArtifactsConvergedToReady),
            _ => None,
        }
    }

    pub fn descriptor(self) -> &'static MlsCreatorBootstrapTransitionDescriptor {
        &MLS_CREATOR_BOOTSTRAP_TRANSITIONS[self as usize]
    }

    pub fn from_state(self) -> Option<MlsCreatorBootstrapState> {
        self.descriptor().from_state
    }

    pub fn to_state(self) -> MlsCreatorBootstrapState {
        self.descriptor().to_state
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsCreatorBootstrapTransitionDescriptor {
    pub transition: MlsCreatorBootstrapTransition,
    pub from_state: Option<MlsCreatorBootstrapState>,
    pub to_state: MlsCreatorBootstrapState,
}

pub const MLS_CREATOR_BOOTSTRAP_TRANSITIONS: &[MlsCreatorBootstrapTransitionDescriptor] = &[
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::AbsentToGenesisIntentPersisted,
        from_state: None,
        to_state: MlsCreatorBootstrapState::GenesisIntentPersisted,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::GenesisIntentPersistedToGenesisIntentPersisted,
        from_state: Some(MlsCreatorBootstrapState::GenesisIntentPersisted),
        to_state: MlsCreatorBootstrapState::GenesisIntentPersisted,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::GenesisIntentPersistedToRealmAccepted,
        from_state: Some(MlsCreatorBootstrapState::GenesisIntentPersisted),
        to_state: MlsCreatorBootstrapState::RealmAccepted,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::RealmAcceptedToGovernanceResultPinned,
        from_state: Some(MlsCreatorBootstrapState::RealmAccepted),
        to_state: MlsCreatorBootstrapState::GovernanceResultPinned,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::GovernanceResultPinnedToEpoch0StatePersisted,
        from_state: Some(MlsCreatorBootstrapState::GovernanceResultPinned),
        to_state: MlsCreatorBootstrapState::Epoch0StatePersisted,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::Epoch0StatePersistedToGenesisQueued,
        from_state: Some(MlsCreatorBootstrapState::Epoch0StatePersisted),
        to_state: MlsCreatorBootstrapState::GenesisQueued,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::GenesisQueuedToGenesisAccepted,
        from_state: Some(MlsCreatorBootstrapState::GenesisQueued),
        to_state: MlsCreatorBootstrapState::GenesisAccepted,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::GenesisAcceptedToArtifactsConverged,
        from_state: Some(MlsCreatorBootstrapState::GenesisAccepted),
        to_state: MlsCreatorBootstrapState::ArtifactsConverged,
    },
    MlsCreatorBootstrapTransitionDescriptor {
        transition: MlsCreatorBootstrapTransition::ArtifactsConvergedToReady,
        from_state: Some(MlsCreatorBootstrapState::ArtifactsConverged),
        to_state: MlsCreatorBootstrapState::Ready,
    },
];

impl std::fmt::Display for MlsCreatorBootstrapStateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl Serialize for MlsCreatorBootstrapStateKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for MlsCreatorBootstrapStateKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown MlsCreatorBootstrapStateKind value: {raw}"))
        })
    }
}
impl std::fmt::Display for MlsCreatorBootstrapState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl Serialize for MlsCreatorBootstrapState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for MlsCreatorBootstrapState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown MlsCreatorBootstrapState value: {raw}"))
        })
    }
}
impl std::fmt::Display for MlsCreatorBootstrapTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl Serialize for MlsCreatorBootstrapTransition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for MlsCreatorBootstrapTransition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown MlsCreatorBootstrapTransition value: {raw}"
            ))
        })
    }
}
