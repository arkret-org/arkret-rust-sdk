//! Direct-conversation lookup over current authority projections.

use arkret_wire::{CommittedEventRef, Hash, RealmId, StrandId};
use serde::{Deserialize, Serialize};

use crate::contact_operations::ContactPeer;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationResolveRequestBody {
    pub peer: ContactPeer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationCoordinates {
    pub pair_key: Hash,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_ref: Option<CommittedEventRef>,
}

/// Authority-evaluated reasons why an otherwise materialized conversation
/// cannot currently send. These values intentionally describe current state,
/// not a peer-reconciliation protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationSendBlocker {
    SessionMissing,
    PresenceOffline,
    KeypackageEmpty,
    GrantMissing,
    PolicyStale,
    ContactScopeStale,
    MlsReconcileRequired,
    AgentRuntimeUnavailable,
    PeerNotJoinedMls,
    MemberCountInvalid,
    PairMaterializationConflict,
    RealmTerminalFault,
    GovernanceStationUnavailable,
    UnsupportedProfile,
}

#[cfg(test)]
mod tests {
    use super::DirectConversationSendBlocker;

    #[test]
    fn direct_conversation_send_blockers_match_the_closed_wire_literals() {
        let cases = [
            (DirectConversationSendBlocker::MemberCountInvalid, "member_count_invalid"),
            (DirectConversationSendBlocker::ContactScopeStale, "contact_scope_stale"),
            (
                DirectConversationSendBlocker::GovernanceStationUnavailable,
                "governance_station_unavailable",
            ),
            (DirectConversationSendBlocker::UnsupportedProfile, "unsupported_profile"),
        ];
        for (blocker, expected) in cases {
            assert_eq!(serde_json::to_value(blocker).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<DirectConversationSendBlocker>(expected.into()).unwrap(),
                blocker
            );
        }
    }
}

/// Holder-device-only blockers. This deliberately has no Serde surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirectConversationClientLocalBlocker {
    PersonalBlocked,
    LocalSecretUnavailable,
}

impl DirectConversationClientLocalBlocker {
    pub const ALL: [Self; 2] = [Self::PersonalBlocked, Self::LocalSecretUnavailable];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersonalBlocked => "personal_blocked",
            Self::LocalSecretUnavailable => "local_secret_unavailable",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectConversationResolveOutcome {
    CreationRequired {
        expected_contact_revision: u64,
    },
    CreationBlocked {
        blockers: Vec<DirectConversationSendBlocker>,
    },
    AwaitingFounder {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    AwaitingAuthority {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    ProvisionallyCommitted {
        coordinates: DirectConversationCoordinates,
        creation_ref: CommittedEventRef,
    },
    Found {
        coordinates: DirectConversationCoordinates,
        group_state_ref: CommittedEventRef,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        send_blockers: Vec<DirectConversationSendBlocker>,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        blockers: Vec<DirectConversationSendBlocker>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_state_ref: Option<CommittedEventRef>,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}

impl DirectConversationResolveOutcome {
    #[must_use]
    pub fn coordinates(&self) -> Option<&DirectConversationCoordinates> {
        match self {
            Self::ProvisionallyCommitted { coordinates, .. }
            | Self::Found { coordinates, .. }
            | Self::Suspended { coordinates, .. } => Some(coordinates),
            _ => None,
        }
    }

    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if let Self::Found { coordinates, .. } = self
            && coordinates.binding_ref.is_none()
        {
            return Err(arkret_wire::WireError::Protocol(
                "found conversation requires an authority-committed binding".into(),
            ));
        }
        Ok(())
    }
}
