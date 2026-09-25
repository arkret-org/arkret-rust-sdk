//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-25.3;
//! sha256=6041e454dc981dbeb1718d03de4d1ae6c5294b9e0c9422d2d703ed15998472a5 Entries: registered=5

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthoritySourceId {
    DirectConversationBootstrapParticipantV1,
    DirectConversationParticipantV1,
    DirectConversationRepairV1,
    MembershipCompensationV1,
    SidecarParentBootstrapV1,
}

impl AuthoritySourceId {
    pub const ALL: &'static [Self] = &[
        Self::DirectConversationBootstrapParticipantV1,
        Self::DirectConversationParticipantV1,
        Self::DirectConversationRepairV1,
        Self::MembershipCompensationV1,
        Self::SidecarParentBootstrapV1,
    ];

    pub const DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1: &'static str =
        "ak.authority.direct_conversation_bootstrap_participant.v1";
    pub const DIRECT_CONVERSATION_PARTICIPANT_V1: &'static str =
        "ak.authority.direct_conversation_participant.v1";
    pub const DIRECT_CONVERSATION_REPAIR_V1: &'static str =
        "ak.authority.direct_conversation_repair.v1";
    pub const MEMBERSHIP_COMPENSATION_V1: &'static str = "ak.authority.membership_compensation.v1";
    pub const SIDECAR_PARENT_BOOTSTRAP_V1: &'static str =
        "ak.authority.sidecar_parent_bootstrap.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectConversationBootstrapParticipantV1 => {
                Self::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1
            }
            Self::DirectConversationParticipantV1 => Self::DIRECT_CONVERSATION_PARTICIPANT_V1,
            Self::DirectConversationRepairV1 => Self::DIRECT_CONVERSATION_REPAIR_V1,
            Self::MembershipCompensationV1 => Self::MEMBERSHIP_COMPENSATION_V1,
            Self::SidecarParentBootstrapV1 => Self::SIDECAR_PARENT_BOOTSTRAP_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1 => {
                Some(Self::DirectConversationBootstrapParticipantV1)
            }
            Self::DIRECT_CONVERSATION_PARTICIPANT_V1 => Some(Self::DirectConversationParticipantV1),
            Self::DIRECT_CONVERSATION_REPAIR_V1 => Some(Self::DirectConversationRepairV1),
            Self::MEMBERSHIP_COMPENSATION_V1 => Some(Self::MembershipCompensationV1),
            Self::SIDECAR_PARENT_BOOTSTRAP_V1 => Some(Self::SidecarParentBootstrapV1),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthoritySourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl Serialize for AuthoritySourceId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for AuthoritySourceId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown authority source id: {raw}")))
    }
}
