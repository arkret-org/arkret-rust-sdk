//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/did-freshness-profile-registry.json; version=2026-08-31.2;
//! sha256=571b0c8ebc99ce98531d17c969dffd36bd7340b13f9fa7dae0addaa0b026d3e8 Entries: registered=6

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidFreshnessProfileId {
    CurrentExternalClaimV1,
    MethodSuccessorV1,
    OngoingGovernanceV1,
    OptionalDidRootRecoveryV1,
    RegistrationCurrentV1,
    UnregisteredFailClosedV1,
}

/// Registered risk tier of a freshness profile. Fixed by registration:
/// a deployment declares only the numeric windows.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DidFreshnessRiskTier {
    Low,
    Medium,
    High,
}

impl DidFreshnessProfileId {
    pub const ALL: &'static [Self] = &[
        Self::CurrentExternalClaimV1,
        Self::MethodSuccessorV1,
        Self::OngoingGovernanceV1,
        Self::OptionalDidRootRecoveryV1,
        Self::RegistrationCurrentV1,
        Self::UnregisteredFailClosedV1,
    ];

    pub const CURRENT_EXTERNAL_CLAIM_V1: &'static str =
        "ak.did_freshness.current_external_claim.v1";
    pub const METHOD_SUCCESSOR_V1: &'static str = "ak.did_freshness.method_successor.v1";
    pub const ONGOING_GOVERNANCE_V1: &'static str = "ak.did_freshness.ongoing_governance.v1";
    pub const OPTIONAL_DID_ROOT_RECOVERY_V1: &'static str =
        "ak.did_freshness.optional_did_root_recovery.v1";
    pub const REGISTRATION_CURRENT_V1: &'static str = "ak.did_freshness.registration_current.v1";
    pub const UNREGISTERED_FAIL_CLOSED_V1: &'static str =
        "ak.did_freshness.unregistered_fail_closed.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentExternalClaimV1 => Self::CURRENT_EXTERNAL_CLAIM_V1,
            Self::MethodSuccessorV1 => Self::METHOD_SUCCESSOR_V1,
            Self::OngoingGovernanceV1 => Self::ONGOING_GOVERNANCE_V1,
            Self::OptionalDidRootRecoveryV1 => Self::OPTIONAL_DID_ROOT_RECOVERY_V1,
            Self::RegistrationCurrentV1 => Self::REGISTRATION_CURRENT_V1,
            Self::UnregisteredFailClosedV1 => Self::UNREGISTERED_FAIL_CLOSED_V1,
        }
    }

    pub const fn risk_tier(self) -> DidFreshnessRiskTier {
        match self {
            Self::CurrentExternalClaimV1 => DidFreshnessRiskTier::High,
            Self::MethodSuccessorV1 => DidFreshnessRiskTier::High,
            Self::OngoingGovernanceV1 => DidFreshnessRiskTier::High,
            Self::OptionalDidRootRecoveryV1 => DidFreshnessRiskTier::High,
            Self::RegistrationCurrentV1 => DidFreshnessRiskTier::High,
            Self::UnregisteredFailClosedV1 => DidFreshnessRiskTier::High,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::CURRENT_EXTERNAL_CLAIM_V1 => Some(Self::CurrentExternalClaimV1),
            Self::METHOD_SUCCESSOR_V1 => Some(Self::MethodSuccessorV1),
            Self::ONGOING_GOVERNANCE_V1 => Some(Self::OngoingGovernanceV1),
            Self::OPTIONAL_DID_ROOT_RECOVERY_V1 => Some(Self::OptionalDidRootRecoveryV1),
            Self::REGISTRATION_CURRENT_V1 => Some(Self::RegistrationCurrentV1),
            Self::UNREGISTERED_FAIL_CLOSED_V1 => Some(Self::UnregisteredFailClosedV1),
            _ => None,
        }
    }
}
