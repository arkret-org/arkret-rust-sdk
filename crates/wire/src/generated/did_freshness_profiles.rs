//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/did-freshness-profile-registry.json; version=2026-08-29.1;
//! sha256=829d97ed88073110327cea8f97cf80ac89ae0043a317fc380c721d247e403da9 Entries: registered=6

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// §5.4: an unknown id resolves to the strictest tier, never to
    /// "any cached binding will do".
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
