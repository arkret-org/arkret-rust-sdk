//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/did-freshness-profile-registry.json; version=2026-08-01;
//! sha256=20557e38f5626ba304e82da83fb90e4fdfce0d0364c8b701c8d50b403ca34593 Entries: registered=3

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidFreshnessProfileId {
    AuthorityControllerV1,
    AuthorityHighRiskV1,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DidFreshnessProfileDescriptor {
    pub freshness_profile_id: &'static str,
    pub risk_tier: DidFreshnessRiskTier,
    pub stale_behavior: &'static str,
}

impl DidFreshnessProfileId {
    pub const ALL: &'static [Self] = &[
        Self::AuthorityControllerV1,
        Self::AuthorityHighRiskV1,
        Self::UnregisteredFailClosedV1,
    ];

    pub const AUTHORITY_CONTROLLER_V1: &'static str = "ak.did_freshness.authority_controller.v1";
    pub const AUTHORITY_HIGH_RISK_V1: &'static str = "ak.did_freshness.authority_high_risk.v1";
    pub const UNREGISTERED_FAIL_CLOSED_V1: &'static str =
        "ak.did_freshness.unregistered_fail_closed.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityControllerV1 => Self::AUTHORITY_CONTROLLER_V1,
            Self::AuthorityHighRiskV1 => Self::AUTHORITY_HIGH_RISK_V1,
            Self::UnregisteredFailClosedV1 => Self::UNREGISTERED_FAIL_CLOSED_V1,
        }
    }

    pub const fn risk_tier(self) -> DidFreshnessRiskTier {
        match self {
            Self::AuthorityControllerV1 => DidFreshnessRiskTier::High,
            Self::AuthorityHighRiskV1 => DidFreshnessRiskTier::High,
            Self::UnregisteredFailClosedV1 => DidFreshnessRiskTier::High,
        }
    }

    /// §5.4: an unknown id resolves to the strictest tier, never to
    /// "any cached binding will do".
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::AUTHORITY_CONTROLLER_V1 => Some(Self::AuthorityControllerV1),
            Self::AUTHORITY_HIGH_RISK_V1 => Some(Self::AuthorityHighRiskV1),
            Self::UNREGISTERED_FAIL_CLOSED_V1 => Some(Self::UnregisteredFailClosedV1),
            _ => None,
        }
    }
}

pub const REGISTERED_DID_FRESHNESS_PROFILES: &[DidFreshnessProfileDescriptor] = &[
    DidFreshnessProfileDescriptor {
        freshness_profile_id: DidFreshnessProfileId::AUTHORITY_CONTROLLER_V1,
        risk_tier: DidFreshnessRiskTier::High,
        stale_behavior: "synchronous_refresh_or_fail_closed",
    },
    DidFreshnessProfileDescriptor {
        freshness_profile_id: DidFreshnessProfileId::AUTHORITY_HIGH_RISK_V1,
        risk_tier: DidFreshnessRiskTier::High,
        stale_behavior: "synchronous_refresh_or_fail_closed",
    },
    DidFreshnessProfileDescriptor {
        freshness_profile_id: DidFreshnessProfileId::UNREGISTERED_FAIL_CLOSED_V1,
        risk_tier: DidFreshnessRiskTier::High,
        stale_behavior: "synchronous_refresh_or_fail_closed",
    },
];
