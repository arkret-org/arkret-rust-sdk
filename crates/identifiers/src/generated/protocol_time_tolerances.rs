//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-19.25;
//! sha256=2ce945877fe843ef6f91c005d21607cff97376ad203a82a3078f681ba996ddac
//! Entries: protocol_time_tolerances=2, protocol_time_tolerance_scenarios=3

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolTimeToleranceDirection {
    FutureOnly,
    SymmetricNotBeforeAndExpiry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolTimeToleranceDescriptor {
    pub tolerance_id: &'static str,
    pub name: &'static str,
    pub value_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolTimeToleranceScenarioDescriptor {
    pub scenario_id: &'static str,
    pub tolerance_id: &'static str,
    pub direction: ProtocolTimeToleranceDirection,
    pub comparison: &'static str,
}

pub const HARD_FUTURE_SKEW_MS: i64 = 300000;
pub const EXPECTED_FUTURE_SKEW_MS: i64 = 30000;

pub const PROTOCOL_TIME_TOLERANCES: &[ProtocolTimeToleranceDescriptor] = &[
    ProtocolTimeToleranceDescriptor {
        tolerance_id: "ak.time_tolerance.hard_future_skew.v1",
        name: "hard_future_skew_ms",
        value_ms: HARD_FUTURE_SKEW_MS,
    },
    ProtocolTimeToleranceDescriptor {
        tolerance_id: "ak.time_tolerance.expected_future_skew.v1",
        name: "expected_future_skew_ms",
        value_ms: EXPECTED_FUTURE_SKEW_MS,
    },
];

pub const PROTOCOL_TIME_TOLERANCE_SCENARIOS: &[ProtocolTimeToleranceScenarioDescriptor] = &[
    ProtocolTimeToleranceScenarioDescriptor {
        scenario_id: "ak.time_tolerance.approval_approved_at.v1",
        tolerance_id: "ak.time_tolerance.hard_future_skew.v1",
        direction: ProtocolTimeToleranceDirection::FutureOnly,
        comparison: "approved_at <= verification_time + tolerance, inclusive",
    },
    ProtocolTimeToleranceScenarioDescriptor {
        scenario_id: "ak.time_tolerance.temporal_constraint.v1",
        tolerance_id: "ak.time_tolerance.hard_future_skew.v1",
        direction: ProtocolTimeToleranceDirection::SymmetricNotBeforeAndExpiry,
        comparison: "not_before <= verification_time + tolerance and expires_at >= verification_time - tolerance, both inclusive",
    },
    ProtocolTimeToleranceScenarioDescriptor {
        scenario_id: "ak.time_tolerance.blob_presign_ttl.v1",
        tolerance_id: "ak.time_tolerance.expected_future_skew.v1",
        direction: ProtocolTimeToleranceDirection::SymmetricNotBeforeAndExpiry,
        comparison: "issued_at <= verification_time + tolerance and expires_at >= verification_time - tolerance, both inclusive",
    },
];

pub fn protocol_time_tolerance(value: &str) -> Option<&'static ProtocolTimeToleranceDescriptor> {
    PROTOCOL_TIME_TOLERANCES
        .iter()
        .find(|row| row.tolerance_id == value)
}

pub fn protocol_time_tolerance_scenario(
    value: &str,
) -> Option<&'static ProtocolTimeToleranceScenarioDescriptor> {
    PROTOCOL_TIME_TOLERANCE_SCENARIOS
        .iter()
        .find(|row| row.scenario_id == value)
}
