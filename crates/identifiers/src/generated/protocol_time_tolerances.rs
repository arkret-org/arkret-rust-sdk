//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-29.2;
//! sha256=e8e1ba111871ea8b1dfdd89c1f770cac370d10efd3e3e1133cd41d4bf8685161
//! Entries: protocol_time_tolerances=2, protocol_time_tolerance_scenarios=3

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolTimeToleranceDirection {
    FutureOnly,
    SymmetricNotBeforeAndExpiry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolTimeToleranceScenario {
    ApprovalApprovedAt,
    TemporalConstraint,
    BlobPresignTtl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolTimeToleranceDescriptor {
    pub tolerance_id: &'static str,
    pub name: &'static str,
    pub value_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolTimeToleranceScenarioDescriptor {
    pub scenario: ProtocolTimeToleranceScenario,
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
        scenario: ProtocolTimeToleranceScenario::ApprovalApprovedAt,
        scenario_id: "ak.time_tolerance.approval_approved_at.v1",
        tolerance_id: "ak.time_tolerance.hard_future_skew.v1",
        direction: ProtocolTimeToleranceDirection::FutureOnly,
        comparison: "approved_at <= verification_time + tolerance, inclusive",
    },
    ProtocolTimeToleranceScenarioDescriptor {
        scenario: ProtocolTimeToleranceScenario::TemporalConstraint,
        scenario_id: "ak.time_tolerance.temporal_constraint.v1",
        tolerance_id: "ak.time_tolerance.hard_future_skew.v1",
        direction: ProtocolTimeToleranceDirection::SymmetricNotBeforeAndExpiry,
        comparison: "not_before <= verification_time + tolerance and expires_at >= verification_time - tolerance, both inclusive",
    },
    ProtocolTimeToleranceScenarioDescriptor {
        scenario: ProtocolTimeToleranceScenario::BlobPresignTtl,
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

pub const fn protocol_time_tolerance_scenario_descriptor(
    scenario: ProtocolTimeToleranceScenario,
) -> &'static ProtocolTimeToleranceScenarioDescriptor {
    &PROTOCOL_TIME_TOLERANCE_SCENARIOS[scenario as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_and_wire_scenario_lookups_are_bijective() {
        for row in PROTOCOL_TIME_TOLERANCE_SCENARIOS {
            assert_eq!(
                protocol_time_tolerance_scenario_descriptor(row.scenario),
                row
            );
            assert_eq!(protocol_time_tolerance_scenario(row.scenario_id), Some(row));
        }
        assert_eq!(
            PROTOCOL_TIME_TOLERANCE_SCENARIOS.len(),
            ProtocolTimeToleranceScenario::BlobPresignTtl as usize + 1
        );
        assert!(protocol_time_tolerance_scenario("ak.time_tolerance.unknown.v1").is_none());
    }
}
