use arkret_schema::{
    ApprovalRequirementEligibility, CapabilityRiskTier, approval_evidence_carrier_for_action,
    capability_action_descriptor,
};
use arkret_wire::CapabilityActionId;

#[test]
fn capability_descriptor_is_indexed_by_canonical_action_id() {
    let descriptor = capability_action_descriptor(CapabilityActionId::CircleManage);

    assert_eq!(descriptor.action, CapabilityActionId::CircleManage);
    assert_eq!(descriptor.risk_tier, CapabilityRiskTier::Medium);
    assert_eq!(descriptor.required_constraints, &["allowed_circle_ids"]);
    assert_eq!(descriptor.event_mapping_kind, "aggregate_admin");
}

#[test]
fn durable_event_action_uses_the_registered_submission_carrier() {
    let descriptor = capability_action_descriptor(CapabilityActionId::CircleManage);

    assert_eq!(
        descriptor.approval_requirement_eligibility,
        ApprovalRequirementEligibility::EventSubmissionCarrier
    );
    let carrier = approval_evidence_carrier_for_action(descriptor.action)
        .expect("event-backed action has a registered approval evidence carrier");
    assert_eq!(carrier.operation_id, "ak.self.events.command.submit.v1");
    assert_eq!(carrier.carrier_field, "approval_signatures");
    assert_eq!(carrier.allowed_target_kinds, &["event", "operation"]);
}

#[test]
fn non_event_action_without_an_override_is_not_approval_eligible() {
    let descriptor = capability_action_descriptor(CapabilityActionId::ApprovalVote);

    assert_eq!(
        descriptor.approval_requirement_eligibility,
        ApprovalRequirementEligibility::IneligibleNoRegisteredCarrier
    );
    assert!(approval_evidence_carrier_for_action(descriptor.action).is_none());
}
