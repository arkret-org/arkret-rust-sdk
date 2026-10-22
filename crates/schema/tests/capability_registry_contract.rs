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

#[test]
fn only_registered_creation_approvals_use_an_explicit_administrator_grant() {
    let overridden = arkret_schema::REGISTERED_CAPABILITY_ACTIONS
        .iter()
        .filter_map(|descriptor| {
            descriptor
                .approver_capability_action
                .map(|action| (descriptor.action, action))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        overridden,
        vec![
            (
                CapabilityActionId::AppletBotProvision,
                CapabilityActionId::RealmAdmin
            ),
            (
                CapabilityActionId::AppletConfigure,
                CapabilityActionId::RealmAdmin
            ),
            (
                CapabilityActionId::AppletGhostProvision,
                CapabilityActionId::RealmAdmin
            ),
        ]
    );
    for (action, _) in overridden {
        let descriptor = capability_action_descriptor(action);
        let carrier = approval_evidence_carrier_for_action(action).unwrap();
        assert_eq!(carrier.carrier_field, "approval_signatures");
        match action {
            CapabilityActionId::AppletConfigure => {
                assert_eq!(
                    descriptor.approval_requirement_eligibility,
                    ApprovalRequirementEligibility::RegisteredOperationCarrier
                );
                assert!(descriptor.target_event_kinds.is_empty());
                assert_eq!(
                    carrier.carrier_id,
                    "applet_configuration.approval_signatures"
                );
                assert_eq!(
                    carrier.operation_id,
                    "ak.self.applet.configuration.command.submit.v1"
                );
                assert_eq!(carrier.allowed_target_kinds, &["operation"]);
                assert_eq!(carrier.carrier_class, "non_event_operation");
            }
            CapabilityActionId::AppletBotProvision | CapabilityActionId::AppletGhostProvision => {
                assert_eq!(
                    descriptor.approval_requirement_eligibility,
                    ApprovalRequirementEligibility::EventSubmissionCarrier
                );
                assert_eq!(
                    descriptor.target_event_kinds,
                    &[arkret_wire::event_kind_str::REALM_ACTOR_CREATE]
                );
                assert_eq!(
                    carrier.carrier_id,
                    "event_admission_submission.approval_signatures"
                );
                assert_eq!(carrier.operation_id, "ak.self.events.command.submit.v1");
                assert_eq!(carrier.carrier_field, "approval_signatures");
                assert_eq!(carrier.allowed_target_kinds, &["event", "operation"]);
                assert_eq!(carrier.carrier_class, "event_submission");
            }
            _ => panic!("unexpected explicit administrator approval override"),
        }
    }
}
