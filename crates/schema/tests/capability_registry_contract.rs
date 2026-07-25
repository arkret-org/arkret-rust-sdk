use arkret_schema::{CapabilityRiskTier, capability_action_descriptor};
use arkret_wire::CapabilityActionId;

#[test]
fn capability_descriptor_is_indexed_by_canonical_action_id() {
    let descriptor = capability_action_descriptor(CapabilityActionId::CircleManage);

    assert_eq!(descriptor.action, CapabilityActionId::CircleManage);
    assert_eq!(descriptor.risk_tier, CapabilityRiskTier::Medium);
    assert_eq!(descriptor.required_constraints, &["allowed_circle_ids"]);
    assert_eq!(descriptor.event_mapping_kind, "aggregate_admin");
}
