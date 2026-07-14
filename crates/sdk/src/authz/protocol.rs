//! Protocol-facing authorization DTO aliases.
//!
//! Grant constraints are owned by `arkret-core` because they are part of the
//! canonical capability grant wire artifact. This module intentionally re-exports
//! those core types instead of maintaining an SDK-local parallel model.

pub type ProtocolGrantApprovalMode = arkret_core::ApprovalWorkflowMode;
pub type ProtocolGrantApprovalRelation = arkret_core::GrantApprovalRelation;
pub type ProtocolGrantClaimRequirement = arkret_core::GrantConstraintClaimRequirement;
pub type ProtocolGrantConstraint = arkret_core::GrantConstraint;
pub type ProtocolGrantConstraintEffect = arkret_core::GrantConstraintEffect;
pub type ProtocolGrantConstraintScope = arkret_core::GrantConstraintScope;
pub type ProtocolGrantConstraintSubtype = arkret_core::GrantConstraintSubtype;
pub type ProtocolGrantConstraintType = arkret_core::GrantConstraintType;
pub type ProtocolGrantExtensionKey = arkret_core::GrantConstraintExtensionKey;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn approval_relation_uses_realm_admin_wire_value() {
        assert_eq!(
            serde_json::to_string(&ProtocolGrantApprovalRelation::RealmAdmin).unwrap(),
            "\"realm_admin\""
        );
        assert!(serde_json::from_str::<ProtocolGrantApprovalRelation>("\"space_admin\"").is_err());
    }

    #[test]
    fn grant_constraint_rejects_non_schema_extension_keys() {
        let value = json!({
            "constraint_type": "claim_based",
            "subtype": "approval",
            "effect": "require_review",
            "priority": 10
        });
        assert!(serde_json::from_value::<ProtocolGrantConstraint>(value).is_err());

        let value = json!({
            "constraint_type": "claim_based",
            "subtype": "approval",
            "effect": "require_review",
            "x_approval_profile": {"name": "ops"}
        });
        let parsed: ProtocolGrantConstraint = serde_json::from_value(value).unwrap();
        let extension_key = ProtocolGrantExtensionKey::new("x_approval_profile").unwrap();
        assert!(parsed.extensions.contains_key(extension_key.as_str()));
    }

    #[test]
    fn scaffold_examples_emit_schema_approval_modes() {
        let examples = ProtocolGrantConstraint::scaffold_examples();
        let serialized = serde_json::to_value(examples).unwrap();
        assert!(!serialized.to_string().contains("two_man_rule"));
        assert!(!serialized.to_string().contains("move_gate"));
    }
}
