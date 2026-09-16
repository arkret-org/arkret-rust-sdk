//! Governance-materialized signer policy for recovery and admission authority.
//!
//! The object is produced by the current governance Station from accepted
//! control state; it is not an offline publication lease and carries no
//! issuer-side bearer material. It is restored here because the PCR recovery
//! session snapshots one verbatim into its publication authority context.

use arkret_wire::{
    AuthoritySetPolicyKind, DidUrl, RealmCommitId, Result, SchemaId, ScopeRef, WireError,
};
use serde::{Deserialize, Serialize};

/// Maximum authorization rules one materialized policy may carry.
pub const AUTHORITY_SET_POLICY_MAX_RULES: usize = 32;
/// Maximum issuers a single authorization rule may carry.
pub const AUTHORITY_SET_RULE_MAX_ISSUERS: usize = 32;
/// Maximum allowed actions a single authorization rule may carry.
pub const AUTHORITY_SET_RULE_MAX_ALLOWED_ACTIONS: usize = 64;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySetIssuerRole {
    IdentityRecovery,
    AcceptedDevice,
    RealmAdmission,
}

// Field declaration order is byte-for-byte the properties order of
// authority-set-policy.schema.json#/properties/authorization_rules/items/
// properties/issuers/items.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetAuthorizationIssuer {
    pub verification_method: DidUrl,
}

// Field declaration order is byte-for-byte the properties order of
// authority-set-policy.schema.json#/properties/authorization_rules/items.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetAuthorizationRule {
    pub rule_id: String,
    pub issuer_role: AuthoritySetIssuerRole,
    pub allowed_actions: Vec<String>,
    pub issuers: Vec<AuthoritySetAuthorizationIssuer>,
    pub threshold: u32,
}

// Field declaration order is byte-for-byte the properties order of
// authority-set-policy.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetPolicy {
    pub schema: String,
    pub authority_set_id: String,
    pub policy_kind: AuthoritySetPolicyKind,
    pub scope_ref: ScopeRef,
    pub source_commit_id: RealmCommitId,
    pub authorization_rules: Vec<AuthoritySetAuthorizationRule>,
}

impl AuthoritySetPolicy {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != SchemaId::AUTHORITY_SET_POLICY_V1 {
            return Err(WireError::Protocol(
                "authority set policy schema is invalid".to_owned(),
            ));
        }
        if self.authorization_rules.is_empty()
            || self.authorization_rules.len() > AUTHORITY_SET_POLICY_MAX_RULES
        {
            return Err(WireError::Protocol(
                "authority set policy carries 1..=32 authorization rules".to_owned(),
            ));
        }
        for rule in &self.authorization_rules {
            if rule.allowed_actions.is_empty()
                || rule.allowed_actions.len() > AUTHORITY_SET_RULE_MAX_ALLOWED_ACTIONS
            {
                return Err(WireError::Protocol(
                    "authority set rule carries 1..=64 allowed actions".to_owned(),
                ));
            }
            if rule.issuers.is_empty() || rule.issuers.len() > AUTHORITY_SET_RULE_MAX_ISSUERS {
                return Err(WireError::Protocol(
                    "authority set rule carries 1..=32 issuers".to_owned(),
                ));
            }
            if rule.threshold == 0 || rule.threshold as usize > AUTHORITY_SET_RULE_MAX_ISSUERS {
                return Err(WireError::Protocol(
                    "authority set rule threshold is 1..=32".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm_id_value() -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [7; 32],
        ))
    }

    fn policy_value() -> serde_json::Value {
        json!({
            "schema": "ak.schema.authority_set_policy.v1",
            "authority_set_id": "ak.authority_set.principal_control.v1",
            "policy_kind": "principal_control",
            "scope_ref": {"kind": "realm", "realm_id": realm_id_value()},
            "source_commit_id": RealmCommitId::from_digest([9; 32]),
            "authorization_rules": [{
                "rule_id": "identity_recovery",
                "issuer_role": "identity_recovery",
                "allowed_actions": ["ak.device.reanchor"],
                "issuers": [{"verification_method": "did:webvh:z6mkfixture:alice.example#recovery-1"}],
                "threshold": 1
            }]
        })
    }

    #[test]
    fn authority_set_policy_round_trips_and_is_closed() {
        let value = policy_value();
        let parsed: AuthoritySetPolicy =
            serde_json::from_value(value.clone()).expect("closed policy");
        parsed.validate_shape().expect("valid policy");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("lattice".to_owned(), json!(1));
        assert!(serde_json::from_value::<AuthoritySetPolicy>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("source_commit_id");
        assert!(serde_json::from_value::<AuthoritySetPolicy>(missing).is_err());
    }

    #[test]
    fn authorization_rule_threshold_floor_is_enforced() {
        let mut value = policy_value();
        value["authorization_rules"][0]["threshold"] = json!(0);
        let parsed: AuthoritySetPolicy = serde_json::from_value(value).expect("shape parses");
        assert!(parsed.validate_shape().is_err());
    }
}
