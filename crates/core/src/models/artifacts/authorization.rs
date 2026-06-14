//! Authorization and policy schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/authz-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthzOperations {
    AuthzInviteList(AuthzInviteList),
}

/// Counterpart for `spec/v1/artifacts/schemas/policy.schema.json#/$defs/domain_name`.
pub type DomainName = String;

/// Counterpart for `spec/v1/artifacts/schemas/policy.schema.json#/$defs/server_selector`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSelector {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_subdomains: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
}

/// Counterpart for `spec/v1/artifacts/schemas/policy.schema.json#/$defs/trust_domain`.
pub type TrustDomain = String;
