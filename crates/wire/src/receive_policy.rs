use serde::{Deserialize, Serialize};

use crate::Did;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteReceiveAction {
    Drop,
    Quarantine,
    Notify,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum UnknownInviteAction {
    Drop,
    Quarantine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceivePolicySurface {
    InviteDelivery,
    ContactRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivePolicyConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<Vec<ReceivePolicySurface>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permitted_introduction_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_introduction_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claim_max_behavior: Option<InviteReceiveAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_address_max_behavior: Option<InviteReceiveAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_invites_max_behavior: Option<UnknownInviteAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_handle_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_handle_issuers: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_directory_services: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_principal_services: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_principal_services: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_subject_did_methods: Option<Vec<String>>,
}
