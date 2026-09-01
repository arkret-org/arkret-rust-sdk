use serde::{Deserialize, Serialize};

use crate::DidCoreId;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveDisclosureLevel {
    Opaque,
    Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveDisclosureMax {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_trust_max: Option<ReceiveDisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_trust_max: Option<ReceiveDisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_trust_max: Option<ReceiveDisclosureLevel>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivePolicyConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<Vec<ReceivePolicySurface>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_allowed_introduction_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_denied_introduction_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claim_max_behavior: Option<InviteReceiveAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_address_max_behavior: Option<InviteReceiveAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_invites_max_behavior: Option<UnknownInviteAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_max: Option<ReceiveDisclosureMax>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_handle_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_handle_issuer_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_directory_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_source_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_source_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_subject_did_methods: Option<Vec<String>>,
}
