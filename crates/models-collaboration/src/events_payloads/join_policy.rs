//! Join-policy event payloads.

use arkret_wire::{AccountId, ActorId, Did, DidCoreId, RealmId};

use crate::internal_prelude::*;

/// Canonical DID method selector (`did:<lowercase-method>`), distinct from a
/// DID subject identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DidMethod(String);

impl DidMethod {
    pub fn new(value: String) -> Result<Self> {
        let Some(method) = value.strip_prefix("did:") else {
            return Err(WireError::Protocol(
                "DID method selector must start with 'did:'".to_owned(),
            ));
        };
        if method.is_empty()
            || !method
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(WireError::Protocol(
                "DID method selector must match ^did:[a-z0-9]+$".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DidMethod {
    type Error = WireError;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<DidMethod> for String {
    fn from(value: DidMethod) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JoinPolicyPayloadGatesItem {
    ClaimRequired {
        gate_id: JoinPolicyGateId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_resolve: Option<bool>,
        required_claims: Vec<String>,
    },
    ChallengeResponse {
        gate_id: JoinPolicyGateId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_resolve: Option<bool>,
        provider_did: Did,
        challenge_kinds: Vec<JoinPolicyDirectoryChallengeKind>,
        max_proof_age: String,
    },
    ParentMembership {
        gate_id: JoinPolicyGateId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_resolve: Option<bool>,
        membership_source_realm_ids: Vec<RealmId>,
        require_min_membership: JoinPolicyRequiredMembership,
    },
    PrincipalAdmission {
        gate_id: JoinPolicyGateId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_resolve: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_did_methods: Option<Vec<DidMethod>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_account_ids: Option<Vec<AccountId>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_account_ids: Option<Vec<AccountId>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_actor_ids: Option<Vec<ActorId>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_actor_ids: Option<Vec<ActorId>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_principal_ids: Option<Vec<DidCoreId>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_principal_ids: Option<Vec<DidCoreId>>,
    },
    Cooldown {
        gate_id: JoinPolicyGateId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_resolve: Option<bool>,
        min_interval_since_leave: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyRequiredMembership {
    Join,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicyDirectoryChallengeKind {
    Captcha,
    Pow,
    AttestedHuman,
    IdpOidc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyDirectoryHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_kinds_displayed: Option<Vec<JoinPolicyDirectoryChallengeKind>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinPolicyPayload {
    pub gates: Vec<JoinPolicyPayloadGatesItem>,
    pub combinator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hint: Option<JoinPolicyDirectoryHint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_policy_is_closed_and_kind_typed() {
        let value = serde_json::json!({
            "gates": [{
                "gate_id": "membership",
                "kind": "parent_membership",
                "membership_source_realm_ids": ["ak:realm:ASOikrLmQRDmUfDmMaw1Bx-NCkNptz9Sw2olIhr_M_23"],
                "require_min_membership": "join"
            }],
            "combinator": "all",
            "directory_hint": {
                "summary": "Membership required",
                "challenge_kinds_displayed": ["captcha"]
            }
        });
        let payload: JoinPolicyPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), value);

        let mut gate_extension = value.clone();
        gate_extension["gates"][0]["x_gate_extension"] = serde_json::json!({"enabled": true});
        assert!(serde_json::from_value::<JoinPolicyPayload>(gate_extension).is_err());
        let mut policy_extension = value.clone();
        policy_extension["x_policy_extension"] = serde_json::json!({"enabled": true});
        assert!(serde_json::from_value::<JoinPolicyPayload>(policy_extension).is_err());

        for (field, retired_value) in [
            ("expected_review_time", serde_json::json!("PT1H")),
            ("human_review_required", serde_json::json!(true)),
        ] {
            let mut retired = value.clone();
            retired["directory_hint"][field] = retired_value;
            assert!(serde_json::from_value::<JoinPolicyPayload>(retired).is_err());
        }
    }

    #[test]
    fn principal_admission_principal_ids_round_trip() {
        let value = serde_json::json!({
            "gates": [{
                "gate_id": "identity",
                "kind": "principal_admission",
                "allowed_principal_ids": ["ak:did_core:webvh:z6mkallowed"],
                "denied_principal_ids": ["ak:did_core:webvh:z6mkdenied"]
            }],
            "combinator": "all"
        });
        let payload: JoinPolicyPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), value);
    }

    #[test]
    fn principal_admission_rejects_unknown_principal_list_fields() {
        for disposition in ["allowed", "denied"] {
            let mut value = serde_json::json!({
                "gates": [{
                    "gate_id": "identity",
                    "kind": "principal_admission"
                }],
                "combinator": "all"
            });
            let legacy_field = [disposition, "_principal_", "core_ids"].concat();
            value["gates"][0][legacy_field] = serde_json::json!(["ak:did_core:webvh:z6mkfixture"]);
            assert!(serde_json::from_value::<JoinPolicyPayload>(value).is_err());
        }
    }

    #[test]
    fn did_method_selector_is_not_parsed_as_a_did() {
        let method: DidMethod = serde_json::from_str(r#""did:webvh""#).unwrap();
        assert_eq!(method.as_str(), "did:webvh");
        assert!(serde_json::from_str::<DidMethod>(r#""did:webvh:alice""#).is_err());
        assert!(serde_json::from_str::<DidMethod>(r#""webvh""#).is_err());
    }
}
