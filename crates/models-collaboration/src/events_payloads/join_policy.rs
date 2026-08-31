//! Join-policy event payloads.

use arkret_wire::DidCoreId;

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
pub struct JoinPolicyPayloadGatesItem {
    pub gate_id: JoinPolicyGateId,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_resolve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_did_methods: Option<Vec<DidMethod>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_principal_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_principal_ids: Option<Vec<DidCoreId>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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
pub struct JoinPolicyPayload {
    pub gates: Vec<JoinPolicyPayloadGatesItem>,
    pub combinator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hint: Option<JoinPolicyDirectoryHint>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_policy_keeps_open_extensions_but_rejects_retired_review_hints() {
        let value = serde_json::json!({
            "gates": [{
                "gate_id": "membership",
                "kind": "parent_membership",
                "x_gate_extension": {"enabled": true}
            }],
            "combinator": "all",
            "directory_hint": {
                "summary": "Membership required",
                "challenge_kinds_displayed": ["captcha"]
            },
            "x_policy_extension": {"enabled": true}
        });
        let payload: JoinPolicyPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), value);

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
    fn did_method_selector_is_not_parsed_as_a_did() {
        let method: DidMethod = serde_json::from_str(r#""did:webvh""#).unwrap();
        assert_eq!(method.as_str(), "did:webvh");
        assert!(serde_json::from_str::<DidMethod>(r#""did:webvh:alice""#).is_err());
        assert!(serde_json::from_str::<DidMethod>(r#""webvh""#).is_err());
    }
}
