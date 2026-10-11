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
pub enum JoinPolicyGate {
    ClaimRequired {
        gate_id: JoinPolicyGateId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_resolve: Option<bool>,
        required_claims: Vec<String>,
        /// Issuer boundary of the presented claims (`join-policy.md` §3.1).
        /// Required: a gate without one would accept a self-signed claim, so
        /// there is no shape of this gate that omits it.
        trusted_issuer_ids: Vec<DidCoreId>,
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
        /// Every source must have a current active `join_gate_from` link from
        /// the target Realm and share its current governing Station. The
        /// Station resolves authoritative current membership in the same
        /// durable final-admission transaction; callers provide no proof or
        /// cached authority basis for this gate.
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
    pub gates: Vec<JoinPolicyGate>,
    pub combinator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hint: Option<JoinPolicyDirectoryHint>,
}
