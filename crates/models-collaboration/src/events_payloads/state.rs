//! Generic state event payloads.

use std::fmt;

use crate::internal_prelude::*;

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

macro_rules! validated_string_newtype {
    ($name:ident, $validator:ident, $message:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$validator(&value) {
                    return schema_violation($message);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn reducer_profile_id_is_valid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak.reducer") else {
        return false;
    };
    let Some((namespace, version)) = rest.rsplit_once(".v") else {
        return false;
    };
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    namespace.is_empty()
        || namespace.strip_prefix('.').is_some_and(|name| {
            name.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.' | b'-')
                })
        })
}

fn trust_domain_id_is_valid(value: &str) -> bool {
    let Some(body) = value.strip_prefix("ak:trust_domain:") else {
        return false;
    };
    (1..=128).contains(&body.len())
        && body
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && body.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':')
        })
}

fn policy_rule_id_is_valid(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

validated_string_newtype!(
    ReducerProfileId,
    reducer_profile_id_is_valid,
    "invalid reducer profile id"
);
validated_string_newtype!(
    TrustDomainId,
    trust_domain_id_is_valid,
    "invalid trust domain id"
);
validated_string_newtype!(
    PolicyRuleId,
    policy_rule_id_is_valid,
    "invalid policy rule id"
);

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePayload {
    /// Spec-declared open state value. `state` is lifecycle metadata and does
    /// not discriminate this value's shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `event-payload.schema.json#/$defs/realm_upgrade_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmUpgradeStatePayload {
    pub target_reducer_profile: ReducerProfileId,
}

macro_rules! state_payload_with_subject {
    ($name:ident, $field:ident, $field_type:ty) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub $field: $field_type,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub value: Option<Value>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub state: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub reason: Option<String>,
        }
    };
}

state_payload_with_subject!(OrganizationDiscoveryStatePayload, organization_did, Did);
state_payload_with_subject!(ResourceDiscoveryStatePayload, resource_id, NonEmptyString);
state_payload_with_subject!(DidProofStatePayload, did, Did);
state_payload_with_subject!(
    IdentityDisclosurePolicyStatePayload,
    policy_id,
    NonEmptyString
);
state_payload_with_subject!(IdentityDisclosureReceiptStatePayload, holder_did, Did);
state_payload_with_subject!(
    IdentityPresentationRequestStatePayload,
    request_id,
    NonEmptyString
);
state_payload_with_subject!(SchemaDefineStatePayload, schema_id, NonEmptyString);
state_payload_with_subject!(PolicySetStatePayload, policy_id, NonEmptyString);
state_payload_with_subject!(PolicyRuleStatePayload, rule_id, PolicyRuleId);
state_payload_with_subject!(SovereignDidPolicyStatePayload, trust_domain, TrustDomainId);

/// The response and request kinds intentionally share one schema.
pub type IdentityPresentationResponseStatePayload = IdentityPresentationRequestStatePayload;

/// Define and update intentionally share one schema.
pub type SchemaUpdateStatePayload = SchemaDefineStatePayload;

/// Counterpart for
/// `event-payload.schema.json#/$defs/organization_moderation_policy_state_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyStatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<NonEmptyString>,
    /// Spec-declared open moderation-policy value. `state` is independent status
    /// metadata, not a discriminator for this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizationModerationPolicyStatePayloadWire {
    organization_did: Option<Did>,
    organization_id: Option<NonEmptyString>,
    value: Option<Value>,
    state: Option<String>,
    reason: Option<String>,
}

impl OrganizationModerationPolicyStatePayload {
    pub fn validate(&self) -> Result<()> {
        if self.organization_did.is_some() == self.organization_id.is_some() {
            return schema_violation(
                "organization moderation policy requires exactly one organization identifier",
            );
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for OrganizationModerationPolicyStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = OrganizationModerationPolicyStatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            organization_did: wire.organization_did,
            organization_id: wire.organization_id,
            value: wire.value,
            state: wire.state,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/policy_action_state_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionStatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<NonEmptyString>,
    /// Spec-declared open action result. `state` is independent status
    /// metadata, not a discriminator for this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyActionStatePayloadWire {
    policy_id: Option<NonEmptyString>,
    action_id: Option<NonEmptyString>,
    value: Option<Value>,
    state: Option<String>,
    reason: Option<String>,
}

impl PolicyActionStatePayload {
    pub fn validate(&self) -> Result<()> {
        if self.policy_id.is_some() == self.action_id.is_some() {
            return schema_violation("policy action requires exactly one policy_id or action_id");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PolicyActionStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PolicyActionStatePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            policy_id: wire.policy_id,
            action_id: wire.action_id,
            value: wire.value,
            state: wire.state,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/state_conflict_recovery_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateConflictRecoveryPayload {
    pub target_cell: CellRef,
    pub resolved_value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateConflictRecoveryPayloadWire {
    target_cell: CellRef,
    resolved_value: Value,
    reason: Option<String>,
}

impl StateConflictRecoveryPayload {
    pub fn validate(&self) -> Result<()> {
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.chars().count() > 512)
        {
            return schema_violation("conflict recovery reason exceeds 512 characters");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for StateConflictRecoveryPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StateConflictRecoveryPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            target_cell: wire.target_cell,
            resolved_value: wire.resolved_value,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/notary_fault_equivocation_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryFaultEquivocationPayload {
    pub signer_id: Did,
    pub seal_a: Seal,
    pub seal_b: Seal,
}

/// Open signed receipt object used by notary censorship evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotaryCensorshipReceipt {
    pub event_digest: Value,
    pub received_at: Value,
    pub signature: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `event-payload.schema.json#/$defs/notary_fault_censorship_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryFaultCensorshipPayload {
    pub signer_id: Did,
    pub receipt: NotaryCensorshipReceipt,
    pub seal_ref: SealId,
    pub non_membership_proof: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_rejection_or_defer_proof: Option<BTreeMap<String, Value>>,
}
