//! Operation identifiers, signatures, and membership-compensation evidence.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    ActorId, AuthorizationRef, Base64UrlString, DidCoreId, DidUrl, Event, EventId, Hash, RealmId,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolOpaqueId(String);

impl ProtocolOpaqueId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.chars().count() > 512 {
            return Err("protocol opaque id must contain 1 to 512 characters");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProtocolOpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ProtocolOpaqueId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolOpaqueId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

macro_rules! semantic_opaque_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
        pub struct $name(ProtocolOpaqueId);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                ProtocolOpaqueId::new(value)
                    .map(Self)
                    .map_err(|_| concat!($label, " must contain 1 to 512 characters"))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }

        impl From<ProtocolOpaqueId> for $name {
            fn from(value: ProtocolOpaqueId) -> Self {
                Self(value)
            }
        }

        impl From<$name> for ProtocolOpaqueId {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

semantic_opaque_id!(IdempotencyKey, "idempotency key");
semantic_opaque_id!(ReservationHandle, "reservation handle");
semantic_opaque_id!(KeyPackageRef, "key package ref");
semantic_opaque_id!(KeyPackageClaimId, "key package claim id");
semantic_opaque_id!(EffectId, "effect id");
semantic_opaque_id!(MlsCiphersuiteId, "MLS ciphersuite id");

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolOperationId(String);

impl ProtocolOperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let suffix = value
            .strip_prefix("ak:operation:")
            .ok_or("operation id must start with ak:operation:")?;
        if suffix.is_empty()
            || !suffix.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
        {
            return Err("operation id has an invalid suffix");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProtocolOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ProtocolOperationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolOperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolSignature {
    pub verification_method: DidUrl,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipCompensationAction {
    #[serde(rename = "ak.member.compensate.leave")]
    Leave,
    #[serde(rename = "ak.member.compensate.remove")]
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipCompensationDelegationRef(String);

impl MembershipCompensationDelegationRef {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let suffix = value
            .strip_prefix("ak:membership_compensation_delegation:sha256:")
            .ok_or("invalid membership compensation delegation prefix")?;
        if suffix.len() != 64
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("membership compensation delegation requires 64 lowercase hex digits");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for MembershipCompensationDelegationRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MembershipCompensationDelegationRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipCompensationAuthority {
    V1,
}

impl Serialize for MembershipCompensationAuthority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(crate::AuthoritySourceId::MEMBERSHIP_COMPENSATION_V1)
    }
}

impl<'de> Deserialize<'de> for MembershipCompensationAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        (value == crate::AuthoritySourceId::MEMBERSHIP_COMPENSATION_V1)
            .then_some(Self::V1)
            .ok_or_else(|| de::Error::custom("unknown membership compensation authority"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipCompensationDelegationCore {
    pub authority: MembershipCompensationAuthority,
    pub admission_id: ProtocolOpaqueId,
    pub join_event_id: EventId,
    pub membership_cell_id: ProtocolOpaqueId,
    pub member_id: ActorId,
    pub join_actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<AuthorizationRef>,
    pub verification_method: DidUrl,
    pub executor_id: ActorId,
    pub executor_proof_key_kid: DidUrl,
    pub resource_id: RealmId,
    pub action: MembershipCompensationAction,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub deadline: DateTime<Utc>,
}

impl MembershipCompensationDelegationCore {
    pub fn validate(&self) -> crate::Result<()> {
        if self.executed_by.is_some() != self.authorization_ref.is_some() {
            return Err(crate::WireError::Protocol(
                "membership compensation executed_by requires authorization_ref".to_owned(),
            ));
        }
        let expected_action = if self.executed_by.is_none() && self.join_actor_id == self.member_id
        {
            MembershipCompensationAction::Leave
        } else {
            MembershipCompensationAction::Remove
        };
        if self.action != expected_action {
            return Err(crate::WireError::Protocol(
                "membership compensation action does not match join authorship".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipCompensationExecutorDelegation {
    pub delegation_id: MembershipCompensationDelegationRef,
    pub core: MembershipCompensationDelegationCore,
    pub delegation_digest: Hash,
    pub signature: ProtocolSignature,
}

impl MembershipCompensationExecutorDelegation {
    pub fn validate_content_address(&self) -> crate::Result<()> {
        self.core.validate()?;
        let bytes = crate::canonical::canonical_json_bytes(&self.core)?;
        let digest = crate::canonical::sha256_digest(bytes);
        if digest != self.delegation_digest.as_str() {
            return Err(crate::WireError::Protocol(
                "membership compensation delegation digest mismatch".to_owned(),
            ));
        }
        let suffix = digest.strip_prefix("sha256:").unwrap_or_default();
        if self.delegation_id.as_str()
            != format!("ak:membership_compensation_delegation:sha256:{suffix}")
        {
            return Err(crate::WireError::Protocol(
                "membership compensation delegation id mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipJoinAcceptedProof {
    pub admission_id: ProtocolOpaqueId,
    pub join_event_id: EventId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipCompensationTerminalState {
    FailedAfterMembershipAcceptance,
    FailedAfterMlsAdd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipCompensationTerminalDomain {
    #[serde(rename = "ak.membership_compensation.terminal_certificate.v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipCompensationTerminalCertificate {
    pub domain: MembershipCompensationTerminalDomain,
    pub admission_id: ProtocolOpaqueId,
    pub delegation_id: MembershipCompensationDelegationRef,
    pub operation_id: ProtocolOperationId,
    pub terminal_state: MembershipCompensationTerminalState,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub certified_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipCompensationCasDomain {
    #[serde(rename = "ak.membership_compensation.single_use_cas.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MembershipCompensationExpectedState {
    Unused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipCompensationCasToken {
    pub domain: MembershipCompensationCasDomain,
    pub admission_id: ProtocolOpaqueId,
    pub delegation_id: MembershipCompensationDelegationRef,
    pub expected_state: MembershipCompensationExpectedState,
    pub destination_id: DidCoreId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MembershipCompensationSubmissionEvidence {
    pub delegation: MembershipCompensationExecutorDelegation,
    pub join_accepted_proof: MembershipJoinAcceptedProof,
    pub terminal_certificate: MembershipCompensationTerminalCertificate,
    pub single_use_cas_token: MembershipCompensationCasToken,
}

impl MembershipCompensationSubmissionEvidence {
    pub fn validate_bindings(&self) -> crate::Result<()> {
        self.delegation.validate_content_address()?;
        let core = &self.delegation.core;
        if self.join_accepted_proof.admission_id != core.admission_id
            || self.join_accepted_proof.join_event_id != core.join_event_id
            || self.terminal_certificate.admission_id != core.admission_id
            || self.terminal_certificate.delegation_id != self.delegation.delegation_id
            || self.single_use_cas_token.admission_id != core.admission_id
            || self.single_use_cas_token.delegation_id != self.delegation.delegation_id
            || self.single_use_cas_token.destination_id != *core.executor_id.route_service_id()
        {
            return Err(crate::WireError::Protocol(
                "membership compensation evidence cross-binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate the evidence's exact binding to the submitted Event. This is
    /// semantic admission, not JSON shape validation; receivers map failures
    /// to `membership_compensation_conflict`.
    pub fn validate_for_event(&self, event: &Event) -> crate::Result<()> {
        self.validate_bindings()?;
        let core = &self.delegation.core;
        if event.kind.as_str() != crate::event_kind_str::MEMBER_STATE
            || event.executed_by.as_ref() != Some(&core.executor_id)
            || event.authorization_ref.as_ref().map(|value| value.as_str())
                != Some(self.delegation.delegation_id.as_str())
            || event.actor_id != core.join_actor_id
            || event.realm_id != core.resource_id
            || event
                .payload
                .get("member_id")
                .and_then(|value| serde_json::from_value::<ActorId>(value.clone()).ok())
                .as_ref()
                != Some(&core.member_id)
            || event
                .payload
                .get("membership")
                .and_then(serde_json::Value::as_str)
                != Some("leave")
        {
            return Err(crate::WireError::Protocol(
                "membership compensation evidence does not bind the submitted Event".to_owned(),
            ));
        }
        Ok(())
    }
}
