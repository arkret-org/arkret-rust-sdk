//! Operation identifiers, signatures, and membership-compensation evidence.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::DidUrl;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolSignature {
    pub verification_method: DidUrl,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

impl<'de> Deserialize<'de> for ProtocolSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSignature {
            verification_method: DidUrl,
            #[serde(with = "crate::serde_helpers::canonical_timestamp")]
            created_at: DateTime<Utc>,
            jws: String,
        }

        let value = WireSignature::deserialize(deserializer)?;
        if !crate::is_compact_detached_jws(&value.jws) {
            return Err(de::Error::custom(
                "protocol signature jws must be protected..signature compact detached JWS",
            ));
        }
        Ok(Self {
            verification_method: value.verification_method,
            created_at: value.created_at,
            jws: value.jws,
        })
    }
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
    pub const ID_KIND: &'static str = "membership_compensation_delegation";
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
