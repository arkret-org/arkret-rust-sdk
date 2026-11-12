//! Preview-policy event payloads.

use crate::internal_prelude::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueToken {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub token_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_target_digest_binding_required"
    )]
    pub target_digest_binding_required: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValue {
    pub mode: String,
    pub audiences: Vec<String>,
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<PreviewPolicyPayloadValueHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<PreviewPolicyPayloadValueToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayload {
    pub value: PreviewPolicyPayloadValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

include!("generated/preview_contracts.rs");

fn deserialize_optional_target_digest_binding_required<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<bool>, D::Error> {
    let value = bool::deserialize(deserializer)?;
    if !value {
        return Err(serde::de::Error::custom(
            "target_digest_binding_required must be true",
        ));
    }
    Ok(Some(value))
}

impl PreviewPolicyPayloadValueToken {
    pub fn validate(&self) -> Result<()> {
        if self.target_digest_binding_required == Some(false) {
            return Err(WireError::Protocol(
                "target_digest_binding_required must be true".into(),
            ));
        }
        Ok(())
    }
}
