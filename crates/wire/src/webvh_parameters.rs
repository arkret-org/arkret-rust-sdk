//! Closed `did:webvh:1.0` method-parameter registry.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The complete parameter-name allowlist defined by `did:webvh` v1.0.
/// Arkret governance is carried by DID Document overlays and is intentionally
/// absent from this method-native registry.
pub const DID_WEBVH_V1_PARAMETER_NAMES: [&str; 7] = [
    "method",
    "scid",
    "updateKeys",
    "nextKeyHashes",
    "witness",
    "watchers",
    "portable",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DidWebvhV1ParameterName {
    #[serde(rename = "method")]
    Method,
    #[serde(rename = "scid")]
    Scid,
    #[serde(rename = "updateKeys")]
    UpdateKeys,
    #[serde(rename = "nextKeyHashes")]
    NextKeyHashes,
    #[serde(rename = "witness")]
    Witness,
    #[serde(rename = "watchers")]
    Watchers,
    #[serde(rename = "portable")]
    Portable,
}

impl DidWebvhV1ParameterName {
    pub const ALL: [Self; 7] = [
        Self::Method,
        Self::Scid,
        Self::UpdateKeys,
        Self::NextKeyHashes,
        Self::Witness,
        Self::Watchers,
        Self::Portable,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        DID_WEBVH_V1_PARAMETER_NAMES[self as usize]
    }

    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|parameter| parameter.as_str() == value)
    }
}

/// Fail closed on any parameter name outside the v1.0 method registry.
pub fn validate_did_webvh_v1_parameter_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    for name in names {
        if DidWebvhV1ParameterName::from_wire(name).is_none() {
            return Err(Error::Protocol(format!(
                "param_invalid: unknown did:webvh:1.0 parameter {name:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_closed_and_excludes_governance() {
        validate_did_webvh_v1_parameter_names(DID_WEBVH_V1_PARAMETER_NAMES).unwrap();
        let error = validate_did_webvh_v1_parameter_names(["governance"]).unwrap_err();
        assert!(error.to_string().contains("param_invalid"));
    }
}
