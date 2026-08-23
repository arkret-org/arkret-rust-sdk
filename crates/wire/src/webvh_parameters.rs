//! Closed `did:webvh:1.0` method-parameter registry.

use crate::{Result, WireError};

/// The complete parameter-name allowlist defined by `did:webvh` v1.0.
/// Arkret governance is carried by DID Document overlays and is intentionally
/// absent from this method-native registry.
const DID_WEBVH_V1_PARAMETER_NAMES: [&str; 7] = [
    "method",
    "scid",
    "updateKeys",
    "nextKeyHashes",
    "witness",
    "watchers",
    "portable",
];

/// Fail closed on any parameter name outside the v1.0 method registry.
pub fn validate_did_webvh_v1_parameter_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    for name in names {
        if !DID_WEBVH_V1_PARAMETER_NAMES.contains(&name) {
            return Err(WireError::Protocol(format!(
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
