//! Closed `did:webvh:1.0` method-parameter registry.

use serde_json::{Map, Value};

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

/// Apply one entry's `portable` parameter to its predecessor effective state.
///
/// WebVH parameters are state transitions: omission inherits the predecessor,
/// while an explicit boolean replaces it. A verifier must test a relocation
/// against the predecessor value before applying the successor parameters.
pub fn did_webvh_v1_effective_portable(
    predecessor_effective: bool,
    parameters: &Map<String, Value>,
) -> Result<bool> {
    match parameters.get("portable") {
        None => Ok(predecessor_effective),
        Some(Value::Bool(portable)) => Ok(*portable),
        Some(_) => Err(WireError::Protocol(
            "param_invalid: did:webvh:1.0 portable must be a boolean".to_owned(),
        )),
    }
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

    #[test]
    fn portable_is_an_effective_transition_value() {
        let absent = Map::new();
        assert!(!did_webvh_v1_effective_portable(false, &absent).unwrap());
        assert!(did_webvh_v1_effective_portable(true, &absent).unwrap());

        let enable = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
            "portable": true
        }))
        .unwrap();
        let disable = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
            "portable": false
        }))
        .unwrap();
        assert!(did_webvh_v1_effective_portable(false, &enable).unwrap());
        assert!(!did_webvh_v1_effective_portable(true, &disable).unwrap());
    }
}
