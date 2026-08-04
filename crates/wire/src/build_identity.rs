use serde::{Deserialize, Serialize};

use crate::{EVENT_KIND_REGISTRY_SHA256, Error, Result};

/// Vendor extension key carrying the exact shared SDK identity in a service
/// description. This is a development build guard, not a compatibility range.
pub const ARKRET_BUILD_IDENTITY_EXTENSION: &str = "x_arkret_build_identity";

/// Development request header used to reject a browser bundle compiled from a
/// different shared SDK checkout before its body is parsed or persisted.
pub const HEADER_ARKRET_SDK_SOURCE_SHA256: &str = "X-Arkret-SDK-Source-SHA256";

/// Identity of the shared SDK contract compiled into one executable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkretBuildIdentity {
    pub event_kind_registry_sha256: String,
    pub sdk_source_sha256: String,
}

impl ArkretBuildIdentity {
    #[must_use]
    pub fn current() -> Self {
        Self {
            event_kind_registry_sha256: EVENT_KIND_REGISTRY_SHA256.to_owned(),
            sdk_source_sha256: SDK_SOURCE_SHA256.to_owned(),
        }
    }

    pub fn validate_current(&self) -> Result<()> {
        let current = Self::current();
        if self == &current {
            return Ok(());
        }
        Err(Error::Protocol(format!(
            "Arkret SDK build identity mismatch: local registry={}, local SDK={}, remote registry={}, remote SDK={}",
            current.event_kind_registry_sha256,
            current.sdk_source_sha256,
            self.event_kind_registry_sha256,
            self.sdk_source_sha256,
        )))
    }
}

/// SHA-256 over every shared SDK Cargo manifest and Rust source file.
///
/// Unlike the event-kind registry digest, this changes when a shared Rust wire
/// shape changes without changing a generated specification artifact.
pub const SDK_SOURCE_SHA256: &str = env!("ARKRET_SDK_SOURCE_SHA256");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_identity_validates() {
        ArkretBuildIdentity::current().validate_current().unwrap();
    }

    #[test]
    fn changed_sdk_identity_is_rejected() {
        let mut identity = ArkretBuildIdentity::current();
        identity.sdk_source_sha256 = "stale".to_owned();
        let error = identity.validate_current().unwrap_err().to_string();
        assert!(error.contains("SDK build identity mismatch"));
        assert!(error.contains("remote SDK=stale"));
    }
}
