//! Closed external protocol-execution attestation DTO.

use std::collections::BTreeSet;
use std::fmt;

use arkret_wire::{Base64UrlString, Did, Hash, NonEmptyString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A canonical lowercase 40-hex Git object identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct GitSha(String);

impl GitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Git SHA must contain exactly 40 lowercase hexadecimal characters");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for GitSha {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GitSha {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Non-empty, duplicate-free artifact digest list.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolArtifactDigests(Vec<Hash>);

impl ProtocolArtifactDigests {
    pub fn new(values: Vec<Hash>) -> Result<Self, &'static str> {
        if values.is_empty() {
            return Err("artifact_digests must not be empty");
        }
        let mut seen = BTreeSet::new();
        if values.iter().any(|value| !seen.insert(value.as_str())) {
            return Err("artifact_digests must be unique");
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[Hash] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<Hash> {
        self.0
    }
}

impl Serialize for ProtocolArtifactDigests {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProtocolArtifactDigests {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::<Hash>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ProtocolExecutionResult {
    Passed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolExecutionAttestation {
    pub spec_sha: GitSha,
    pub cotest_sha: GitSha,
    pub runner_sha: GitSha,
    pub command: NonEmptyString,
    pub result: ProtocolExecutionResult,
    pub artifact_digests: ProtocolArtifactDigests,
    pub issuer: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_manifest_digest: Option<Hash>,
    pub protected: Base64UrlString,
    pub signature: Base64UrlString,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid_attestation() -> serde_json::Value {
        json!({
            "spec_sha":"8c409c2dbb75bd7f48bc8034a3bb8b7d198d9439",
            "cotest_sha":"1111111111111111111111111111111111111111",
            "runner_sha":"2222222222222222222222222222222222222222",
            "command":"cargo test --locked",
            "result":"passed",
            "artifact_digests":[format!("sha256:{}", "a".repeat(64))],
            "issuer":"did:webvh:z6mkfixture:ci.example",
            "protected":"ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbXRwWkNJNkltdHBMVEVpZlE",
            "signature":"c2lnbmF0dXJl"
        })
    }

    #[test]
    fn attestation_roundtrips_as_a_closed_object() {
        let value = valid_attestation();
        let attestation: ProtocolExecutionAttestation =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(attestation.result, ProtocolExecutionResult::Passed);
        assert_eq!(serde_json::to_value(attestation).unwrap(), value);

        let mut unknown = valid_attestation();
        unknown["execution_status"] = json!("verified");
        assert!(serde_json::from_value::<ProtocolExecutionAttestation>(unknown).is_err());
    }

    #[test]
    fn sha_and_artifact_digest_constraints_fail_closed() {
        let mut uppercase_sha = valid_attestation();
        uppercase_sha["spec_sha"] = json!("8C409C2DBB75BD7F48BC8034A3BB8B7D198D9439");
        assert!(serde_json::from_value::<ProtocolExecutionAttestation>(uppercase_sha).is_err());

        let mut empty = valid_attestation();
        empty["artifact_digests"] = json!([]);
        assert!(serde_json::from_value::<ProtocolExecutionAttestation>(empty).is_err());

        let mut duplicate = valid_attestation();
        let digest = format!("sha256:{}", "a".repeat(64));
        duplicate["artifact_digests"] = json!([digest.clone(), digest]);
        assert!(serde_json::from_value::<ProtocolExecutionAttestation>(duplicate).is_err());
    }
}
