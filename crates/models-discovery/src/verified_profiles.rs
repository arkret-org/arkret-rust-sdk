//! Parser for cotest-produced `verified-profiles.json` artifacts.
//!
//! The artifact is consumed by every Arkret service that advertises
//! `ServiceDescribe::verified_profiles`. Parsing and validation live here so
//! services cannot drift on required fields, digest syntax or DID handling.

use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProfileArtifactEntry {
    pub profile_id: String,
    pub service_role: String,
    pub verification_run_id: String,
    pub artifact_digest: String,
    pub artifact_ref: String,
    pub verifier_id: DidCoreId,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub test_count: u64,
    pub spec_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedVerifiedProfileEntry {
    pub profile_id: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProfilesArtifactReport {
    pub version: Option<String>,
    pub run_id: Option<String>,
    pub total_entries: usize,
    pub entries: Vec<VerifiedProfileArtifactEntry>,
    pub dropped: Vec<DroppedVerifiedProfileEntry>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Debug, Deserialize)]
struct VerifiedProfilesArtifact {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    verified: Vec<RawVerifiedEntry>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Debug, Deserialize)]
struct RawVerifiedEntry {
    profile_id: String,
    #[serde(default)]
    claim_kind: Option<String>,
    #[serde(default)]
    verification_run_id: Option<String>,
    #[serde(default)]
    service_role: Option<String>,
    #[serde(default)]
    test_count: Option<u64>,
    #[serde(default)]
    spec_file: Option<String>,
    #[serde(default)]
    artifact_digest: Option<String>,
    #[serde(default)]
    artifact_ref: Option<String>,
    #[serde(default)]
    verifier_id: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    timestamp: Option<DateTime<Utc>>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
}

pub fn parse_verified_profiles_artifact(
    bytes: &[u8],
    expected_service_role: &str,
) -> Result<VerifiedProfilesArtifactReport, serde_json::Error> {
    let parsed: VerifiedProfilesArtifact = serde_json::from_slice(bytes)?;
    let total_entries = parsed.verified.len();
    let mut entries = Vec::with_capacity(total_entries);
    let mut dropped = Vec::new();

    for raw in parsed.verified {
        let profile_id = raw.profile_id.clone();
        let Some(service_role) = raw.service_role.filter(|value| !value.trim().is_empty()) else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "missing service_role",
            });
            continue;
        };
        if service_role != expected_service_role {
            continue;
        }
        if raw.claim_kind.as_deref() != Some("conformance_verified") {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "claim_kind must be conformance_verified",
            });
            continue;
        }
        let Some(verification_run_id) = non_empty(raw.verification_run_id) else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "missing verification_run_id",
            });
            continue;
        };
        let Some(artifact_digest) = valid_artifact_digest(raw.artifact_digest) else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "artifact_digest must match sha256:<64 lowercase hex>",
            });
            continue;
        };
        let Some(artifact_ref) = non_empty(raw.artifact_ref) else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "missing artifact_ref",
            });
            continue;
        };
        let Some(verifier_id) =
            non_empty(raw.verifier_id).and_then(|value| DidCoreId::new(value).ok())
        else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "missing or invalid verifier_id",
            });
            continue;
        };
        let Some(signature) = non_empty(raw.signature) else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "missing signature",
            });
            continue;
        };
        let Some(timestamp) = raw.timestamp else {
            dropped.push(DroppedVerifiedProfileEntry {
                profile_id,
                reason: "missing timestamp",
            });
            continue;
        };
        entries.push(VerifiedProfileArtifactEntry {
            profile_id: raw.profile_id,
            service_role,
            verification_run_id,
            artifact_digest,
            artifact_ref,
            verifier_id,
            signature,
            timestamp,
            expires_at: raw.expires_at,
            test_count: raw.test_count.unwrap_or(0),
            spec_file: raw.spec_file,
        });
    }

    Ok(VerifiedProfilesArtifactReport {
        version: parsed.version,
        run_id: parsed.run_id,
        total_entries,
        entries,
        dropped,
    })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

fn valid_artifact_digest(value: Option<String>) -> Option<String> {
    let digest = non_empty(value)?;
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .then_some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_role_and_validates_required_fields() {
        let report = parse_verified_profiles_artifact(
            br#"{
                "version": "1",
                "run_id": "run",
                "verified": [
                    {
                        "profile_id": "ak.profile.principal_server.v1",
                        "claim_kind": "conformance_verified",
                        "verification_run_id": "run",
                        "service_role": "principal_server",
                        "artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "artifact_ref": "file:///artifact.json",
                        "verifier_id": "ak:did_core:web:cotest.example",
                        "signature": "signature",
                        "timestamp": "2026-05-20T00:00:00.000Z"
                    },
                    {
                        "profile_id": "ak.profile.auth_server.v1",
                        "service_role": "auth_server"
                    }
                ]
            }"#,
            "principal_server",
        )
        .unwrap();

        assert_eq!(report.total_entries, 2);
        assert_eq!(report.entries.len(), 1);
        assert!(report.dropped.is_empty());
    }

    #[test]
    fn reports_invalid_matching_entry() {
        let report = parse_verified_profiles_artifact(
            br#"{
                "verified": [{
                    "profile_id": "ak.profile.principal_server.v1",
                    "claim_kind": "wrong",
                    "service_role": "principal_server"
                }]
            }"#,
            "principal_server",
        )
        .unwrap();
        assert_eq!(
            report.dropped[0].reason,
            "claim_kind must be conformance_verified"
        );
    }
}
