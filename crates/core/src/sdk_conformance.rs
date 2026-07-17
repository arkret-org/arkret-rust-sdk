use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Did, canonical};

pub const SDK_CONFORMANCE_CLAIM_DOMAIN: &str = "arkret-sdk-conformance-claim-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkConformanceClaim {
    pub sdk_name: String,
    pub sdk_version: String,
    pub sdk_artifact: SdkArtifactSubject,
    pub spec_revision: String,
    pub contract_digest: String,
    pub issued_at: DateTime<Utc>,
    pub issuer: SdkClaimIssuer,
    pub clause_claims: Vec<SdkClauseClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_variants: Option<Vec<SdkBuildVariant>>,
    pub proof: SdkConformanceProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkBuildVariant {
    pub variant_id: String,
    pub feature_set_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    pub claimed_profiles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkArtifactSubject {
    pub uri: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: Did,
    pub verification_method: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkConformanceProof {
    pub kid: String,
    pub alg: SdkConformanceProofAlgorithm,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdkConformanceProofAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClauseClaim {
    pub clause_id: String,
    pub result: SdkClauseResult,
    pub evidence: Vec<SdkConformanceEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdkClauseResult {
    Pass,
    Fail,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkConformanceEvidence {
    pub kind: SdkEvidenceKind,
    pub evidence_ref: String,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdkEvidenceKind {
    VectorResult,
    PublicApiInventory,
    BuildVariantInventory,
    CodeAudit,
    ConfigAudit,
    DataFlowAudit,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SdkConformanceClaimError {
    #[error("duplicate_clause_claim: {0}")]
    DuplicateClauseClaim(String),
    #[error("unknown SDK conformance clause: {0}")]
    UnknownClause(String),
    #[error("invalid SDK conformance claim field: {0}")]
    InvalidField(String),
    #[error("not_applicable clause {0} requires a rationale")]
    MissingRationale(String),
    #[error("pass/fail clause {0} requires evidence")]
    MissingEvidence(String),
    #[error("SDK conformance claim binding mismatch: {0}")]
    BindingMismatch(String),
    #[error("SDK conformance claim signature is invalid")]
    InvalidSignature,
    #[error("failed to construct SDK conformance signing input: {0}")]
    SigningInput(String),
}

impl SdkConformanceClaim {
    pub fn validate<'a>(
        &self,
        known_clauses: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), SdkConformanceClaimError> {
        validate_text("sdk_name", &self.sdk_name, 128)?;
        validate_text("sdk_version", &self.sdk_version, 128)?;
        if self.sdk_artifact.uri.len() > 2048
            || !["https:", "oci:", "git:", "urn:"]
                .iter()
                .any(|prefix| self.sdk_artifact.uri.starts_with(prefix))
        {
            return Err(SdkConformanceClaimError::InvalidField(
                "sdk_artifact.uri".to_owned(),
            ));
        }
        validate_nonzero_digest("sdk_artifact.digest", &self.sdk_artifact.digest)?;
        if !is_nonzero_lower_hex(&self.spec_revision, 40) {
            return Err(SdkConformanceClaimError::InvalidField(
                "spec_revision".to_owned(),
            ));
        }
        validate_nonzero_digest("contract_digest", &self.contract_digest)?;
        validate_did_url(
            "issuer.verification_method",
            &self.issuer.verification_method,
        )?;
        validate_did_url("proof.kid", &self.proof.kid)?;
        if self.proof.kid != self.issuer.verification_method {
            return Err(SdkConformanceClaimError::BindingMismatch(
                "proof.kid must equal issuer.verification_method".to_owned(),
            ));
        }
        if !(43..=8192).contains(&self.proof.signature.len())
            || !self
                .proof
                .signature
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(SdkConformanceClaimError::InvalidField(
                "proof.signature".to_owned(),
            ));
        }
        if self.clause_claims.is_empty() || self.clause_claims.len() > 256 {
            return Err(SdkConformanceClaimError::InvalidField(
                "clause_claims".to_owned(),
            ));
        }

        self.validate_build_variants()?;

        let known = known_clauses.into_iter().collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        for claim in &self.clause_claims {
            if !is_clause_id(&claim.clause_id) {
                return Err(SdkConformanceClaimError::InvalidField(format!(
                    "clause_claims[{}].clause_id",
                    claim.clause_id
                )));
            }
            if !seen.insert(claim.clause_id.as_str()) {
                return Err(SdkConformanceClaimError::DuplicateClauseClaim(
                    claim.clause_id.clone(),
                ));
            }
            if !known.contains(claim.clause_id.as_str()) {
                return Err(SdkConformanceClaimError::UnknownClause(
                    claim.clause_id.clone(),
                ));
            }
            if claim.evidence.len() > 32 {
                return Err(SdkConformanceClaimError::InvalidField(format!(
                    "{}.evidence",
                    claim.clause_id
                )));
            }
            match claim.result {
                SdkClauseResult::NotApplicable
                    if claim.rationale.as_deref().is_none_or(str::is_empty) =>
                {
                    return Err(SdkConformanceClaimError::MissingRationale(
                        claim.clause_id.clone(),
                    ));
                }
                SdkClauseResult::Pass | SdkClauseResult::Fail if claim.evidence.is_empty() => {
                    return Err(SdkConformanceClaimError::MissingEvidence(
                        claim.clause_id.clone(),
                    ));
                }
                _ => {}
            }
            if let Some(rationale) = &claim.rationale {
                validate_text("clause_claim.rationale", rationale, 2048)?;
            }
            for evidence in &claim.evidence {
                validate_text("evidence.evidence_ref", &evidence.evidence_ref, 2048)?;
                validate_nonzero_digest("evidence.digest", &evidence.digest)?;
            }
        }
        Ok(())
    }

    fn validate_build_variants(&self) -> Result<(), SdkConformanceClaimError> {
        let Some(variants) = &self.build_variants else {
            return Ok(());
        };
        if variants.is_empty() || variants.len() > 256 {
            return Err(SdkConformanceClaimError::InvalidField(
                "build_variants".to_owned(),
            ));
        }
        let known_profiles = crate::schema::known_profile_ids()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut variant_ids = BTreeSet::new();
        for variant in variants {
            if !is_build_variant_id(&variant.variant_id) {
                return Err(SdkConformanceClaimError::InvalidField(format!(
                    "build_variants[{}].variant_id",
                    variant.variant_id
                )));
            }
            if !variant_ids.insert(variant.variant_id.as_str()) {
                return Err(SdkConformanceClaimError::InvalidField(
                    "build_variants.variant_id must be unique".to_owned(),
                ));
            }
            validate_nonzero_digest(
                "build_variant.feature_set_digest",
                &variant.feature_set_digest,
            )?;
            if let Some(features) = &variant.features {
                if features.len() > 512 || !all_unique(features) {
                    return Err(SdkConformanceClaimError::InvalidField(format!(
                        "build_variants[{}].features",
                        variant.variant_id
                    )));
                }
                if features.iter().any(|feature| !is_build_feature(feature)) {
                    return Err(SdkConformanceClaimError::InvalidField(format!(
                        "build_variants[{}].features",
                        variant.variant_id
                    )));
                }
            }
            if variant.claimed_profiles.len() > 256 || !all_unique(&variant.claimed_profiles) {
                return Err(SdkConformanceClaimError::InvalidField(format!(
                    "build_variants[{}].claimed_profiles",
                    variant.variant_id
                )));
            }
            for profile in &variant.claimed_profiles {
                if !is_profile_id(profile) || !known_profiles.contains(profile.as_str()) {
                    return Err(SdkConformanceClaimError::InvalidField(format!(
                        "build_variants[{}].claimed_profiles",
                        variant.variant_id
                    )));
                }
            }
        }

        let inventory_evidence = self
            .clause_claims
            .iter()
            .find(|claim| claim.clause_id == "AK-SDK-015")
            .and_then(|claim| {
                claim
                    .evidence
                    .iter()
                    .find(|evidence| evidence.kind == SdkEvidenceKind::BuildVariantInventory)
            })
            .ok_or_else(|| SdkConformanceClaimError::MissingEvidence("AK-SDK-015".to_owned()))?;
        let inventory_bytes = canonical::canonical_json_bytes(variants)
            .map_err(|error| SdkConformanceClaimError::SigningInput(error.to_string()))?;
        canonical::verify_digest(&inventory_bytes, &inventory_evidence.digest).map_err(|_| {
            SdkConformanceClaimError::BindingMismatch(
                "AK-SDK-015 build_variant_inventory digest".to_owned(),
            )
        })?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, SdkConformanceClaimError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| SdkConformanceClaimError::SigningInput(error.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                SdkConformanceClaimError::SigningInput(
                    "claim did not serialize as an object".to_owned(),
                )
            })?
            .remove("proof");
        let canonical = canonical::canonical_json_bytes(&value)
            .map_err(|error| SdkConformanceClaimError::SigningInput(error.to_string()))?;
        let mut bytes =
            Vec::with_capacity(SDK_CONFORMANCE_CLAIM_DOMAIN.len() + 1 + canonical.len());
        bytes.extend_from_slice(SDK_CONFORMANCE_CLAIM_DOMAIN.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub fn validate_against<'a>(
        &self,
        known_clauses: impl IntoIterator<Item = &'a str>,
        expected_artifact_digest: &str,
        expected_spec_revision: &str,
        expected_contract_digest: &str,
        verify_signature: impl FnOnce(&SdkClaimIssuer, &SdkConformanceProof, &[u8]) -> bool,
    ) -> Result<(), SdkConformanceClaimError> {
        self.validate(known_clauses)?;
        for (field, actual, expected) in [
            (
                "sdk_artifact.digest",
                self.sdk_artifact.digest.as_str(),
                expected_artifact_digest,
            ),
            (
                "spec_revision",
                self.spec_revision.as_str(),
                expected_spec_revision,
            ),
            (
                "contract_digest",
                self.contract_digest.as_str(),
                expected_contract_digest,
            ),
        ] {
            if actual != expected {
                return Err(SdkConformanceClaimError::BindingMismatch(field.to_owned()));
            }
        }
        let signing_bytes = self.signing_bytes()?;
        if !verify_signature(&self.issuer, &self.proof, &signing_bytes) {
            return Err(SdkConformanceClaimError::InvalidSignature);
        }
        Ok(())
    }
}

fn validate_text(field: &str, value: &str, max_len: usize) -> Result<(), SdkConformanceClaimError> {
    if value.is_empty() || value.len() > max_len {
        return Err(SdkConformanceClaimError::InvalidField(field.to_owned()));
    }
    Ok(())
}

fn validate_nonzero_digest(field: &str, digest: &str) -> Result<(), SdkConformanceClaimError> {
    let Some((algorithm, value)) = digest.split_once(':') else {
        return Err(SdkConformanceClaimError::InvalidField(field.to_owned()));
    };
    if !matches!(algorithm, "sha256" | "blake3") || !is_nonzero_lower_hex(value, 64) {
        return Err(SdkConformanceClaimError::InvalidField(field.to_owned()));
    }
    Ok(())
}

fn is_nonzero_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn validate_did_url(field: &str, value: &str) -> Result<(), SdkConformanceClaimError> {
    let Some((did, fragment)) = value.split_once('#') else {
        return Err(SdkConformanceClaimError::InvalidField(field.to_owned()));
    };
    if fragment.is_empty()
        || value.len() > 2048
        || value.chars().any(char::is_whitespace)
        || Did::new(did).is_err()
    {
        return Err(SdkConformanceClaimError::InvalidField(field.to_owned()));
    }
    Ok(())
}

fn is_clause_id(value: &str) -> bool {
    value.len() == 10
        && value.starts_with("AK-SDK-")
        && value[7..].bytes().all(|byte| byte.is_ascii_digit())
}

fn all_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn is_build_variant_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_build_feature(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b':' | b'/' | b'-')
        })
}

fn is_profile_id(value: &str) -> bool {
    value
        .strip_prefix("ak.profile.")
        .and_then(|value| value.strip_suffix(".v1"))
        .is_some_and(|body| {
            !body.is_empty()
                && body.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_claim() -> SdkConformanceClaim {
        SdkConformanceClaim {
            sdk_name: "arkret-rust-sdk".to_owned(),
            sdk_version: "0.3.0".to_owned(),
            sdk_artifact: SdkArtifactSubject {
                uri: "urn:arkret:sdk:test".to_owned(),
                digest: format!("sha256:{}", "2".repeat(64)),
            },
            spec_revision: "1".repeat(40),
            contract_digest: format!("sha256:{}", "3".repeat(64)),
            issued_at: "2026-07-11T00:00:00Z".parse().unwrap(),
            issuer: SdkClaimIssuer {
                id: Did::new("did:webvh:z6mkfixture:release.example").unwrap(),
                verification_method: "did:webvh:z6mkfixture:release.example#claim-key-1".to_owned(),
            },
            clause_claims: vec![SdkClauseClaim {
                clause_id: "AK-SDK-001".to_owned(),
                result: SdkClauseResult::Pass,
                evidence: vec![SdkConformanceEvidence {
                    kind: SdkEvidenceKind::VectorResult,
                    evidence_ref: "ci://run/1".to_owned(),
                    digest: format!("sha256:{}", "4".repeat(64)),
                }],
                rationale: None,
            }],
            build_variants: None,
            proof: SdkConformanceProof {
                kid: "did:webvh:z6mkfixture:release.example#claim-key-1".to_owned(),
                alg: SdkConformanceProofAlgorithm::EdDsa,
                signature: "A".repeat(43),
            },
        }
    }

    fn claim_with_build_variants() -> SdkConformanceClaim {
        let variants = vec![SdkBuildVariant {
            variant_id: "full-native".to_owned(),
            feature_set_digest: format!("sha256:{}", "5".repeat(64)),
            features: Some(vec!["full-surface".to_owned(), "mls".to_owned()]),
            claimed_profiles: vec!["ak.profile.chat_mvp.v1".to_owned()],
        }];
        let inventory_bytes = canonical::canonical_json_bytes(&variants).unwrap();
        let inventory_digest = canonical::sha256_digest(&inventory_bytes);
        let mut claim = valid_claim();
        claim.clause_claims.push(SdkClauseClaim {
            clause_id: "AK-SDK-015".to_owned(),
            result: SdkClauseResult::Pass,
            evidence: vec![SdkConformanceEvidence {
                kind: SdkEvidenceKind::BuildVariantInventory,
                evidence_ref: "ci://run/1/build-variants".to_owned(),
                digest: inventory_digest,
            }],
            rationale: None,
        });
        claim.build_variants = Some(variants);
        claim
    }

    #[test]
    fn duplicate_clause_claim_is_rejected() {
        let mut claim = valid_claim();
        claim.clause_claims.push(claim.clause_claims[0].clone());
        assert!(matches!(
            claim.validate(["AK-SDK-001"]),
            Err(SdkConformanceClaimError::DuplicateClauseClaim(_))
        ));
    }

    #[test]
    fn signing_bytes_are_domain_separated_and_omit_proof() {
        let claim = valid_claim();
        let bytes = claim.signing_bytes().unwrap();
        assert!(bytes.starts_with(b"arkret-sdk-conformance-claim-v1\n{"));
        let canonical = std::str::from_utf8(&bytes).unwrap();
        assert!(!canonical.contains("\"proof\""));
        assert!(canonical.contains("\"sdk_artifact\""));
    }

    #[test]
    fn build_variant_inventory_is_validated_and_signed() {
        let claim = claim_with_build_variants();
        claim
            .validate(["AK-SDK-001", "AK-SDK-015"])
            .expect("valid registered build inventory");
        let signing = String::from_utf8(claim.signing_bytes().unwrap()).unwrap();
        assert!(signing.contains("\"build_variants\""));
        assert!(signing.contains("\"build_variant_inventory\""));
    }

    #[test]
    fn duplicate_variant_id_is_rejected() {
        let mut claim = claim_with_build_variants();
        let variants = claim.build_variants.as_mut().unwrap();
        variants.push(variants[0].clone());
        assert!(matches!(
            claim.validate(["AK-SDK-001", "AK-SDK-015"]),
            Err(SdkConformanceClaimError::InvalidField(field))
                if field.contains("variant_id")
        ));
    }

    #[test]
    fn unregistered_variant_profile_is_rejected() {
        let mut claim = claim_with_build_variants();
        claim.build_variants.as_mut().unwrap()[0].claimed_profiles =
            vec!["ak.profile.unregistered.v1".to_owned()];
        assert!(matches!(
            claim.validate(["AK-SDK-001", "AK-SDK-015"]),
            Err(SdkConformanceClaimError::InvalidField(field))
                if field.contains("claimed_profiles")
        ));
    }

    #[test]
    fn mismatched_build_inventory_digest_is_rejected() {
        let mut claim = claim_with_build_variants();
        claim
            .clause_claims
            .iter_mut()
            .find(|clause| clause.clause_id == "AK-SDK-015")
            .unwrap()
            .evidence[0]
            .digest = format!("sha256:{}", "9".repeat(64));
        assert!(matches!(
            claim.validate(["AK-SDK-001", "AK-SDK-015"]),
            Err(SdkConformanceClaimError::BindingMismatch(field))
                if field.contains("build_variant_inventory")
        ));
    }

    #[test]
    fn fixture_schema_cases_match_typed_claim_validation() {
        let fixture =
            crate::schema::embedded_json_artifact("fixtures/sdk-conformance-claim-fixture.json")
                .unwrap();
        for case in fixture["schema_validation_cases"].as_array().unwrap() {
            let expect_valid = case["expect_valid"].as_bool().unwrap();
            let parsed = serde_json::from_value::<SdkConformanceClaim>(case["instance"].clone());
            let accepted = parsed
                .and_then(|claim| {
                    claim
                        .validate(["AK-SDK-001"])
                        .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))
                })
                .is_ok();
            assert_eq!(
                accepted, expect_valid,
                "fixture case {} drifted",
                case["name"]
            );
        }
    }

    #[test]
    fn validate_against_checks_bindings_and_signature() {
        let claim = valid_claim();
        claim
            .validate_against(
                ["AK-SDK-001"],
                &claim.sdk_artifact.digest,
                &claim.spec_revision,
                &claim.contract_digest,
                |issuer, proof, bytes| {
                    proof.kid == issuer.verification_method
                        && bytes.starts_with(b"arkret-sdk-conformance-claim-v1\n")
                },
            )
            .unwrap();
        assert!(matches!(
            claim.validate_against(
                ["AK-SDK-001"],
                &claim.sdk_artifact.digest,
                &claim.spec_revision,
                &claim.contract_digest,
                |_, _, _| false,
            ),
            Err(SdkConformanceClaimError::InvalidSignature)
        ));
    }
}
