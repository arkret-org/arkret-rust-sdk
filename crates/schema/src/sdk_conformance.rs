use std::collections::BTreeSet;

use arkret_canonical::canonical;
use arkret_identifiers::Did;
use arkret_wire::{DidCoreId, DidUrl, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const SDK_CONFORMANCE_CLAIM_DOMAIN: &str = "arkret-sdk-conformance-claim-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkConformanceClaim {
    pub sdk_name: String,
    pub sdk_version: String,
    pub sdk_artifact: SdkArtifactSubject,
    pub spec_revision: String,
    pub contract_digest: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub features: Vec<String>,
    pub configuration: std::collections::BTreeMap<String, String>,
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
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkConformanceProof {
    pub kid: DidUrl,
    pub signature_algorithm: SdkConformanceProofAlgorithm,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdkConformanceProofAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covers_vectors: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    SignatureInvalid,
    #[error("failed to construct SDK conformance signing input: {0}")]
    SigningInput(String),
    #[error("invalid SDK conformance contract: {0}")]
    InvalidContract(String),
    #[error("SDK conformance vector coverage mismatch: {0}")]
    VectorCoverage(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractClause {
    clause_id: String,
    grades: Vec<String>,
    source_anchor: String,
    summary: String,
    required_evidence: Vec<SdkEvidenceKind>,
    #[serde(default)]
    vector_evidence: Option<ContractVectorEvidence>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractVectorEvidence {
    vectors: Vec<String>,
    decision_points: Vec<ContractDecisionPoint>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractDecisionPoint {
    id: String,
    requirement: String,
    vectors: Vec<String>,
    #[serde(default)]
    required_case_refs: Vec<Value>,
}

/// Parsed view of the canonical `sdk_conformance_contract` together with its
/// exact JCS commitment and expanded vector sets.
#[derive(Clone, Debug)]
pub struct SdkConformanceContract {
    digest: String,
    clauses: std::collections::BTreeMap<String, ExpandedContractClause>,
}

#[derive(Clone, Debug)]
struct ExpandedContractClause {
    required_evidence: BTreeSet<SdkEvidenceKind>,
    vectors: BTreeSet<String>,
    decision_point_vectors: BTreeSet<String>,
}

impl SdkConformanceContract {
    /// Parse the exact contract object and expand `.*` vector families against
    /// the active vector ids from the same specification revision.
    pub fn from_value<'a>(
        value: &Value,
        active_vector_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, SdkConformanceClaimError> {
        let object = value.as_object().ok_or_else(|| {
            SdkConformanceClaimError::InvalidContract("contract must be an object".to_owned())
        })?;
        let clauses_value = object.get("clauses").ok_or_else(|| {
            SdkConformanceClaimError::InvalidContract("contract.clauses is missing".to_owned())
        })?;
        let clauses: Vec<ContractClause> = serde_json::from_value(clauses_value.clone())
            .map_err(|error| SdkConformanceClaimError::InvalidContract(error.to_string()))?;
        let active = active_vector_ids.into_iter().collect::<BTreeSet<_>>();
        let mut expanded = std::collections::BTreeMap::new();

        for clause in clauses {
            if !is_clause_id(&clause.clause_id) || expanded.contains_key(&clause.clause_id) {
                return Err(SdkConformanceClaimError::InvalidContract(format!(
                    "invalid or duplicate clause id {}",
                    clause.clause_id
                )));
            }
            // These fields are signed by the contract digest. Touch them here
            // so a malformed hand-written partial contract is not accepted as
            // a generator input merely because coverage fields happen to parse.
            if clause.grades.is_empty()
                || clause.source_anchor.is_empty()
                || clause.summary.is_empty()
            {
                return Err(SdkConformanceClaimError::InvalidContract(format!(
                    "{} has incomplete metadata",
                    clause.clause_id
                )));
            }
            let required_evidence = clause
                .required_evidence
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut vectors = BTreeSet::new();
            let mut decision_point_vectors = BTreeSet::new();
            match clause.vector_evidence {
                Some(vector_evidence) => {
                    for pattern in &vector_evidence.vectors {
                        vectors.extend(expand_vector_pattern(pattern, &active)?);
                    }
                    for decision_point in vector_evidence.decision_points {
                        if decision_point.id.is_empty() || decision_point.requirement.is_empty() {
                            return Err(SdkConformanceClaimError::InvalidContract(format!(
                                "{} has an incomplete decision point",
                                clause.clause_id
                            )));
                        }
                        let _ = decision_point.required_case_refs;
                        for vector in decision_point.vectors {
                            if !vectors.contains(&vector) {
                                return Err(SdkConformanceClaimError::InvalidContract(format!(
                                    "{} decision point names vector outside clause set: {}",
                                    clause.clause_id, vector
                                )));
                            }
                            decision_point_vectors.insert(vector);
                        }
                    }
                    if !required_evidence.contains(&SdkEvidenceKind::VectorResult) {
                        return Err(SdkConformanceClaimError::InvalidContract(format!(
                            "{} has vector_evidence without vector_result requirement",
                            clause.clause_id
                        )));
                    }
                }
                None if required_evidence.contains(&SdkEvidenceKind::VectorResult) => {
                    return Err(SdkConformanceClaimError::InvalidContract(format!(
                        "{} requires vector_result but has no vector_evidence",
                        clause.clause_id
                    )));
                }
                None => {}
            }
            expanded.insert(
                clause.clause_id,
                ExpandedContractClause {
                    required_evidence,
                    vectors,
                    decision_point_vectors,
                },
            );
        }

        Ok(Self {
            digest: sdk_conformance_contract_digest(value)?,
            clauses: expanded,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn clause_ids(&self) -> impl Iterator<Item = &str> {
        self.clauses.keys().map(String::as_str)
    }

    /// Construct claim evidence from the contract rather than a caller-owned
    /// vector list. Wildcard families have already been expanded.
    pub fn vector_result_evidence(
        &self,
        clause_id: &str,
        evidence_ref: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<SdkConformanceEvidence, SdkConformanceClaimError> {
        let clause = self
            .clauses
            .get(clause_id)
            .ok_or_else(|| SdkConformanceClaimError::UnknownClause(clause_id.to_owned()))?;
        if !clause
            .required_evidence
            .contains(&SdkEvidenceKind::VectorResult)
        {
            return Err(SdkConformanceClaimError::InvalidContract(format!(
                "{clause_id} does not require vector_result"
            )));
        }
        Ok(SdkConformanceEvidence {
            kind: SdkEvidenceKind::VectorResult,
            evidence_ref: evidence_ref.into(),
            digest: digest.into(),
            covers_vectors: Some(clause.vectors.iter().cloned().collect()),
        })
    }

    pub fn validate_claim_coverage(
        &self,
        claim: &SdkConformanceClaim,
    ) -> Result<(), SdkConformanceClaimError> {
        if claim.contract_digest != self.digest {
            return Err(SdkConformanceClaimError::BindingMismatch(
                "contract_digest".to_owned(),
            ));
        }
        for clause_claim in &claim.clause_claims {
            let clause = self.clauses.get(&clause_claim.clause_id).ok_or_else(|| {
                SdkConformanceClaimError::UnknownClause(clause_claim.clause_id.clone())
            })?;
            let covered = clause_claim
                .evidence
                .iter()
                .filter(|evidence| evidence.kind == SdkEvidenceKind::VectorResult)
                .flat_map(|evidence| evidence.covers_vectors.iter().flatten())
                .cloned()
                .collect::<BTreeSet<_>>();
            if !covered.is_subset(&clause.vectors) {
                return Err(SdkConformanceClaimError::VectorCoverage(format!(
                    "{} names vectors outside its expanded contract set",
                    clause_claim.clause_id
                )));
            }
            if matches!(
                clause_claim.result,
                SdkClauseResult::Pass | SdkClauseResult::Fail
            ) && clause
                .required_evidence
                .contains(&SdkEvidenceKind::VectorResult)
                && !clause.decision_point_vectors.is_subset(&covered)
            {
                return Err(SdkConformanceClaimError::VectorCoverage(format!(
                    "{} does not cover every decision-point vector",
                    clause_claim.clause_id
                )));
            }
        }
        Ok(())
    }
}

pub fn sdk_conformance_contract_digest(
    contract: &Value,
) -> Result<String, SdkConformanceClaimError> {
    let bytes = canonical::canonical_json_bytes(contract)
        .map_err(|error| SdkConformanceClaimError::InvalidContract(error.to_string()))?;
    Ok(canonical::sha256_digest(&bytes))
}

fn expand_vector_pattern<'a>(
    pattern: &str,
    active: &BTreeSet<&'a str>,
) -> Result<Vec<String>, SdkConformanceClaimError> {
    if let Some(prefix) = pattern.strip_suffix(".*") {
        let prefix = format!("{prefix}.");
        let matches = active
            .iter()
            .filter(|candidate| candidate.starts_with(&prefix))
            .map(|candidate| (*candidate).to_owned())
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(SdkConformanceClaimError::InvalidContract(format!(
                "vector family {pattern} expands to an empty set"
            )));
        }
        Ok(matches)
    } else if active.contains(pattern) {
        Ok(vec![pattern.to_owned()])
    } else {
        Err(SdkConformanceClaimError::InvalidContract(format!(
            "unknown or inactive vector {pattern}"
        )))
    }
}

impl SdkConformanceClaim {
    pub const SCHEMA: &'static str = SchemaId::SDK_CONFORMANCE_CLAIM_V1;
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
                match (evidence.kind, evidence.covers_vectors.as_deref()) {
                    (SdkEvidenceKind::VectorResult, Some(vectors))
                        if !vectors.is_empty()
                            && vectors.len() <= 1024
                            && vectors.iter().all(|vector| is_vector_id(vector))
                            && all_unique(vectors) => {}
                    (SdkEvidenceKind::VectorResult, _) => {
                        return Err(SdkConformanceClaimError::InvalidField(
                            "vector_result.covers_vectors".to_owned(),
                        ));
                    }
                    (_, None) => {}
                    (_, Some(_)) => {
                        return Err(SdkConformanceClaimError::InvalidField(
                            "covers_vectors is only valid for vector_result".to_owned(),
                        ));
                    }
                }
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
        let known_profiles = arkret_wire::generated::profile_requirements::known_profile_ids()
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
            if variant.features.len() > 512
                || variant.features.windows(2).any(|pair| pair[0] >= pair[1])
                || variant
                    .features
                    .iter()
                    .any(|feature| !is_build_feature(feature))
                || variant.configuration.len() > 128
                || variant
                    .configuration
                    .iter()
                    .any(|(key, value)| !is_build_feature(key) || value.chars().count() > 2048)
            {
                return Err(SdkConformanceClaimError::InvalidField(format!(
                    "build_variants[{}].features/configuration",
                    variant.variant_id
                )));
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
            return Err(SdkConformanceClaimError::SignatureInvalid);
        }
        Ok(())
    }

    pub fn validate_against_contract(
        &self,
        contract: &SdkConformanceContract,
        expected_artifact_digest: &str,
        expected_spec_revision: &str,
        verify_signature: impl FnOnce(&SdkClaimIssuer, &SdkConformanceProof, &[u8]) -> bool,
    ) -> Result<(), SdkConformanceClaimError> {
        self.validate_against(
            contract.clause_ids(),
            expected_artifact_digest,
            expected_spec_revision,
            contract.digest(),
            verify_signature,
        )?;
        contract.validate_claim_coverage(self)
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

fn is_vector_id(value: &str) -> bool {
    let Some((body, version)) = value
        .strip_prefix("ak.vector.")
        .and_then(|value| value.rsplit_once(".v"))
    else {
        return false;
    };
    !body.is_empty()
        && body.contains('.')
        && body.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
        })
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
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
            issued_at: "2026-07-11T00:00:00.000Z".parse().unwrap(),
            issuer: SdkClaimIssuer {
                id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkfixture:release.example#claim-key-1",
                )
                .unwrap(),
            },
            clause_claims: vec![SdkClauseClaim {
                clause_id: "AK-SDK-001".to_owned(),
                result: SdkClauseResult::Pass,
                evidence: vec![SdkConformanceEvidence {
                    kind: SdkEvidenceKind::VectorResult,
                    evidence_ref: "ci://run/1".to_owned(),
                    digest: format!("sha256:{}", "4".repeat(64)),
                    covers_vectors: Some(vec![
                        "ak.vector.sdk.envelope_precheck_rejects_before_consumption.v1".to_owned(),
                    ]),
                }],
                rationale: None,
            }],
            build_variants: None,
            proof: SdkConformanceProof {
                kid: DidUrl::new("did:webvh:z6mkfixture:release.example#claim-key-1".to_owned())
                    .expect("valid did url"),
                signature_algorithm: SdkConformanceProofAlgorithm::Ed25519,
                signature: "A".repeat(43),
            },
        }
    }

    fn claim_with_build_variants() -> SdkConformanceClaim {
        let variants = vec![SdkBuildVariant {
            variant_id: "full-native".to_owned(),
            features: vec!["client".to_owned(), "mls".to_owned()],
            configuration: [(
                "rust:target".to_owned(),
                "x86_64-pc-windows-msvc".to_owned(),
            )]
            .into(),
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
                covers_vectors: None,
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
    fn changed_build_configuration_invalidates_inventory_commitment() {
        let mut claim = claim_with_build_variants();
        claim.build_variants.as_mut().unwrap()[0]
            .configuration
            .insert(
                "rust:target".to_owned(),
                "wasm32-unknown-unknown".to_owned(),
            );
        assert!(matches!(
            claim.validate(["AK-SDK-001", "AK-SDK-015"]),
            Err(SdkConformanceClaimError::BindingMismatch(_))
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
    fn fixture_schema_cases_match_the_published_schema() {
        let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../arkret-spec/spec/v1/artifacts");
        let path = artifacts.join("fixtures/sdk-conformance-claim-fixture.json");
        let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let schema: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("schemas/sdk-conformance-claim.schema.json")).unwrap(),
        )
        .unwrap();
        let mut registry = crate::ProtocolSchemaRegistry::new();
        for entry in std::fs::read_dir(artifacts.join("schemas")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if document.get("$id").and_then(Value::as_str).is_some() {
                registry
                    .register_reference_document_from(document, path.display().to_string())
                    .unwrap();
            }
        }
        registry.register("test:sdk-conformance-claim", schema);
        for case in fixture["schema_validation_cases"].as_array().unwrap() {
            let expect_valid = case["expect_valid"].as_bool().unwrap();
            let validation =
                registry.validate_value("test:sdk-conformance-claim", &case["instance"]);
            let accepted = validation.is_ok();
            assert_eq!(
                accepted, expect_valid,
                "fixture case {} drifted: {validation:?}",
                case["name"],
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
            Err(SdkConformanceClaimError::SignatureInvalid)
        ));
    }

    #[test]
    fn formal_contract_digest_and_vector_evidence_are_generated_from_artifacts() {
        let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../arkret-spec/spec/v1/artifacts");
        let profiles: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("profiles/conformance-profiles.json")).unwrap(),
        )
        .unwrap();
        let registry: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("registry/vector-registry.json")).unwrap(),
        )
        .unwrap();
        let active = registry["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["status"] == "active")
            .map(|row| row["vector_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        let contract_value = &profiles["sdk_conformance_contract"];
        let contract = SdkConformanceContract::from_value(contract_value, active).unwrap();
        assert_eq!(
            contract.digest(),
            "sha256:48731f15bfbb66db140d48c893a5e4cf2b5bc18602dee84ee817e00afeb82dd2"
        );

        let evidence = contract
            .vector_result_evidence(
                "AK-SDK-014",
                "ci://run/identity-test-material",
                format!("sha256:{}", "7".repeat(64)),
            )
            .unwrap();
        assert_eq!(
            evidence.covers_vectors.unwrap(),
            vec![
                "ak.vector.identity.reserved_test_identifier_rejected.v1".to_owned(),
                "ak.vector.identity.test_signing_material_rejected.v1".to_owned(),
            ]
        );
    }

    #[test]
    fn contract_validation_rejects_missing_or_out_of_clause_vector_coverage() {
        let contract_value = serde_json::json!({
            "clauses": [{
                "clause_id": "AK-SDK-001",
                "grades": ["V"],
                "source_anchor": "spec/test",
                "summary": "test",
                "required_evidence": ["vector_result"],
                "vector_evidence": {
                    "vectors": ["ak.vector.sdk.sample.v1"],
                    "decision_points": [{
                        "id": "sample",
                        "requirement": "sample decision",
                        "vectors": ["ak.vector.sdk.sample.v1"]
                    }]
                }
            }]
        });
        let contract = SdkConformanceContract::from_value(
            &contract_value,
            ["ak.vector.sdk.sample.v1", "ak.vector.sdk.other.v1"],
        )
        .unwrap();
        let mut claim = valid_claim();
        claim.contract_digest = contract.digest().to_owned();
        claim.clause_claims[0].evidence[0].covers_vectors = Some(vec![]);
        assert!(matches!(
            claim.validate(contract.clause_ids()),
            Err(SdkConformanceClaimError::InvalidField(field))
                if field == "vector_result.covers_vectors"
        ));

        claim.clause_claims[0].evidence[0].covers_vectors =
            Some(vec!["ak.vector.sdk.other.v1".to_owned()]);
        assert!(matches!(
            contract.validate_claim_coverage(&claim),
            Err(SdkConformanceClaimError::VectorCoverage(_))
        ));

        claim.clause_claims[0].evidence[0].covers_vectors =
            Some(vec!["ak.vector.sdk.sample.v1".to_owned()]);
        contract.validate_claim_coverage(&claim).unwrap();
    }

    #[test]
    fn non_vector_evidence_cannot_claim_vector_coverage() {
        let mut claim = claim_with_build_variants();
        claim
            .clause_claims
            .iter_mut()
            .find(|clause| clause.clause_id == "AK-SDK-015")
            .unwrap()
            .evidence[0]
            .covers_vectors = Some(vec!["ak.vector.sdk.sample.v1".to_owned()]);
        assert!(matches!(
            claim.validate(["AK-SDK-001", "AK-SDK-015"]),
            Err(SdkConformanceClaimError::InvalidField(field))
                if field == "covers_vectors is only valid for vector_result"
        ));
    }
}
