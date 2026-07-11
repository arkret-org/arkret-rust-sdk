use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkConformanceClaim {
    pub sdk_name: String,
    pub sdk_version: String,
    pub spec_revision: String,
    pub contract_digest: String,
    pub clause_claims: Vec<SdkClauseClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct SdkConformanceEvidence {
    pub kind: SdkEvidenceKind,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdkEvidenceKind {
    VectorResult,
    PublicApiInventory,
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
    #[error("not_applicable clause {0} requires a rationale")]
    MissingRationale(String),
    #[error("pass/fail clause {0} requires evidence")]
    MissingEvidence(String),
}

impl SdkConformanceClaim {
    pub fn validate<'a>(
        &self,
        known_clauses: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), SdkConformanceClaimError> {
        let known = known_clauses.into_iter().collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        for claim in &self.clause_claims {
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
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_clause_claim_is_rejected() {
        let clause = SdkClauseClaim {
            clause_id: "AK-SDK-001".to_owned(),
            result: SdkClauseResult::Pass,
            evidence: vec![SdkConformanceEvidence {
                kind: SdkEvidenceKind::VectorResult,
                reference: "ci://run/1".to_owned(),
                digest: None,
            }],
            rationale: None,
        };
        let claim = SdkConformanceClaim {
            sdk_name: "arkret-rust-sdk".to_owned(),
            sdk_version: "0.3.0".to_owned(),
            spec_revision: "0".repeat(40),
            contract_digest: format!("sha256:{}", "0".repeat(64)),
            clause_claims: vec![clause.clone(), clause],
        };
        assert!(matches!(
            claim.validate(["AK-SDK-001"]),
            Err(SdkConformanceClaimError::DuplicateClauseClaim(_))
        ));
    }
}
