//! Directory claim-presentation and agent-selector claim wire shapes
//! (identity-issued claims presented to directory services).

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    DidCoreId, DidUrl, Error, Hash, PayloadProof, ProofContextId, Result, SchemaId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::handle::{HandleBindingState, HandleVisibility};

pub const DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND: &str =
    "ak.directory.restricted_claim_presentation.v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPresentedClaim {
    pub claim_id: String,
    pub subject: DidCoreId,
    pub issuer: DidCoreId,
    pub claim_kind: String,
    pub value: BTreeMap<String, Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub refreshed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disclosed_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRestrictedClaimPresentation {
    pub kind: String,
    pub iss: DidCoreId,
    pub verification_method: DidUrl,
    pub audience: DidCoreId,
    pub nonce: String,
    pub claim: DirectoryPresentedClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

fn default_agent_selector_claim_schema() -> String {
    SchemaId::AGENT_SELECTOR_CLAIM_V1.to_owned()
}

/// Signed controller-scoped selector claim for
/// `@<controller-handle>/<agent_slug>` resolution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSelectorClaim {
    #[serde(default = "default_agent_selector_claim_schema")]
    pub schema: String,
    pub controller_subject: DidCoreId,
    pub agent_slug: String,
    pub subject: DidCoreId,
    pub issuer: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_service_id: Option<DidCoreId>,
    pub binding_state: HandleBindingState,
    pub visibility: HandleVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default)]
    pub proofs: Vec<PayloadProof>,
}

impl AgentSelectorClaim {
    /// Canonical claim bytes covered by selector payload proofs.
    pub fn canonical_payload_without_proofs(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AgentSelectorClaim serializes as an object")
            .remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(
            &self.canonical_payload_without_proofs()?,
        ))
        .map_err(|reason| Error::Protocol(reason.to_string()))
    }

    /// Canonical `ak.agent-selector-claim-proof-v1` transcript shared by
    /// producers and verifiers.
    pub fn canonical_proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest {
            return Err(Error::Protocol(
                "agent_selector_claim proof payload_digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::from_iter([
            (
                "context".to_owned(),
                Value::String(ProofContextId::AGENT_SELECTOR_CLAIM_PROOF_V1.to_owned()),
            ),
            (
                "payload_digest".to_owned(),
                serde_json::to_value(&payload_digest)?,
            ),
            (
                "controller_subject".to_owned(),
                serde_json::to_value(&self.controller_subject)?,
            ),
            ("subject".to_owned(), serde_json::to_value(&self.subject)?),
            (
                "agent_slug".to_owned(),
                Value::String(self.agent_slug.clone()),
            ),
            (
                "verification_method".to_owned(),
                Value::String(proof.verification_method.as_str().to_owned()),
            ),
            (
                "created_at".to_owned(),
                serde_json::to_value(proof.created_at)?,
            ),
        ]);
        if let Some(domain) = &proof.domain {
            binding.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &proof.audience {
            binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(binding))?)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::AGENT_SELECTOR_CLAIM_V1 {
            return Err(Error::Protocol(format!(
                "agent_selector_claim schema must be {schemaid_agent_selector_claim_v1}",
                schemaid_agent_selector_claim_v1 = SchemaId::AGENT_SELECTOR_CLAIM_V1
            )));
        }
        validate_agent_slug(&self.agent_slug)?;
        if matches!(self.binding_state, HandleBindingState::Verified) && self.proofs.is_empty() {
            return Err(Error::Protocol(
                "verified agent_selector_claim requires proofs".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn validate_agent_slug(value: &str) -> Result<()> {
    arkret_wire::validate_canonical_agent_slug(value)
}

#[cfg(test)]
mod agent_selector_tests {
    use super::*;

    #[test]
    fn validates_agent_slug_pattern() {
        for value in ["s", "summary", "summary_v2", "summary-v2", "总结助手"] {
            validate_agent_slug(value).unwrap();
        }
        for value in ["", "Summary", "sum/mary", "e\u{301}xample"] {
            assert!(validate_agent_slug(value).is_err(), "{value}");
        }
    }
}
