//! Directory claim-presentation and agent-selector claim wire shapes
//! (identity-issued claims presented to directory services).

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    AccountId, DidCoreId, DidUrl, Hash, PayloadProof, ProofContextId, Result, SchemaId, WireError,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::handle::HandleVisibility;

pub const DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND: &str =
    "ak.directory.restricted_claim_presentation.v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPresentedClaim {
    pub claim_id: String,
    pub subject_id: DidCoreId,
    pub issuer_id: DidCoreId,
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
    pub issuer_id: DidCoreId,
    pub verification_method: DidUrl,
    pub audience_id: DidCoreId,
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
    /// Controller principal that owns the selector namespace. It names the
    /// namespace only; it does not name the account the slug points at.
    pub controller_subject_id: DidCoreId,
    pub agent_slug: String,
    /// Exact Agent account the controller signed this slug onto.
    ///
    /// The namespace stays principal-scoped while the target is
    /// account-scoped, and neither is derived from the other. A consumer
    /// copies this value verbatim into the mention node: it must not be
    /// rebuilt from a bare principal, the controller handle's Station, a DID
    /// default Station or the resolving facade. Ruling:
    /// tasks/spec-done/2026-09-05-1310-agent-selector-mention-has-no-normative-station-source.md.
    #[serde(deserialize_with = "required_nullable_account")]
    pub subject_account_id: Option<AccountId>,
    pub issuer_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vouching_id: Option<DidCoreId>,
    pub visibility: HandleVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
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

fn required_nullable_account<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<AccountId>, D::Error> {
    Option::<AccountId>::deserialize(deserializer)
}

impl AgentSelectorClaim {
    /// Canonical claim bytes covered by selector payload proofs.
    pub fn canonical_payload_without_proofs(&self) -> Result<Vec<u8>> {
        let value = canonical::unsigned_value(self, &["proofs"])?;
        Ok(canonical::canonical_json_value_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(
            &self.canonical_payload_without_proofs()?,
        ))
        .map_err(|reason| WireError::Protocol(reason.to_string()))
    }

    /// Canonical `ak.agent_selector_claim_proof.v1` transcript shared by
    /// producers and verifiers.
    pub fn canonical_proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest {
            return Err(WireError::Protocol(
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
                "controller_subject_id".to_owned(),
                serde_json::to_value(&self.controller_subject_id)?,
            ),
            (
                "subject_account_id".to_owned(),
                serde_json::to_value(&self.subject_account_id)?,
            ),
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
                Value::String(canonical::format_timestamp_canonical(proof.created_at)),
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
            return Err(WireError::Protocol(format!(
                "agent_selector_claim schema must be {schemaid_agent_selector_claim_v1}",
                schemaid_agent_selector_claim_v1 = SchemaId::AGENT_SELECTOR_CLAIM_V1
            )));
        }
        validate_agent_slug(&self.agent_slug)?;
        if self.issuer_id != self.controller_subject_id {
            return Err(WireError::Protocol(
                "selector issuer must be its controller".to_owned(),
            ));
        }
        if self.subject_account_id.is_none() && self.source_refs.is_empty() {
            return Err(WireError::Protocol(
                "selector unbind requires source_refs".to_owned(),
            ));
        }
        {
            let mut seen = BTreeSet::new();
            for source in &self.source_refs {
                arkret_wire::EventId::new(source.clone())?;
                if !seen.insert(source) {
                    return Err(WireError::Protocol(
                        "duplicate selector unbind source".to_owned(),
                    ));
                }
            }
        }
        if self
            .expires_at
            .is_some_and(|expiry| expiry <= self.created_at)
        {
            return Err(WireError::Protocol(
                "selector expiry must follow creation".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "agent_selector_claim requires proofs".to_owned(),
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
