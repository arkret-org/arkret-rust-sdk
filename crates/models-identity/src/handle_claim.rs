//! Handle-claim wire models for exact account discovery.

use std::collections::BTreeMap;

use arkret_wire::{AccountId, DidCoreId, PayloadProof, Result, SchemaId, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::handle::{Handle, HandleBindingState, HandleClaimKind, HandleVisibility};

fn default_handle_claim_schema() -> String {
    SchemaId::HANDLE_CLAIM_V1.to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleClaim {
    #[serde(default = "default_handle_claim_schema")]
    pub schema: String,
    pub handle: Handle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    /// The handle identifies an exact account, not a bare principal DID.
    pub subject_account_id: AccountId,
    pub issuer_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vouching_id: Option<DidCoreId>,
    pub binding_state: HandleBindingState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_kind: Option<HandleClaimKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<HandleVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl HandleClaim {
    pub const SCHEMA: &'static str = SchemaId::HANDLE_CLAIM_V1;

    pub fn validate(&self) -> Result<()> {
        self.subject_account_id.validate()?;
        if self.binding_state == HandleBindingState::Verified && self.expires_at.is_none() {
            return Err(WireError::Protocol(
                "binding_state=verified requires expires_at".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_remote_resolution(
        &self,
        expected_audience: Option<&str>,
        expected_account_id: Option<&AccountId>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if self.schema != SchemaId::HANDLE_CLAIM_V1 {
            return Err(WireError::Protocol(
                "handle claim schema mismatch".to_owned(),
            ));
        }
        if self.binding_state != HandleBindingState::Verified {
            return Err(WireError::Protocol(
                "handle claim must be verified".to_owned(),
            ));
        }
        if self
            .expires_at
            .ok_or_else(|| WireError::Protocol("handle claim requires expires_at".to_owned()))?
            <= now
        {
            return Err(WireError::Protocol("handle claim expired".to_owned()));
        }
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "handle claim requires proof".to_owned(),
            ));
        }
        if let Some(expected_audience) = expected_audience
            && self.audience.as_deref() != Some(expected_audience)
        {
            return Err(WireError::Protocol(
                "handle claim audience mismatch".to_owned(),
            ));
        }
        if expected_account_id.is_some_and(|expected| expected != &self.subject_account_id) {
            return Err(WireError::Protocol(
                "handle claim account id mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn handle_canonical(&self) -> Option<&str> {
        Some(self.handle.canonical())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, Hash};

    use super::*;

    fn account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
        )
    }

    fn fixture_claim() -> HandleClaim {
        HandleClaim {
            schema: HandleClaim::SCHEMA.to_owned(),
            handle: Handle::parse("alice:example.com").unwrap(),
            handle_aliases: Vec::new(),
            subject_account_id: account_id(),
            issuer_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureissuer").unwrap(),
            vouching_id: None,
            binding_state: HandleBindingState::Verified,
            claim_kind: Some(HandleClaimKind::HandleBinding),
            visibility: None,
            audience: Some("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned()),
            challenge: None,
            claim_scope: BTreeMap::new(),
            claims: Vec::new(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer.example#key-1")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: Utc::now(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "placeholder".to_owned(),
            }],
        }
    }

    #[test]
    fn verified_claim_uses_exact_account_id() {
        let claim = fixture_claim();
        claim.validate().unwrap();
        let value = serde_json::to_value(&claim).unwrap();
        assert_eq!(
            value["subject_account_id"]["principal_id"],
            account_id().principal_id.as_str()
        );
        assert!(value.get("subject_id").is_none());
        assert!(value.get("member_delivery_binding").is_none());
    }

    #[test]
    fn remote_resolution_compares_the_complete_pair() {
        let claim = fixture_claim();
        let different_server = AccountId::new(
            claim.subject_account_id.principal_id.clone(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureother").unwrap(),
        );
        assert!(
            claim
                .validate_remote_resolution(
                    claim.audience.as_deref(),
                    Some(&different_server),
                    Utc::now(),
                )
                .is_err()
        );
    }
}
