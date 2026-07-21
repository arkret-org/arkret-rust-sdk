//! Accountability-grant wire model and payload-proof transcript.

use std::collections::BTreeSet;

use arkret_models_identity::actor_profile::ActorProfile;
use arkret_wire::{Did, Hash, PayloadProof, ProofContextId, Result, WireError, canonical};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ACCOUNTABILITY_GRANT_SCHEMA: &str = "ak.schema.accountability_grant.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityGrantStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityScopeKind {
    Employment,
    ContractedService,
    AgentOperator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountabilityScope {
    Single(AccountabilityScopeKind),
    Multiple(Vec<AccountabilityScopeKind>),
}

impl AccountabilityScope {
    pub fn validate(&self) -> Result<()> {
        let Self::Multiple(scopes) = self else {
            return Ok(());
        };
        if scopes.is_empty() {
            return Err(WireError::Protocol(
                "accountability_scope list must not be empty".to_owned(),
            ));
        }
        if scopes.iter().copied().collect::<BTreeSet<_>>().len() != scopes.len() {
            return Err(WireError::Protocol(
                "accountability_scope list must contain unique values".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityGrantPayload {
    pub schema: String,
    pub issuer: Did,
    pub subject: Did,
    pub accountability_scope: AccountabilityScope,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub grant_status: AccountabilityGrantStatus,
    pub proof: PayloadProof,
}

impl AccountabilityGrantPayload {
    pub fn new(
        issuer: Did,
        subject: Did,
        accountability_scope: AccountabilityScope,
        not_before: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        proof: PayloadProof,
    ) -> Self {
        Self {
            schema: ACCOUNTABILITY_GRANT_SCHEMA.to_owned(),
            issuer,
            subject,
            accountability_scope,
            not_before,
            expires_at,
            grant_status: AccountabilityGrantStatus::Active,
            proof,
        }
    }

    pub fn canonical_payload_without_proof(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AccountabilityGrantPayload serializes as an object")
            .remove("proof");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        let mut input = b"ak.accountability-grant-v1\n".to_vec();
        input.extend(self.canonical_payload_without_proof()?);
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if self.proof.payload_digest != payload_digest {
            return Err(WireError::Protocol(
                "accountability_grant proof payload_digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::from_iter([
            (
                "context".to_owned(),
                Value::String(ProofContextId::ACCOUNTABILITY_GRANT_PROOF_V1.to_owned()),
            ),
            (
                "payload_digest".to_owned(),
                serde_json::to_value(&payload_digest)?,
            ),
            ("issuer".to_owned(), serde_json::to_value(&self.issuer)?),
            ("subject".to_owned(), serde_json::to_value(&self.subject)?),
            (
                "verification_method".to_owned(),
                Value::String(self.proof.verification_method.clone()),
            ),
            (
                "created_at".to_owned(),
                serde_json::to_value(self.proof.created_at)?,
            ),
        ]);
        if let Some(domain) = &self.proof.domain {
            binding.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.proof.audience {
            binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(binding))?)
    }

    pub fn validate_lifecycle_at(&self, now: DateTime<Utc>) -> Result<()> {
        self.accountability_scope.validate()?;
        if let Some(expires_at) = self.expires_at {
            if self.not_before >= expires_at {
                return Err(WireError::Protocol(
                    "accountability_grant not_before must be before expires_at".to_owned(),
                ));
            }
            if now > expires_at {
                return Err(WireError::Protocol(
                    "accountability_grant has expired".to_owned(),
                ));
            }
        }
        if self.grant_status != AccountabilityGrantStatus::Active {
            return Err(WireError::Protocol(
                "accountability_grant is not active".to_owned(),
            ));
        }
        if now < self.not_before {
            return Err(WireError::Protocol(
                "accountability_grant is not yet active".to_owned(),
            ));
        }
        self.proof.validate_production()
    }

    pub fn validate_for_profile(&self, profile: &ActorProfile, now: DateTime<Utc>) -> Result<()> {
        self.validate_lifecycle_at(now)?;
        if self.subject != profile.principal_id {
            return Err(WireError::Protocol(
                "accountability_grant subject does not match actor profile principal_id".to_owned(),
            ));
        }
        if !profile
            .accountable_principal_ids
            .iter()
            .any(|did| did == &self.issuer)
        {
            return Err(WireError::Protocol(
                "accountability_grant issuer is not in actor profile accountable_principal_ids"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accountability_scope_is_closed_non_empty_and_unique() {
        assert!(
            serde_json::from_value::<AccountabilityScope>(serde_json::json!("custom")).is_err()
        );
        assert!(
            AccountabilityScope::Multiple(Vec::new())
                .validate()
                .is_err()
        );
        assert!(
            AccountabilityScope::Multiple(vec![
                AccountabilityScopeKind::ContractedService,
                AccountabilityScopeKind::ContractedService,
            ])
            .validate()
            .is_err()
        );
    }
}
