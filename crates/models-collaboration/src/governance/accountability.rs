//! Accountability-grant wire model and payload-proof transcript.

use std::collections::BTreeSet;

use arkret_models_identity::actor_profile::ActorProfile;
use arkret_wire::{
    DidCoreId, Hash, PayloadProof, ProofContextId, Result, SchemaId, WireError, canonical,
    composite_subject, string_set_digest_component,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ACCOUNTABILITY_SCOPE_SET_CONTEXT: &str =
    arkret_wire::DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1;

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

impl AccountabilityScopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Employment => "employment",
            Self::ContractedService => "contracted_service",
            Self::AgentOperator => "agent_operator",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountabilityScope {
    Single(AccountabilityScopeKind),
    Multiple(Vec<AccountabilityScopeKind>),
}

impl AccountabilityScope {
    fn canonical_kinds_unchecked(&self) -> Vec<AccountabilityScopeKind> {
        let mut scopes = match self {
            Self::Single(scope) => vec![*scope],
            Self::Multiple(scopes) => scopes.clone(),
        };
        scopes.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        scopes.dedup();
        scopes
    }

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

    pub fn canonical_set(&self) -> Result<Vec<AccountabilityScopeKind>> {
        self.validate()?;
        Ok(self.canonical_kinds_unchecked())
    }

    pub fn canonicalized_for_authoring(&self) -> Result<Self> {
        let scopes = self.canonical_set()?;
        Ok(match scopes.as_slice() {
            [scope] => Self::Single(*scope),
            _ => Self::Multiple(scopes),
        })
    }

    pub fn scope_set_component(&self) -> Result<String> {
        let values = self
            .canonical_set()?
            .into_iter()
            .map(|scope| scope.as_str().to_owned())
            .collect::<Vec<_>>();
        string_set_digest_component(&values, ACCOUNTABILITY_SCOPE_SET_CONTEXT)
    }
}

impl PartialEq for AccountabilityScope {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_kinds_unchecked() == other.canonical_kinds_unchecked()
    }
}

impl Eq for AccountabilityScope {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityGrantPayload {
    pub schema: String,
    pub issuer_id: DidCoreId,
    pub subject_id: DidCoreId,
    pub accountability_scope: AccountabilityScope,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub grant_status: AccountabilityGrantStatus,
    pub proof: PayloadProof,
}

impl AccountabilityGrantPayload {
    pub const SCHEMA: &'static str = SchemaId::ACCOUNTABILITY_GRANT_V1;
    pub fn new(
        issuer_id: DidCoreId,
        subject_id: DidCoreId,
        accountability_scope: AccountabilityScope,
        not_before: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        proof: PayloadProof,
    ) -> Self {
        Self {
            schema: SchemaId::ACCOUNTABILITY_GRANT_V1.to_owned(),
            issuer_id,
            subject_id,
            accountability_scope: accountability_scope
                .canonicalized_for_authoring()
                .unwrap_or(accountability_scope),
            not_before,
            expires_at,
            grant_status: AccountabilityGrantStatus::Active,
            proof,
        }
    }

    pub fn canonical_payload_without_proof(&self) -> Result<Vec<u8>> {
        let value = canonical::unsigned_value(self, &["proof"])?;
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        let mut input = b"ak.accountability-grant-v1\n".to_vec();
        input.extend(self.canonical_payload_without_proof()?);
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn cell_subject(&self) -> Result<String> {
        let scope_component = self.accountability_scope.scope_set_component()?;
        composite_subject(&[
            self.issuer_id.as_str(),
            self.subject_id.as_str(),
            scope_component.as_str(),
        ])
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
            (
                "issuer_id".to_owned(),
                serde_json::to_value(&self.issuer_id)?,
            ),
            (
                "subject_id".to_owned(),
                serde_json::to_value(&self.subject_id)?,
            ),
            (
                "verification_method".to_owned(),
                Value::String(self.proof.verification_method.as_str().to_owned()),
            ),
            (
                "created_at".to_owned(),
                Value::String(arkret_canonical::format_timestamp_canonical(
                    self.proof.created_at,
                )),
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
        if self.subject_id != profile.principal_id {
            return Err(WireError::Protocol(
                "accountability_grant subject_id does not match actor profile principal_id"
                    .to_owned(),
            ));
        }
        if !profile
            .accountable_principal_ids
            .iter()
            .any(|principal_id| principal_id.as_core_id() == self.issuer_id.as_core_id())
        {
            return Err(WireError::Protocol(
                "accountability_grant issuer_id is not in actor profile accountable_principal_ids"
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

    #[test]
    fn accountability_scope_kats_and_domain_equality_are_canonical() {
        let singleton = AccountabilityScope::Single(AccountabilityScopeKind::Employment);
        let singleton_array =
            AccountabilityScope::Multiple(vec![AccountabilityScopeKind::Employment]);
        assert_eq!(singleton, singleton_array);
        assert_eq!(
            singleton.scope_set_component().unwrap(),
            "CbgdIHArQNPwYmdaAOdv1G1B9LEmtBtgkYaG6tLR2Bg"
        );

        let reordered = AccountabilityScope::Multiple(vec![
            AccountabilityScopeKind::Employment,
            AccountabilityScopeKind::AgentOperator,
        ]);
        let canonical = AccountabilityScope::Multiple(vec![
            AccountabilityScopeKind::AgentOperator,
            AccountabilityScopeKind::Employment,
        ]);
        assert_eq!(reordered, canonical);
        assert_eq!(
            reordered.scope_set_component().unwrap(),
            "AWANhOFZ5FNgAQMK9mqCeI3ATOZR6o7qwshmpk3ij3U"
        );

        let all = AccountabilityScope::Multiple(vec![
            AccountabilityScopeKind::Employment,
            AccountabilityScopeKind::ContractedService,
            AccountabilityScopeKind::AgentOperator,
        ]);
        assert_eq!(
            all.scope_set_component().unwrap(),
            "0sKY5mg--AeXwZefBw5FAjz9rpQ3NuCVm22vRPKJrLE"
        );

        let duplicated = AccountabilityScope::Multiple(vec![
            AccountabilityScopeKind::Employment,
            AccountabilityScopeKind::Employment,
        ]);
        assert!(duplicated.canonicalized_for_authoring().is_err());
    }
}
