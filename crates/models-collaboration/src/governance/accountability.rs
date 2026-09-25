//! Accountability-grant wire model and payload-proof transcript.

use std::collections::BTreeSet;

use arkret_models_identity::actor_profile::ActorProfile;
pub use arkret_wire::{AccountabilityScopeKind, AccountabilityScopeSet};
use arkret_wire::{
    DidCoreId, Hash, PayloadProof, ProofContextId, Result, SchemaId, WireError, canonical,
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

    /// The normalized exact set the `identity_accountability` subject and
    /// value carry (`zh/models/actor.md` section 3.3.1).
    pub fn normalized_set(&self) -> Result<AccountabilityScopeSet> {
        AccountabilityScopeSet::normalize(match self {
            Self::Single(scope) => vec![*scope],
            Self::Multiple(scopes) => scopes.clone(),
        })
    }

    pub fn canonicalized_for_authoring(&self) -> Result<Self> {
        let scopes = self.canonical_set()?;
        Ok(match scopes.as_slice() {
            [scope] => Self::Single(*scope),
            _ => Self::Multiple(scopes),
        })
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

    /// Admission-time shape checks that need no accepted state: the closed
    /// schema constant, a normalizable scope set, an ordered validity window
    /// and a production proof carrier.
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != SchemaId::ACCOUNTABILITY_GRANT_V1 {
            return Err(WireError::Protocol(
                "accountability_grant schema must be ak.schema.accountability_grant.v1".to_owned(),
            ));
        }
        self.accountability_scope.normalized_set()?;
        if self
            .expires_at
            .is_some_and(|expires_at| self.not_before >= expires_at)
        {
            return Err(WireError::Protocol(
                "accountability_grant not_before must be before expires_at".to_owned(),
            ));
        }
        if self.proof.kind != "detached_jws" {
            return Err(WireError::Protocol(
                "accountability_grant proof must be a detached JWS".to_owned(),
            ));
        }
        self.proof.validate_production()
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

/// Canonical business value of the `identity_accountability` typed current
/// result (`accountability-grant.schema.json#/$defs/accountability_projection`).
///
/// One record has two registered writers: the independent
/// `ak.identity.accountability_grant` and the atomic accountability projection
/// of `ak.agent.provision` (`zh/models/actor.md` section 3.3.1). Neither the
/// inner proof nor a source Event reference is part of the value; the head
/// Event and its accepting Commit carry provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityProjection {
    pub issuer_id: DidCoreId,
    pub subject_id: DidCoreId,
    pub accountability_scope: AccountabilityScopeSet,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub grant_status: AccountabilityGrantStatus,
}

impl AccountabilityProjection {
    /// The independent writer's `value_projection`: every member is the signed
    /// payload member, the scope normalized, `expires_at` only when present.
    pub fn from_grant(grant: &AccountabilityGrantPayload) -> Result<Self> {
        grant.validate_shape()?;
        Ok(Self {
            issuer_id: grant.issuer_id.clone(),
            subject_id: grant.subject_id.clone(),
            accountability_scope: grant.accountability_scope.normalized_set()?,
            not_before: grant.not_before,
            expires_at: grant.expires_at,
            grant_status: grant.grant_status,
        })
    }

    /// The provision writer's `value_projection`: `not_before` is the carrying
    /// envelope's `created_at`, which admission requires to equal the signed
    /// payload time byte for byte; `expires_at` is absent and the status is
    /// the literal `active`.
    pub fn from_provision(
        provision: &crate::events_payloads::agent::AgentProvisionPayload,
        envelope_created_at: DateTime<Utc>,
    ) -> Result<Self> {
        if canonical::format_timestamp_canonical(provision.created_at)
            != canonical::format_timestamp_canonical(envelope_created_at)
        {
            return Err(WireError::Protocol(
                "ak.agent.provision payload.created_at must equal envelope.created_at".to_owned(),
            ));
        }
        Ok(Self {
            issuer_id: provision.controller_principal_id.clone(),
            subject_id: provision.agent_id.clone(),
            accountability_scope: AccountabilityScopeSet::normalize([
                AccountabilityScopeKind::AgentOperator,
            ])?,
            not_before: envelope_created_at,
            expires_at: None,
            grant_status: AccountabilityGrantStatus::Active,
        })
    }

    /// Whether this record verifies an `accountable_principal_ids` entry at
    /// the frozen admission time `now` (`zh/models/actor.md` section 3.3.1).
    pub fn verifies_at(&self, now: DateTime<Utc>) -> bool {
        self.grant_status == AccountabilityGrantStatus::Active
            && self.not_before <= now
            && self.expires_at.is_none_or(|expires_at| now <= expires_at)
    }
}

#[cfg(test)]
mod projection_tests {
    use serde_json::json;

    use super::*;

    fn grant(scope: Value, expires_at: Option<&str>) -> AccountabilityGrantPayload {
        let mut value = json!({
            "schema": "ak.schema.accountability_grant.v1",
            "issuer_id": "ak:did_core:web:alice.example",
            "subject_id": "ak:did_core:web:agent.example",
            "accountability_scope": scope,
            "not_before": "2026-01-01T00:00:00.000Z",
            "grant_status": "active",
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:alice.example#key-1",
                "payload_digest": format!("sha256:{}", "3".repeat(64)),
                "created_at": "2026-01-01T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZERTQSJ9..c2lnbmF0dXJl"
            }
        });
        if let Some(expires_at) = expires_at {
            value["expires_at"] = json!(expires_at);
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn grant_projection_normalizes_scope_and_keeps_absent_expiry_absent() {
        let single =
            AccountabilityProjection::from_grant(&grant(json!("employment"), None)).unwrap();
        let array =
            AccountabilityProjection::from_grant(&grant(json!(["employment"]), None)).unwrap();
        assert_eq!(single, array);
        let value = serde_json::to_value(&single).unwrap();
        assert_eq!(value["accountability_scope"], json!(["employment"]));
        assert!(value.get("expires_at").is_none());
        assert!(value.get("proof").is_none());
    }

    #[test]
    fn verification_window_is_inclusive_and_status_gated() {
        let projection = AccountabilityProjection::from_grant(&grant(
            json!(["employment", "agent_operator"]),
            Some("2026-06-01T00:00:00.000Z"),
        ))
        .unwrap();
        let at = |value: &str| value.parse::<DateTime<Utc>>().unwrap();
        assert!(!projection.verifies_at(at("2025-12-31T23:59:59.999Z")));
        assert!(projection.verifies_at(at("2026-01-01T00:00:00.000Z")));
        assert!(projection.verifies_at(at("2026-06-01T00:00:00.000Z")));
        assert!(!projection.verifies_at(at("2026-06-01T00:00:00.001Z")));
        let revoked = AccountabilityProjection {
            grant_status: AccountabilityGrantStatus::Revoked,
            ..projection
        };
        assert!(!revoked.verifies_at(at("2026-03-01T00:00:00.000Z")));
    }
}
