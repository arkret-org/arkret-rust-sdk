//! Ghost Actor profile and accountability-grant builders retained by
//! `arkret-core`.
//!
//! The provision request/response bodies and the delegated-event
//! authorization envelope migrated to `arkret-models-integration`
//! (re-exported via the parent module). The builders kept here construct
//! `ObjectCreatePayload` events (collaboration-owned envelope) and the
//! governance-owned accountability grant, pending the accountability
//! carve-out into `arkret-models-collaboration`.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ACTOR_PROFILE_SCHEMA, ActorKind, ActorProfile, ActorProfileId,
    AppletDelegatedEventAuthorization, AppletId, BlobRef, Did, Error, Event,
    GhostActorProfileFields, Hash, Hlc, ObjectCreatePayload, PayloadProof, RealmId, Result,
    canonical,
};

pub const ACCOUNTABILITY_GRANT_SCHEMA: &str = "ak.schema.accountability_grant.v1";

/// SDK request object for constructing the schema-legal Ghost Actor profile
/// used by `ak.profile.create`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProfileRequest {
    pub id: ActorProfileId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub principal_id: Did,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<Did>,
    pub profile_fields: GhostActorProfileFields,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl GhostActorProfileRequest {
    pub fn new(
        id: ActorProfileId,
        principal_id: Did,
        display_name: impl Into<String>,
        managed_by_applet: AppletId,
    ) -> Self {
        Self {
            id,
            realm_id: None,
            principal_id,
            actor_kind: ActorKind::Integration,
            display_name: display_name.into(),
            handle: None,
            avatar_blob_ref: None,
            accountable_principal_ids: Vec::new(),
            profile_fields: GhostActorProfileFields::new(managed_by_applet),
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }

    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    pub fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    pub fn with_avatar_blob_ref(mut self, avatar_blob_ref: BlobRef) -> Self {
        self.avatar_blob_ref = Some(avatar_blob_ref);
        self
    }

    pub fn with_accountable_principal_ids(mut self, accountable_principal_ids: Vec<Did>) -> Self {
        self.accountable_principal_ids = accountable_principal_ids;
        self
    }

    pub fn with_external_ref(mut self, external_ref: BTreeMap<String, Value>) -> Self {
        self.profile_fields.external_ref = external_ref;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.actor_kind != ActorKind::Integration {
            return Err(Error::Protocol(
                "ghost actor profile requires actor_kind=integration".to_owned(),
            ));
        }
        if self.display_name.trim().is_empty() {
            return Err(Error::Protocol(
                "ghost actor display_name must not be empty".to_owned(),
            ));
        }
        if self.display_name.chars().count() > 128 {
            return Err(Error::Protocol(
                "ghost actor display_name must not exceed 128 chars".to_owned(),
            ));
        }
        if self.accountable_principal_ids.is_empty() {
            return Err(Error::Protocol(
                "ghost actor profile requires accountable_principal_ids".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_actor_profile(&self) -> Result<ActorProfile> {
        self.validate()?;
        let mut profile_fields = BTreeMap::from([(
            "managed_by_applet".to_owned(),
            Value::String(self.profile_fields.managed_by_applet.to_string()),
        )]);
        if !self.profile_fields.external_ref.is_empty() {
            profile_fields.insert(
                "external_ref".to_owned(),
                serde_json::to_value(&self.profile_fields.external_ref)
                    .map_err(Error::CanonicalJson)?,
            );
        }
        Ok(ActorProfile {
            id: self.id.clone(),
            schema: ACTOR_PROFILE_SCHEMA.to_owned(),
            realm_id: self.realm_id.clone(),
            principal_id: self.principal_id.clone(),
            actor_kind: ActorKind::Integration,
            display_name: self.display_name.clone(),
            handle: self.handle.clone(),
            agent_slug: None,
            avatar_blob_ref: self.avatar_blob_ref.clone(),
            status: None,
            accountable_principal_ids: self.accountable_principal_ids.clone(),
            profile_fields,
            created_at: self.created_at,
            updated_by: self.updated_by.clone(),
            updated_at: self.updated_at,
        })
    }

    pub fn profile_create_payload(&self) -> Result<Value> {
        Ok(ObjectCreatePayload::new(self.to_actor_profile()?).to_value()?)
    }

    pub fn profile_create_event(
        &self,
        realm_id: RealmId,
        actor_seq: u64,
        hlc: Hlc,
        authorization: Option<&AppletDelegatedEventAuthorization>,
    ) -> Result<Event> {
        let mut event = Event::new(
            "ak.profile.create",
            realm_id,
            self.principal_id.clone(),
            actor_seq,
            hlc,
            self.profile_create_payload()?,
        )?;
        if let Some(authorization) = authorization {
            authorization.apply_to_event(&mut event)?;
        }
        Ok(event)
    }
}

/// `ak.identity.accountability_grant.grant_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityGrantStatus {
    Active,
    Revoked,
}

/// `ak.identity.accountability_grant.accountability_scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityScopeKind {
    Employment,
    ContractedService,
    AgentOperator,
}

/// A single accountability scope or a non-empty unique set of scopes.
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
            return Err(Error::Protocol(
                "accountability_scope list must not be empty".to_owned(),
            ));
        }
        if scopes.iter().copied().collect::<BTreeSet<_>>().len() != scopes.len() {
            return Err(Error::Protocol(
                "accountability_scope list must contain unique values".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Payload for durable `ak.identity.accountability_grant` events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityGrantPayload {
    pub schema: String,
    pub issuer: Did,
    pub subject: Did,
    pub accountability_scope: AccountabilityScope,
    pub not_before: DateTime<Utc>,
    /// Optional: absent means the grant is non-expiring and governed by
    /// `grant_status` revocation and controller lifecycle cascade
    /// (actor.md §3.3.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

    /// Canonical accountability-grant payload bytes with the detached
    /// `proof` member omitted. This is the only protocol implementation of
    /// the payload covered by an accountability proof.
    pub fn canonical_payload_without_proof(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AccountabilityGrantPayload serializes as an object")
            .remove("proof");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    /// `sha256(utf8("ak.accountability-grant-v1\\n") || canonical_payload)`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut input = b"ak.accountability-grant-v1\n".to_vec();
        input.extend(self.canonical_payload_without_proof()?);
        Hash::new(canonical::sha256_digest(&input))
            .map_err(|reason| Error::Protocol(reason.to_string()))
    }

    /// Canonical proof transcript shared by all accountability-grant
    /// producers and verifiers.
    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if self.proof.payload_digest != payload_digest {
            return Err(Error::Protocol(
                "accountability_grant proof payload_digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::from_iter([
            (
                "context".to_owned(),
                Value::String(crate::ProofContextId::ACCOUNTABILITY_GRANT_PROOF_V1.to_owned()),
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
                return Err(Error::Protocol(
                    "accountability_grant not_before must be before expires_at".to_owned(),
                ));
            }
            if now > expires_at {
                return Err(Error::Protocol(
                    "accountability_grant has expired".to_owned(),
                ));
            }
        }
        if self.grant_status != AccountabilityGrantStatus::Active {
            return Err(Error::Protocol(
                "accountability_grant is not active".to_owned(),
            ));
        }
        if now < self.not_before {
            return Err(Error::Protocol(
                "accountability_grant is not yet active".to_owned(),
            ));
        }
        Ok(self.proof.validate_production()?)
    }

    pub fn validate_for_profile(&self, profile: &ActorProfile, now: DateTime<Utc>) -> Result<()> {
        self.validate_lifecycle_at(now)?;
        if self.subject != profile.principal_id {
            return Err(Error::Protocol(
                "accountability_grant subject does not match actor profile principal_id".to_owned(),
            ));
        }
        if !profile
            .accountable_principal_ids
            .iter()
            .any(|did| did == &self.issuer)
        {
            return Err(Error::Protocol(
                "accountability_grant issuer is not in actor profile accountable_principal_ids"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_event(
        &self,
        realm_id: RealmId,
        actor_seq: u64,
        hlc: Hlc,
        authorization: Option<&AppletDelegatedEventAuthorization>,
    ) -> Result<Event> {
        let mut event = Event::new(
            crate::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
            realm_id,
            self.issuer.clone(),
            actor_seq,
            hlc,
            serde_json::to_value(self)?,
        )?;
        if let Some(authorization) = authorization {
            authorization.apply_to_event(&mut event)?;
        }
        Ok(event)
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
