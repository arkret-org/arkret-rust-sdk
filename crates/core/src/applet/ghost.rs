use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ACTOR_PROFILE_SCHEMA, ActorKind, ActorProfile, ActorProfileId, AppletId, BlobRef, Did, Error,
    Event, ExternalRef, Hash, Hlc, ObjectCreatePayload, PayloadProof, RealmId, Result, canonical,
};

pub const ACCOUNTABILITY_GRANT_SCHEMA: &str = "ak.schema.accountability_grant.v1";

/// `POST /_arkret/self/applets/{applet_id}/ghosts/provision` request body.
///
/// An Applet service / bridge asks the Principal Server to provision (or
/// re-validate) an Applet-managed Ghost Actor profile plus accountability
/// grant for one external user. Built by the bridge side and parsed by the
/// authz service; the server still re-checks `applet_id`/`service_id`/
/// `realm_id` against the installed package before minting anything.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GhostActorProvisionRequestBody {
    /// Always [`GhostActorProvisionRequestBody::SCHEMA`].
    pub schema: String,
    pub applet_id: AppletId,
    pub service_id: Did,
    pub ghost_actor_id: Did,
    pub protocol: String,
    pub tenant: String,
    pub external_user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub realm_id: RealmId,
    pub external_ref: ExternalRef,
}

impl GhostActorProvisionRequestBody {
    pub const SCHEMA: &'static str = "ak.applet.ghost_actor.provision_request.v1";

    /// Build a request body with `schema` stamped and no `display_name`.
    /// Add a display name with [`with_display_name`](Self::with_display_name).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applet_id: AppletId,
        service_id: Did,
        ghost_actor_id: Did,
        protocol: impl Into<String>,
        tenant: impl Into<String>,
        external_user_id: impl Into<String>,
        realm_id: RealmId,
        external_ref: ExternalRef,
    ) -> Self {
        Self {
            schema: Self::SCHEMA.to_owned(),
            applet_id,
            service_id,
            ghost_actor_id,
            protocol: protocol.into(),
            tenant: tenant.into(),
            external_user_id: external_user_id.into(),
            display_name: None,
            realm_id,
            external_ref,
        }
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

/// `POST /_arkret/self/applets/{applet_id}/ghosts/provision` response.
///
/// Carries the durable event refs the Principal Server minted: the Ghost
/// Actor `ak.profile.create` ref, the `ak.identity.accountability_grant` ref
/// (also surfaced as the delegated `authorization_ref` for subsequent ghost
/// events).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GhostActorProvisionOutcome {
    pub ghost_actor_id: Did,
    pub profile_event_ref: String,
    pub accountability_grant_ref: String,
    pub authorization_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/applet-ghost-operations.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletGhostOperations {
    GhostActorProvisionRequestBody(Box<GhostActorProvisionRequestBody>),
    GhostActorProvisionOutcome(GhostActorProvisionOutcome),
}

/// Applet delegation fields required when an applet or delegated agent signs
/// on behalf of another actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletDelegatedEventAuthorization {
    pub executed_by: Did,
    pub authorization_ref: String,
    pub applet_id: AppletId,
}

impl AppletDelegatedEventAuthorization {
    pub fn new(
        executed_by: Did,
        authorization_ref: impl Into<String>,
        applet_id: AppletId,
    ) -> Self {
        Self {
            executed_by,
            authorization_ref: authorization_ref.into(),
            applet_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.authorization_ref.trim().is_empty() {
            return Err(Error::Protocol(
                "authorization_ref must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn apply_to_event(&self, event: &mut Event) -> Result<()> {
        self.validate()?;
        event.executed_by = Some(self.executed_by.clone());
        event.authorization_ref = Some(self.authorization_ref.clone());
        Ok(())
    }
}

/// Typed `profile_fields` payload for an Applet-managed Ghost Actor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProfileFields {
    pub managed_by_applet: AppletId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub external_ref: BTreeMap<String, Value>,
}

impl GhostActorProfileFields {
    pub fn new(managed_by_applet: AppletId) -> Self {
        Self {
            managed_by_applet,
            external_ref: BTreeMap::new(),
        }
    }
}

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
        ObjectCreatePayload::new(self.to_actor_profile()?).to_value()
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountabilityScope {
    Single(String),
    Multiple(Vec<String>),
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
