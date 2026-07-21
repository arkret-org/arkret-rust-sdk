//! Ghost Actor profile builders retained by `arkret-core`.
//!
//! The provision request/response bodies and the delegated-event
//! authorization envelope migrated to `arkret-models-integration`
//! (re-exported via the parent module). The builders kept here construct
//! `ObjectCreatePayload` events (collaboration-owned envelope) and the
//! governance-owned accountability grant is re-exported from
//! `arkret-models-collaboration`.

use std::collections::BTreeMap;

pub use arkret_models_collaboration::governance::accountability::{
    ACCOUNTABILITY_GRANT_SCHEMA, AccountabilityGrantPayload, AccountabilityGrantStatus,
    AccountabilityScope, AccountabilityScopeKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ACTOR_PROFILE_SCHEMA, ActorKind, ActorProfile, ActorProfileId,
    AppletDelegatedEventAuthorization, AppletId, BlobRef, Did, Error, Event,
    GhostActorProfileFields, Hlc, ObjectCreatePayload, RealmId, Result,
};

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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
