//! Ghost Actor profile drafting and Event materialization.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ObjectCreatePayload;
use arkret_models_identity::ActorProfile;
use arkret_models_integration::{AppletDelegatedEventAuthorization, GhostActorProfileFields};
use arkret_wire::{
    ActorKind, ActorProfileId, AppletId, BlobRef, Did, Event, Hlc, RealmId, SchemaId, ScopeRef,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EventDraftError, Result};

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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
            return Err(EventDraftError::Protocol(
                "ghost actor profile requires actor_kind=integration".to_owned(),
            ));
        }
        if self.display_name.trim().is_empty() {
            return Err(EventDraftError::Protocol(
                "ghost actor display_name must not be empty".to_owned(),
            ));
        }
        if self.display_name.chars().count() > 128 {
            return Err(EventDraftError::Protocol(
                "ghost actor display_name must not exceed 128 chars".to_owned(),
            ));
        }
        if self.accountable_principal_ids.is_empty() {
            return Err(EventDraftError::Protocol(
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
                serde_json::to_value(&self.profile_fields.external_ref)?,
            );
        }
        Ok(ActorProfile {
            id: self.id.clone(),
            schema: SchemaId::ACTOR_PROFILE_V1.to_owned(),
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
        scope_ref: ScopeRef,
        actor_seq: u64,
        hlc: Hlc,
        authorization: Option<&AppletDelegatedEventAuthorization>,
    ) -> Result<Event> {
        let mut event = Event::new(
            "ak.profile.create",
            scope_ref,
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
    use arkret_wire::{ActorKind, EventKind};

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn profile_id() -> ActorProfileId {
        ActorProfileId::new("ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap()
    }

    fn applet_id() -> AppletId {
        AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    #[test]
    fn request_builds_schema_legal_profile_shape() {
        let request =
            GhostActorProfileRequest::new(profile_id(), did("ghost"), "Ghost", applet_id())
                .with_accountable_principal_ids(vec![did("owner")]);

        let profile = request.to_actor_profile().unwrap();

        assert_eq!(profile.actor_kind, ActorKind::Integration);
        assert_eq!(
            profile.profile_fields["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
    }

    #[test]
    fn request_builds_profile_create_event() {
        let request =
            GhostActorProfileRequest::new(profile_id(), did("ghost"), "Ghost", applet_id())
                .with_accountable_principal_ids(vec![did("owner")]);
        let event = request
            .profile_create_event(
                ScopeRef::Realm {
                    realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-cccccccccccc")
                        .unwrap(),
                },
                1,
                Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
                None,
            )
            .unwrap();

        assert_eq!(event.kind, EventKind::PROFILE_CREATE);
        assert_eq!(
            event.payload["object"]["profile_fields"]["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
    }
}
