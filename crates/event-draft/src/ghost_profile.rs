//! Ghost Actor profile drafting and Event materialization.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
use arkret_models_identity::ActorProfile;
use arkret_models_integration::{AppletDelegatedEventAuthorization, GhostActorProfileFields};
use arkret_wire::{
    ActorId, ActorKind, AppletId, BlobRef, CoreId, Event, Hlc, RealmId, SchemaId, ScopeRef,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub principal_id: CoreId,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<CoreId>,
    pub profile_fields: GhostActorProfileFields,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<CoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl GhostActorProfileRequest {
    /// There is no `id` parameter: this builds the `ak.profile.create` payload,
    /// and the profile id is derived from that create Event (spec
    /// `zh/models/common-fields.md` section 6.0).
    pub fn new(
        principal_id: CoreId,
        display_name: impl Into<String>,
        managed_by_applet: AppletId,
    ) -> Self {
        Self {
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

    pub fn with_accountable_principal_ids(
        mut self,
        accountable_principal_ids: Vec<CoreId>,
    ) -> Self {
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
            id: None,
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
            resolution: None,
            profile_fields,
            created_at: self.created_at,
            updated_by: self.updated_by.clone(),
            updated_at: self.updated_at,
        })
    }

    pub fn profile_create_payload(&self) -> Result<Value> {
        Ok(serde_json::to_value(ActorProfileCreatePayload {
            object: self.to_actor_profile()?,
        })?)
    }

    pub fn profile_create_event(
        &self,
        scope_ref: ScopeRef,
        actor_seq: u64,
        hlc: Hlc,
        authorization: Option<&AppletDelegatedEventAuthorization>,
    ) -> Result<Event> {
        let payload = ActorProfileCreatePayload {
            object: self.to_actor_profile()?,
        };
        let mut draft = crate::TypedEventDraft::<arkret_wire::event_spec::ProfileCreate>::new(
            scope_ref,
            ActorId::from(self.principal_id.clone()),
            payload,
        )?;
        if let Some(authorization) = authorization {
            authorization.validate()?;
            draft = draft
                .with_executed_by(authorization.executed_by.clone())
                .with_authorization_ref(authorization.authorization_ref.clone())
                .with_applet_id(authorization.applet_id.clone());
        }
        draft.author_now(actor_seq, hlc)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{ActorKind, EventKind};

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn applet_id() -> AppletId {
        AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    #[test]
    fn request_builds_schema_legal_profile_shape() {
        let request = GhostActorProfileRequest::new(did("ghost"), "Ghost", applet_id())
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
        let request = GhostActorProfileRequest::new(did("ghost"), "Ghost", applet_id())
            .with_accountable_principal_ids(vec![did("owner")]);
        let event = request
            .profile_create_event(
                ScopeRef::Realm {
                    realm_id: RealmId::new("ak:realm:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM")
                        .unwrap(),
                },
                1,
                Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
                None,
            )
            .unwrap();

        assert_eq!(event.kind, EventKind::ProfileCreate);
        assert_eq!(
            event.payload["object"]["profile_fields"]["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
    }
}
