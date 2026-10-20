//! Ghost Actor profile drafting and Event materialization.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
use arkret_models_identity::ActorProfileDefinition;
use arkret_models_integration::{GhostActorProfileFields, GhostExternalTuple};
use arkret_wire::{ActorKind, AppletId, BlobRef, RealmActorId, ScopeRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EventDraftError, Result};

/// SDK request object for constructing the schema-legal Ghost Actor profile
/// definition carried by `ak.profile.create`.
///
/// Only author input is representable: the schema, Realm, creation time and
/// update members are reducer derivations of the accepted create Event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProfileRequest {
    pub realm_actor_id: RealmActorId,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub profile_fields: GhostActorProfileFields,
}

impl GhostActorProfileRequest {
    /// There is no `id` parameter: this builds the `ak.profile.create` payload,
    /// and the profile id is derived from that create Event (spec
    /// `zh/models/common-fields.md` section 6.0).
    pub fn new(
        realm_actor_id: RealmActorId,
        display_name: impl Into<String>,
        managed_by_applet: AppletId,
        external_ref: GhostExternalTuple,
    ) -> Self {
        Self {
            realm_actor_id,
            actor_kind: ActorKind::Integration,
            display_name: display_name.into(),
            avatar_blob_ref: None,
            profile_fields: GhostActorProfileFields::new(managed_by_applet, external_ref),
        }
    }

    pub fn with_external_ref(mut self, external_ref: GhostExternalTuple) -> Self {
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
        self.realm_actor_id.validate()?;
        Ok(())
    }

    pub fn to_definition(&self) -> Result<ActorProfileDefinition> {
        self.validate()?;
        let mut profile_fields = BTreeMap::from([(
            "managed_by_applet".to_owned(),
            Value::String(self.profile_fields.managed_by_applet.to_string()),
        )]);
        profile_fields.insert(
            "external_ref".to_owned(),
            serde_json::to_value(&self.profile_fields.external_ref)?,
        );
        Ok(ActorProfileDefinition {
            principal_id: None,
            actor_id: Some(arkret_wire::ActorId::realm(self.realm_actor_id.clone())),
            actor_kind: ActorKind::Integration,
            display_name: self.display_name.clone(),
            handle: None,
            agent_slug: None,
            avatar_blob_ref: self.avatar_blob_ref.clone(),
            accountable_principal_ids: None,
            profile_fields,
        })
    }

    pub fn profile_create_intent(&self, created_at: DateTime<Utc>) -> Result<crate::EventIntent> {
        let payload = ActorProfileCreatePayload {
            object: self.to_definition()?,
        };
        crate::TypedEventDraft::<arkret_wire::event_spec::ProfileCreate>::new(
            ScopeRef::RealmControl {
                realm_id: self.realm_actor_id.realm_id.clone(),
            },
            arkret_wire::ActorId::realm(self.realm_actor_id.clone()),
            payload,
        )?
        .with_applet_id(self.profile_fields.managed_by_applet.clone())
        .into_intent(created_at)
    }
}
