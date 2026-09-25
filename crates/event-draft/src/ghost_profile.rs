//! Ghost Actor profile drafting and Event materialization.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
use arkret_models_identity::ActorProfileDefinition;
use arkret_models_integration::{
    AppletDelegatedEventAuthorization, GhostActorProfileFields, GhostExternalTuple,
};
use arkret_wire::{ActorKind, AppletId, BlobRef, DidCoreId, ScopeRef};
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
    pub principal_id: DidCoreId,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<DidCoreId>,
    pub profile_fields: GhostActorProfileFields,
}

impl GhostActorProfileRequest {
    /// There is no `id` parameter: this builds the `ak.profile.create` payload,
    /// and the profile id is derived from that create Event (spec
    /// `zh/models/common-fields.md` section 6.0).
    pub fn new(
        principal_id: DidCoreId,
        display_name: impl Into<String>,
        managed_by_applet: AppletId,
        external_ref: GhostExternalTuple,
    ) -> Self {
        Self {
            principal_id,
            actor_kind: ActorKind::Integration,
            display_name: display_name.into(),
            handle: None,
            avatar_blob_ref: None,
            accountable_principal_ids: Vec::new(),
            profile_fields: GhostActorProfileFields::new(managed_by_applet, external_ref),
        }
    }

    pub fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    pub fn with_accountable_principal_ids(
        mut self,
        accountable_principal_ids: Vec<DidCoreId>,
    ) -> Self {
        self.accountable_principal_ids = accountable_principal_ids;
        self
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
        if self.accountable_principal_ids.is_empty() {
            return Err(EventDraftError::Protocol(
                "ghost actor profile requires accountable_principal_ids".to_owned(),
            ));
        }
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
            principal_id: self.principal_id.clone(),
            actor_kind: ActorKind::Integration,
            display_name: self.display_name.clone(),
            handle: self.handle.clone(),
            agent_slug: None,
            avatar_blob_ref: self.avatar_blob_ref.clone(),
            accountable_principal_ids: self.accountable_principal_ids.clone(),
            profile_fields,
        })
    }

    pub fn profile_create_intent(
        &self,
        scope_ref: ScopeRef,
        actor_id: arkret_wire::ActorId,
        created_at: DateTime<Utc>,
        authorization: Option<&AppletDelegatedEventAuthorization>,
    ) -> Result<crate::EventIntent> {
        let payload = ActorProfileCreatePayload {
            object: self.to_definition()?,
        };
        let mut draft = crate::TypedEventDraft::<arkret_wire::event_spec::ProfileCreate>::new(
            scope_ref, actor_id, payload,
        )?;
        if let Some(authorization) = authorization {
            authorization.validate()?;
            draft = draft
                .with_executed_by(arkret_wire::ActorId::service(
                    authorization.executed_by.clone(),
                ))
                .with_authorization_ref(authorization.authorization_ref.clone())
                .with_applet_id(authorization.applet_id.clone());
        }
        draft.into_intent(created_at)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{ActorKind, EventKind, RealmId};

    use super::*;

    fn principal(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn applet_id() -> AppletId {
        AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    fn external_ref() -> GhostExternalTuple {
        GhostExternalTuple {
            protocol: "fixture".to_owned(),
            instance_id: "instance-1".to_owned(),
            external_id: "external-1".to_owned(),
        }
    }

    #[test]
    fn request_builds_schema_legal_profile_shape() {
        let request =
            GhostActorProfileRequest::new(principal("ghost"), "Ghost", applet_id(), external_ref())
                .with_accountable_principal_ids(vec![principal("owner")]);

        let profile = request.to_definition().unwrap();

        assert_eq!(profile.actor_kind, ActorKind::Integration);
        assert_eq!(
            profile.profile_fields["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
    }

    #[test]
    fn request_builds_profile_create_intent() {
        let request =
            GhostActorProfileRequest::new(principal("ghost"), "Ghost", applet_id(), external_ref())
                .with_accountable_principal_ids(vec![principal("owner")]);
        let intent = request
            .profile_create_intent(
                ScopeRef::Realm {
                    realm_id: RealmId::new("ak:realm:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM")
                        .unwrap(),
                },
                arkret_wire::ActorId::service(principal("ghost")),
                "2026-05-26T10:30:00.000Z".parse().unwrap(),
                None,
            )
            .unwrap();

        assert_eq!(intent.kind(), &EventKind::ProfileCreate);
        assert_eq!(
            intent.payload()["object"]["profile_fields"]["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
    }

    #[test]
    fn request_round_trips_without_reducer_members() {
        let request =
            GhostActorProfileRequest::new(principal("ghost"), "Ghost", applet_id(), external_ref());
        let serialized = serde_json::to_value(&request).unwrap();
        for member in ["realm_id", "created_at", "updated_by", "updated_at"] {
            assert!(!serialized.as_object().unwrap().contains_key(member));
        }
        let restored: GhostActorProfileRequest = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored, request);
    }
}
