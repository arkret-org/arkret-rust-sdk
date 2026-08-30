//! Ghost Actor profile drafting and Event materialization.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
use arkret_models_identity::ActorProfile;
use arkret_models_integration::{
    AppletDelegatedEventAuthorization, GhostActorProfileFields, GhostExternalTuple,
};
use arkret_wire::{ActorKind, AppletId, BlobRef, DidCoreId, RealmId, SchemaId, ScopeRef};
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<arkret_wire::ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
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
            realm_id: None,
            principal_id,
            actor_kind: ActorKind::Integration,
            display_name: display_name.into(),
            handle: None,
            avatar_blob_ref: None,
            accountable_principal_ids: Vec::new(),
            profile_fields: GhostActorProfileFields::new(managed_by_applet, external_ref),
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

    pub fn to_actor_profile(&self) -> Result<ActorProfile> {
        self.validate()?;
        let mut profile_fields = BTreeMap::from([(
            "managed_by_applet".to_owned(),
            Value::String(self.profile_fields.managed_by_applet.to_string()),
        )]);
        profile_fields.insert(
            "external_ref".to_owned(),
            serde_json::to_value(&self.profile_fields.external_ref)?,
        );
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

    pub fn profile_create_intent(
        &self,
        scope_ref: ScopeRef,
        actor_id: arkret_wire::ActorId,
        created_at: DateTime<Utc>,
        authorization: Option<&AppletDelegatedEventAuthorization>,
    ) -> Result<crate::EventIntent> {
        let payload = ActorProfileCreatePayload {
            object: self.to_actor_profile()?,
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
    use arkret_wire::{ActorKind, EventKind};

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

        let profile = request.to_actor_profile().unwrap();

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
    fn request_omitted_updated_at_round_trip() {
        let mut request =
            GhostActorProfileRequest::new(principal("ghost"), "Ghost", applet_id(), external_ref());
        // Canonical timestamps carry millisecond precision; pin created_at so the
        // round-trip comparison is not foiled by sub-millisecond clock digits.
        request.created_at = "2026-08-18T00:00:00.000Z".parse().unwrap();

        let serialized = serde_json::to_value(&request).unwrap();
        assert!(!serialized.as_object().unwrap().contains_key("updated_at"));

        let restored: GhostActorProfileRequest = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored, request);
    }
}
