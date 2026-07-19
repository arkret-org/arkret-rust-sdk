use std::collections::BTreeMap;

use arkret_wire::{AppletId, Did, Error, Event, RealmId, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts_applet::ExternalRef;

/// `POST /_arkret/self/applets/{applet_id}/ghosts/provision` request body.
///
/// An Applet service / bridge asks the Principal Server to provision (or
/// re-validate) an Applet-managed Ghost Actor profile plus accountability
/// grant for one external user. Built by the bridge side and parsed by the
/// authz service; the server still re-checks `applet_id`/`service_id`/
/// `realm_id` against the installed package before minting anything.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
        event.applet_id = Some(self.applet_id.clone());
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

#[cfg(test)]
mod tests {
    use arkret_wire::Hlc;

    use super::*;

    #[test]
    fn applet_delegation_applies_all_signed_envelope_fields() {
        let mut event = Event::new(
            "ak.profile.create",
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            Did::new("did:web:ghost.example").unwrap(),
            1,
            Hlc::new("019041000000-0000-00000000").unwrap(),
            serde_json::json!({"object": {}}),
        )
        .unwrap();
        let authorization = AppletDelegatedEventAuthorization::new(
            Did::new("did:web:applet.example").unwrap(),
            "ak:event:01904100-0000-7000-8000-000000000002",
            AppletId::new("ak:applet:01904100-0000-7000-8000-000000000003").unwrap(),
        );

        authorization.apply_to_event(&mut event).unwrap();

        assert_eq!(event.executed_by.as_ref(), Some(&authorization.executed_by));
        assert_eq!(
            event.authorization_ref.as_deref(),
            Some(authorization.authorization_ref.as_str())
        );
        assert_eq!(event.applet_id.as_ref(), Some(&authorization.applet_id));
    }
}
