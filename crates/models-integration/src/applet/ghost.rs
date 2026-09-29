use arkret_wire::{
    ActorId, AppletId, AuthorizationRef, DidCoreId, EventId, RealmId, Result,
};
use serde::{Deserialize, Serialize};

use crate::{AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest};

/// Immutable external identity tuple for one Applet-managed Ghost.
///
/// Display metadata and URLs are deliberately excluded: they may change and
/// therefore cannot participate in provisioning identity or idempotency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct GhostExternalTuple {
    pub protocol: String,
    pub instance_id: String,
    pub external_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct GhostPreviewRequestBody {
    pub realm_id: RealmId,
    pub external_ref: GhostExternalTuple,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostPreviewOutcome {
    pub authoring_request: AppletManagedActorAuthoringRequest,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProvisionRequestBody {
    pub authoring_request: AppletManagedActorAuthoringRequest,
    pub managed_actor_bundle: AppletManagedActorAuthoringBundle,
}

impl GhostActorProvisionRequestBody {
    pub fn authoring_basis(&self) -> Option<&crate::AppletGhostAuthoringRequestBasis> {
        self.authoring_request.basis.ghost()
    }

    pub fn managed_actor_provision_payload(
        &self,
    ) -> Result<crate::AppletManagedActorProvisionPayload> {
        serde_json::from_value(serde_json::to_value(
            &self
                .managed_actor_bundle
                .managed_actor_provision_event
                .payload,
        )?)
        .map_err(Into::into)
    }
}

/// `POST /_arkret/self/applets/{applet_id}/ghosts/provision` response.
///
/// Carries the durable refs the Station atomically accepted. The
/// `authorization_ref` is the active Applet capability grant used by the
/// provisioning unit; an accountability grant records responsibility and is
/// never itself treated as authorization for later Ghost Actor actions.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProvisionOutcome {
    pub ghost_actor_id: ActorId,
    pub managed_actor_provision_ref: EventId,
    pub principal_control_realm_id: RealmId,
    pub profile_event_ref: EventId,
    pub accountability_grant_ref: EventId,
    pub authorization_ref: arkret_wire::GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Applet delegation fields required when an applet or delegated agent signs
/// on behalf of another actor.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletDelegatedEventAuthorization {
    pub executed_by: DidCoreId,
    pub authorization_ref: AuthorizationRef,
    pub applet_id: AppletId,
}

impl AppletDelegatedEventAuthorization {
    pub fn new(
        executed_by: DidCoreId,
        authorization_ref: AuthorizationRef,
        applet_id: AppletId,
    ) -> Self {
        Self {
            executed_by,
            authorization_ref,
            applet_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Typed `profile_fields` payload for an Applet-managed Ghost Actor.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProfileFields {
    pub managed_by_applet: AppletId,
    pub external_ref: GhostExternalTuple,
}

impl GhostActorProfileFields {
    pub fn new(managed_by_applet: AppletId, external_ref: GhostExternalTuple) -> Self {
        Self {
            managed_by_applet,
            external_ref,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghost_preview_request_is_closed() {
        let value = serde_json::json!({
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "external_ref": {
                "protocol": "slack",
                "instance_id": "tenant-1",
                "external_id": "user-1"
            },
            "display_name": "Example Ghost"
        });
        let request: GhostPreviewRequestBody = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(request.external_ref.protocol, "slack");

        let mut unknown = value;
        unknown["unknown_actor_id"] = serde_json::json!("ak:did_core:web:ghost.example");
        assert!(serde_json::from_value::<GhostPreviewRequestBody>(unknown).is_err());
    }
}
