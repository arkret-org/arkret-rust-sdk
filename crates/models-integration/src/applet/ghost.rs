use std::collections::BTreeMap;

use arkret_wire::{AppletId, AuthorizationRef, DidCoreId, Event, RealmId, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts_applet::ExternalRef;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum GhostActorProvisionRequestSchema {
    #[serde(rename = "ak.applet.ghost_actor.provision_request.v1")]
    V1,
}

/// `POST /_arkret/self/applets/{applet_id}/ghosts/provision` request body.
///
/// An Applet service / bridge asks the Principal Server to provision (or
/// re-validate) an Applet-managed Ghost Actor profile plus accountability
/// grant for one external user. The bridge supplies the two complete,
/// caller-signed Events; the Principal Server validates their exact business
/// binding and commits them as one atomic provisioning unit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GhostActorProvisionRequestBody {
    /// Always [`GhostActorProvisionRequestBody::SCHEMA`].
    pub schema: GhostActorProvisionRequestSchema,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub ghost_actor_id: DidCoreId,
    pub protocol: String,
    pub tenant: String,
    pub external_user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub realm_id: RealmId,
    pub external_ref: ExternalRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accountability_grant_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile_event: Event,
}

impl GhostActorProvisionRequestBody {
    /// `schema` const of `applet-ghost-operations.schema.json`
    /// `#/$defs/ghost_actor_provision_request_body`. Fixed by the DTO schema rather than registered
    /// as a `schema-registry.json` row.
    pub const SCHEMA: GhostActorProvisionRequestSchema = GhostActorProvisionRequestSchema::V1;
    /// Build a request body with `schema` stamped and no `display_name`.
    /// Add a display name with [`with_display_name`](Self::with_display_name).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applet_id: AppletId,
        service_id: DidCoreId,
        ghost_actor_id: DidCoreId,
        protocol: impl Into<String>,
        tenant: impl Into<String>,
        external_user_id: impl Into<String>,
        realm_id: RealmId,
        external_ref: ExternalRef,
        accountability_grant_event: Event,
        profile_event: Event,
    ) -> Self {
        Self {
            schema: GhostActorProvisionRequestBody::SCHEMA,
            applet_id,
            service_id,
            ghost_actor_id,
            protocol: protocol.into(),
            tenant: tenant.into(),
            external_user_id: external_user_id.into(),
            display_name: None,
            realm_id,
            external_ref,
            accountability_grant_event,
            profile_event,
        }
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

/// `POST /_arkret/self/applets/{applet_id}/ghosts/provision` response.
///
/// Carries the durable refs the Principal Server atomically accepted. The
/// `authorization_ref` is the active Applet capability grant used by the
/// provisioning pair; an accountability grant records responsibility and is
/// never itself treated as authorization for later Ghost Actor actions.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GhostActorProvisionOutcome {
    pub ghost_actor_id: DidCoreId,
    pub profile_event_ref: String,
    pub accountability_grant_ref: String,
    pub authorization_ref: String,
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

    pub fn apply_to_event(&self, event: &mut Event) -> Result<()> {
        self.validate()?;
        event.executed_by = Some(self.executed_by.clone());
        event.authorization_ref = Some(self.authorization_ref.clone());
        event.applet_id = Some(self.applet_id.clone());
        Ok(())
    }
}

/// Typed `profile_fields` payload for an Applet-managed Ghost Actor.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    use arkret_wire::{Hlc, ScopeRef};

    use super::*;

    fn event(kind: &str, actor: &str, suffix: &str) -> Event {
        arkret_wire::test_support::raw_event(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            DidCoreId::new(actor.replace("did:", "ak:did_core:")).unwrap(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            0,
            Hlc::new(format!("019041000000-0000-{suffix}")).unwrap(),
            serde_json::json!({"object": {}}),
        )
        .unwrap()
    }

    #[test]
    fn applet_delegation_applies_all_signed_envelope_fields() {
        let mut event = arkret_wire::test_support::raw_event(
            "ak.profile.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            DidCoreId::new("ak:did_core:web:ghost.example").unwrap(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            Hlc::new("019041000000-0000-00000000").unwrap(),
            serde_json::json!({"object": {}}),
        )
        .unwrap();
        let authorization = AppletDelegatedEventAuthorization::new(
            DidCoreId::new("ak:did_core:web:applet.example").unwrap(),
            AuthorizationRef::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
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

    #[test]
    fn ghost_provision_request_carries_both_complete_events() {
        let accountability = event(
            "ak.identity.accountability_grant",
            "did:web:applet.example",
            "00000001",
        );
        let profile = event("ak.profile.create", "did:web:ghost.example", "00000002");
        let request = GhostActorProvisionRequestBody::new(
            AppletId::new("ak:applet:01904100-0000-7000-8000-000000000003").unwrap(),
            DidCoreId::new("ak:did_core:web:applet.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ghost.example").unwrap(),
            "slack",
            "tenant-1",
            "user-1",
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            serde_json::from_value(serde_json::json!({
                "protocol": "slack",
                "external_id": "user-1"
            }))
            .unwrap(),
            accountability.clone(),
            profile.clone(),
        );

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value["accountability_grant_event"]["event_id"],
            accountability.event_id.as_str()
        );
        assert_eq!(
            value["profile_event"]["event_id"],
            profile.event_id.as_str()
        );
        assert_eq!(
            serde_json::from_value::<GhostActorProvisionRequestBody>(value).unwrap(),
            request
        );
    }

    #[test]
    fn ghost_provision_request_rejects_missing_event_pair() {
        let value = serde_json::json!({
            "schema": GhostActorProvisionRequestBody::SCHEMA,
            "applet_id": "ak:applet:01904100-0000-7000-8000-000000000003",
            "service_id": "did:web:applet.example",
            "ghost_actor_id": "did:web:ghost.example",
            "protocol": "slack",
            "tenant": "tenant-1",
            "external_user_id": "user-1",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "external_ref": {
                "protocol": "slack",
                "external_id": "user-1"
            }
        });

        assert!(serde_json::from_value::<GhostActorProvisionRequestBody>(value).is_err());
    }
}
