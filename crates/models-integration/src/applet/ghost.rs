use arkret_wire::{AppletId, AuthorizationRef, DidCoreId, Event, EventId, RealmId, Result};
use serde::{Deserialize, Serialize};

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
/// grant for one external user. The bridge supplies the four complete,
/// caller-signed provision/PCR/accountability/profile Events; the Principal
/// Server validates their exact binding and commits one atomic unit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProvisionRequestBody {
    /// Always [`GhostActorProvisionRequestBody::SCHEMA`].
    pub schema: GhostActorProvisionRequestSchema,
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub ghost_actor_id: DidCoreId,
    pub actor_principal_server_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub realm_id: RealmId,
    pub external_ref: GhostExternalTuple,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub managed_actor_provision_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub pcr_genesis_event: Event,
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
        actor_principal_server_id: DidCoreId,
        realm_id: RealmId,
        external_ref: GhostExternalTuple,
        managed_actor_provision_event: Event,
        pcr_genesis_event: Event,
        accountability_grant_event: Event,
        profile_event: Event,
    ) -> Self {
        Self {
            schema: GhostActorProvisionRequestBody::SCHEMA,
            applet_id,
            service_id,
            ghost_actor_id,
            actor_principal_server_id,
            display_name: None,
            realm_id,
            external_ref,
            managed_actor_provision_event,
            pcr_genesis_event,
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
/// provisioning unit; an accountability grant records responsibility and is
/// never itself treated as authorization for later Ghost Actor actions.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorProvisionOutcome {
    pub ghost_actor_id: DidCoreId,
    pub actor_principal_server_id: DidCoreId,
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
    use arkret_wire::{Hlc, ScopeRef};

    use super::*;

    fn event(kind: &str, actor: &str, suffix: &str) -> Event {
        let scope_ref = if kind == "ak.realm.create" {
            ScopeRef::RealmGenesis
        } else {
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            }
        };
        arkret_wire::test_support::raw_event(
            kind,
            scope_ref,
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
        let provision = event(
            "ak.applet.managed_actor.provision",
            "did:web:applet.example",
            "00000003",
        );
        let genesis = event("ak.realm.create", "did:web:ghost.example", "00000004");
        let request = GhostActorProvisionRequestBody::new(
            AppletId::new("ak:applet:01904100-0000-7000-8000-000000000003").unwrap(),
            DidCoreId::new("ak:did_core:web:applet.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ghost.example").unwrap(),
            DidCoreId::new("ak:did_core:web:principal-server.example").unwrap(),
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            serde_json::from_value(serde_json::json!({
                "protocol": "slack",
                "instance_id": "tenant-1",
                "external_id": "user-1"
            }))
            .unwrap(),
            provision,
            genesis,
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
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "external_ref": {
                "protocol": "slack",
                "instance_id": "tenant-1",
                "external_id": "user-1"
            }
        });

        assert!(serde_json::from_value::<GhostActorProvisionRequestBody>(value).is_err());
    }
}
