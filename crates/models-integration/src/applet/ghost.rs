use arkret_wire::{ActorId, AppletId, AuthorizationRef, DidCoreId, Result, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::AppletManagedActorAuthoringRequest;

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
    pub effective_scope: ScopeRef,
    pub external_ref: GhostExternalTuple,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostPreviewResponseBody {
    pub authoring_request: AppletManagedActorAuthoringRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_managed_actor: Option<ExistingManagedActor>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingManagedActor {
    pub ghost_actor_id: ActorId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub creation_ref: arkret_wire::CommittedEventRef,
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
    /// Extract only the reserved identity members from an independently
    /// validated extensible ActorProfile. Other display/interaction members
    /// are not part of this closed identity carrier.
    pub fn from_profile_fields(
        fields: &std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self> {
        Ok(serde_json::from_value(serde_json::json!({
            "managed_by_applet":fields.get("managed_by_applet"),
            "external_ref":fields.get("external_ref"),
        }))?)
    }

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
    fn reserved_ghost_identity_allows_other_profile_members_without_widening_its_carrier() {
        let fields = std::collections::BTreeMap::from([
            (
                "managed_by_applet".into(),
                serde_json::json!("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa"),
            ),
            (
                "external_ref".into(),
                serde_json::json!({"protocol":"slack","instance_id":"tenant","external_id":"user"}),
            ),
            ("biography".into(), serde_json::json!("Display biography")),
            (
                "applet_interaction".into(),
                serde_json::json!({"mode":"private","effective_scope":{"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"}}),
            ),
        ]);
        let identity = GhostActorProfileFields::from_profile_fields(&fields).unwrap();
        assert_eq!(identity.external_ref.external_id, "user");
        assert!(
            serde_json::from_value::<GhostActorProfileFields>(
                serde_json::to_value(&fields).unwrap()
            )
            .is_err()
        );
        let mut missing = fields.clone();
        missing.remove("external_ref");
        assert!(GhostActorProfileFields::from_profile_fields(&missing).is_err());
        let mut changed = fields;
        changed.insert("external_ref".into(),serde_json::json!({"protocol":"slack","instance_id":"tenant","external_id":"user","other":"hidden"}));
        assert!(GhostActorProfileFields::from_profile_fields(&changed).is_err());
    }

    #[test]
    fn ghost_preview_request_is_closed() {
        let value = serde_json::json!({
            "effective_scope": { "kind":"realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19" },
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
