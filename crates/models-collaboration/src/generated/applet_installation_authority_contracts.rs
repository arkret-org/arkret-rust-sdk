// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-authority-material.schema.json
// sha256=5bb72c3387ae9b80e121b309ef918785949ec7fec69d14d064720dc7de976713
//
// Bindings: tools/closed-model-bindings.json
// sha256=dd0891cd81e0fc2caaf499fd178468a13da86ea101d8780b59ca3e5c661eeecd

/// Counterpart:
/// `applet-authority-material.schema.json#/$defs/applet_authority_material_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthorityMaterialRequestBody {
    pub effective_scope: arkret_wire::ScopeRef,
    pub grant_ids: Vec<arkret_wire::GrantId>,
}

/// Counterpart: `applet-authority-material.schema.json#/$defs/response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthorityMaterialResponseBody {
    pub applet_id: arkret_wire::AppletId,
    pub service_id: arkret_wire::DidCoreId,
    pub effective_scope: arkret_wire::ScopeRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration: AppletCommittedEvent,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub grant_events: Vec<AppletCommittedEvent>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    #[serde(
        deserialize_with = "deserialize_present_current_states",
        serialize_with = "serialize_present_current_states"
    )]
    pub current_states: Vec<ExactCurrentStateReadResponseBody>,
    pub current_binding: AppletInstallationCurrentBinding,
}
