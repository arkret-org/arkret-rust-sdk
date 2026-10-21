// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-authority-material.schema.json
// sha256=f8400dece56a5000e75825d2222eddfcedfe31a265b43e7fe1fc823e7f888bc2
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

/// Counterpart: `applet-authority-material.schema.json#/$defs/request`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthorityMaterialRequestBody {
    pub effective_scope: arkret_wire::ScopeRef,
    pub grant_ids: Vec<arkret_wire::GrantId>,
}

/// Counterpart: `applet-authority-material.schema.json#/$defs/outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthorityMaterialOutcome {
    pub applet_id: arkret_wire::AppletId,
    pub effective_scope: arkret_wire::ScopeRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration: AppletCommittedEvent,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub grant_events: Vec<AppletCommittedEvent>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    #[serde(
        deserialize_with = "deserialize_present_current_results",
        serialize_with = "serialize_present_current_results"
    )]
    pub current_results: Vec<ExactCurrentResultsReadOutcome>,
    pub current_binding: AppletInstallationCurrentBinding,
}
