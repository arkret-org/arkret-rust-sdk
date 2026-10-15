// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/media-service-binding-result.schema.json
// sha256=a817ab2c547d0ddf1ad5884e5243e7250ce9de63b86f5cc9aef146b05f3d9cb0
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart: `media-service-binding-result.schema.json#/$defs/service_signing_key`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSigningKey {
    pub verification_method: DidUrl,
    pub public_key_b64u: String,
}

/// Counterpart:
/// `media-service-binding-result.schema.json#/$defs/media_service_binding_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaServiceBindingRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
}

/// Counterpart: `media-service-binding-result.schema.json#/$defs/media_service_binding_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaServiceBindingOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub route: ServiceResolutionProjection,
    pub signing_keys: Vec<ServiceSigningKey>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}
