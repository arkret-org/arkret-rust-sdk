// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/identity-resolution.schema.json
// sha256=fc7a8a96b196876b8ff58ef3f414a046b7ffebdd8cc825008e916da5d759a9f0
//
// Bindings: tools/closed-model-bindings.json
// sha256=f8598148149e81024ca07d8b02d6f7c48f1dc0672c100b2e8e4103790a652e46

/// Counterpart: `identity-resolution.schema.json#/$defs/service_route_projection`.
/// Derived route projection of one verified service DID state.
///
/// This is the single Rust expression of
/// `identity-resolution.schema.json#/$defs/service_route_projection`
/// (`sync/service-surface.md` §2.6). It is produced either locally by
/// [`AuthenticatedServiceResolution::projection`] after method-native
/// verification, or handed over already verified inside an own-Station result
/// such as the media service binding. There is deliberately only one type: a
/// second "wire-only" copy would let a consumer accept a route the local
/// verifier would have rejected.
///
/// Every coordinate comes from the verified method-native state and its unique
/// `ArkretService` entry. The projection creates no signed address history and
/// carries no method evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceResolutionProjection {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub did: Did,
    pub method_history_head: String,
    pub version_id: String,
    pub resolution_event_ref: String,
    pub base_url: String,
}
