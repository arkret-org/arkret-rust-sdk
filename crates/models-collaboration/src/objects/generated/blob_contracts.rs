// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/blob-operations.schema.json
// sha256=22b779f50a4244645e0612c92ca7dece6ceb7df005f32fa36391c12d47664955
//
// Bindings: tools/closed-model-bindings.json
// sha256=a09494f9b20fd0b06cee86eb504c26b02dab5a7b147a7e5a1034a07d05811aef

/// Counterpart: `blob-operations.schema.json#/$defs/signature`.
/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/upload_receipt`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureValue {
    pub kid: DidUrl,
    pub signature_algorithm: String,
    pub sig: String,
}
