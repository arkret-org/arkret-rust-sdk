// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/blob-operations.schema.json
// sha256=22ea9fba9b25f14681d440a87a556beed4b74611057513e66a5178d01fdfa094
//
// Bindings: tools/closed-model-bindings.json
// sha256=7d1fdb47ec4baf0bbf7ecbf1969f8fff785140d5d15b0d6fadc690db7bbd4a62

/// Counterpart: `blob-operations.schema.json#/$defs/signature`.
/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/upload_receipt`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureValue {
    pub kid: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
}
