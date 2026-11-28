// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mls-roster-authority.schema.json
// sha256=dee63e65a130d3197a1eae05184a89637332e74a32b63bdad23c9e44f3f37981
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `mls-roster-authority.schema.json#/$defs/roster_recovery_signing_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterRecoverySigningKey {
    pub record_digest: Hash,
    pub public_key_base64url: Base64UrlString,
}
