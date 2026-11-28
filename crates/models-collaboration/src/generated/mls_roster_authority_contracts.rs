// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mls-roster-authority.schema.json
// sha256=dee63e65a130d3197a1eae05184a89637332e74a32b63bdad23c9e44f3f37981
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

/// Counterpart: `mls-roster-authority.schema.json#/$defs/roster_recovery_signing_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterRecoverySigningKey {
    pub record_digest: Hash,
    pub public_key_base64url: Base64UrlString,
}
