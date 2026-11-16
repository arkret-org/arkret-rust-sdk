// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mls-roster-authority.schema.json
// sha256=604f3952669062046a31da0efbf09a9d6ce3ff089e909eadb2f68044a7ea8ea4
//
// Bindings: tools/closed-model-bindings.json
// sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

/// Counterpart: `mls-roster-authority.schema.json#/$defs/roster_recovery_signing_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterRecoverySigningKey {
    pub record_digest: Hash,
    pub public_key_base64url: Base64UrlString,
}
