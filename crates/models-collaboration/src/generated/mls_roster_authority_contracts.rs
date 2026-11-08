// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mls-roster-authority.schema.json
// sha256=604f3952669062046a31da0efbf09a9d6ce3ff089e909eadb2f68044a7ea8ea4
//
// Bindings: tools/closed-model-bindings.json
// sha256=f277aac30f4b23b2e663aeb5c59ddf9a6e2b3af9eb64854335f03d715718292a

/// Counterpart: `mls-roster-authority.schema.json#/$defs/roster_recovery_signing_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterRecoverySigningKey {
    pub record_digest: Hash,
    pub public_key_base64url: Base64UrlString,
}
