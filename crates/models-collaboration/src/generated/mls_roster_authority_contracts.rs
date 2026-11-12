// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mls-roster-authority.schema.json
// sha256=604f3952669062046a31da0efbf09a9d6ce3ff089e909eadb2f68044a7ea8ea4
//
// Bindings: tools/closed-model-bindings.json
// sha256=14d7f312a6557af02e4e1a8496c76be3e3c902a74c9d7d175190d30caaf07567

/// Counterpart: `mls-roster-authority.schema.json#/$defs/roster_recovery_signing_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsRosterRecoverySigningKey {
    pub record_digest: Hash,
    pub public_key_base64url: Base64UrlString,
}
