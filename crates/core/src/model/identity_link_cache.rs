//! Identity-link cache projection helpers.

use super::*;
/// Compute the canonical-JSON SHA-256 of the four policy-frontier fields
/// that gate identity link routing. Round R2/R3.
///
/// Used by `IdentityLinkCacheEntry.policy_frontier_digest` to invalidate
/// cached identity-link routing decisions when any of these four governance
/// inputs change. Canonicalisation per RFC 8785 JCS over the JSON object
/// `{disclosure_policy, history_visibility, identity_disclosure_profile,
/// minimal_metadata_mode}`.
pub fn compute_policy_frontier_digest(
    disclosure_policy: &Value,

    history_visibility: &Value,

    identity_disclosure_profile: &Value,

    minimal_metadata_mode: &Value,
) -> Result<[u8; 32]> {
    let canonical = canonical::canonical_json_bytes(&serde_json::json!({

        "disclosure_policy": disclosure_policy,

        "history_visibility": history_visibility,

        "identity_disclosure_profile": identity_disclosure_profile,

        "minimal_metadata_mode": minimal_metadata_mode,

    }))?;

    let digest = Sha256::digest(&canonical);

    Ok(digest.into())
}
/// Cached projection of an identity-link routing decision.
///
/// Round R2/R3 — adds `policy_frontier_digest` so consumers can detect
/// when the four governance inputs (`disclosure_policy`,
/// `history_visibility`, `identity_disclosure_profile`,
/// `minimal_metadata_mode`) have shifted at the policy frontier and the
/// cached link must be re-derived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLinkCacheEntry {
    pub pairwise_did: Did,

    pub principal_id: Did,

    pub device_id: DeviceId,

    pub realm_id: RealmId,

    pub mls_epoch: u64,
    /// SHA-256 of canonical JSON over the four policy-frontier inputs.
    /// See [`compute_policy_frontier_digest`].
    #[serde(with = "serde_bytes_32_hex")]
    pub policy_frontier_digest: [u8; 32],

    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

mod serde_bytes_32_hex {

    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();

        hex.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;

        if s.len() != 64 {
            return Err(D::Error::custom("policy_frontier_digest hex must be 64 chars"));
        }

        let mut out = [0u8; 32];

        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(D::Error::custom)?;

            out[i] = u8::from_str_radix(pair, 16).map_err(D::Error::custom)?;
        }

        Ok(out)
    }
}
