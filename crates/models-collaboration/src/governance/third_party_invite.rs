//! Third-party invite wire payloads.

use arkret_wire::{DidCoreId, Error, Hash, Result};
use serde::{Deserialize, Serialize};

// ── ThirdPartyInvite (3PID) ─────────────────────────────────────────────
/// Round 4 — discriminator for the 3PID invite OOB mode.
///
/// `ak.schema.invite.v1` carries a `oneOf` of:
/// - `offline_token`: token_commitment + token_salt_id + token_entropy_bits (>= 128).
/// - `lookup`: lookup_table_ref + pepper_id, rate-limited (3 errors invalidates the entry).
///
/// The plaintext 3PID (email / SMS) MUST NEVER appear on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteOobKind {
    OfflineToken,

    Lookup,
}
/// Round 4 — `ak.schema.invite.v1` third_party_invite (3PID) carrier.
///
/// Two-mode `oneOf`:
/// - `offline_token` requires `token_commitment` + `token_salt_id` + `token_entropy_bits >= 128`.
/// - `lookup` requires `lookup_table_ref` + `pepper_id`.
///
/// Both modes ALWAYS carry `max_claims`,
/// `verification_service_id`, and `verification_public_key`. Internal
/// verifier chain (`verification_service_id` chain of trust + replay
/// guard against `pepper_id` reuse) is handled by verifier/reducer layers;
/// the SDK model carries the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInvite {
    pub oob_code_kind: ThirdPartyInviteOobKind,
    /// Optional non-identifying UI hint; never a plaintext email or phone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_hint: Option<String>,
    /// `offline_token` mode — SHA-256 of `token | salt[salt_id]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_commitment: Option<Hash>,
    /// `offline_token` mode — opaque salt id, MUST be rotated per token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_salt_id: Option<String>,
    /// `offline_token` mode — claimed entropy. MUST be >= 128.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_entropy_bits: Option<u32>,
    /// `lookup` mode — opaque reference to the auth-server-side lookup
    /// table holding the (peppered) 3PID hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_table_ref: Option<String>,
    /// `lookup` mode — opaque pepper id; rotate after 3 verification
    /// failures (`invalidated_by_rate_limit` terminal state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pepper_id: Option<String>,
    /// Maximum claim attempts before terminal `invalidated_by_rate_limit`.
    #[serde(default = "single_claim")]
    pub max_claims: u32,
    /// DID of the auth server expected to verify the OOB code.
    pub verification_service_id: DidCoreId,
    /// Verifying public key for the verification proof chain.
    pub verification_public_key: String,
}

impl ThirdPartyInvite {
    /// Reject envelopes whose `oob_code_kind` is incompatible with the
    /// populated fields. Round 4 (spec a77b995 §third_party_invite).
    pub fn validate_minimal(&self) -> Result<()> {
        if self.max_claims != 1
            || self
                .display_name_hint
                .as_ref()
                .is_some_and(|hint| hint.len() > 128)
            || self.verification_public_key.is_empty()
        {
            return Err(Error::Protocol(
                "third_party_invite requires max_claims=1, a non-empty verification key, and display_name_hint<=128 bytes"
                    .to_owned(),
            ));
        }
        match self.oob_code_kind {
            ThirdPartyInviteOobKind::OfflineToken => {
                if self.token_commitment.is_none()
                    || self.token_salt_id.is_none()
                    || self.token_entropy_bits.is_none()
                {
                    return Err(Error::Protocol(
                        "third_party_invite offline_token mode requires token_commitment + token_salt_id + token_entropy_bits"
                            .to_owned(),
                    ));
                }

                if self.token_entropy_bits.is_some_and(|bits| bits < 128) {
                    return Err(Error::Protocol(
                        "third_party_invite offline_token token_entropy_bits MUST be >= 128"
                            .to_owned(),
                    ));
                }

                if self.lookup_table_ref.is_some() || self.pepper_id.is_some() {
                    return Err(Error::Protocol(
                        "third_party_invite offline_token mode must NOT set lookup fields"
                            .to_owned(),
                    ));
                }
            }

            ThirdPartyInviteOobKind::Lookup => {
                if self.lookup_table_ref.is_none() || self.pepper_id.is_none() {
                    return Err(Error::Protocol(
                        "third_party_invite lookup mode requires lookup_table_ref + pepper_id"
                            .to_owned(),
                    ));
                }

                if self.token_commitment.is_some()
                    || self.token_salt_id.is_some()
                    || self.token_entropy_bits.is_some()
                {
                    return Err(Error::Protocol(
                        "third_party_invite lookup mode must NOT set offline_token fields"
                            .to_owned(),
                    ));
                }
            }
        }

        Ok(())
    }
}

const fn single_claim() -> u32 {
    1
}
