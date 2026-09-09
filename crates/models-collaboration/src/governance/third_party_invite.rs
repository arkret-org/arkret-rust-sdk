//! Third-party invite wire payloads.

use arkret_wire::{AccountId, Did, DidCoreId, Hash, InviteId, RealmId, Result, WireError};
use serde::{Deserialize, Serialize};

use crate::governance::membership_invite::InviteClaimBindingProof;

/// Body of `ak.open.third_party_invite.command.present_token.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInvitePresentRequestBody {
    pub invite_token: String,
    pub realm_id: RealmId,
    pub subject_account_id: AccountId,
    pub subject_did: Did,
    pub claim_nonce: String,
}

impl ThirdPartyInvitePresentRequestBody {
    pub fn validate_minimal(&self) -> Result<()> {
        if !(6..=512).contains(&self.invite_token.len())
            || !self
                .invite_token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !(16..=128).contains(&self.claim_nonce.chars().count())
            || self.subject_account_id.principal_id
                != arkret_identifiers::project_did_to_core_id(&self.subject_did)?
        {
            return Err(WireError::Protocol(
                "invalid third-party invite presentation request".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Success body of `ak.open.third_party_invite.command.present_token.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInvitePresentOutcome {
    pub invite_id: InviteId,
    pub token_commitment: Hash,
    pub binding_proof: InviteClaimBindingProof,
}

// ── ThirdPartyInvite (3PID) ─────────────────────────────────────────────
/// Discriminator for the 3PID invite OOB mode.
///
/// `ak.schema.invite.v1` carries a `oneOf` of:
/// - `offline_token`: token_commitment + token_salt_id + token_entropy_bits (>= 128).
/// - `lookup`: token_commitment + lookup_table_ref + pepper_id, rate-limited (3 errors invalidates
///   the entry).
///
/// Plaintext 3PID (email / SMS) never appears in the public Event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteOobKind {
    OfflineToken,

    Lookup,
}
/// `ak.schema.invite.v1` third_party_invite (3PID) carrier.
///
/// Two-mode `oneOf`:
/// - `offline_token` requires `token_commitment` + `token_salt_id` + `token_entropy_bits >= 128`.
/// - `lookup` requires `token_commitment` + `lookup_table_ref` + `pepper_id`.
///
/// Both modes ALWAYS carry `max_claims`,
/// `verification_id`, and `verification_public_key`. Internal
/// verifier chain (`verification_id` chain of trust + replay
/// guard against `pepper_id` reuse) is handled by verifier/reducer layers;
/// the SDK model carries the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInvite {
    pub oob_code_kind: ThirdPartyInviteOobKind,
    /// Optional non-identifying UI hint; never a plaintext email or phone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_hint: Option<String>,
    /// Both modes: SHA-256 of the private salt followed by the raw token bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_commitment: Option<Hash>,
    /// `offline_token` mode — opaque salt id, MUST be rotated per token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_salt_id: Option<String>,
    /// `offline_token` mode — claimed entropy. MUST be >= 128.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_entropy_bits: Option<u32>,
    /// `lookup` mode — opaque reference to the verifier-side lookup
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
    /// Core identity of the verifier expected to verify the OOB code.
    pub verification_id: DidCoreId,
    /// Verifying public key for the verification proof chain.
    pub verification_public_key: String,
}

impl ThirdPartyInvite {
    /// Reject envelopes whose `oob_code_kind` is incompatible with the
    /// populated fields.
    pub fn validate_minimal(&self) -> Result<()> {
        if self.max_claims != 1
            || self
                .display_name_hint
                .as_ref()
                .is_some_and(|hint| hint.chars().count() > 128)
            || self.verification_public_key.is_empty()
            || self
                .token_commitment
                .as_ref()
                .is_none_or(|commitment| !commitment.as_str().starts_with("sha256:"))
            || [&self.token_salt_id, &self.pepper_id]
                .into_iter()
                .flatten()
                .any(|value| {
                    !(1..=128).contains(&value.chars().count()) || value.starts_with("ak:")
                })
            || self
                .lookup_table_ref
                .as_ref()
                .is_some_and(|value| !(1..=128).contains(&value.chars().count()))
        {
            return Err(WireError::Protocol(
                "third_party_invite requires max_claims=1, a SHA-256 commitment, a non-empty verification key, and bounded public fields"
                    .to_owned(),
            ));
        }
        match self.oob_code_kind {
            ThirdPartyInviteOobKind::OfflineToken => {
                if self.token_commitment.is_none()
                    || self.token_salt_id.is_none()
                    || self.token_entropy_bits.is_none()
                {
                    return Err(WireError::Protocol(
                        "third_party_invite offline_token mode requires token_commitment + token_salt_id + token_entropy_bits"
                            .to_owned(),
                    ));
                }

                if self.token_entropy_bits.is_some_and(|bits| bits < 128) {
                    return Err(WireError::Protocol(
                        "third_party_invite offline_token token_entropy_bits MUST be >= 128"
                            .to_owned(),
                    ));
                }

                if self.lookup_table_ref.is_some() || self.pepper_id.is_some() {
                    return Err(WireError::Protocol(
                        "third_party_invite offline_token mode must NOT set lookup fields"
                            .to_owned(),
                    ));
                }
            }

            ThirdPartyInviteOobKind::Lookup => {
                if self.token_commitment.is_none()
                    || self.lookup_table_ref.is_none()
                    || self.pepper_id.is_none()
                {
                    return Err(WireError::Protocol(
                        "third_party_invite lookup mode requires token_commitment + lookup_table_ref + pepper_id"
                            .to_owned(),
                    ));
                }

                if self.token_salt_id.is_some() || self.token_entropy_bits.is_some() {
                    return Err(WireError::Protocol(
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
