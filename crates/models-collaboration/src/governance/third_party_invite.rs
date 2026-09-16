//! Third-party invite wire payloads.

use std::fmt;

use arkret_wire::{
    AccountId, CommittedEventRef, Did, DidCoreId, Hash, InviteId, PayloadProof, ProofContextId,
    RealmId, RequestId, Result, ServiceOperationId, WireError,
};
use chrono::{DateTime, Utc};
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

// ── Private material lifecycle (third-party-invites.md §7) ──────────────
/// Registered prefix of the opaque verification-service provisioning handle.
pub const THIRD_PARTY_INVITE_PROVISIONING_ID_PREFIX: &str = "third_party_invite_provisioning:";

/// Freshness window of the inviter provisioning proof (§7.2).
pub const THIRD_PARTY_INVITE_PROOF_FRESHNESS_SECONDS: i64 = 300;

/// Opaque verification-service handle for one private provisioning record.
///
/// It is deliberately **not** an `ak:` typed id: it addresses service-private
/// state, never a protocol object. It must never be written into a durable
/// Realm Event, and it is neither invite permission nor activation authority.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ThirdPartyInviteProvisioningId(String);

impl ThirdPartyInviteProvisioningId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some(entropy) = value.strip_prefix(THIRD_PARTY_INVITE_PROVISIONING_ID_PREFIX) else {
            return Err(WireError::Protocol(
                "third-party invite provisioning id must carry its registered prefix".to_owned(),
            ));
        };
        if entropy.len() != 43
            || !entropy
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(WireError::Protocol(
                "third-party invite provisioning id must carry 256 bits of unpadded base64url"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ThirdPartyInviteProvisioningId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for ThirdPartyInviteProvisioningId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ThirdPartyInviteProvisioningId")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ThirdPartyInviteProvisioningId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Verification-service-private lifecycle of one provisioning record.
///
/// It is service-local state: never a Realm invite cell state, never a reducer
/// input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteProvisioningState {
    Provisioned,
    Activated,
    Consumed,
    Expired,
    Revoked,
}

/// Out-of-band delivery progress of an activated provisioning record.
///
/// `failed` reports only that the service exhausted its retry budget; the
/// Realm-visible transition still requires an authorized writer to submit
/// `ak.invite.revoke` with `target_state = send_failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteDeliveryState {
    NotStarted,
    Queued,
    Delivered,
    Failed,
}

/// Private out-of-band delivery target (RFC 6068 `mailto:` or RFC 3966 `tel:`).
///
/// It appears only in the provisioning request body. The verification service
/// must never echo it in a response, write it into a durable Event,
/// account-data cell, notification or ordinary log. `Debug` is redacted for
/// that reason, so a derived `Debug` on an enclosing body cannot leak a 3PID.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ThirdPartyInviteDeliveryTargetUri(String);

impl ThirdPartyInviteDeliveryTargetUri {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let scheme_len = if value.starts_with("mailto:") {
            "mailto:".len()
        } else if value.starts_with("tel:") {
            "tel:".len()
        } else {
            return Err(WireError::Protocol(
                "third-party invite delivery target must be a mailto: or tel: URI".to_owned(),
            ));
        };
        let body_len = value.len() - scheme_len;
        if value.len() > 1024
            || !(1..=1000).contains(&body_len)
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(WireError::Protocol(
                "third-party invite delivery target is out of bounds or not printable ASCII"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Deliberately consuming: the plaintext 3PID leaves this type only where a
    /// caller explicitly asks for it.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for ThirdPartyInviteDeliveryTargetUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ThirdPartyInviteDeliveryTargetUri(<redacted 3PID>)")
    }
}

impl<'de> Deserialize<'de> for ThirdPartyInviteDeliveryTargetUri {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Body of `ak.open.third_party_invite.command.provision.v1`
/// (`POST /_arkret/open/third-party-invites/provision`).
///
/// The inviter asks the verification service to mint the private token, salt or
/// pepper and per-invite ephemeral key, and to return only the public material.
/// A successful provisioning is neither invite permission, nor a pending Realm
/// Invite, nor authority to deliver anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteProvisionRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub inviter_account_id: AccountId,
    pub verification_id: DidCoreId,
    pub oob_code_kind: ThirdPartyInviteOobKind,
    pub delivery_target_uri: ThirdPartyInviteDeliveryTargetUri,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl ThirdPartyInviteProvisionRequestBody {
    /// `SHA-256(JCS(body without signature))`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let unsigned = arkret_canonical::canonical::unsigned_value(self, &["signature"])?;
        Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
            &unsigned,
        )?)?)
    }

    /// Canonical detached-JWS binding bytes of the inviter proof.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.signature.validate_production()?;
        self.unsigned_proof_binding_bytes(&self.signature.unsigned())
    }

    /// Construct the signing preimage before a signature exists.
    pub fn unsigned_proof_binding_bytes(
        &self,
        proof: &arkret_wire::UnsignedPayloadProof,
    ) -> Result<Vec<u8>> {
        arkret_wire::service_operation_proof_binding_bytes(
            ProofContextId::THIRD_PARTY_INVITE_PROVISION_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1,
            Some(serde_json::to_value(&self.inviter_account_id)?),
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }

    /// Structural checks a verification service runs before it mints anything.
    ///
    /// It proves the proof audience is this service and that the signer projects
    /// onto the claimed inviter principal. Whether the verification method is
    /// *currently* valid, and the one-time replay ledger, stay with the service.
    pub fn validate_for_service(&self, verification_id: &DidCoreId) -> Result<()> {
        self.inviter_account_id.validate()?;
        if &self.verification_id != verification_id {
            return Err(WireError::Protocol(
                "third-party invite provisioning request names another verification service"
                    .to_owned(),
            ));
        }
        validate_invite_proof_binding(
            &self.signature,
            verification_id,
            &self.payload_digest()?,
            &self.inviter_account_id.principal_id,
            "third-party invite provisioning proof",
        )
    }

    /// The registered `created_at` freshness window of this proof context.
    pub fn validate_proof_freshness(&self, now: DateTime<Utc>) -> Result<()> {
        let age = now.signed_duration_since(self.signature.created_at);
        if age < chrono::Duration::zero()
            || age > chrono::Duration::seconds(THIRD_PARTY_INVITE_PROOF_FRESHNESS_SECONDS)
        {
            return Err(WireError::Protocol(
                "third-party invite provisioning proof is outside its freshness window".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Shared audience / digest / signer checks of the two 3PID proof contexts.
fn validate_invite_proof_binding(
    signature: &PayloadProof,
    audience_id: &DidCoreId,
    expected_digest: &Hash,
    expected_signer: &DidCoreId,
    label: &str,
) -> Result<()> {
    signature.validate_production()?;
    let audience = signature
        .audience
        .as_ref()
        .ok_or_else(|| WireError::Protocol(format!("{label} requires an audience")))?;
    if *audience != arkret_wire::Audience::Single(audience_id.as_str().to_owned()) {
        return Err(WireError::Protocol(format!(
            "{label} audience is not the exact expected service"
        )));
    }
    if &signature.payload_digest != expected_digest {
        return Err(WireError::Protocol(format!(
            "{label} does not cover this object"
        )));
    }
    let controller = signature
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            WireError::Protocol(format!("{label} verification_method has no fragment"))
        })?;
    if arkret_identifiers::project_did_to_core_id(&Did::new(controller.to_owned())?)?
        != *expected_signer
    {
        return Err(WireError::Protocol(format!(
            "{label} signer does not project onto its declared issuer"
        )));
    }
    Ok(())
}

/// Success body of `ak.open.third_party_invite.command.provision.v1`.
///
/// It carries exactly the public material the inviter puts into
/// `ak.invite.third_party` plus the opaque handle that later binds the accepted
/// invite back to the private record. It never carries the raw token, salt,
/// pepper, ephemeral private key or delivery target, and it is never presented
/// to the invitee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteProvisionOutcome {
    pub provisioning_id: ThirdPartyInviteProvisioningId,
    pub realm_id: RealmId,
    pub inviter_account_id: AccountId,
    pub third_party_invite: ThirdPartyInvite,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub activation_expires_at: DateTime<Utc>,
}

impl ThirdPartyInviteProvisionOutcome {
    pub fn validate(&self) -> Result<()> {
        self.third_party_invite.validate_minimal()?;
        if self.activation_expires_at > self.expires_at {
            return Err(WireError::Protocol(
                "third-party invite activation window must not outlive the invite".to_owned(),
            ));
        }
        Ok(())
    }

    /// Bind the outcome to the exact request that minted it. The mode the
    /// caller asked for is never silently downgraded, and the effective expiry
    /// is only ever clamped down by the profile ceiling.
    pub fn validate_for_request(
        &self,
        request: &ThirdPartyInviteProvisionRequestBody,
    ) -> Result<()> {
        self.validate()?;
        if self.realm_id != request.realm_id
            || self.inviter_account_id != request.inviter_account_id
            || self.third_party_invite.oob_code_kind != request.oob_code_kind
            || self.third_party_invite.verification_id != request.verification_id
            || self.expires_at > request.expires_at
        {
            return Err(WireError::Protocol(
                "third-party invite provisioning outcome does not answer this request".to_owned(),
            ));
        }
        Ok(())
    }
}

/// There is no attestation shape for any invite state other than `pending`: a
/// non-pending invite yields no attestation at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteAttestedState {
    Pending,
}

/// Canonical `invite_digest` preimage of §4.2.
///
/// The four members are exactly what the acceptance attestation carries, so an
/// independent verification service recomputes the digest from committed
/// material instead of trusting a caller-reported value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ThirdPartyInviteDigestPreimage<'a> {
    pub invite_id: &'a InviteId,
    pub realm_id: &'a RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub third_party_invite: &'a ThirdPartyInvite,
}

impl ThirdPartyInviteDigestPreimage<'_> {
    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
            self,
        )?)?)
    }
}

/// Station-signed, purpose-scoped observation that one exact
/// `ak.invite.third_party` is accepted and still pending.
///
/// It is the only standard carrier that lets an independent verification
/// service activate its private record without holding Realm state. A
/// caller-reported invite id, invite digest, Event signature or HTTP success is
/// never accepted in its place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteAcceptanceAttestation {
    pub station_id: DidCoreId,
    pub verification_id: DidCoreId,
    pub realm_id: RealmId,
    pub invite_id: InviteId,
    pub inviter_account_id: AccountId,
    pub provisioning_id: ThirdPartyInviteProvisioningId,
    pub third_party_invite: ThirdPartyInvite,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub invite_expires_at: DateTime<Utc>,
    pub invite_state: ThirdPartyInviteAttestedState,
    pub accepted_commit_ref: CommittedEventRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl ThirdPartyInviteAcceptanceAttestation {
    /// `SHA-256(JCS(attestation without signature))`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let unsigned = arkret_canonical::canonical::unsigned_value(self, &["signature"])?;
        Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
            &unsigned,
        )?)?)
    }

    /// Canonical detached-JWS binding bytes of the issuing Station's proof.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.signature.validate_production()?;
        self.unsigned_proof_binding_bytes(&self.signature.unsigned())
    }

    /// Construct the signing preimage before a signature exists.
    pub fn unsigned_proof_binding_bytes(
        &self,
        proof: &arkret_wire::UnsignedPayloadProof,
    ) -> Result<Vec<u8>> {
        arkret_wire::service_operation_proof_binding_bytes(
            ProofContextId::THIRD_PARTY_INVITE_ACCEPTANCE_ATTESTATION_PROOF_V1,
            ServiceOperationId::SELF_THIRD_PARTY_INVITE_READ_ACCEPTANCE_ATTESTATION_V1,
            Some(serde_json::to_value(&self.station_id)?),
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }

    /// Recompute the §4.2 `invite_digest` from the committed invite material.
    ///
    /// `expires_at` in the preimage is the attestation's `invite_expires_at`,
    /// never the attestation's own validity end.
    pub fn invite_digest(&self) -> Result<Hash> {
        ThirdPartyInviteDigestPreimage {
            invite_id: &self.invite_id,
            realm_id: &self.realm_id,
            expires_at: self.invite_expires_at,
            third_party_invite: &self.third_party_invite,
        }
        .digest()
    }

    pub fn validate(&self) -> Result<()> {
        self.inviter_account_id.validate()?;
        self.third_party_invite.validate_minimal()?;
        if self.expires_at <= self.observed_at || self.expires_at > self.invite_expires_at {
            return Err(WireError::Protocol(
                "acceptance attestation window must be positive and within the invite lifetime"
                    .to_owned(),
            ));
        }
        validate_invite_proof_binding(
            &self.signature,
            &self.verification_id,
            &self.payload_digest()?,
            &self.station_id,
            "acceptance attestation proof",
        )
    }

    /// The freshness judgement an independent verification service can make
    /// without holding any Realm policy: the issuing Station already clamped
    /// `expires_at` to the Realm revocation freshness window.
    pub fn validate_freshness(&self, now: DateTime<Utc>) -> Result<()> {
        if now >= self.expires_at {
            return Err(WireError::Protocol(
                "acceptance attestation observation is stale".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Body of `ak.self.third_party_invite.read.acceptance_attestation.v1`
/// (`POST /_arkret/self/third-party-invites/acceptance-attestation`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteAcceptanceAttestationRequestBody {
    pub realm_id: RealmId,
    pub invite_id: InviteId,
    pub provisioning_id: ThirdPartyInviteProvisioningId,
    pub verification_id: DidCoreId,
}

/// Success body of `ak.self.third_party_invite.read.acceptance_attestation.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteAcceptanceAttestationOutcome {
    pub acceptance_attestation: ThirdPartyInviteAcceptanceAttestation,
}

impl ThirdPartyInviteAcceptanceAttestationOutcome {
    pub fn validate_for_request(
        &self,
        request: &ThirdPartyInviteAcceptanceAttestationRequestBody,
    ) -> Result<()> {
        let attestation = &self.acceptance_attestation;
        attestation.validate()?;
        if attestation.realm_id != request.realm_id
            || attestation.invite_id != request.invite_id
            || attestation.provisioning_id != request.provisioning_id
            || attestation.verification_id != request.verification_id
        {
            return Err(WireError::Protocol(
                "acceptance attestation does not answer the exact request".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Body of `ak.open.third_party_invite.command.activate.v1`
/// (`POST /_arkret/open/third-party-invites/activate`).
///
/// The attestation is the whole authorization: a bare invite id, a
/// caller-computed invite digest, or the service's own optimistic read of a
/// remote Realm is never accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteActivationRequestBody {
    pub provisioning_id: ThirdPartyInviteProvisioningId,
    pub acceptance_attestation: ThirdPartyInviteAcceptanceAttestation,
}

impl ThirdPartyInviteActivationRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.acceptance_attestation.validate()?;
        if self.provisioning_id != self.acceptance_attestation.provisioning_id {
            return Err(WireError::Protocol(
                "activation addresses another provisioning record than its attestation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Success body of `ak.open.third_party_invite.command.activate.v1`: the
/// immutable binding this activation established.
///
/// A byte-identical retry, a concurrent duplicate and a retry after a process
/// restart all return this same body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteActivationOutcome {
    pub provisioning_id: ThirdPartyInviteProvisioningId,
    pub realm_id: RealmId,
    pub invite_id: InviteId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub activated_at: DateTime<Utc>,
}

impl ThirdPartyInviteActivationOutcome {
    pub fn validate_for_request(
        &self,
        request: &ThirdPartyInviteActivationRequestBody,
    ) -> Result<()> {
        request.validate()?;
        let attestation = &request.acceptance_attestation;
        if self.provisioning_id != request.provisioning_id
            || self.realm_id != attestation.realm_id
            || self.invite_id != attestation.invite_id
        {
            return Err(WireError::Protocol(
                "activation outcome binds another provisioning record or invite".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Body of `ak.open.third_party_invite.read.provisioning_status.v1`
/// (`POST /_arkret/open/third-party-invites/status`).
///
/// `provisioning_id` is the whole query credential and travels only in this
/// JSON body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteProvisioningStatusRequestBody {
    pub provisioning_id: ThirdPartyInviteProvisioningId,
}

/// Lifecycle and delivery position of one provisioning record.
///
/// It is the recovery surface for a lost provisioning or activation response.
/// It never carries the raw token, salt, pepper, ephemeral private key,
/// delivery target or any 3PID-derived value, and never reveals whether the
/// invitee opened the invite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteProvisioningStatusOutcome {
    pub provisioning_id: ThirdPartyInviteProvisioningId,
    pub realm_id: RealmId,
    pub provisioning_state: ThirdPartyInviteProvisioningState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub activated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_state: Option<ThirdPartyInviteDeliveryState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_attempt_count: Option<u32>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub activation_expires_at: DateTime<Utc>,
}

impl ThirdPartyInviteProvisioningStatusOutcome {
    pub fn validate(&self) -> Result<()> {
        let bound = self.invite_id.is_some()
            || self.activated_at.is_some()
            || self.delivery_state.is_some()
            || self.delivery_attempt_count.is_some();
        let complete = self.invite_id.is_some()
            && self.activated_at.is_some()
            && self.delivery_state.is_some()
            && self.delivery_attempt_count.is_some();
        match self.provisioning_state {
            ThirdPartyInviteProvisioningState::Provisioned if bound => Err(WireError::Protocol(
                "an unbound provisioning record must not report an invite or a delivery position"
                    .to_owned(),
            )),
            ThirdPartyInviteProvisioningState::Activated
            | ThirdPartyInviteProvisioningState::Consumed
                if !complete =>
            {
                Err(WireError::Protocol(
                    "a bound provisioning record must report its invite and delivery position"
                        .to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Delivery is only permitted once the record is bound to an accepted
    /// invite (§7.6).
    #[must_use]
    pub fn may_deliver(&self) -> bool {
        self.provisioning_state == ThirdPartyInviteProvisioningState::Activated
    }
}
