//! Closed HandleClaim core, revocation and signed status-view wire models.

use arkret_wire::{
    AccountId, Audience, DidCoreId, DidUrl, EventId, Hash, PayloadProof, PayloadProofPurpose,
    Result, SchemaId, WireError,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::handle::{Handle, HandleVisibility};

pub const HANDLE_CLAIM_CORE_SCHEMA: &str = "ak.schema.handle_claim_core.v1";
pub const HANDLE_CLAIM_REVOCATION_SCHEMA: &str = "ak.schema.handle_claim_revocation.v1";
pub const HANDLE_CLAIM_PROOF_DOMAIN: &str = "ak.handle_claim_proof.v1";
pub const HANDLE_CLAIM_STATUS_DOMAIN: &str = "ak.handle_claim_status.v1";
pub const HANDLE_CLAIM_REVOCATION_DOMAIN: &str = "ak.handle_claim_revocation.v1";
pub const HANDLE_CLAIM_STATUS_MAX_FRESHNESS_SECONDS: i64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandleClaimVariant {
    HandleBinding,
    OrganizationHandle { organization_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleClaimStatus {
    Pending,
    Verified,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandleClaimRevoker {
    Issuer { issuer_id: DidCoreId },
    Holder { subject_account_id: AccountId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleClaimCore {
    pub schema: String,
    pub handle: Handle,
    pub handle_aliases: Vec<String>,
    pub subject_account_id: AccountId,
    pub issuer_id: DidCoreId,
    pub claim: HandleClaimVariant,
    pub visibility: HandleVisibility,
    pub audience: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub source_refs: Vec<EventId>,
    pub proofs: [PayloadProof; 2],
}

#[derive(Serialize)]
struct HandleClaimCoreDigestInput<'a> {
    schema: &'a str,
    handle: &'a Handle,
    handle_aliases: &'a [String],
    subject_account_id: &'a AccountId,
    issuer_id: &'a DidCoreId,
    claim: &'a HandleClaimVariant,
    visibility: HandleVisibility,
    audience: &'a Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    expires_at: &'a Option<DateTime<Utc>>,
    source_refs: &'a [EventId],
}

impl HandleClaimCore {
    pub const SCHEMA: &'static str = HANDLE_CLAIM_CORE_SCHEMA;

    pub fn claim_digest(&self) -> Result<Hash> {
        domain_separated_digest(
            b"ak.handle_claim_proof.v1\n",
            &HandleClaimCoreDigestInput {
                schema: &self.schema,
                handle: &self.handle,
                handle_aliases: &self.handle_aliases,
                subject_account_id: &self.subject_account_id,
                issuer_id: &self.issuer_id,
                claim: &self.claim,
                visibility: self.visibility,
                audience: &self.audience,
                issued_at: self.issued_at,
                expires_at: &self.expires_at,
                source_refs: &self.source_refs,
            },
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.subject_account_id.validate()?;
        if self.schema != Self::SCHEMA {
            return Err(protocol("handle claim core schema mismatch"));
        }
        if matches!(self.claim, HandleClaimVariant::OrganizationHandle { ref organization_id } if organization_id.is_empty())
        {
            return Err(protocol("organization handle requires organization_id"));
        }
        if (self.visibility == HandleVisibility::Public) != self.audience.is_none()
            || self.audience.as_ref().is_some_and(String::is_empty)
        {
            return Err(protocol("handle claim visibility/audience mismatch"));
        }
        if self
            .expires_at
            .is_some_and(|expires| expires <= self.issued_at)
        {
            return Err(protocol("handle claim expiry must follow issuance"));
        }
        validate_sorted_unique(&self.handle_aliases, "handle_aliases")?;
        validate_sorted_unique(&self.source_refs, "source_refs")?;
        let digest = self.claim_digest()?;
        validate_proof(
            &self.proofs[0],
            HANDLE_CLAIM_PROOF_DOMAIN,
            PayloadProofPurpose::IssuerAttestation,
            &digest,
        )?;
        validate_proof(
            &self.proofs[1],
            HANDLE_CLAIM_PROOF_DOMAIN,
            PayloadProofPurpose::HolderAcceptance,
            &digest,
        )?;
        if self.proofs.iter().any(|proof| {
            proof.created_at < self.issued_at
                || self
                    .expires_at
                    .is_some_and(|expires| proof.created_at >= expires)
        }) {
            return Err(protocol("handle claim proof is outside core validity"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleClaimRevocation {
    pub schema: String,
    pub claim_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub revoker: HandleClaimRevoker,
    pub proof: PayloadProof,
}

#[derive(Serialize)]
struct HandleClaimRevocationDigestInput<'a> {
    schema: &'a str,
    claim_digest: &'a Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    revoked_at: DateTime<Utc>,
    revoker: &'a HandleClaimRevoker,
}

impl HandleClaimRevocation {
    pub const SCHEMA: &'static str = HANDLE_CLAIM_REVOCATION_SCHEMA;

    pub fn digest(&self) -> Result<Hash> {
        domain_separated_digest(
            b"ak.handle_claim_revocation.v1\n",
            &HandleClaimRevocationDigestInput {
                schema: &self.schema,
                claim_digest: &self.claim_digest,
                revoked_at: self.revoked_at,
                revoker: &self.revoker,
            },
        )
    }

    fn validate_for(&self, core: &HandleClaimCore, now: DateTime<Utc>) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.claim_digest != core.claim_digest()?
            || self.revoked_at < core.issued_at
            || self.revoked_at > now
        {
            return Err(protocol("handle claim revocation binding mismatch"));
        }
        match &self.revoker {
            HandleClaimRevoker::Issuer { issuer_id } if issuer_id == &core.issuer_id => {}
            HandleClaimRevoker::Holder { subject_account_id }
                if subject_account_id == &core.subject_account_id => {}
            _ => return Err(protocol("handle claim revoker role/id mismatch")),
        }
        validate_proof(
            &self.proof,
            HANDLE_CLAIM_REVOCATION_DOMAIN,
            PayloadProofPurpose::RevocationAuthorization,
            &self.digest()?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleClaim {
    pub schema: String,
    pub claim: HandleClaimCore,
    pub status: HandleClaimStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    pub verifier_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub verified_at: Option<DateTime<Utc>>,
    pub revocation: Option<HandleClaimRevocation>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fresh_until: DateTime<Utc>,
    pub status_proof: PayloadProof,
}

/// The status transcript is the canonical status view with `status_proof`
/// removed, member for member (`zh/identity/identity-handles.md` §3.2). The two
/// derived digests are deliberately absent from both the wire shape and this
/// preimage: a verifier recomputes them from `claim` / `revocation`, and
/// putting them back here would restore exactly the mirror the schema deleted.
#[derive(Serialize)]
struct HandleClaimStatusDigestInput<'a> {
    schema: &'a str,
    claim: &'a HandleClaimCore,
    status: HandleClaimStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    as_of: DateTime<Utc>,
    verifier_id: &'a DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    verified_at: &'a Option<DateTime<Utc>>,
    revocation: &'a Option<HandleClaimRevocation>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    fresh_until: DateTime<Utc>,
}

impl HandleClaim {
    pub const SCHEMA: &'static str = SchemaId::HANDLE_CLAIM_V1;

    pub fn status_digest(&self) -> Result<Hash> {
        domain_separated_digest(
            b"ak.handle_claim_status.v1\n",
            &HandleClaimStatusDigestInput {
                schema: &self.schema,
                claim: &self.claim,
                status: self.status,
                as_of: self.as_of,
                verifier_id: &self.verifier_id,
                verified_at: &self.verified_at,
                revocation: &self.revocation,
                fresh_until: self.fresh_until,
            },
        )
    }

    /// Derived from the carried `claim`; the status view never ships it
    /// (`zh/identity/identity-handles.md` §3.2).
    pub fn claim_digest(&self) -> Result<Hash> {
        self.claim.claim_digest()
    }

    pub fn validate(&self) -> Result<()> {
        self.claim.validate()?;
        if self.schema != Self::SCHEMA {
            return Err(protocol("handle claim status schema mismatch"));
        }
        if self.fresh_until <= self.as_of
            || self.fresh_until
                > self.as_of + Duration::seconds(HANDLE_CLAIM_STATUS_MAX_FRESHNESS_SECONDS)
            || self
                .claim
                .expires_at
                .is_some_and(|expires| self.fresh_until > expires)
        {
            return Err(protocol("handle claim status freshness is invalid"));
        }
        match self.status {
            HandleClaimStatus::Pending => {
                if self.verified_at.is_some() || self.revocation.is_some() {
                    return Err(protocol("pending handle claim status fields are invalid"));
                }
            }
            HandleClaimStatus::Verified => {
                if self
                    .verified_at
                    .is_none_or(|verified| verified < self.claim.issued_at || verified > self.as_of)
                    || self.revocation.is_some()
                {
                    return Err(protocol("verified handle claim status fields are invalid"));
                }
            }
            HandleClaimStatus::Revoked => {
                let revocation = self
                    .revocation
                    .as_ref()
                    .ok_or_else(|| protocol("revoked handle claim is missing carrier"))?;
                revocation.validate_for(&self.claim, self.as_of)?;
            }
        }
        validate_proof(
            &self.status_proof,
            HANDLE_CLAIM_STATUS_DOMAIN,
            PayloadProofPurpose::StatusAttestation,
            &self.status_digest()?,
        )
    }

    pub fn validate_remote_resolution(
        &self,
        expected_audience: Option<&str>,
        expected_account_id: Option<&AccountId>,
        trusted_verifier_ids: &[DidCoreId],
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if self.status != HandleClaimStatus::Verified
            || now < self.as_of
            || now >= self.fresh_until
            || self.claim.expires_at.is_some_and(|expires| expires <= now)
        {
            return Err(protocol("handle claim is not currently verified and fresh"));
        }
        if !trusted_verifier_ids
            .iter()
            .any(|id| id == &self.verifier_id)
        {
            return Err(protocol("handle claim verifier is not trusted"));
        }
        if expected_audience != self.claim.audience.as_deref() && self.claim.audience.is_some() {
            return Err(protocol("handle claim audience mismatch"));
        }
        if expected_account_id.is_some_and(|expected| expected != &self.claim.subject_account_id) {
            return Err(protocol("handle claim account id mismatch"));
        }
        Ok(())
    }

    pub fn handle_canonical(&self) -> Option<&str> {
        Some(self.claim.handle.canonical())
    }
}

fn validate_proof(
    proof: &PayloadProof,
    domain: &str,
    purpose: PayloadProofPurpose,
    digest: &Hash,
) -> Result<()> {
    proof.validate()?;
    if proof.domain.as_deref() != Some(domain)
        || proof.proof_purpose.as_ref() != Some(&purpose)
        || &proof.payload_digest != digest
    {
        return Err(protocol("handle claim proof transcript mismatch"));
    }
    Ok(())
}

#[derive(Serialize)]
struct HandleClaimProofSigningInput<'a> {
    kind: &'a str,
    verification_method: &'a DidUrl,
    payload_digest: &'a Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    created_at: DateTime<Utc>,
    domain: &'a Option<String>,
    audience: &'a Option<Audience>,
    proof_purpose: &'a Option<PayloadProofPurpose>,
}

/// Exact detached-JWS transcript shared by HandleClaim core, status and
/// revocation proofs. The JWS covers all proof role/binding metadata as well
/// as the domain-separated payload digest.
pub fn handle_claim_proof_signing_bytes(proof: &PayloadProof) -> Result<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(&HandleClaimProofSigningInput {
        kind: &proof.kind,
        verification_method: &proof.verification_method,
        payload_digest: &proof.payload_digest,
        created_at: proof.created_at,
        domain: &proof.domain,
        audience: &proof.audience,
        proof_purpose: &proof.proof_purpose,
    })
    .map_err(|error| protocol(error.to_string()))
}

fn validate_sorted_unique<T: Ord>(values: &[T], field: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(protocol(format!(
            "handle claim {field} is not sorted and unique"
        )));
    }
    Ok(())
}

fn domain_separated_digest(domain: &[u8], value: &impl Serialize) -> Result<Hash> {
    let canonical = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| protocol(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(preimage)).map_err(Into::into)
}

fn protocol(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}
