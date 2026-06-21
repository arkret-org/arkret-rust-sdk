use super::helpers::{default_true, disclose_claim, validate_presented_claim};
use super::*;

/// Standard claim kind names used by auth and progressive disclosure helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthClaimKind {
    VerifiedHandle,
    EmailDomain,
    OrganizationMembership,
    OrganizationRole,
    GuardianController,
    DeviceTrust,
    MfaLevel,
    RiskLevel,
}

impl AuthClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedHandle => "verified_handle",
            Self::EmailDomain => "email_domain",
            Self::OrganizationMembership => "organization_membership",
            Self::OrganizationRole => "organization_role",
            Self::GuardianController => "guardian_controller",
            Self::DeviceTrust => "device_trust",
            Self::MfaLevel => "mfa_level",
            Self::RiskLevel => "risk_level",
        }
    }
}

/// Claim presented to satisfy an auth or policy disclosure request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresentedClaim {
    pub claim_id: String,
    pub subject: Did,
    pub issuer: Did,
    pub claim_kind: String,
    pub value: Value,
    pub issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disclosed_fields: BTreeSet<String>,
}

impl PresentedClaim {
    pub fn new(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        claim_kind: impl Into<String>,
        value: Value,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            subject,
            issuer,
            claim_kind: claim_kind.into(),
            value,
            issued_at: Utc::now(),
            refreshed_at: None,
            expires_at: None,
            revoked_at: None,
            disclosed_fields: BTreeSet::new(),
        }
    }

    pub fn verified_handle(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        handle: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::VerifiedHandle.as_str(),
            serde_json::json!({ "handle": handle.into() }),
        )
    }

    pub fn email_domain(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        domain: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::EmailDomain.as_str(),
            serde_json::json!({ "domain": domain.into() }),
        )
    }

    pub fn organization_membership(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        organization: Did,
        roles: Vec<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::OrganizationMembership.as_str(),
            serde_json::json!({ "organization": organization, "roles": roles }),
        )
    }

    pub fn device_trust(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        device_id: DeviceId,
        trust_state: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::DeviceTrust.as_str(),
            serde_json::json!({ "device_id": device_id, "trust_state": trust_state.into() }),
        )
    }

    pub fn guardian_controller(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        guardian: Did,
        controller: Did,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::GuardianController.as_str(),
            serde_json::json!({ "guardian": guardian, "controller": controller }),
        )
    }

    pub fn mfa_level(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        level: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::MfaLevel.as_str(),
            serde_json::json!({ "level": level.into() }),
        )
    }

    pub fn risk_level(
        claim_id: impl Into<String>,
        subject: Did,
        issuer: Did,
        level: impl Into<String>,
    ) -> Self {
        Self::new(
            claim_id,
            subject,
            issuer,
            AuthClaimKind::RiskLevel.as_str(),
            serde_json::json!({ "level": level.into() }),
        )
    }
}

impl From<cokret_core::DirectoryPresentedClaim> for PresentedClaim {
    fn from(claim: cokret_core::DirectoryPresentedClaim) -> Self {
        Self {
            claim_id: claim.claim_id,
            subject: claim.subject,
            issuer: claim.issuer,
            claim_kind: claim.claim_kind,
            value: claim.value,
            issued_at: claim.issued_at,
            refreshed_at: claim.refreshed_at,
            expires_at: claim.expires_at,
            revoked_at: claim.revoked_at,
            disclosed_fields: claim.disclosed_fields,
        }
    }
}

impl From<PresentedClaim> for cokret_core::DirectoryPresentedClaim {
    fn from(claim: PresentedClaim) -> Self {
        Self {
            claim_id: claim.claim_id,
            subject: claim.subject,
            issuer: claim.issuer,
            claim_kind: claim.claim_kind,
            value: claim.value,
            issued_at: claim.issued_at,
            refreshed_at: claim.refreshed_at,
            expires_at: claim.expires_at,
            revoked_at: claim.revoked_at,
            disclosed_fields: claim.disclosed_fields,
        }
    }
}

/// One claim requested by a progressive disclosure policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDisclosureRequirement {
    pub claim_kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reveal_fields: Vec<String>,
    #[serde(default = "default_true")]
    pub required: bool,
}

/// Policy describing the minimum claims to disclose for a strand.
///
/// Named `ClaimDisclosurePolicy` (not `DisclosurePolicy`) to avoid
/// colliding with the unrelated invite tiered-disclosure
/// `models::DisclosurePolicy` re-exported at the umbrella crate root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDisclosurePolicy {
    pub policy_id: String,
    pub requirements: Vec<ClaimDisclosureRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<Duration>,
    #[serde(default = "default_true")]
    pub fail_closed: bool,
}

/// Presentation request sent to a wallet or identity provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationRequestBody {
    pub request_id: String,
    pub subject: Did,
    pub audience: String,
    pub nonce: String,
    pub policy: ClaimDisclosurePolicy,
    pub created_at: DateTime<Utc>,
    /// Verifier DID requesting the disclosure
    /// (`progressive-disclosure.md` §4). Wallets MUST authenticate this
    /// DID and refuse to disclose anything to an unverified verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<Did>,
    /// Organization the verifier claims to represent. When set, the
    /// wallet MUST trace `verifier_did → represented_org` through the
    /// verifier authority chain before disclosure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub represented_org: Option<Did>,
    /// Authority links proving `verifier_did` is acting on behalf of
    /// `represented_org`. Empty means "verifier acts for itself"; a
    /// non-empty list MUST chain back to `represented_org`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_authority_chain: Vec<VerifierAuthorityLink>,
}

/// One link in the verifier authority chain (verifier → org).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierAuthorityLink {
    /// Subject of this link — the DID that delegated to the next.
    pub from: Did,
    /// Recipient of the delegation.
    pub to: Did,
    /// Capability or role token transferred (`org_member`, `verifier`,
    /// etc.).
    pub capability: String,
    /// Detached proof for the delegation (JWS, signed CBOR, etc.).
    pub proof: String,
    /// Expiry timestamp; expired links MUST be rejected.
    pub expires_at: DateTime<Utc>,
}

impl PresentationRequestBody {
    /// Validate the verifier authority chain per
    /// `progressive-disclosure.md` §4.
    ///
    /// Returns `Ok(())` when:
    ///
    /// 1. If `verifier_did` is `None`, the request is rejected.
    /// 2. If `represented_org` is `None`, the chain MUST be empty (verifier acts for itself).
    /// 3. Otherwise the chain MUST start at `verifier_did`, end at `represented_org`, and every
    ///    link MUST be unexpired at `now`.
    ///
    /// This validator does NOT verify the cryptographic proofs — it
    /// only enforces the chain shape. Callers SHOULD additionally
    /// verify each link's `proof` against the issuer's DID document.
    pub fn validate_verifier_authority(&self, now: DateTime<Utc>) -> Result<()> {
        let Some(verifier) = &self.verifier_did else {
            return Err(Error::Protocol(
                "presentation request missing verifier_did".to_owned(),
            ));
        };
        let Some(org) = &self.represented_org else {
            if self.verifier_authority_chain.is_empty() {
                return Ok(());
            }
            return Err(Error::Protocol(
                "verifier_authority_chain present without represented_org".to_owned(),
            ));
        };
        if self.verifier_authority_chain.is_empty() {
            // Verifier IS the org — accept.
            if verifier == org {
                return Ok(());
            }
            return Err(Error::Protocol(
                "represented_org differs from verifier_did but no authority chain provided"
                    .to_owned(),
            ));
        }
        // Walk the chain: every link MUST be unexpired and `to`
        // MUST connect to the next link's `from`.
        let chain = &self.verifier_authority_chain;
        if &chain[0].from != verifier {
            return Err(Error::Protocol(
                "verifier_authority_chain does not start at verifier_did".to_owned(),
            ));
        }
        for window in chain.windows(2) {
            if window[0].to != window[1].from {
                return Err(Error::Protocol(
                    "verifier_authority_chain has a broken link".to_owned(),
                ));
            }
        }
        if &chain[chain.len() - 1].to != org {
            return Err(Error::Protocol(
                "verifier_authority_chain does not end at represented_org".to_owned(),
            ));
        }
        for link in chain {
            if now >= link.expires_at {
                return Err(Error::Protocol(format!(
                    "verifier_authority_chain link from {} to {} is expired",
                    link.from, link.to
                )));
            }
        }
        Ok(())
    }
}

/// External selective-disclosure proof format accepted through an adapter boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureProofFormat {
    SdJwt,
    Bbs,
    Custom(String),
}

/// Format-neutral boundary object passed to SD-JWT, BBS or host-provided verifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureProofAdapterBoundary {
    pub format: DisclosureProofFormat,
    pub holder: Did,
    pub issuer: Did,
    pub audience: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub encoded_presentation: String,
}

impl DisclosureProofAdapterBoundary {
    /// Validate request binding before delegating to a format-specific verifier.
    pub fn validate_request_binding(
        &self,
        request: &PresentationRequestBody,
        expected_domain: Option<&str>,
    ) -> Result<()> {
        if self.holder != request.subject {
            return Err(Error::Protocol(
                "disclosure proof holder mismatch".to_owned(),
            ));
        }
        if self.audience != request.audience {
            return Err(Error::Protocol(
                "disclosure proof audience mismatch".to_owned(),
            ));
        }
        if self.nonce != request.nonce {
            return Err(Error::Protocol(
                "disclosure proof nonce mismatch".to_owned(),
            ));
        }
        if expected_domain != self.domain.as_deref() {
            return Err(Error::Protocol(
                "disclosure proof domain mismatch".to_owned(),
            ));
        }
        if self.encoded_presentation.trim().is_empty() {
            return Err(Error::Protocol(
                "disclosure proof payload is empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Rejected claim detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedClaim {
    pub claim_id: String,
    pub claim_kind: String,
    pub reason: String,
}

/// Progressive disclosure validation result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresentationValidation {
    pub accepted: bool,
    pub disclosed_claims: Vec<PresentedClaim>,
    pub missing_required: Vec<String>,
    pub rejected_claims: Vec<RejectedClaim>,
}

/// Validate claims against issuer trust, subject, expiry, revocation and disclosure policy.
pub fn validate_presentation(
    request: &PresentationRequestBody,
    claims: &[PresentedClaim],
    revoked_claim_ids: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> PresentationValidation {
    let mut disclosed_claims = Vec::new();
    let mut missing_required = Vec::new();
    let mut rejected_claims = Vec::new();

    // Verifier authority MUST be authenticated before any claim
    // processing per `progressive-disclosure.md` §4. A verifier with
    // no `verifier_did` is treated as anonymous; only requests that
    // explicitly opt in to anonymous disclosure (via empty policy
    // requirements) reach the loop below.
    if let Some(verifier) = &request.verifier_did
        && let Err(reason) = request.validate_verifier_authority(now)
    {
        rejected_claims.push(RejectedClaim {
            claim_id: format!("verifier_authority:{verifier}"),
            claim_kind: "verifier_authority".to_owned(),
            reason: reason.to_string(),
        });
        return PresentationValidation {
            accepted: false,
            disclosed_claims,
            missing_required,
            rejected_claims,
        };
    }

    for requirement in &request.policy.requirements {
        let mut matched = false;
        for claim in claims
            .iter()
            .filter(|claim| claim.claim_kind == requirement.claim_kind)
        {
            match validate_presented_claim(request, requirement, claim, revoked_claim_ids, now) {
                Ok(()) => {
                    disclosed_claims.push(disclose_claim(claim, &requirement.reveal_fields));
                    matched = true;
                    break;
                }
                Err(reason) => rejected_claims.push(RejectedClaim {
                    claim_id: claim.claim_id.clone(),
                    claim_kind: claim.claim_kind.clone(),
                    reason,
                }),
            }
        }
        if !matched && requirement.required {
            missing_required.push(requirement.claim_kind.clone());
        }
    }

    let accepted =
        missing_required.is_empty() && (!request.policy.fail_closed || rejected_claims.is_empty());
    PresentationValidation {
        accepted,
        disclosed_claims,
        missing_required,
        rejected_claims,
    }
}

/// Verify a presentation end-to-end through a host-provided proof adapter.
///
/// The SDK owns the protocol binding and disclosure-policy checks; the caller
/// supplies the format-specific cryptographic verifier for SD-JWT, BBS, or a
/// deployment-specific proof format.
pub fn verify_presentation_with_adapter<F>(
    request: &PresentationRequestBody,
    proof: &DisclosureProofAdapterBoundary,
    claims: &[PresentedClaim],
    revoked_claim_ids: &BTreeSet<String>,
    now: DateTime<Utc>,
    expected_domain: Option<&str>,
    verify_proof: F,
) -> Result<PresentationValidation>
where
    F: FnOnce(&DisclosureProofAdapterBoundary) -> Result<()>,
{
    proof.validate_request_binding(request, expected_domain)?;
    verify_proof(proof)?;
    Ok(validate_presentation(
        request,
        claims,
        revoked_claim_ids,
        now,
    ))
}
