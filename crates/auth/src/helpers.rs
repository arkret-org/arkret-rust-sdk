use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
pub(super) use arkret_canonical::canonical::sha256_hex;

use super::*;

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn validate_presented_claim(
    request: &PresentationRequestBody,
    requirement: &ClaimDisclosureRequirement,
    claim: &PresentedClaim,
    revoked_claim_ids: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> std::result::Result<(), String> {
    if claim.subject != request.subject {
        return Err("claim subject mismatch".to_owned());
    }
    if !requirement.trusted_issuers.is_empty()
        && !requirement.trusted_issuers.contains(&claim.issuer)
    {
        return Err("claim issuer is not trusted".to_owned());
    }
    if revoked_claim_ids.contains(&claim.claim_id) {
        return Err("claim is revoked".to_owned());
    }
    if claim.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
        return Err("claim is revoked".to_owned());
    }
    if claim.expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err("claim is expired".to_owned());
    }
    if let Some(max_age) = request.policy.max_age {
        let basis = claim.refreshed_at.unwrap_or(claim.issued_at);
        if now - basis > max_age {
            return Err("claim is stale".to_owned());
        }
    }
    Ok(())
}

pub(super) fn disclose_claim(claim: &PresentedClaim, reveal_fields: &[String]) -> PresentedClaim {
    let mut disclosed = claim.clone();
    disclosed.disclosed_fields = reveal_fields.iter().cloned().collect();
    if reveal_fields.is_empty() {
        disclosed.value.clear();
        return disclosed;
    }
    if reveal_fields.iter().any(|field| field == "*") {
        return disclosed;
    }
    let mut filtered = BTreeMap::new();
    for field in reveal_fields {
        if let Some(value) = claim.value.get(field) {
            filtered.insert(field.clone(), value.clone());
        }
    }
    disclosed.value = filtered;
    disclosed
}

/// Hash a password with the built-in Argon2id helper, returning a salted
/// PHC string (`$argon2id$...`) that carries its own random salt and
/// parameters. This replaces the previous unsalted, work-factorless
/// SHA-256 default so leaked hashes cannot be batch-reversed with rainbow
/// tables / GPUs. Applications that run their own KDF should instead use
/// [`super::manager::AuthManager::register_password_hash`] /
/// `login_password_with_verifier`.
pub(super) fn hash_password(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes)
        .map_err(|error| Error::Crypto(format!("password salt rng: {error}")))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|error| Error::Crypto(format!("password salt encode: {error}")))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| Error::Crypto(format!("argon2 hash: {error}")))?;
    Ok(hash.to_string())
}

/// Verify a password against a PHC string produced by [`hash_password`].
/// Returns `false` for any malformed hash or mismatch (fail-closed). The
/// Argon2 verification itself is constant-time.
pub(super) fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Constant-time string comparison — delegates to the single crate-wide
/// implementation in the shared constant-time helper (hash both inputs
/// to a fixed-length SHA-256 digest, then compare with `subtle`).
pub(super) fn constant_time_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    let left = arkret_canonical::canonical::sha256_bytes(left.as_bytes());
    let right = arkret_canonical::canonical::sha256_bytes(right.as_bytes());
    left.ct_eq(&right).into()
}

/// Verify a built-in account-recovery proof.
///
/// Only [`AccountRecoveryMethod::PasswordReset`] has a built-in proof: the
/// caller presents the reset token whose hash was registered out of band,
/// which is a real shared secret. `DidProof` and `PasskeyWebAuthnRebinding`
/// MUST be completed through [`super::manager::AuthManager::complete_recovery_with_did_verifier`]
/// (or an equivalent WebAuthn verifier) because their identifiers
/// (`verification_method`, `credential_id`) are **public** values — deriving
/// a "proof" from them would let anyone who knows the public identifier take
/// over the account. We therefore fail closed here for those methods.
pub(super) fn recovery_proof_matches(method: &AccountRecoveryMethod, proof: &str) -> bool {
    match method {
        AccountRecoveryMethod::PasswordReset { reset_token_hash } => {
            constant_time_eq(proof, reset_token_hash)
        }
        AccountRecoveryMethod::DidProof { .. }
        | AccountRecoveryMethod::PasskeyWebAuthnRebinding { .. } => false,
    }
}
