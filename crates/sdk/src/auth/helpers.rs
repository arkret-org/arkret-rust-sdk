use super::*;

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn validate_presented_claim(
    request: &PresentationReqBody,
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
        disclosed.value = Value::Null;
        return disclosed;
    }
    if reveal_fields.iter().any(|field| field == "*") {
        return disclosed;
    }
    let Some(object) = claim.value.as_object() else {
        disclosed.value = Value::Null;
        return disclosed;
    };
    let mut filtered = serde_json::Map::new();
    for field in reveal_fields {
        if let Some(value) = object.get(field) {
            filtered.insert(field.clone(), value.clone());
        }
    }
    disclosed.value = Value::Object(filtered);
    disclosed
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for idx in 0..max_len {
        let left_byte = left.get(idx).copied().unwrap_or(0);
        let right_byte = right.get(idx).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }

    diff == 0
}

pub(super) fn recovery_proof_matches(method: &AccountRecoveryMethod, proof: &str) -> bool {
    match method {
        AccountRecoveryMethod::DidProof { verification_method } => {
            constant_time_eq(proof, &sha256_hex(verification_method.as_bytes()))
        }
        AccountRecoveryMethod::PasswordReset { reset_token_hash } => {
            constant_time_eq(proof, reset_token_hash)
        }
        AccountRecoveryMethod::PasskeyWebAuthnRebinding { credential_id } => {
            constant_time_eq(proof, &sha256_hex(credential_id.as_bytes()))
        }
    }
}
