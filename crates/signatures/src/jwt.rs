//! EdDSA JWT verification against JWKS.
//!
//! This module intentionally supports only the algorithm family this SDK can
//! verify without external crypto adapters: compact JWS/JWT with `alg=EdDSA`
//! and `OKP` / `Ed25519` JWKs. RSA and ECDSA JWTs must be verified by a host
//! adapter until the SDK owns those algorithm implementations.

use arkret_core::base64url_decode;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Verification policy for a compact JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtVerificationPolicy {
    /// Expected `iss` claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Expected `aud` claim. Accepts either a string claim or an array
    /// containing this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Current Unix timestamp in seconds.
    pub now_unix_seconds: i64,
    /// Accepted clock skew for `exp`, `nbf`, and `iat`.
    pub max_clock_skew_seconds: i64,
    /// Require an `exp` claim. OIDC-facing callers should leave this enabled.
    #[serde(default = "default_require_exp")]
    pub require_exp: bool,
}

impl Default for JwtVerificationPolicy {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            now_unix_seconds: 0,
            max_clock_skew_seconds: 0,
            require_exp: true,
        }
    }
}

impl JwtVerificationPolicy {
    pub fn new(now_unix_seconds: i64) -> Self {
        Self {
            now_unix_seconds,
            max_clock_skew_seconds: 60,
            ..Self::default()
        }
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn max_clock_skew_seconds(mut self, seconds: i64) -> Self {
        self.max_clock_skew_seconds = seconds.max(0);
        self
    }

    pub fn require_exp(mut self, require_exp: bool) -> Self {
        self.require_exp = require_exp;
        self
    }
}

fn default_require_exp() -> bool {
    true
}

/// Verified JWT material returned after signature and claim policy checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedJwt {
    pub header: Value,
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwtVerificationError {
    #[error("JWT compact serialization is malformed")]
    MalformedCompact,
    #[error("JWT header or claims are not valid base64url JSON")]
    MalformedJson,
    #[error("JWT algorithm is unsupported: `{0}`")]
    UnsupportedAlgorithm(String),
    #[error("JWT critical headers are unsupported")]
    UnsupportedCriticalHeader,
    #[error("JWKS is malformed")]
    MalformedJwks,
    #[error("JWKS does not contain a matching Ed25519 key")]
    KeyNotFound,
    #[error("JWT key selection is ambiguous")]
    AmbiguousKeySelection,
    #[error("JWT signature is malformed")]
    MalformedSignature,
    #[error("JWT signature verification failed")]
    InvalidSignature,
    #[error("JWT issuer claim mismatch")]
    IssuerMismatch,
    #[error("JWT audience claim mismatch")]
    AudienceMismatch,
    #[error("JWT is expired")]
    Expired,
    #[error("JWT is not yet valid")]
    NotYetValid,
    #[error("JWT issued-at claim is in the future")]
    IssuedAtInFuture,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    crit: Option<Value>,
}

#[derive(Clone)]
struct JwksKey {
    kid: Option<String>,
    public_key: VerifyingKey,
}

/// Verify a compact EdDSA JWT against a JWKS JSON object.
///
/// `jwks` must be an object with a `keys` array. Key selection uses `kid` when
/// the JWT supplies it; without `kid`, the JWKS must contain exactly one
/// Ed25519-compatible key.
pub fn verify_eddsa_jwt_with_jwks(
    jwt: &str,
    jwks: &Value,
    policy: &JwtVerificationPolicy,
) -> Result<VerifiedJwt, JwtVerificationError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(JwtVerificationError::MalformedCompact);
    }

    let header_bytes =
        base64url_decode(parts[0]).map_err(|_| JwtVerificationError::MalformedJson)?;
    let claims_bytes =
        base64url_decode(parts[1]).map_err(|_| JwtVerificationError::MalformedJson)?;
    let header_value: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtVerificationError::MalformedJson)?;
    let header: JwtHeader = serde_json::from_value(header_value.clone())
        .map_err(|_| JwtVerificationError::MalformedJson)?;
    let claims: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| JwtVerificationError::MalformedJson)?;

    if header.alg != "EdDSA" {
        return Err(JwtVerificationError::UnsupportedAlgorithm(header.alg));
    }
    if header.crit.is_some() {
        return Err(JwtVerificationError::UnsupportedCriticalHeader);
    }
    if let Some(typ) = header.typ.as_deref()
        && typ != "JWT"
    {
        return Err(JwtVerificationError::MalformedJson);
    }

    let key = select_jwks_key(jwks, header.kid.as_deref())?;
    let signature_bytes =
        base64url_decode(parts[2]).map_err(|_| JwtVerificationError::MalformedSignature)?;
    if signature_bytes.len() != 64 {
        return Err(JwtVerificationError::MalformedSignature);
    }
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&signature_array);
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.public_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| JwtVerificationError::InvalidSignature)?;

    validate_claims(&claims, policy)?;

    Ok(VerifiedJwt {
        header: header_value,
        claims,
        key_id: key.kid,
    })
}

fn select_jwks_key(jwks: &Value, kid: Option<&str>) -> Result<JwksKey, JwtVerificationError> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(JwtVerificationError::MalformedJwks)?;
    let mut candidates = Vec::new();
    for key in keys {
        let Some(candidate) = decode_jwks_ed25519_key(key)? else {
            continue;
        };
        if kid.is_none_or(|expected| candidate.kid.as_deref() == Some(expected)) {
            candidates.push(candidate);
        }
    }
    match (kid, candidates.len()) {
        (_, 0) => Err(JwtVerificationError::KeyNotFound),
        (Some(_), 1) => Ok(candidates.remove(0)),
        (Some(_), _) => Err(JwtVerificationError::AmbiguousKeySelection),
        (None, 1) => Ok(candidates.remove(0)),
        (None, _) => Err(JwtVerificationError::AmbiguousKeySelection),
    }
}

fn decode_jwks_ed25519_key(key: &Value) -> Result<Option<JwksKey>, JwtVerificationError> {
    if key.get("kty").and_then(Value::as_str) != Some("OKP")
        || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
    {
        return Ok(None);
    }
    let x = key
        .get("x")
        .and_then(Value::as_str)
        .ok_or(JwtVerificationError::MalformedJwks)?;
    let raw = base64url_decode(x).map_err(|_| JwtVerificationError::MalformedJwks)?;
    if raw.len() != 32 {
        return Err(JwtVerificationError::MalformedJwks);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&raw);
    let public_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| JwtVerificationError::MalformedJwks)?;
    let kid = key
        .get("kid")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(Some(JwksKey { kid, public_key }))
}

fn validate_claims(
    claims: &Value,
    policy: &JwtVerificationPolicy,
) -> Result<(), JwtVerificationError> {
    if let Some(expected_issuer) = &policy.issuer
        && claims.get("iss").and_then(Value::as_str) != Some(expected_issuer.as_str())
    {
        return Err(JwtVerificationError::IssuerMismatch);
    }
    if let Some(expected_audience) = &policy.audience
        && !claim_audience_contains(claims.get("aud"), expected_audience)
    {
        return Err(JwtVerificationError::AudienceMismatch);
    }

    let now = policy.now_unix_seconds;
    let skew = policy.max_clock_skew_seconds.max(0);
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp < now.saturating_sub(skew) => {
            return Err(JwtVerificationError::Expired);
        }
        Some(_) => {}
        None if policy.require_exp => return Err(JwtVerificationError::Expired),
        None => {}
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64)
        && nbf > now.saturating_add(skew)
    {
        return Err(JwtVerificationError::NotYetValid);
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64)
        && iat > now.saturating_add(skew)
    {
        return Err(JwtVerificationError::IssuedAtInFuture);
    }
    Ok(())
}

fn claim_audience_contains(claim: Option<&Value>, expected: &str) -> bool {
    match claim {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use arkret_core::base64url_encode;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;

    fn jwt_fixture(now: i64, kid: Option<&str>) -> (String, Value) {
        jwt_fixture_with_claims(
            kid,
            json!({
                "iss": "https://issuer.example",
                "aud": ["arkret-client", "other"],
                "sub": "alice",
                "iat": now - 1,
                "nbf": now - 1,
                "exp": now + 60
            }),
        )
    }

    fn jwt_fixture_with_claims(kid: Option<&str>, claims: Value) -> (String, Value) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key();
        let header = match kid {
            Some(kid) => json!({"alg": "EdDSA", "kid": kid, "typ": "JWT"}),
            None => json!({"alg": "EdDSA", "typ": "JWT"}),
        };
        let header_b64 = base64url_encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = base64url_encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", base64url_encode(signature.to_bytes()));
        let mut jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64url_encode(public_key.to_bytes())
        });
        if let Some(kid) = kid {
            jwk["kid"] = json!(kid);
        }
        (jwt, json!({ "keys": [jwk] }))
    }

    #[test]
    fn verifies_eddsa_jwt_against_jwks() {
        let now = 1_715_990_000;
        let (jwt, jwks) = jwt_fixture(now, Some("key-1"));
        let policy = JwtVerificationPolicy::new(now)
            .issuer("https://issuer.example")
            .audience("arkret-client");

        let verified = verify_eddsa_jwt_with_jwks(&jwt, &jwks, &policy).unwrap();
        assert_eq!(verified.key_id.as_deref(), Some("key-1"));
        assert_eq!(verified.claims["sub"], json!("alice"));
    }

    #[test]
    fn rejects_jwt_body_tampering_and_policy_mismatch() {
        let now = 1_715_990_000;
        let (jwt, jwks) = jwt_fixture(now, Some("key-1"));
        let mut parts: Vec<&str> = jwt.split('.').collect();
        parts[1] = "eyJzdWIiOiJib2IifQ";
        let tampered = parts.join(".");
        let policy = JwtVerificationPolicy::new(now)
            .issuer("https://issuer.example")
            .audience("arkret-client");
        assert_eq!(
            verify_eddsa_jwt_with_jwks(&tampered, &jwks, &policy),
            Err(JwtVerificationError::InvalidSignature)
        );

        let wrong_audience = JwtVerificationPolicy::new(now).audience("unknown-client");
        assert_eq!(
            verify_eddsa_jwt_with_jwks(&jwt, &jwks, &wrong_audience),
            Err(JwtVerificationError::AudienceMismatch)
        );
    }

    #[test]
    fn requires_unambiguous_key_when_jwt_has_no_kid() {
        let now = 1_715_990_000;
        let (jwt, mut jwks) = jwt_fixture(now, None);
        let second = jwks["keys"][0].clone();
        jwks["keys"].as_array_mut().unwrap().push(second);
        assert_eq!(
            verify_eddsa_jwt_with_jwks(&jwt, &jwks, &JwtVerificationPolicy::new(now)),
            Err(JwtVerificationError::AmbiguousKeySelection)
        );
    }

    #[test]
    fn requires_exp_by_default() {
        let now = 1_715_990_000;
        let (jwt, jwks) = jwt_fixture_with_claims(
            Some("key-1"),
            json!({
                "iss": "https://issuer.example",
                "aud": "arkret-client",
                "sub": "alice",
                "iat": now - 1,
                "nbf": now - 1
            }),
        );

        assert_eq!(
            verify_eddsa_jwt_with_jwks(&jwt, &jwks, &JwtVerificationPolicy::new(now)),
            Err(JwtVerificationError::Expired)
        );

        let policy = JwtVerificationPolicy::new(now).require_exp(false);
        assert!(verify_eddsa_jwt_with_jwks(&jwt, &jwks, &policy).is_ok());
    }
}
