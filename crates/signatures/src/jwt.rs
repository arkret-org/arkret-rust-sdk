//! EdDSA JWT verification against JSON Web Key Sets.
//!
//! This module intentionally supports only compact JWS/JWT with `alg=EdDSA`
//! and `OKP` / `Ed25519` keys. RSA and ECDSA JWTs must be verified by a host
//! adapter until the SDK owns those algorithm implementations.

use std::collections::{BTreeMap, BTreeSet};
use std::result::Result;

use arkret_canonical::base64url_decode;
use arkret_core::NonEmptyString;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::jwk::JsonWebKeySet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtType {
    #[serde(rename = "JWT")]
    Jwt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct JwtAudience(JwtAudienceValue);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum JwtAudienceValue {
    Single(NonEmptyString),
    Multiple(Vec<NonEmptyString>),
}

impl<'de> Deserialize<'de> for JwtAudience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = JwtAudienceValue::deserialize(deserializer)?;
        if let JwtAudienceValue::Multiple(audiences) = &value {
            if audiences.is_empty() {
                return Err(serde::de::Error::custom(
                    "JWT audience array must not be empty",
                ));
            }
            let unique: BTreeSet<&str> = audiences.iter().map(NonEmptyString::as_str).collect();
            if unique.len() != audiences.len() {
                return Err(serde::de::Error::custom(
                    "JWT audience array must not contain duplicates",
                ));
            }
        }
        Ok(Self(value))
    }
}

impl JwtAudience {
    pub fn single(audience: NonEmptyString) -> Self {
        Self(JwtAudienceValue::Single(audience))
    }

    pub fn multiple(audiences: Vec<NonEmptyString>) -> Result<Self, &'static str> {
        if audiences.is_empty() {
            return Err("JWT audience array must not be empty");
        }
        let unique: BTreeSet<&str> = audiences.iter().map(NonEmptyString::as_str).collect();
        if unique.len() != audiences.len() {
            return Err("JWT audience array must not contain duplicates");
        }
        Ok(Self(JwtAudienceValue::Multiple(audiences)))
    }

    pub fn contains(&self, expected: &str) -> bool {
        match &self.0 {
            JwtAudienceValue::Single(audience) => audience.as_str() == expected,
            JwtAudienceValue::Multiple(audiences) => audiences
                .iter()
                .any(|audience| audience.as_str() == expected),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonWebTokenHeader {
    pub alg: JwtAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<JwtType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<NonEmptyString>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonWebTokenClaims {
    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    issuer: Option<NonEmptyString>,
    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    subject: Option<NonEmptyString>,
    #[serde(rename = "aud", default, skip_serializing_if = "Option::is_none")]
    audience: Option<JwtAudience>,
    #[serde(rename = "exp", default, skip_serializing_if = "Option::is_none")]
    expiration: Option<i64>,
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    not_before: Option<i64>,
    #[serde(rename = "iat", default, skip_serializing_if = "Option::is_none")]
    issued_at: Option<i64>,
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    jwt_id: Option<NonEmptyString>,
    #[serde(flatten)]
    additional: BTreeMap<String, Value>,
}

impl JsonWebTokenClaims {
    pub fn issuer(&self) -> Option<&NonEmptyString> {
        self.issuer.as_ref()
    }

    pub fn subject(&self) -> Option<&NonEmptyString> {
        self.subject.as_ref()
    }

    pub fn audience(&self) -> Option<&JwtAudience> {
        self.audience.as_ref()
    }

    pub fn expiration(&self) -> Option<i64> {
        self.expiration
    }

    pub fn not_before(&self) -> Option<i64> {
        self.not_before
    }

    pub fn issued_at(&self) -> Option<i64> {
        self.issued_at
    }

    pub fn jwt_id(&self) -> Option<&NonEmptyString> {
        self.jwt_id.as_ref()
    }

    pub fn additional(&self, name: &str) -> Option<&Value> {
        self.additional.get(name)
    }
}

/// Verification policy for a compact JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtVerificationPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<NonEmptyString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<NonEmptyString>,
    now_unix_seconds: i64,
    max_clock_skew_seconds: u64,
    #[serde(default = "default_require_exp")]
    require_exp: bool,
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

    pub fn issuer(mut self, issuer: NonEmptyString) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn audience(mut self, audience: NonEmptyString) -> Self {
        self.audience = Some(audience);
        self
    }

    pub fn max_clock_skew_seconds(mut self, seconds: u64) -> Self {
        self.max_clock_skew_seconds = seconds;
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
    pub header: JsonWebTokenHeader,
    pub claims: JsonWebTokenClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<NonEmptyString>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwtVerificationError {
    #[error("JWT compact serialization is malformed")]
    MalformedCompact,
    #[error("JWT header or claims are not valid base64url JSON")]
    MalformedJson,
    #[error("JWT critical headers are unsupported")]
    UnsupportedCriticalHeader,
    #[error("JSON Web Key contains malformed Ed25519 material")]
    MalformedKey,
    #[error("JSON Web Key Set does not contain a matching Ed25519 key")]
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

#[derive(Clone)]
struct VerificationKey {
    kid: Option<NonEmptyString>,
    public_key: VerifyingKey,
}

pub fn verify_eddsa_jwt_with_jwks(
    jwt: &str,
    jwks: &JsonWebKeySet,
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
    let header: JsonWebTokenHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtVerificationError::MalformedJson)?;
    let claims: JsonWebTokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| JwtVerificationError::MalformedJson)?;

    if header.crit.is_some() {
        return Err(JwtVerificationError::UnsupportedCriticalHeader);
    }

    let key = select_verification_key(jwks, header.kid.as_ref())?;
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
        header,
        claims,
        key_id: key.kid,
    })
}

fn select_verification_key(
    jwks: &JsonWebKeySet,
    kid: Option<&NonEmptyString>,
) -> Result<VerificationKey, JwtVerificationError> {
    let mut candidates = Vec::new();
    for key in jwks.keys() {
        let Some(x) = key.ed25519_x_for_verification() else {
            continue;
        };
        if kid.is_some_and(|expected| key.kid() != Some(expected)) {
            continue;
        }
        let raw = base64url_decode(x.as_str()).map_err(|_| JwtVerificationError::MalformedKey)?;
        if raw.len() != 32 {
            return Err(JwtVerificationError::MalformedKey);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&raw);
        let public_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| JwtVerificationError::MalformedKey)?;
        candidates.push(VerificationKey {
            kid: key.kid().cloned(),
            public_key,
        });
    }

    match candidates.len() {
        0 => Err(JwtVerificationError::KeyNotFound),
        1 => Ok(candidates.remove(0)),
        _ => Err(JwtVerificationError::AmbiguousKeySelection),
    }
}

fn validate_claims(
    claims: &JsonWebTokenClaims,
    policy: &JwtVerificationPolicy,
) -> Result<(), JwtVerificationError> {
    if let Some(expected_issuer) = &policy.issuer
        && claims.issuer() != Some(expected_issuer)
    {
        return Err(JwtVerificationError::IssuerMismatch);
    }
    if let Some(expected_audience) = &policy.audience
        && !claims
            .audience()
            .is_some_and(|audience| audience.contains(expected_audience.as_str()))
    {
        return Err(JwtVerificationError::AudienceMismatch);
    }

    let now = policy.now_unix_seconds;
    let skew = i64::try_from(policy.max_clock_skew_seconds).unwrap_or(i64::MAX);
    match claims.expiration() {
        Some(expiration) if expiration < now.saturating_sub(skew) => {
            return Err(JwtVerificationError::Expired);
        }
        Some(_) => {}
        None if policy.require_exp => return Err(JwtVerificationError::Expired),
        None => {}
    }
    if claims
        .not_before()
        .is_some_and(|not_before| not_before > now.saturating_add(skew))
    {
        return Err(JwtVerificationError::NotYetValid);
    }
    if claims
        .issued_at()
        .is_some_and(|issued_at| issued_at > now.saturating_add(skew))
    {
        return Err(JwtVerificationError::IssuedAtInFuture);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_encode;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    use super::*;

    fn non_empty(value: &str) -> NonEmptyString {
        NonEmptyString::new(value).unwrap()
    }

    fn jwt_fixture(now: i64, kid: Option<&str>) -> (String, JsonWebKeySet) {
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

    fn jwt_fixture_with_claims(kid: Option<&str>, claims: Value) -> (String, JsonWebKeySet) {
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
        let jwks = serde_json::from_value(json!({ "keys": [jwk] })).unwrap();
        (jwt, jwks)
    }

    #[test]
    fn verifies_eddsa_jwt_against_jwks() {
        let now = 1_715_990_000;
        let (jwt, jwks) = jwt_fixture(now, Some("key-1"));
        let policy = JwtVerificationPolicy::new(now)
            .issuer(non_empty("https://issuer.example"))
            .audience(non_empty("arkret-client"));

        let verified = verify_eddsa_jwt_with_jwks(&jwt, &jwks, &policy).unwrap();
        assert_eq!(
            verified.key_id.as_ref().map(NonEmptyString::as_str),
            Some("key-1")
        );
        assert_eq!(
            verified.claims.subject().map(NonEmptyString::as_str),
            Some("alice")
        );
    }

    #[test]
    fn rejects_jwt_body_tampering_and_policy_mismatch() {
        let now = 1_715_990_000;
        let (jwt, jwks) = jwt_fixture(now, Some("key-1"));
        let mut parts: Vec<&str> = jwt.split('.').collect();
        parts[1] = "eyJzdWIiOiJib2IifQ";
        let tampered = parts.join(".");
        let policy = JwtVerificationPolicy::new(now)
            .issuer(non_empty("https://issuer.example"))
            .audience(non_empty("arkret-client"));
        assert_eq!(
            verify_eddsa_jwt_with_jwks(&tampered, &jwks, &policy),
            Err(JwtVerificationError::InvalidSignature)
        );

        let wrong_audience = JwtVerificationPolicy::new(now).audience(non_empty("unknown-client"));
        assert_eq!(
            verify_eddsa_jwt_with_jwks(&jwt, &jwks, &wrong_audience),
            Err(JwtVerificationError::AudienceMismatch)
        );
    }

    #[test]
    fn requires_unambiguous_key_when_jwt_has_no_kid() {
        let now = 1_715_990_000;
        let (jwt, jwks) = jwt_fixture(now, None);
        let second = jwks.keys()[0].clone();
        let ambiguous = JsonWebKeySet::new(vec![jwks.keys()[0].clone(), second]).unwrap();
        assert_eq!(
            verify_eddsa_jwt_with_jwks(&jwt, &ambiguous, &JwtVerificationPolicy::new(now)),
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

    #[test]
    fn rejects_empty_or_duplicate_audience_arrays() {
        assert!(serde_json::from_value::<JwtAudience>(json!([])).is_err());
        assert!(serde_json::from_value::<JwtAudience>(json!(["client", "client"])).is_err());
    }
}
