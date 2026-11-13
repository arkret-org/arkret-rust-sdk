//! DPoP helper types for session-grant issuance and self-surface requests.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::jwk::JsonWebKey;
use crate::{Error, Result};

pub const DPOP_PROOF_TYP: &str = "dpop+jwt";
pub const DPOP_PROOF_ALG: &str = "Ed25519";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDpopClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    pub jkt: String,
    pub claims: VerifiedDpopClaims,
    pub public_jwk: JsonWebKey,
}

#[derive(Clone, Debug)]
pub struct DpopVerificationRequest<'a> {
    pub proof_jwt: &'a str,
    pub method: &'a str,
    pub htu: &'a str,
    pub access_token: Option<&'a str>,
    pub expected_nonce: Option<&'a str>,
    pub now: DateTime<Utc>,
    pub max_age: chrono::Duration,
    pub max_future_skew: chrono::Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DpopVerificationError {
    #[error("DPoP proof is not a compact JWS")]
    Malformed,
    #[error("DPoP proof segment is not valid base64url JSON")]
    InvalidJson,
    #[error("DPoP proof typ is not dpop+jwt")]
    InvalidType,
    #[error("DPoP proof alg is not Ed25519")]
    InvalidAlgorithm,
    #[error("DPoP proof header is missing a valid Ed25519 public JWK")]
    InvalidJwk,
    #[error("DPoP proof signature is invalid")]
    SignatureInvalid,
    #[error("DPoP proof is missing claim {0}")]
    MissingClaim(&'static str),
    #[error("DPoP htm does not match the request method")]
    MethodMismatch,
    #[error("DPoP htu is not an absolute HTTP(S) URI")]
    InvalidTargetUri,
    #[error("DPoP htu does not match the request URI")]
    TargetUriMismatch,
    #[error("DPoP iat is outside the accepted freshness window")]
    IssuedAtOutOfRange,
    #[error("DPoP ath is required for the presented access token")]
    MissingAccessTokenHash,
    #[error("DPoP ath does not match the presented access token")]
    AccessTokenHashMismatch,
    #[error("DPoP nonce is required for this request")]
    MissingNonce,
    #[error("DPoP nonce does not match the server challenge")]
    NonceMismatch,
}

#[derive(Deserialize)]
struct DpopProtectedHeader {
    typ: String,
    alg: String,
    jwk: JsonWebKey,
}

pub fn canonicalize_dpop_htu(input: &str) -> std::result::Result<String, DpopVerificationError> {
    let mut uri =
        url::Url::parse(input.trim()).map_err(|_| DpopVerificationError::InvalidTargetUri)?;
    if !matches!(uri.scheme(), "http" | "https")
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
    {
        return Err(DpopVerificationError::InvalidTargetUri);
    }
    uri.set_query(None);
    uri.set_fragment(None);
    Ok(uri.to_string())
}

pub fn verify_dpop_proof(
    request: &DpopVerificationRequest<'_>,
) -> std::result::Result<VerifiedDpopProof, DpopVerificationError> {
    let mut parts = request.proof_jwt.trim().split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopVerificationError::Malformed);
    };
    let header: DpopProtectedHeader = serde_json::from_slice(
        &arkret_canonical::base64url_decode(header_b64)
            .map_err(|_| DpopVerificationError::InvalidJson)?,
    )
    .map_err(|_| DpopVerificationError::InvalidJson)?;
    if header.typ != DPOP_PROOF_TYP {
        return Err(DpopVerificationError::InvalidType);
    }
    if header.alg != DPOP_PROOF_ALG {
        return Err(DpopVerificationError::InvalidAlgorithm);
    }
    let x = header
        .jwk
        .ed25519_x_for_verification()
        .ok_or(DpopVerificationError::InvalidJwk)?;
    let key_bytes: [u8; 32] = arkret_canonical::base64url_decode(x.as_str())
        .map_err(|_| DpopVerificationError::InvalidJwk)?
        .try_into()
        .map_err(|_| DpopVerificationError::InvalidJwk)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| DpopVerificationError::InvalidJwk)?;
    let signature_bytes: [u8; 64] = arkret_canonical::base64url_decode(signature_b64)
        .map_err(|_| DpopVerificationError::SignatureInvalid)?
        .try_into()
        .map_err(|_| DpopVerificationError::SignatureInvalid)?;
    verifying_key
        .verify(
            format!("{header_b64}.{payload_b64}").as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| DpopVerificationError::SignatureInvalid)?;

    let claims: VerifiedDpopClaims = serde_json::from_slice(
        &arkret_canonical::base64url_decode(payload_b64)
            .map_err(|_| DpopVerificationError::InvalidJson)?,
    )
    .map_err(|_| DpopVerificationError::InvalidJson)?;
    for (name, value) in [
        ("jti", claims.jti.as_str()),
        ("htm", claims.htm.as_str()),
        ("htu", claims.htu.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(DpopVerificationError::MissingClaim(name));
        }
    }
    if !claims.htm.eq_ignore_ascii_case(request.method) {
        return Err(DpopVerificationError::MethodMismatch);
    }
    let expected_htu = canonicalize_dpop_htu(request.htu)?;
    let actual_htu = canonicalize_dpop_htu(&claims.htu)?;
    if actual_htu != expected_htu {
        return Err(DpopVerificationError::TargetUriMismatch);
    }
    let issued_at = DateTime::<Utc>::from_timestamp(claims.iat, 0)
        .ok_or(DpopVerificationError::IssuedAtOutOfRange)?;
    if issued_at < request.now - request.max_age
        || issued_at > request.now + request.max_future_skew
    {
        return Err(DpopVerificationError::IssuedAtOutOfRange);
    }
    if let Some(access_token) = request.access_token {
        let actual = claims
            .ath
            .as_deref()
            .ok_or(DpopVerificationError::MissingAccessTokenHash)?;
        if actual != dpop_access_token_hash(access_token) {
            return Err(DpopVerificationError::AccessTokenHashMismatch);
        }
    }
    if let Some(expected_nonce) = request.expected_nonce {
        let actual = claims
            .nonce
            .as_deref()
            .ok_or(DpopVerificationError::MissingNonce)?;
        if actual != expected_nonce {
            return Err(DpopVerificationError::NonceMismatch);
        }
    }

    let jkt = dpop_jwk_thumbprint(&header.jwk).map_err(|_| DpopVerificationError::InvalidJwk)?;
    Ok(VerifiedDpopProof {
        jkt,
        claims,
        public_jwk: header.jwk,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpopProofRequest {
    pub method: String,
    pub htu: String,
    pub access_token: Option<String>,
    pub nonce: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub jti: String,
}

impl DpopProofRequest {
    pub fn new(method: impl Into<String>, htu: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            htu: htu.into(),
            access_token: None,
            nonce: None,
            issued_at: Utc::now(),
            jti: format!("urn:uuid:{}", Uuid::now_v7()),
        }
    }

    pub fn access_token(mut self, access_token: impl Into<String>) -> Self {
        self.access_token = Some(access_token.into());
        self
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.issued_at = issued_at;
        self
    }

    pub fn jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = jti.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopProof {
    pub proof_jwt: String,
    pub header_value: String,
    pub public_jwk: JsonWebKey,
    pub jkt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

pub fn dpop_access_token_hash(access_token: &str) -> String {
    arkret_canonical::canonical::sha256_base64url(access_token.as_bytes())
}

pub fn dpop_jwk_thumbprint(jwk: &JsonWebKey) -> Result<String> {
    let (crv, x) = jwk
        .ed25519_thumbprint_members()
        .ok_or_else(|| Error::Protocol("DPoP public JWK must be an Ed25519 key".to_owned()))?;
    let thumbprint_object = json!({
        "crv": crv,
        "kty": "OKP",
        "x": x,
    });
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&thumbprint_object)?;
    Ok(arkret_canonical::canonical::sha256_base64url(bytes))
}

pub fn build_dpop_proof(request: &DpopProofRequest, signing_key: &SigningKey) -> Result<DpopProof> {
    if request.method.trim().is_empty() {
        return Err(Error::Protocol("DPoP method must not be empty".to_owned()));
    }
    if request.htu.trim().is_empty() {
        return Err(Error::Protocol("DPoP htu must not be empty".to_owned()));
    }
    if request.jti.trim().is_empty() {
        return Err(Error::Protocol("DPoP jti must not be empty".to_owned()));
    }

    let public_jwk = JsonWebKey::from_ed25519_verifying_key(&signing_key.verifying_key());
    let jkt = dpop_jwk_thumbprint(&public_jwk)?;
    let ath = request.access_token.as_deref().map(dpop_access_token_hash);

    let header = json!({
        "alg": DPOP_PROOF_ALG,
        "jwk": public_jwk,
        "typ": DPOP_PROOF_TYP,
    });
    let mut claims = serde_json::Map::new();
    claims.insert(
        "htm".to_owned(),
        Value::String(request.method.to_uppercase()),
    );
    claims.insert("htu".to_owned(), Value::String(request.htu.clone()));
    claims.insert(
        "iat".to_owned(),
        Value::Number(serde_json::Number::from(request.issued_at.timestamp())),
    );
    claims.insert("jti".to_owned(), Value::String(request.jti.clone()));
    if let Some(ath) = &ath {
        claims.insert("ath".to_owned(), Value::String(ath.clone()));
    }
    if let Some(nonce) = &request.nonce {
        claims.insert("nonce".to_owned(), Value::String(nonce.clone()));
    }

    let header_b64 = arkret_canonical::base64url_encode(
        arkret_canonical::canonical::canonical_json_bytes(&header)?,
    );
    let payload_b64 = arkret_canonical::base64url_encode(
        arkret_canonical::canonical::canonical_json_bytes(&Value::Object(claims))?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let proof_jwt = format!(
        "{signing_input}.{}",
        arkret_canonical::base64url_encode(signature.to_bytes())
    );

    Ok(DpopProof {
        header_value: proof_jwt.clone(),
        proof_jwt,
        public_jwk,
        jkt,
        ath,
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    #[test]
    fn access_token_hash_is_base64url_sha256() {
        let expected = "bSv8AUcFSz0K2drI0GtvZb95JwN4SY-KIMuH228H47Y";
        assert_eq!(dpop_access_token_hash("grant-token"), expected);
        assert_ne!(
            dpop_access_token_hash("grant-token"),
            dpop_access_token_hash("other-token")
        );
    }

    #[test]
    fn dpop_proof_binds_method_htu_key_and_access_token() {
        let key = signing_key();
        let request = DpopProofRequest::new("post", "https://arkret.example/_arkret/self/events")
            .access_token("grant-token")
            .nonce("server-nonce")
            .issued_at(Utc.timestamp_opt(1_780_000_000, 0).unwrap())
            .jti("urn:uuid:01970000-0000-7000-8000-000000000001");

        let proof = build_dpop_proof(&request, &key).unwrap();
        let expected_ath = dpop_access_token_hash("grant-token");
        assert_eq!(proof.proof_jwt, proof.header_value);
        assert_eq!(proof.ath.as_deref(), Some(expected_ath.as_str()));
        assert_eq!(proof.jkt, dpop_jwk_thumbprint(&proof.public_jwk).unwrap());

        let parts: Vec<&str> = proof.proof_jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&arkret_canonical::base64url_decode(parts[0]).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&arkret_canonical::base64url_decode(parts[1]).unwrap()).unwrap();

        assert_eq!(header["typ"], DPOP_PROOF_TYP);
        assert_eq!(header["alg"], DPOP_PROOF_ALG);
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "https://arkret.example/_arkret/self/events");
        assert_eq!(payload["ath"], dpop_access_token_hash("grant-token"));
        assert_eq!(payload["nonce"], "server-nonce");
    }

    #[test]
    fn verifier_checks_full_target_and_access_token() {
        let key = signing_key();
        let now = Utc.timestamp_opt(1_780_000_000, 0).unwrap();
        let proof = build_dpop_proof(
            &DpopProofRequest::new(
                "POST",
                "https://Account.Example/_arkret/self/events?ignored=1#fragment",
            )
            .access_token("grant-token")
            .nonce("server-nonce")
            .issued_at(now)
            .jti("proof-1"),
            &key,
        )
        .unwrap();
        let request = DpopVerificationRequest {
            proof_jwt: &proof.proof_jwt,
            method: "POST",
            htu: "https://account.example/_arkret/self/events",
            access_token: Some("grant-token"),
            expected_nonce: Some("server-nonce"),
            now,
            max_age: chrono::Duration::seconds(300),
            max_future_skew: chrono::Duration::seconds(30),
        };
        let verified = verify_dpop_proof(&request).unwrap();
        assert_eq!(verified.jkt, proof.jkt);

        let wrong_nonce = DpopVerificationRequest {
            expected_nonce: Some("different-nonce"),
            ..request.clone()
        };
        assert_eq!(
            verify_dpop_proof(&wrong_nonce),
            Err(DpopVerificationError::NonceMismatch)
        );

        let wrong_origin = DpopVerificationRequest {
            htu: "https://other.example/_arkret/self/events",
            ..request
        };
        assert_eq!(
            verify_dpop_proof(&wrong_origin),
            Err(DpopVerificationError::TargetUriMismatch)
        );
    }

    #[test]
    fn verifier_rejects_stale_proof() {
        let key = signing_key();
        let now = Utc.timestamp_opt(1_780_000_000, 0).unwrap();
        let proof = build_dpop_proof(
            &DpopProofRequest::new("GET", "https://account.example/_arkret/self")
                .issued_at(now - chrono::Duration::seconds(301))
                .jti("proof-2"),
            &key,
        )
        .unwrap();
        let error = verify_dpop_proof(&DpopVerificationRequest {
            proof_jwt: &proof.proof_jwt,
            method: "GET",
            htu: "https://account.example/_arkret/self",
            access_token: None,
            expected_nonce: None,
            now,
            max_age: chrono::Duration::seconds(300),
            max_future_skew: chrono::Duration::seconds(30),
        })
        .unwrap_err();
        assert_eq!(error, DpopVerificationError::IssuedAtOutOfRange);
    }
}
