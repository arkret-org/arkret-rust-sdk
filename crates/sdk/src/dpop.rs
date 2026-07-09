//! DPoP helper types for session-grant issuance and self-surface requests.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{Error, Result};

pub const DPOP_PROOF_TYP: &str = "dpop+jwt";
pub const DPOP_PROOF_ALG: &str = "EdDSA";
pub const DPOP_JWK_KTY_OKP: &str = "OKP";
pub const DPOP_JWK_CRV_ED25519: &str = "Ed25519";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl DpopJwk {
    pub fn from_ed25519_verifying_key(verifying_key: &VerifyingKey) -> Self {
        Self {
            kty: DPOP_JWK_KTY_OKP.to_owned(),
            crv: DPOP_JWK_CRV_ED25519.to_owned(),
            x: cokret_core::base64url_encode(verifying_key.to_bytes()),
        }
    }
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
    pub public_jwk: DpopJwk,
    pub jkt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

pub fn dpop_access_token_hash(access_token: &str) -> String {
    cokret_core::canonical::sha256_base64url(access_token.as_bytes())
}

pub fn dpop_jwk_thumbprint(jwk: &DpopJwk) -> Result<String> {
    let thumbprint_object = json!({
        "crv": jwk.crv,
        "kty": jwk.kty,
        "x": jwk.x,
    });
    let bytes = cokret_core::canonical::canonical_json_bytes(&thumbprint_object)?;
    Ok(cokret_core::canonical::sha256_base64url(bytes))
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

    let public_jwk = DpopJwk::from_ed25519_verifying_key(&signing_key.verifying_key());
    let jkt = dpop_jwk_thumbprint(&public_jwk)?;
    let ath = request.access_token.as_deref().map(dpop_access_token_hash);

    let header = json!({
        "alg": DPOP_PROOF_ALG,
        "jwk": public_jwk.clone(),
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

    let header_b64 =
        cokret_core::base64url_encode(cokret_core::canonical::canonical_json_bytes(&header)?);
    let payload_b64 = cokret_core::base64url_encode(cokret_core::canonical::canonical_json_bytes(
        &Value::Object(claims),
    )?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let proof_jwt = format!(
        "{signing_input}.{}",
        cokret_core::base64url_encode(signature.to_bytes())
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
        let request = DpopProofRequest::new("post", "https://arkret.example/_cokret/self/events")
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
            serde_json::from_slice(&cokret_core::base64url_decode(parts[0]).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&cokret_core::base64url_decode(parts[1]).unwrap()).unwrap();

        assert_eq!(header["typ"], DPOP_PROOF_TYP);
        assert_eq!(header["alg"], DPOP_PROOF_ALG);
        assert_eq!(header["jwk"]["kty"], DPOP_JWK_KTY_OKP);
        assert_eq!(header["jwk"]["crv"], DPOP_JWK_CRV_ED25519);
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "https://arkret.example/_cokret/self/events");
        assert_eq!(payload["ath"], dpop_access_token_hash("grant-token"));
        assert_eq!(payload["nonce"], "server-nonce");
    }
}
