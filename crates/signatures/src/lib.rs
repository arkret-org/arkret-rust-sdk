//! Canonical signatures, proof binding and HTTP message signature helpers.

use chrono::{DateTime, Utc};
use contrix_core::{Audience, Did, Error, Hash, Proof, Result, SignatureBindingPayload, canonical};
use serde::{Deserialize, Serialize};

pub use contrix_core::Proof as ProtocolProof;

pub const PRODUCTION_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES256K", "RS256", "PS256"];
pub const HTTP_MESSAGE_SIGNATURE_PROFILE: &str = "cx.http-message-signature.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetachedSignatureBinding {
    pub payload_hash: Hash,
    pub signer: Did,
    pub verification_method: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

impl DetachedSignatureBinding {
    pub fn from_payload<T: Serialize>(
        payload: &T,
        signer: Did,
        verification_method: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            payload_hash: canonical_payload_hash(payload)?,
            signer,
            verification_method: verification_method.into(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
        })
    }

    pub fn proof_binding_payload(&self) -> SignatureBindingPayload {
        SignatureBindingPayload {
            payload_hash: self.payload_hash.clone(),
            actor_id: self.signer.clone(),
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_hash: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

impl DetachedSignature {
    pub fn from_proof(proof: Proof) -> Self {
        Self {
            kind: proof.kind,
            alg: proof.alg,
            verification_method: proof.verification_method,
            payload_hash: proof.payload_hash,
            created_at: proof.created_at,
            domain: proof.domain,
            audience: proof.audience,
            jws: proof.jws,
        }
    }

    pub fn into_proof(self) -> Proof {
        Proof {
            kind: self.kind,
            alg: self.alg,
            verification_method: self.verification_method,
            payload_hash: self.payload_hash,
            created_at: self.created_at,
            domain: self.domain,
            audience: self.audience,
            jws: self.jws,
        }
    }

    pub fn validate_against(&self, binding: &DetachedSignatureBinding) -> Result<()> {
        self.clone().into_proof().validate_binding(&binding.proof_binding_payload())
    }
}

pub trait DetachedSigner {
    fn sign_detached(&self, binding: &DetachedSignatureBinding) -> Result<DetachedSignature>;
}

pub trait DetachedVerifier {
    fn verify_detached(
        &self,
        binding: &DetachedSignatureBinding,
        signature: &DetachedSignature,
    ) -> Result<SignatureVerification>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub valid: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

pub fn canonical_payload_hash<T: Serialize>(payload: &T) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(payload)?).map_err(Into::into)
}

pub fn validate_production_proof(proof: &Proof) -> Result<()> {
    proof.validate_production()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignatureInput {
    pub method: String,
    pub target_uri: String,
    pub authority: String,
    pub content_digest: String,
    pub origin_service_did: Did,
    pub destination_service_did: Did,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl HttpMessageSignatureInput {
    pub fn validate_time_window(&self, now: DateTime<Utc>) -> Result<()> {
        if self.expires_at <= self.created_at {
            return Err(Error::Protocol(
                "signature expires_at must be after created_at".to_owned(),
            ));
        }
        if now < self.created_at - chrono::Duration::minutes(5) {
            return Err(Error::Protocol(
                "signature created_at is too far in the future".to_owned(),
            ));
        }
        if now > self.expires_at {
            return Err(Error::Protocol("signature has expired".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignature {
    pub key_id: String,
    pub alg: String,
    pub signed_fields: Vec<String>,
    pub signature: String,
}

pub fn http_message_signature_base(input: &HttpMessageSignatureInput) -> String {
    [
        ("@method", input.method.as_str()),
        ("@target-uri", input.target_uri.as_str()),
        ("host", input.authority.as_str()),
        ("content-digest", input.content_digest.as_str()),
        ("x-contrix-origin-service", input.origin_service_did.as_str()),
        ("x-contrix-destination-service", input.destination_service_did.as_str()),
    ]
    .into_iter()
    .map(|(name, value)| format!("\"{name}\": {value}"))
    .chain([
        format!("\"created\": {}", input.created_at.timestamp()),
        format!("\"expires\": {}", input.expires_at.timestamp()),
    ])
    .collect::<Vec<_>>()
    .join("\n")
}

pub fn sign_http_message<F>(
    input: &HttpMessageSignatureInput,
    key_id: impl Into<String>,
    alg: impl Into<String>,
    signer: F,
) -> Result<HttpMessageSignature>
where
    F: Fn(&str) -> Result<String>,
{
    let signature_base = http_message_signature_base(input);
    Ok(HttpMessageSignature {
        key_id: key_id.into(),
        alg: alg.into(),
        signed_fields: vec![
            "@method".to_owned(),
            "@target-uri".to_owned(),
            "host".to_owned(),
            "content-digest".to_owned(),
            "x-contrix-origin-service".to_owned(),
            "x-contrix-destination-service".to_owned(),
            "created".to_owned(),
            "expires".to_owned(),
        ],
        signature: signer(&signature_base)?,
    })
}

pub fn verify_http_message<F>(
    input: &HttpMessageSignatureInput,
    signature: &HttpMessageSignature,
    now: DateTime<Utc>,
    verifier: F,
) -> Result<SignatureVerification>
where
    F: Fn(&str, &HttpMessageSignature) -> Result<bool>,
{
    input.validate_time_window(now)?;
    let signature_base = http_message_signature_base(input);
    Ok(SignatureVerification { valid: verifier(&signature_base, signature)?, warnings: Vec::new() })
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn canonical_payload_hash_matches_sha256_shape() {
        let hash = canonical_payload_hash(&json!({"b": 2, "a": 1})).unwrap();
        assert!(hash.as_str().starts_with("sha256:"));
    }

    #[test]
    fn detached_signature_validates_core_proof_binding() {
        let binding = DetachedSignatureBinding::from_payload(
            &json!({"hello": "world"}),
            did("alice"),
            "did:web:alice.example#key-1",
        )
        .unwrap();
        let signature = DetachedSignature {
            kind: "did".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: binding.verification_method.clone(),
            payload_hash: binding.payload_hash.clone(),
            created_at: binding.created_at,
            domain: None,
            audience: None,
            jws: "sig".to_owned(),
        };

        signature.validate_against(&binding).unwrap();
    }

    #[test]
    fn http_message_signature_binds_inputs_and_expires() {
        let now = Utc::now();
        let input = HttpMessageSignatureInput {
            method: "POST".to_owned(),
            target_uri: "https://b.example/api/v1/federation/push-operations".to_owned(),
            authority: "b.example".to_owned(),
            content_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            origin_service_did: did("a"),
            destination_service_did: did("b"),
            created_at: now,
            expires_at: now + Duration::minutes(5),
        };
        let signature = sign_http_message(&input, "did:web:a.example#key-1", "EdDSA", |base| {
            Ok(canonical::sha256_digest(base))
        })
        .unwrap();

        let verified = verify_http_message(&input, &signature, now, |base, signature| {
            Ok(signature.signature == canonical::sha256_digest(base))
        })
        .unwrap();
        assert!(verified.valid);

        let mut expired = input;
        expired.expires_at = now - Duration::seconds(1);
        assert!(verify_http_message(&expired, &signature, now, |_, _| Ok(true)).is_err());
    }
}
