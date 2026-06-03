//! DID continuity proof payloads.

use super::*;
use crate::ERROR_CODE_SCHEMA_VIOLATION;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DidContinuityPurpose {
    PrincipalMethodUpgrade,
    PrincipalMigration,
    AccountBindingContinuity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DidContinuityOobConfirmationMethod {
    OfflinePaper,
    PhysicalMeet,
    IndependentChannel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum DidContinuitySignatureAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "ECDSA-P256-SHA256")]
    EcdsaP256Sha256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidContinuityTransferEvidence {
    pub old_did_document_canonical_digest: Hash,
    pub old_did_document_fetched_at: DateTime<Utc>,
    pub inception_public_key_fingerprint: Hash,
    pub user_oob_confirmation_id: String,
    pub user_oob_confirmation_method: DidContinuityOobConfirmationMethod,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidContinuitySignatureLink {
    pub principal_id: Did,
    pub verification_method: String,
    pub algorithm: DidContinuitySignatureAlgorithm,
    pub payload_digest: Hash,
    pub signature: String,
}

/// `ck.schema.did_continuity_proof.v1` payload profile for DID method upgrades
/// and account-binding continuity claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidContinuityProof {
    pub schema: String,
    pub old_did: Did,
    pub new_did: Did,
    pub purpose: DidContinuityPurpose,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_did_document_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_did_document_digest: Option<Hash>,
    pub transfer_evidence: DidContinuityTransferEvidence,
    pub signature_chain: Vec<DidContinuitySignatureLink>,
}

impl DidContinuityProof {
    pub const SCHEMA: &'static str = "ck.schema.did_continuity_proof.v1";

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "DID continuity proof schema must be {} ({ERROR_CODE_SCHEMA_VIOLATION})",
                Self::SCHEMA
            )));
        }
        if self.signature_chain.len() < 2 {
            return Err(Error::Protocol(format!(
                "DID continuity proof requires at least two signature_chain links \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if let Some(expires_at) = self.expires_at
            && expires_at <= self.issued_at
        {
            return Err(Error::Protocol(format!(
                "DID continuity proof expires_at must be after issued_at \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        let mut seen_audience = BTreeSet::new();
        for audience in &self.audience {
            if audience.trim().is_empty() || !seen_audience.insert(audience) {
                return Err(Error::Protocol(format!(
                    "DID continuity proof audience entries must be non-empty and unique \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
        }
        if self.transfer_evidence.user_oob_confirmation_id.trim().is_empty() {
            return Err(Error::Protocol(format!(
                "DID continuity proof user_oob_confirmation_id is required \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        for link in &self.signature_chain {
            if !link.verification_method.starts_with("did:")
                || !link.verification_method.contains('#')
            {
                return Err(Error::Protocol(format!(
                    "DID continuity proof verification_method must be a DID URL with fragment \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
            if link.signature.trim().is_empty()
                || link
                    .signature
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            {
                return Err(Error::Protocol(format!(
                    "DID continuity proof signature must be base64url-like \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(value: &str) -> Hash {
        Hash::new(format!("sha256:{value:0<64}")).unwrap()
    }

    fn fixture() -> DidContinuityProof {
        DidContinuityProof {
            schema: DidContinuityProof::SCHEMA.to_owned(),
            old_did: Did::new("did:web:old.example").unwrap(),
            new_did: Did::new("did:webvh:new.example").unwrap(),
            purpose: DidContinuityPurpose::PrincipalMethodUpgrade,
            audience: vec!["ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()],
            issued_at: "2026-04-29T00:00:00Z".parse().unwrap(),
            expires_at: Some("2026-04-30T00:00:00Z".parse().unwrap()),
            old_did_document_digest: Some(hash("a")),
            new_did_document_digest: Some(hash("b")),
            transfer_evidence: DidContinuityTransferEvidence {
                old_did_document_canonical_digest: hash("c"),
                old_did_document_fetched_at: "2026-04-28T23:00:00Z".parse().unwrap(),
                inception_public_key_fingerprint: hash("d"),
                user_oob_confirmation_id: "confirm-1".to_owned(),
                user_oob_confirmation_method:
                    DidContinuityOobConfirmationMethod::IndependentChannel,
            },
            signature_chain: vec![
                DidContinuitySignatureLink {
                    principal_id: Did::new("did:web:old.example").unwrap(),
                    verification_method: "did:web:old.example#key-1".to_owned(),
                    algorithm: DidContinuitySignatureAlgorithm::Ed25519,
                    payload_digest: hash("e"),
                    signature: "old_sig".to_owned(),
                },
                DidContinuitySignatureLink {
                    principal_id: Did::new("did:webvh:new.example").unwrap(),
                    verification_method: "did:webvh:new.example#key-1".to_owned(),
                    algorithm: DidContinuitySignatureAlgorithm::MlDsa65,
                    payload_digest: hash("e"),
                    signature: "new_sig".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn did_continuity_proof_roundtrips_and_validates() {
        let proof = fixture();
        proof.validate_minimal().unwrap();

        let encoded = serde_json::to_value(&proof).unwrap();
        assert_eq!(encoded["schema"], DidContinuityProof::SCHEMA);
        assert_eq!(encoded["signature_chain"][1]["algorithm"], "ML-DSA-65");

        let decoded: DidContinuityProof = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn did_continuity_proof_rejects_short_signature_chain() {
        let mut proof = fixture();
        proof.signature_chain.pop();
        let err = proof.validate_minimal().unwrap_err().to_string();
        assert!(err.contains("at least two signature_chain links"));
    }
}
