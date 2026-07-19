//! Identity-receipt schema artifact counterpart.
//!
//! The remaining device-identity artifact counterparts (cross-signing
//! publish/reset proofs, key-verification content, delivery-binding
//! stale) stay in `arkret-core` because they embed core-only validated
//! string scalars (`NonEmptyString`, `DidUrl`, `Base64UrlString`).

use arkret_wire::{
    Audience, Did, Error, Hash, PayloadProof, ProofContextId, ReceiptId, Result, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Counterpart for `spec/v1/artifacts/schemas/identity-receipt.schema.json`.
pub const IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT: &str = ProofContextId::IDENTITY_RECEIPT_PROOF_V1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct IdentityReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub did: Did,
    pub seq: u64,
    pub head_event_digest: Hash,
    pub registry_service_id: Did,
    pub witness_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(
        serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_wire::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl IdentityReceipt {
    pub const SCHEMA: &'static str = "ak.schema.identity_receipt.v1";

    /// `sha256(canonical_json(receipt with signature omitted))`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("IdentityReceipt serializes to an object")
            .remove("signature");
        let bytes = canonical::canonical_json_bytes(&value)?;
        Ok(Hash::new(canonical::sha256_digest(&bytes))?)
    }

    /// Canonical detached-JWS binding bytes defined by `identity-did.md`
    /// section 4.3.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "context".to_owned(),
            Value::String(IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT.to_owned()),
        );
        object.insert(
            "payload_digest".to_owned(),
            Value::String(self.signature.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "registry_service_id".to_owned(),
            Value::String(self.registry_service_id.as_str().to_owned()),
        );
        object.insert(
            "did".to_owned(),
            Value::String(self.did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.signature.verification_method.clone()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(
                self.signature.created_at,
            )),
        );
        if let Some(domain) = &self.signature.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.signature.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        canonical::canonical_json_bytes(&Value::Object(object)).map_err(Into::into)
    }

    /// Validate the receipt body and the plaintext proof bindings before JWS
    /// verification with the registry service key.
    pub fn validate_proof_binding(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "identity receipt schema '{}' is not {}",
                self.schema,
                Self::SCHEMA
            )));
        }
        ReceiptId::new(self.receipt_id.clone())?;
        if !matches!(self.witness_role.as_str(), "writer" | "witness" | "replica") {
            return Err(Error::Protocol(
                "identity receipt witness_role is not registered".to_owned(),
            ));
        }
        self.signature.validate()?;
        if self.signature.created_at != self.created_at {
            return Err(Error::Protocol(
                "identity receipt proof created_at must equal receipt created_at".to_owned(),
            ));
        }
        let expected_method_prefix = format!("{}#", self.registry_service_id);
        if !self
            .signature
            .verification_method
            .starts_with(&expected_method_prefix)
        {
            return Err(Error::Protocol(
                "identity receipt verification_method must be controlled by registry_service_id"
                    .to_owned(),
            ));
        }
        match (&self.audience, &self.signature.audience) {
            (None, None) => {}
            (Some(expected), Some(Audience::Single(actual))) if expected == actual => {}
            _ => {
                return Err(Error::Protocol(
                    "identity receipt and proof audience must be the same single value".to_owned(),
                ));
            }
        }
        if self.payload_digest()? != self.signature.payload_digest {
            return Err(Error::Protocol(
                "identity receipt payload_digest does not match canonical receipt bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn identity_receipt_uses_non_event_payload_proof() {
        let receipt = json!({
            "schema": "ak.schema.identity_receipt.v1",
            "receipt_id": "ak:receipt:019a6aa0-0000-7000-8000-0000000000cc",
            "did": "did:webvh:z6mkfixture:alice.example",
            "seq": 1,
            "head_event_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry_service_id": "did:webvh:z6mkfixture:registry.example",
            "witness_role": "writer",
            "created_at": "2026-07-15T00:00:00Z",
            "signature": {
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:webvh:z6mkfixture:registry.example#service-key",
                "payload_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-15T00:00:00Z",
                "jws": "a..b"
            }
        });

        let parsed = serde_json::from_value::<IdentityReceipt>(receipt.clone())
            .expect("identity receipt must accept the generic non-Event proof shape");
        let serialized = serde_json::to_value(parsed).expect("identity receipt must serialize");
        assert_eq!(serialized, receipt);

        let mut event_proof = receipt;
        event_proof["signature"]["event_digest"] =
            event_proof["signature"]["payload_digest"].take();
        assert!(serde_json::from_value::<IdentityReceipt>(event_proof).is_err());
    }

    #[test]
    fn identity_receipt_binding_is_context_separated_and_closed() {
        let mut receipt: IdentityReceipt = serde_json::from_value(json!({
            "schema": "ak.schema.identity_receipt.v1",
            "receipt_id": "ak:receipt:019a6aa0-0000-7000-8000-0000000000cc",
            "did": "did:webvh:z6mkfixture:alice.example",
            "seq": 1,
            "head_event_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry_service_id": "did:webvh:z6mkfixture:registry.example",
            "witness_role": "writer",
            "created_at": "2026-07-15T00:00:00Z",
            "signature": {
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:webvh:z6mkfixture:registry.example#service-key",
                "payload_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-15T00:00:00Z",
                "jws": "a..b"
            }
        }))
        .unwrap();
        receipt.signature.payload_digest = receipt.payload_digest().unwrap();
        receipt.validate_proof_binding().unwrap();
        let binding: Value =
            serde_json::from_slice(&receipt.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(binding["context"], IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT);
        assert_eq!(
            binding["registry_service_id"],
            receipt.registry_service_id.as_str()
        );
        assert_eq!(binding["did"], receipt.did.as_str());

        receipt.signature.created_at = "2026-07-15T00:00:01Z".parse().unwrap();
        assert!(receipt.validate_proof_binding().is_err());
    }
}
