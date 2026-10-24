//! Signing and native DID verification for the sole canonical IdentityReceipt.

use arkret_canonical::serde_helpers::canonical_timestamp;
pub use arkret_models_identity::{IdentityReceipt, IdentityReceiptWitnessRole};
use arkret_wire::{Did, DidCoreId, UnsignedPayloadProof, project_did_to_core_id};

use super::*;
use crate::verification_method_did;

#[derive(Serialize)]
struct IdentityReceiptSigningFields<'a> {
    schema: &'a str,
    receipt_id: &'a str,
    subject_did: &'a Did,
    sequence: u64,
    accepted_entry_digest: &'a Hash,
    registry_id: &'a DidCoreId,
    witness_role: IdentityReceiptWitnessRole,
    #[serde(with = "canonical_timestamp")]
    created_at: DateTime<Utc>,
}

pub trait IdentityReceiptExt {
    #[allow(clippy::too_many_arguments)]
    fn signed(
        receipt_id: arkret_wire::ReceiptId,
        did: Did,
        sequence: u64,
        accepted_entry_digest: Hash,
        registry_id: DidCoreId,
        witness_role: IdentityReceiptWitnessRole,
        signing_key: &ed25519_dalek::SigningKey,
        verification_method: &DidUrl,
    ) -> Result<Self>
    where
        Self: Sized;
    fn verify(&self, resolver: &dyn DidResolver) -> Result<()>;
    fn verify_with_document(&self, document: &DidDocument) -> Result<()>;
}

impl IdentityReceiptExt for IdentityReceipt {
    fn signed(
        receipt_id: arkret_wire::ReceiptId,
        did: Did,
        sequence: u64,
        accepted_entry_digest: Hash,
        registry_id: DidCoreId,
        witness_role: IdentityReceiptWitnessRole,
        signing_key: &ed25519_dalek::SigningKey,
        verification_method: &DidUrl,
    ) -> Result<Self> {
        let created_at = Utc::now();
        let receipt_id = receipt_id.to_string();
        let fields = IdentityReceiptSigningFields {
            schema: arkret_wire::SchemaId::IDENTITY_RECEIPT_V1,
            receipt_id: &receipt_id,
            subject_did: &did,
            sequence,
            accepted_entry_digest: &accepted_entry_digest,
            registry_id: &registry_id,
            witness_role,
            created_at,
        };
        let proof = UnsignedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: Hash::new(arkret_canonical::canonical::canonical_sha256(&fields)?)?,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
        };
        let binding = arkret_models_identity::identity_receipt_proof_binding_bytes(
            &registry_id,
            &did,
            &proof,
        )?;
        let jws = arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key)
            .map_err(IdentityError::Protocol)?;
        let receipt = Self {
            schema: arkret_wire::SchemaId::IDENTITY_RECEIPT_V1.to_owned(),
            receipt_id,
            subject_did: did,
            sequence,
            accepted_entry_digest,
            registry_id,
            witness_role,
            audience: None,
            created_at,
            signature: proof.finalize(jws)?,
        };
        receipt.validate_proof_binding()?;
        Ok(receipt)
    }

    fn verify(&self, resolver: &dyn DidResolver) -> Result<()> {
        let registry_did = verification_method_did(self.signature.verification_method.as_str())?;
        if project_did_to_core_id(&registry_did)? != self.registry_id {
            return Err(IdentityError::Protocol(
                "identity receipt registry_id does not match proof controller".to_owned(),
            ));
        }
        let document = resolver.resolve_did_document(&registry_did)?;
        verify_receipt_with_document(self, &document, &registry_did)
    }

    fn verify_with_document(&self, document: &DidDocument) -> Result<()> {
        verify_receipt_with_document(self, document, &document.id)
    }
}

fn verify_receipt_with_document(
    receipt: &IdentityReceipt,
    document: &DidDocument,
    registry_did: &Did,
) -> Result<()> {
    receipt.validate_proof_binding()?;
    if project_did_to_core_id(registry_did)? != receipt.registry_id {
        return Err(IdentityError::Protocol(
            "identity receipt registry_id does not match proof controller".to_owned(),
        ));
    }
    verify_jws_with_document_relationship(
        &receipt.proof_binding_bytes()?,
        &receipt.signature.jws,
        &receipt.signature.verification_method,
        registry_did,
        document,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|err| IdentityError::Protocol(err.to_string()))
}
