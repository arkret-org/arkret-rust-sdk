use arkret_canonical::serde_helpers::canonical_timestamp;
use arkret_models_identity::DetachedPayloadProof;
use arkret_wire::{Did, DidCoreId, project_did_to_core_id};

use super::*;
use crate::verification_method_did;

fn constant_time_digest_eq(a: &Hash, b: &Hash) -> bool {
    constant_time_eq(a.as_str(), b.as_str())
}

/// Constant-time string comparison backed by the audited `subtle` crate.
///
/// Both inputs are reduced to a fixed-length SHA-256 digest first so the
/// comparison loop bound never depends on the secret's length, then compared
/// with `subtle::ConstantTimeEq`.
fn constant_time_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    let left = arkret_canonical::canonical::sha256_bytes(left.as_bytes());
    let right = arkret_canonical::canonical::sha256_bytes(right.as_bytes());
    left.ct_eq(&right).into()
}

fn placeholder_digest() -> Hash {
    Hash::new(format!("sha256:{}", "0".repeat(64))).expect("static digest literal is valid")
}

/// Issuer role inside the DID registry consensus group
/// (`identity-receipt.schema.json` `witness_role` enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityReceiptWitnessRole {
    Writer,
    Witness,
    Replica,
}

/// Signed identity receipt from a DID registry
/// (`ak.schema.identity_receipt.v1`, `identity-receipt.schema.json`).
/// The registry / witness endorsement of a key-log head travels here —
/// never inside the key-log entry's `proofs[]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRegistryReceipt {
    /// Canonical schema discriminator (`ak.schema.identity_receipt.v1`).
    pub schema: String,
    pub receipt_id: arkret_wire::ReceiptId,
    /// DID whose key-log head this receipt witnesses.
    pub did: Did,
    /// Key-log sequence number of the witnessed head.
    pub seq: u64,
    /// Witnessed `head_event_digest` (§3.1.3 self-digest rule).
    pub head_event_digest: Hash,
    /// Issuing registry service DID.
    pub registry_id: DidCoreId,
    pub witness_role: IdentityReceiptWitnessRole,
    /// Optional audience binding; verifiers MUST reject the receipt
    /// outside this audience context when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Generic detached-JWS proof
    /// (`event-envelope.schema.json#/$defs/proof`) by the registry
    /// service key. `payload_digest = canonical_digest(receipt without
    /// signature)`; the JWS signs the `ak.identity_receipt_proof.v1`
    /// binding object defined by identity-did.md section 4.3.
    pub signature: DetachedPayloadProof,
}

impl DidRegistryReceipt {
    /// Build and sign a receipt with the **registry's** Ed25519 key.
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        receipt_id: arkret_wire::ReceiptId,
        did: Did,
        seq: u64,
        head_event_digest: Hash,
        registry_id: DidCoreId,
        witness_role: IdentityReceiptWitnessRole,
        signing_key: &ed25519_dalek::SigningKey,
        verification_method: &DidUrl,
    ) -> Result<Self> {
        let created_at = Utc::now();
        let mut receipt = Self {
            schema: arkret_wire::SchemaId::IDENTITY_RECEIPT_V1.to_owned(),
            receipt_id,
            did,
            seq,
            head_event_digest,
            registry_id,
            witness_role,
            audience: None,
            created_at,
            signature: DetachedPayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: verification_method.clone(),
                payload_digest: placeholder_digest(),
                created_at,
                domain: None,
                audience: None,
                jws: String::new(),
            },
        };
        receipt.signature.payload_digest = receipt.payload_digest()?;
        let binding_bytes = receipt.binding_bytes()?;
        receipt.signature.jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding_bytes, signing_key)
                .map_err(IdentityError::Protocol)?;
        Ok(receipt)
    }

    /// `canonical_digest(receipt without signature)`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let value = arkret_canonical::canonical::unsigned_value(self, &["signature"])?;
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&value)?;
        Ok(Hash::new(arkret_canonical::canonical::sha256_digest(
            &bytes,
        ))?)
    }

    fn binding_bytes(&self) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "context".to_owned(),
            Value::String(
                arkret_models_identity::IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT.to_owned(),
            ),
        );
        object.insert(
            "payload_digest".to_owned(),
            Value::String(self.signature.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "registry_id".to_owned(),
            Value::String(self.registry_id.as_str().to_owned()),
        );
        object.insert(
            "did".to_owned(),
            Value::String(self.did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.signature.verification_method.as_str().to_owned()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(arkret_canonical::canonical::format_timestamp_canonical(
                self.signature.created_at,
            )),
        );
        if let Some(domain) = &self.signature.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.signature.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(arkret_canonical::canonical::canonical_json_bytes(
            &Value::Object(object),
        )?)
    }

    /// Resolve the registry authority document, then verify the receipt against
    /// its current `assertionMethod` relationship.
    pub fn verify(&self, resolver: &dyn DidResolver) -> Result<()> {
        let registry_did = verification_method_did(self.signature.verification_method.as_str())?;
        let projected = project_did_to_core_id(&registry_did)?;
        if projected.as_str() != self.registry_id.as_str() {
            return Err(IdentityError::Protocol(
                "identity receipt registry_id does not match proof controller".to_owned(),
            ));
        }
        let document = resolver.resolve_did_document(&registry_did)?;
        self.verify_with_document_and_did(&document, &registry_did)
    }

    /// Verify against an already-pinned current registry authority document.
    ///
    /// The method must be active in `assertionMethod`. An externally-named
    /// method is accepted only when its verification-method object explicitly
    /// declares `controller == registry_id`.
    pub fn verify_with_document(&self, document: &DidDocument) -> Result<()> {
        let registry_did = document.id.clone();
        self.verify_with_document_and_did(document, &registry_did)
    }

    fn verify_with_document_and_did(
        &self,
        document: &DidDocument,
        registry_did: &Did,
    ) -> Result<()> {
        if project_did_to_core_id(registry_did)?.as_str() != self.registry_id.as_str() {
            return Err(IdentityError::Protocol(
                "identity receipt registry_id does not match proof controller".to_owned(),
            ));
        }
        if self.schema != arkret_wire::SchemaId::IDENTITY_RECEIPT_V1 {
            return Err(IdentityError::Protocol(format!(
                "identity receipt schema '{}' is not {}",
                self.schema,
                arkret_wire::SchemaId::IDENTITY_RECEIPT_V1
            )));
        }
        if self.signature.kind != "detached_jws" {
            return Err(IdentityError::Protocol(
                "identity receipt proof kind must be detached_jws".to_owned(),
            ));
        }
        if self.signature.created_at != self.created_at {
            return Err(IdentityError::Protocol(
                "identity receipt proof created_at must equal receipt created_at".to_owned(),
            ));
        }
        match (&self.audience, &self.signature.audience) {
            (None, None) => {}
            (Some(expected), Some(arkret_wire::Audience::Single(actual))) if expected == actual => {
            }
            _ => {
                return Err(IdentityError::Protocol(
                    "identity receipt and proof audience must be the same single value".to_owned(),
                ));
            }
        }
        let recomputed = self.payload_digest()?;
        if !constant_time_digest_eq(&recomputed, &self.signature.payload_digest) {
            return Err(IdentityError::Protocol(
                "identity receipt payload_digest does not match the canonical receipt bytes"
                    .to_owned(),
            ));
        }
        let binding_bytes = self.binding_bytes()?;
        verify_jws_with_document_relationship(
            &binding_bytes,
            &self.signature.jws,
            &self.signature.verification_method,
            registry_did,
            document,
            DidVerificationRelationship::AssertionMethod,
        )
        .map_err(|err| IdentityError::Protocol(err.to_string()))
    }
}
