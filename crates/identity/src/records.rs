use arkret_canonical::serde_helpers::{
    deserialize_canonical_timestamp, serialize_canonical_timestamp,
};
use arkret_models_identity::DetachedPayloadProof;

use super::*;

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

/// Sign a DID key-log entry with the controller key and append the detached proof.
pub fn attach_did_key_log_controller_proof(
    entry: &mut DidKeyLogEntry,
    signing_key: &ed25519_dalek::SigningKey,
    verification_method: &str,
) -> Result<()> {
    entry.head_event_digest = entry.compute_head_event_digest()?;
    let mut proof = DetachedPayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.to_owned(),
        alg: "EdDSA".to_owned(),
        payload_digest: entry.proof_payload_digest()?,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: String::new(),
    };
    let binding_bytes = entry.proof_binding_bytes(&proof)?;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(&binding_bytes, signing_key)
        .map_err(Error::Protocol)?;
    entry.proofs.push(proof);
    Ok(())
}

/// Verified DID key-log state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDidKeyLog {
    /// DID controlled by the log.
    pub did: Did,
    /// Sequence number of the latest accepted entry.
    pub seq: u64,
    /// `head_event_digest` of the latest accepted entry.
    pub head: Hash,
    /// Whether the DID is deactivated.
    pub deactivated: bool,
}

/// Verify a DID key-log per `did-key-log-entry.schema.json` and the
/// §3.1.3 verifier order: for each entry, first recompute and
/// constant-time-compare `head_event_digest` / `proof.payload_digest`,
/// then rebuild the canonical binding object and verify the Ed25519
/// detached JWS via `resolver`. Any failure rejects the entry and the
/// remainder of the chain.
///
/// Method-specific signer authorization (the proof
/// `verification_method` being a controller key valid for the
/// operation at the *previous* accepted entry's state) is dispatched
/// by DID method and `operation_body`; callers MUST enforce it in the
/// supplied resolver / method layer — this generic verifier checks
/// chain shape and proof cryptography only.
pub fn verify_did_key_log(
    entries: &[DidKeyLogEntry],
    resolver: &dyn DidResolver,
) -> Result<VerifiedDidKeyLog> {
    let first = entries
        .first()
        .ok_or_else(|| Error::Protocol("empty DID key log".to_owned()))?;
    if first.operation != DidKeyLogOperation::Inception {
        return Err(Error::Protocol(
            "DID key log must start with inception".to_owned(),
        ));
    }

    let mut prev_head: Option<Hash> = None;
    let mut deactivated = false;

    for (index, entry) in entries.iter().enumerate() {
        if entry.seq != index as u64 {
            return Err(Error::Protocol("DID key log sequence gap".to_owned()));
        }
        if entry.did != first.did {
            return Err(Error::Protocol("DID key log changed DID".to_owned()));
        }
        if deactivated {
            return Err(Error::Protocol(
                "DID key log continues after deactivate".to_owned(),
            ));
        }
        if index > 0 && entry.operation == DidKeyLogOperation::Inception {
            return Err(Error::Protocol(
                "DID key log has duplicate inception".to_owned(),
            ));
        }

        entry.validate()?;

        match (&entry.prev_event_digest, &prev_head) {
            (None, None) => {}
            (Some(prev), Some(head)) if constant_time_digest_eq(prev, head) => {}
            _ => {
                return Err(Error::Protocol(
                    "DID key log hash chain mismatch".to_owned(),
                ));
            }
        }

        let payload_digest = entry.proof_payload_digest()?;
        for proof in &entry.proofs {
            if proof.kind != "detached_jws" {
                return Err(Error::Protocol(format!(
                    "DID key log proof kind '{}' is not detached_jws",
                    proof.kind
                )));
            }
            if proof.alg != "EdDSA" {
                // Fail closed: this verifier implements Ed25519 only.
                return Err(Error::Protocol(format!(
                    "DID key log proof alg '{}' is not supported by this verifier",
                    proof.alg
                )));
            }
            if !constant_time_digest_eq(&payload_digest, &proof.payload_digest) {
                return Err(Error::Protocol(
                    "DID key log proof payload_digest does not match the canonical entry bytes"
                        .to_owned(),
                ));
            }
            let binding_bytes = entry.proof_binding_bytes(proof)?;
            jws::verify_jws_ed25519(
                &binding_bytes,
                &proof.jws,
                &proof.verification_method,
                entry.did.as_str(),
                resolver,
            )
            .map_err(|err| Error::Protocol(err.to_string()))?;
        }

        if entry.operation == DidKeyLogOperation::Deactivate {
            deactivated = true;
        }
        prev_head = Some(entry.head_event_digest.clone());
    }

    Ok(VerifiedDidKeyLog {
        did: first.did.clone(),
        seq: entries.len() as u64 - 1,
        head: prev_head.expect("non-empty chain has a head"),
        deactivated,
    })
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
    pub registry_service_id: Did,
    pub witness_role: IdentityReceiptWitnessRole,
    /// Optional audience binding; verifiers MUST reject the receipt
    /// outside this audience context when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    /// Generic detached-JWS proof
    /// (`event-envelope.schema.json#/$defs/proof`) by the registry
    /// service key. `payload_digest = canonical_digest(receipt without
    /// signature)`; the JWS signs the `ak.identity-receipt-proof-v1`
    /// binding object defined by identity-did.md section 4.3.
    pub signature: DetachedPayloadProof,
}

impl DidRegistryReceipt {
    pub const SCHEMA: &'static str = "ak.schema.identity_receipt.v1";

    /// Build and sign a receipt with the **registry's** Ed25519 key.
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        receipt_id: arkret_wire::ReceiptId,
        did: Did,
        seq: u64,
        head_event_digest: Hash,
        registry_service_id: Did,
        witness_role: IdentityReceiptWitnessRole,
        signing_key: &ed25519_dalek::SigningKey,
        verification_method: &str,
    ) -> Result<Self> {
        let created_at = Utc::now();
        let mut receipt = Self {
            schema: Self::SCHEMA.to_owned(),
            receipt_id,
            did,
            seq,
            head_event_digest,
            registry_service_id,
            witness_role,
            audience: None,
            created_at,
            signature: DetachedPayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: verification_method.to_owned(),
                alg: "EdDSA".to_owned(),
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
                .map_err(Error::Protocol)?;
        Ok(receipt)
    }

    /// `canonical_digest(receipt without signature)`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("DidRegistryReceipt serializes to an object")
            .remove("signature");
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

    /// Verify the receipt: digest recompute (constant-time compare) then
    /// detached-JWS verification with the registry key resolved via
    /// `resolver`.
    pub fn verify(&self, resolver: &dyn DidResolver) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "identity receipt schema '{}' is not {}",
                self.schema,
                Self::SCHEMA
            )));
        }
        if self.signature.kind != "detached_jws" {
            return Err(Error::Protocol(
                "identity receipt proof kind must be detached_jws".to_owned(),
            ));
        }
        if self.signature.created_at != self.created_at {
            return Err(Error::Protocol(
                "identity receipt proof created_at must equal receipt created_at".to_owned(),
            ));
        }
        match (&self.audience, &self.signature.audience) {
            (None, None) => {}
            (Some(expected), Some(arkret_wire::Audience::Single(actual))) if expected == actual => {
            }
            _ => {
                return Err(Error::Protocol(
                    "identity receipt and proof audience must be the same single value".to_owned(),
                ));
            }
        }
        let recomputed = self.payload_digest()?;
        if !constant_time_digest_eq(&recomputed, &self.signature.payload_digest) {
            return Err(Error::Protocol(
                "identity receipt payload_digest does not match the canonical receipt bytes"
                    .to_owned(),
            ));
        }
        let binding_bytes = self.binding_bytes()?;
        jws::verify_jws_ed25519(
            &binding_bytes,
            &self.signature.jws,
            &self.signature.verification_method,
            self.registry_service_id.as_str(),
            resolver,
        )
        .map_err(|err| Error::Protocol(err.to_string()))
    }
}

/// Resolved StarID/DID registry record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaridRegistryRecord {
    pub did: Did,
    pub registry_did: Did,
    pub document: DidDocument,
    pub key_log_head: String,
    pub current_control_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DidRegistryReceipt>,
    pub resolved_at: DateTime<Utc>,
}

impl StaridRegistryRecord {
    pub fn validate(&self) -> Result<()> {
        if self.did != self.document.id {
            return Err(Error::Protocol(
                "StarID record document DID mismatch".to_owned(),
            ));
        }
        if self.key_log_head.trim().is_empty() {
            return Err(Error::Protocol(
                "StarID record key_log_head is empty".to_owned(),
            ));
        }
        if self.current_control_key.trim().is_empty() {
            return Err(Error::Protocol(
                "StarID record current_control_key is empty".to_owned(),
            ));
        }
        Ok(self.document.validate()?)
    }
}

/// Request to prove control of a DID resolved from a StarID registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaridControlProofRequestBody {
    pub did: Did,
    pub verification_method: String,
    pub challenge: String,
    pub proof: String,
}

/// Verified DID control proof result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaridControlProofVerification {
    pub did: Did,
    pub verification_method: String,
    pub verified_at: DateTime<Utc>,
}

/// Compute the deterministic StarID control proof used by local test adapters.
pub fn starid_control_proof(
    did: &Did,
    verification_method: &str,
    challenge: &str,
    public_key: &str,
) -> String {
    sha256_hex(format!("{did}|{verification_method}|{challenge}|{public_key}").as_bytes())
}

/// Registry-backed DID resolver boundary for StarID-style deployments.
///
/// The trait is the stable SDK boundary; concrete production adapters live
/// outside this crate so the SDK does not pull in an HTTP client by default.
/// Implementors MUST:
///
/// * fetch from the configured registry network with explicit timeouts,
/// * enforce response size and content-type limits,
/// * validate signed key-log receipts before trusting any record, and
/// * fail closed on stale or conflicting heads rather than serving cached state.
pub trait StaridRegistryAdapter: DidResolver {
    fn resolve_registry_record(&self, did: &Did) -> Result<StaridRegistryRecord>;

    fn current_key_log_head(&self, did: &Did) -> Result<String> {
        Ok(self.resolve_registry_record(did)?.key_log_head)
    }

    fn current_control_key(&self, did: &Did) -> Result<String> {
        Ok(self.resolve_registry_record(did)?.current_control_key)
    }

    fn verify_control_proof(
        &self,
        request: &StaridControlProofRequestBody,
    ) -> Result<StaridControlProofVerification>;

    fn verify_registry_receipt(
        &self,
        did: &Did,
        resolver: &dyn DidResolver,
    ) -> Result<Option<DidRegistryReceipt>> {
        let record = self.resolve_registry_record(did)?;
        if let Some(receipt) = &record.receipt {
            receipt.verify(resolver)?;
        }
        Ok(record.receipt)
    }
}

/// In-memory StarID adapter for tests and offline development.
#[derive(Clone, Debug)]
pub struct InMemoryStaridRegistryAdapter {
    registry_did: Did,
    records: BTreeMap<Did, StaridRegistryRecord>,
}

impl InMemoryStaridRegistryAdapter {
    pub fn new(registry_did: Did) -> Self {
        Self {
            registry_did,
            records: BTreeMap::new(),
        }
    }

    pub fn registry_did(&self) -> &Did {
        &self.registry_did
    }

    pub fn insert(&mut self, record: StaridRegistryRecord) -> Result<()> {
        record.validate()?;
        if record.registry_did != self.registry_did {
            return Err(Error::Protocol(
                "StarID record registry DID mismatch".to_owned(),
            ));
        }
        self.records.insert(record.did.clone(), record);
        Ok(())
    }
}

impl DidResolver for InMemoryStaridRegistryAdapter {
    fn supports(&self, did: &Did) -> bool {
        matches!(did.method(), "web" | "webvh") || self.records.contains_key(did)
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        Ok(self.resolve_registry_record(did)?.document)
    }
}

impl StaridRegistryAdapter for InMemoryStaridRegistryAdapter {
    fn resolve_registry_record(&self, did: &Did) -> Result<StaridRegistryRecord> {
        self.records
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("StarID registry record not found".to_owned()))
    }

    fn verify_control_proof(
        &self,
        request: &StaridControlProofRequestBody,
    ) -> Result<StaridControlProofVerification> {
        let record = self.resolve_registry_record(&request.did)?;
        let public_key = record
            .document
            .verification_methods
            .get(&request.verification_method)
            .ok_or_else(|| {
                Error::Protocol("StarID control proof verification method not found".to_owned())
            })?;
        let expected = starid_control_proof(
            &request.did,
            &request.verification_method,
            &request.challenge,
            public_key,
        );
        if request.proof != expected {
            return Err(Error::Protocol("invalid StarID control proof".to_owned()));
        }
        Ok(StaridControlProofVerification {
            did: request.did.clone(),
            verification_method: request.verification_method.clone(),
            verified_at: Utc::now(),
        })
    }
}
