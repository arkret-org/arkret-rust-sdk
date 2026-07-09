use arkret_core::DetachedPayloadProof;
use arkret_core::serde_helpers::{deserialize_canonical_timestamp, serialize_canonical_timestamp};

use super::*;

/// Normalized DID key-log operation kind
/// (`did-key-log-entry.schema.json` `operation` enum). The DID
/// method-specific raw operation object travels in
/// [`DidKeyLogEntry::operation_body`]; this discriminator is what the
/// reducer / verifier dispatches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidKeyLogOperation {
    Inception,
    Rotate,
    Recover,
    Deactivate,
    ServiceUpdate,
}

/// Constant-time digest string comparison (service-surface.md §3.1.3 requires
/// constant-time comparison of recomputed digests). Delegates to the single
/// crate-wide [`crate::crypto::constant_time_eq`], which is backed by the
/// audited `subtle` crate (replaces the previous hand-rolled XOR fold).
fn constant_time_digest_eq(a: &crate::Hash, b: &crate::Hash) -> bool {
    crate::crypto::constant_time_eq(a.as_str(), b.as_str())
}

fn placeholder_digest() -> crate::Hash {
    crate::Hash::new(format!("sha256:{}", "0".repeat(64))).expect("static digest literal is valid")
}

/// Append-only DID key-log entry. Mirrors
/// `did-key-log-entry.schema.json` (closed schema): `seq=0` is the
/// inception entry and MUST NOT carry `prev_event_digest`; every
/// `seq>0` entry MUST carry `prev_event_digest` equal to the previous
/// accepted entry's `head_event_digest`. Digest / proof byte semantics
/// are normative in `zh/sync/service-surface.md` §3.1.3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidKeyLogEntry {
    /// DID controlled by this entry.
    pub did: Did,
    /// Monotonic DID method log sequence (zero-based).
    pub seq: u64,
    /// Normalized operation kind.
    pub operation: DidKeyLogOperation,
    /// Digest of the previous accepted entry. Required for `seq>0`,
    /// forbidden for `seq=0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_digest: Option<crate::Hash>,
    /// Self digest of this entry: canonical digest of the entry with
    /// `proofs` and `head_event_digest` removed (§3.1.3).
    pub head_event_digest: crate::Hash,
    /// DID method-specific raw operation object (`minProperties: 1`).
    pub operation_body: serde_json::Map<String, Value>,
    /// Entry creation time (canonical UTC `Z` form on wire).
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    /// Controller proofs over this entry
    /// (`event-envelope.schema.json#/$defs/proof`).
    /// `payload_digest = canonical_digest(entry_without_proofs)`; the
    /// detached JWS signs the canonical binding object of §3.1.3. The
    /// `verification_method` MUST be a controller key authorized for
    /// this operation at the previous accepted entry's state — the
    /// registry host MUST NOT substitute its own key.
    pub proofs: Vec<DetachedPayloadProof>,
}

impl DidKeyLogEntry {
    /// Build an unsigned entry and seal its `head_event_digest`
    /// (§3.1.3: canonical digest of the entry without `proofs` /
    /// `head_event_digest`). Attach controller proofs afterwards via
    /// [`DidKeyLogEntry::attach_controller_proof`].
    pub fn build(
        did: Did,
        seq: u64,
        operation: DidKeyLogOperation,
        prev_event_digest: Option<crate::Hash>,
        operation_body: serde_json::Map<String, Value>,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        let mut entry = Self {
            did,
            seq,
            operation,
            prev_event_digest,
            head_event_digest: placeholder_digest(),
            operation_body,
            created_at,
            proofs: Vec::new(),
        };
        entry.head_event_digest = entry.compute_head_event_digest()?;
        Ok(entry)
    }

    /// JSON view used for digest derivation. `include_head=false` is the
    /// `head_event_digest` transcript (drop `proofs` + `head_event_digest`);
    /// `include_head=true` is the proof `payload_digest` transcript (drop
    /// only `proofs`).
    fn digest_view(&self, include_head: bool) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .expect("DidKeyLogEntry serializes to an object");
        object.remove("proofs");
        if !include_head {
            object.remove("head_event_digest");
        }
        Ok(value)
    }

    /// Recompute `head_event_digest` per §3.1.3.
    pub fn compute_head_event_digest(&self) -> Result<crate::Hash> {
        let bytes = arkret_core::canonical::canonical_json_bytes(&self.digest_view(false)?)?;
        Ok(crate::Hash::new(arkret_core::canonical::sha256_digest(
            &bytes,
        ))?)
    }

    /// Recompute the proof `payload_digest`
    /// (`canonical_digest(entry_without_proofs)`, §3.1.3).
    pub fn proof_payload_digest(&self) -> Result<crate::Hash> {
        let bytes = arkret_core::canonical::canonical_json_bytes(&self.digest_view(true)?)?;
        Ok(crate::Hash::new(arkret_core::canonical::sha256_digest(
            &bytes,
        ))?)
    }

    /// Canonical proof binding object bytes per §3.1.3:
    /// `{payload_digest, did, verification_method, created_at, domain?,
    /// audience?}` in canonical JSON (JCS key order). This is the exact
    /// detached-JWS payload — field-concatenation strings or bare hex
    /// MUST NOT replace this transcript.
    pub fn proof_binding_bytes(&self, proof: &DetachedPayloadProof) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "payload_digest".to_owned(),
            Value::String(proof.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "did".to_owned(),
            Value::String(self.did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(proof.verification_method.clone()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(arkret_core::canonical::format_timestamp_canonical(
                proof.created_at,
            )),
        );
        if let Some(domain) = &proof.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &proof.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        arkret_core::canonical::canonical_json_bytes(&Value::Object(object))
    }

    /// Structural validation against `did-key-log-entry.schema.json` +
    /// the §3.1.3 self-digest rule.
    pub fn validate(&self) -> Result<()> {
        if self.seq == 0 && self.prev_event_digest.is_some() {
            return Err(Error::Protocol(
                "DID key log inception (seq=0) must not carry prev_event_digest".to_owned(),
            ));
        }
        if self.seq > 0 && self.prev_event_digest.is_none() {
            return Err(Error::Protocol(
                "DID key log entry with seq>0 must carry prev_event_digest".to_owned(),
            ));
        }
        if self.operation_body.is_empty() {
            return Err(Error::Protocol(
                "DID key log operation_body must carry at least one property".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "DID key log entry must carry at least one controller proof".to_owned(),
            ));
        }
        let recomputed = self.compute_head_event_digest()?;
        if !constant_time_digest_eq(&recomputed, &self.head_event_digest) {
            return Err(Error::Protocol(
                "DID key log head_event_digest does not match the canonical entry bytes".to_owned(),
            ));
        }
        Ok(())
    }

    /// Sign this entry with the **controller's** Ed25519 key and append
    /// the resulting detached-JWS proof. The SDK never mints
    /// placeholder proofs and never signs with its own or a server key
    /// — `signing_key` MUST be the controller key identified by
    /// `verification_method`, authorized for this operation at the
    /// previous accepted entry's state.
    pub fn attach_controller_proof(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
        verification_method: &str,
    ) -> Result<()> {
        self.head_event_digest = self.compute_head_event_digest()?;
        let mut proof = DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.to_owned(),
            alg: "EdDSA".to_owned(),
            payload_digest: self.proof_payload_digest()?,
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: String::new(),
        };
        let binding_bytes = self.proof_binding_bytes(&proof)?;
        proof.jws =
            crate::jws::sign_jws_ed25519(&binding_bytes, signing_key).map_err(Error::Protocol)?;
        self.proofs.push(proof);
        Ok(())
    }
}

/// Verified DID key-log state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDidKeyLog {
    /// DID controlled by the log.
    pub did: Did,
    /// Sequence number of the latest accepted entry.
    pub seq: u64,
    /// `head_event_digest` of the latest accepted entry.
    pub head: crate::Hash,
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

    let mut prev_head: Option<crate::Hash> = None;
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
            crate::jws::verify_jws_ed25519(
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
/// (`ck.schema.identity_receipt.v1`, `identity-receipt.schema.json`).
/// The registry / witness endorsement of a key-log head travels here —
/// never inside the key-log entry's `proofs[]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRegistryReceipt {
    /// Canonical schema discriminator (`ck.schema.identity_receipt.v1`).
    pub schema: String,
    pub receipt_id: arkret_core::ReceiptId,
    /// DID whose key-log head this receipt witnesses.
    pub did: Did,
    /// Key-log sequence number of the witnessed head.
    pub seq: u64,
    /// Witnessed `head_event_digest` (§3.1.3 self-digest rule).
    pub head_event_digest: crate::Hash,
    /// Issuing registry service DID.
    pub registry_service_did: Did,
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
    /// signature)`; the JWS signs the canonical binding object built
    /// like service-surface.md §3.1.3 with `did =
    /// registry_service_did` (the issuer).
    pub signature: DetachedPayloadProof,
}

impl DidRegistryReceipt {
    pub const SCHEMA: &'static str = "ak.schema.identity_receipt.v1";

    /// Build and sign a receipt with the **registry's** Ed25519 key.
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        receipt_id: arkret_core::ReceiptId,
        did: Did,
        seq: u64,
        head_event_digest: crate::Hash,
        registry_service_did: Did,
        witness_role: IdentityReceiptWitnessRole,
        signing_key: &ed25519_dalek::SigningKey,
        verification_method: &str,
    ) -> Result<Self> {
        let mut receipt = Self {
            schema: Self::SCHEMA.to_owned(),
            receipt_id,
            did,
            seq,
            head_event_digest,
            registry_service_did,
            witness_role,
            audience: None,
            created_at: Utc::now(),
            signature: DetachedPayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: verification_method.to_owned(),
                alg: "EdDSA".to_owned(),
                payload_digest: placeholder_digest(),
                created_at: Utc::now(),
                domain: None,
                audience: None,
                jws: String::new(),
            },
        };
        receipt.signature.payload_digest = receipt.payload_digest()?;
        let binding_bytes = receipt.binding_bytes()?;
        receipt.signature.jws =
            crate::jws::sign_jws_ed25519(&binding_bytes, signing_key).map_err(Error::Protocol)?;
        Ok(receipt)
    }

    /// `canonical_digest(receipt without signature)`.
    pub fn payload_digest(&self) -> Result<crate::Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("DidRegistryReceipt serializes to an object")
            .remove("signature");
        let bytes = arkret_core::canonical::canonical_json_bytes(&value)?;
        Ok(crate::Hash::new(arkret_core::canonical::sha256_digest(
            &bytes,
        ))?)
    }

    fn binding_bytes(&self) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "payload_digest".to_owned(),
            Value::String(self.signature.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "did".to_owned(),
            Value::String(self.registry_service_did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.signature.verification_method.clone()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(arkret_core::canonical::format_timestamp_canonical(
                self.signature.created_at,
            )),
        );
        if let Some(domain) = &self.signature.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.signature.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        arkret_core::canonical::canonical_json_bytes(&Value::Object(object))
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
        let recomputed = self.payload_digest()?;
        if !constant_time_digest_eq(&recomputed, &self.signature.payload_digest) {
            return Err(Error::Protocol(
                "identity receipt payload_digest does not match the canonical receipt bytes"
                    .to_owned(),
            ));
        }
        let binding_bytes = self.binding_bytes()?;
        crate::jws::verify_jws_ed25519(
            &binding_bytes,
            &self.signature.jws,
            &self.signature.verification_method,
            self.registry_service_did.as_str(),
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
        self.document.validate()
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
