use super::*;

/// DID key-log operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DidKeyLogOperation {
    /// Create a DID with initial verification and recovery keys.
    Inception {
        verification_keys: BTreeMap<String, String>,
        recovery_keys: BTreeMap<String, String>,
    },
    /// Rotate verification keys without changing the DID.
    Rotate { verification_keys: BTreeMap<String, String> },
    /// Recover the DID using a recovery key and replace active keys.
    Recover { verification_keys: BTreeMap<String, String>, recovery_keys: BTreeMap<String, String> },
    /// Deactivate the DID.
    Deactivate,
}

/// Append-only DID key-log entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidKeyLogEntry {
    /// Zero-based sequence number.
    pub sequence: u64,
    /// DID controlled by this entry.
    pub did: Did,
    /// Previous entry hash, absent for inception.
    pub previous_hash: Option<String>,
    /// Operation payload.
    pub operation: DidKeyLogOperation,
    /// Verification or recovery key ID that authorizes this entry.
    pub signer: String,
    /// Temporary deterministic test proof.
    pub proof: String,
    /// Entry creation time.
    pub created_at: DateTime<Utc>,
}

impl DidKeyLogEntry {
    /// Build an entry and attach a deterministic test proof with the signer public key.
    pub fn signed(
        sequence: u64,
        did: Did,
        previous_hash: Option<String>,
        operation: DidKeyLogOperation,
        signer: impl Into<String>,
        signer_public_key: &str,
    ) -> Self {
        let signer = signer.into();
        let created_at = Utc::now();
        let proof = did_key_log_proof(
            sequence,
            &did,
            previous_hash.as_deref(),
            &operation,
            &signer,
            created_at,
            signer_public_key,
        );
        Self { sequence, did, previous_hash, operation, signer, proof, created_at }
    }

    /// Stable hash used for chaining entries.
    pub fn entry_hash(&self) -> String {
        sha256_hex(self.signing_payload().as_bytes())
    }

    fn signing_payload(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.sequence,
            self.did,
            self.previous_hash.as_deref().unwrap_or(""),
            operation_payload(&self.operation),
            self.signer,
            self.created_at.to_rfc3339()
        )
    }
}

/// Verified DID key-log state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDidKeyLog {
    /// DID controlled by the log.
    pub did: Did,
    /// Current verification keys.
    pub verification_keys: BTreeMap<String, String>,
    /// Current recovery keys.
    pub recovery_keys: BTreeMap<String, String>,
    /// Latest entry hash.
    pub head: String,
    /// Whether the DID is deactivated.
    pub deactivated: bool,
}

impl VerifiedDidKeyLog {
    /// Convert active state to a DID document.
    pub fn to_document(&self) -> Result<DidDocument> {
        if self.deactivated {
            return Err(Error::Protocol("DID is deactivated".to_owned()));
        }
        let document = DidDocument {
            id: self.did.clone(),
            verification_methods: self.verification_keys.clone(),
            also_known_as: Vec::new(),
            updated_at: Utc::now(),
        };
        document.validate()?;
        Ok(document)
    }
}

/// Verify a DID key-log and return the final state.
pub fn verify_did_key_log(entries: &[DidKeyLogEntry]) -> Result<VerifiedDidKeyLog> {
    let first = entries.first().ok_or_else(|| Error::Protocol("empty DID key log".to_owned()))?;
    let mut state: Option<VerifiedDidKeyLog> = None;
    let mut previous_hash: Option<String> = None;

    for (index, entry) in entries.iter().enumerate() {
        if entry.sequence != index as u64 {
            return Err(Error::Protocol("DID key log sequence gap".to_owned()));
        }
        if entry.did != first.did {
            return Err(Error::Protocol("DID key log changed DID".to_owned()));
        }
        if entry.previous_hash != previous_hash {
            return Err(Error::Protocol("DID key log hash chain mismatch".to_owned()));
        }

        match (&mut state, &entry.operation) {
            (None, DidKeyLogOperation::Inception { verification_keys, recovery_keys }) => {
                ensure_key_set("verification", verification_keys)?;
                let signer_key = verification_keys.get(&entry.signer).ok_or_else(|| {
                    Error::Protocol("inception signer is not a verification key".to_owned())
                })?;
                verify_did_key_log_proof(entry, signer_key)?;
                state = Some(VerifiedDidKeyLog {
                    did: entry.did.clone(),
                    verification_keys: verification_keys.clone(),
                    recovery_keys: recovery_keys.clone(),
                    head: entry.entry_hash(),
                    deactivated: false,
                });
            }
            (None, _) => {
                return Err(Error::Protocol("DID key log must start with inception".to_owned()));
            }
            (Some(_), DidKeyLogOperation::Inception { .. }) => {
                return Err(Error::Protocol("DID key log has duplicate inception".to_owned()));
            }
            (Some(current), DidKeyLogOperation::Rotate { verification_keys }) => {
                ensure_active(current)?;
                ensure_key_set("verification", verification_keys)?;
                let signer_key = current.verification_keys.get(&entry.signer).ok_or_else(|| {
                    Error::Protocol("rotate signer is not an active verification key".to_owned())
                })?;
                verify_did_key_log_proof(entry, signer_key)?;
                current.verification_keys = verification_keys.clone();
                current.head = entry.entry_hash();
            }
            (Some(current), DidKeyLogOperation::Recover { verification_keys, recovery_keys }) => {
                ensure_active(current)?;
                ensure_key_set("verification", verification_keys)?;
                let signer_key = current.recovery_keys.get(&entry.signer).ok_or_else(|| {
                    Error::Protocol("recover signer is not an active recovery key".to_owned())
                })?;
                verify_did_key_log_proof(entry, signer_key)?;
                current.verification_keys = verification_keys.clone();
                current.recovery_keys = recovery_keys.clone();
                current.head = entry.entry_hash();
            }
            (Some(current), DidKeyLogOperation::Deactivate) => {
                ensure_active(current)?;
                let signer_key = current
                    .verification_keys
                    .get(&entry.signer)
                    .or_else(|| current.recovery_keys.get(&entry.signer))
                    .ok_or_else(|| {
                        Error::Protocol("deactivate signer is not an active key".to_owned())
                    })?;
                verify_did_key_log_proof(entry, signer_key)?;
                current.deactivated = true;
                current.head = entry.entry_hash();
            }
        }

        previous_hash = Some(entry.entry_hash());
    }

    state.ok_or_else(|| Error::Protocol("DID key log has no state".to_owned()))
}

/// Compute the temporary deterministic proof for a DID key-log entry.
pub fn did_key_log_proof(
    sequence: u64,
    did: &Did,
    previous_hash: Option<&str>,
    operation: &DidKeyLogOperation,
    signer: &str,
    created_at: DateTime<Utc>,
    signer_public_key: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}",
        sequence,
        did,
        previous_hash.unwrap_or(""),
        operation_payload(operation),
        signer,
        created_at.to_rfc3339()
    );
    sha256_hex(format!("{payload}|{signer_public_key}").as_bytes())
}

/// Signed receipt from an external DID registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidRegistryReceipt {
    pub did: Did,
    pub registry_did: Did,
    pub operation_hash: String,
    pub verification_method: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

impl DidRegistryReceipt {
    /// Build a deterministic signed receipt for tests and local adapters.
    pub fn signed(
        did: Did,
        registry_did: Did,
        operation_hash: impl Into<String>,
        verification_method: impl Into<String>,
        registry_public_key: &str,
    ) -> Self {
        let operation_hash = operation_hash.into();
        let verification_method = verification_method.into();
        let issued_at = Utc::now();
        let signature = did_registry_receipt_signature(
            &did,
            &registry_did,
            &operation_hash,
            &verification_method,
            issued_at,
            registry_public_key,
        );
        Self { did, registry_did, operation_hash, verification_method, issued_at, signature }
    }

    /// Verify this receipt against the registry's public key material.
    pub fn verify(&self, registry_public_key: &str) -> Result<()> {
        if self.operation_hash.trim().is_empty() {
            return Err(Error::Protocol("registry receipt operation hash is empty".to_owned()));
        }
        let expected = did_registry_receipt_signature(
            &self.did,
            &self.registry_did,
            &self.operation_hash,
            &self.verification_method,
            self.issued_at,
            registry_public_key,
        );
        if self.signature != expected {
            return Err(Error::Protocol("invalid registry receipt signature".to_owned()));
        }
        Ok(())
    }
}

/// Compute the deterministic signature binding for a DID registry receipt.
pub fn did_registry_receipt_signature(
    did: &Did,
    registry_did: &Did,
    operation_hash: &str,
    verification_method: &str,
    issued_at: DateTime<Utc>,
    registry_public_key: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        did,
        registry_did,
        operation_hash,
        verification_method,
        issued_at.to_rfc3339()
    );
    sha256_hex(format!("{payload}|{registry_public_key}").as_bytes())
}

/// Resolved StarID/DID registry record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            return Err(Error::Protocol("StarID record document DID mismatch".to_owned()));
        }
        if self.key_log_head.trim().is_empty() {
            return Err(Error::Protocol("StarID record key_log_head is empty".to_owned()));
        }
        if self.current_control_key.trim().is_empty() {
            return Err(Error::Protocol("StarID record current_control_key is empty".to_owned()));
        }
        self.document.validate()
    }
}

/// Request to prove control of a DID resolved from a StarID registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaridControlProofRequest {
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
/// * fail closed on stale or conflicting heads rather than serving cached
///   state.
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
        request: &StaridControlProofRequest,
    ) -> Result<StaridControlProofVerification>;

    fn verify_registry_receipt(
        &self,
        did: &Did,
        registry_public_key: &str,
    ) -> Result<Option<DidRegistryReceipt>> {
        let record = self.resolve_registry_record(did)?;
        if let Some(receipt) = &record.receipt {
            receipt.verify(registry_public_key)?;
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
        Self { registry_did, records: BTreeMap::new() }
    }

    pub fn registry_did(&self) -> &Did {
        &self.registry_did
    }

    pub fn insert(&mut self, record: StaridRegistryRecord) -> Result<()> {
        record.validate()?;
        if record.registry_did != self.registry_did {
            return Err(Error::Protocol("StarID record registry DID mismatch".to_owned()));
        }
        self.records.insert(record.did.clone(), record);
        Ok(())
    }
}

impl DidResolver for InMemoryStaridRegistryAdapter {
    fn supports(&self, did: &Did) -> bool {
        did.is_uuid() || did.method() == "web" || self.records.contains_key(did)
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
        request: &StaridControlProofRequest,
    ) -> Result<StaridControlProofVerification> {
        let record = self.resolve_registry_record(&request.did)?;
        let public_key =
            record.document.verification_methods.get(&request.verification_method).ok_or_else(
                || Error::Protocol("StarID control proof verification method not found".to_owned()),
            )?;
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

