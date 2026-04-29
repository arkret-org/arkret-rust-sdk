//! DID, DID document and handle management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Did, Error, Result};

pub const DID_WEB_MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Resolve DID documents for one or more DID methods.
pub trait DidResolver {
    /// Return whether this resolver can handle the DID method or concrete DID.
    fn supports(&self, did: &Did) -> bool;

    /// Resolve a DID document.
    fn resolve_did(&self, did: &Did) -> Result<DidDocument>;
}

/// Minimal DID document model used by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// DID subject.
    pub id: Did,
    /// Verification methods by key ID.
    pub verification_methods: BTreeMap<String, String>,
    /// Also-known-as handles or URLs.
    pub also_known_as: Vec<String>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

impl DidDocument {
    /// Create a DID document with one key.
    pub fn new(id: Did, key_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            id,
            verification_methods: BTreeMap::from([(key_id.into(), public_key.into())]),
            also_known_as: Vec::new(),
            updated_at: Utc::now(),
        }
    }

    /// Validate required DID document fields.
    pub fn validate(&self) -> Result<()> {
        if self.verification_methods.is_empty() {
            return Err(Error::Protocol("did document has no verification methods".to_owned()));
        }
        Ok(())
    }

    /// Return the DID method (e.g., `"uuid"`, `"web"`, `"key"`).
    pub fn method(&self) -> &str {
        let remainder = &self.id.as_str()[4..];
        remainder.split(':').next().unwrap_or("")
    }

    /// Return all key IDs and their public key material.
    pub fn control_keys(&self) -> &BTreeMap<String, String> {
        &self.verification_methods
    }

    /// Return the first verification method (key ID, public key), if any.
    pub fn primary_key(&self) -> Option<(&str, &str)> {
        self.verification_methods.iter().next().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Return `also_known_as` entries that look like handles (not URLs).
    pub fn handles(&self) -> Vec<&str> {
        self.also_known_as
            .iter()
            .filter(|entry| !entry.starts_with("http://") && !entry.starts_with("https://"))
            .map(String::as_str)
            .collect()
    }

    /// Return `also_known_as` entries that are URLs.
    pub fn service_urls(&self) -> Vec<&str> {
        self.also_known_as
            .iter()
            .filter(|entry| entry.starts_with("http://") || entry.starts_with("https://"))
            .map(String::as_str)
            .collect()
    }
}

/// In-memory resolver for registered `did:uuid` documents.
#[derive(Clone, Debug, Default)]
pub struct DidUuidResolver {
    documents: BTreeMap<Did, DidDocument>,
}

impl DidUuidResolver {
    /// Create an empty `did:uuid` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `did:uuid` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if !document.id.is_uuid() {
            return Err(Error::Protocol("did:uuid resolver only accepts did:uuid".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }
}

impl DidResolver for DidUuidResolver {
    fn supports(&self, did: &Did) -> bool {
        did.is_uuid()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol("unsupported DID method for did:uuid resolver".to_owned()));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:uuid document not found".to_owned()))
    }
}

/// Limited `did:web` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidWebResolver {
    documents: BTreeMap<Did, DidDocument>,
}

/// Host-fetched `did:web` document response validated by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebDocumentResponse {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl DidWebResolver {
    /// Create an empty `did:web` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a limited `did:web` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "web" || did_web_document_url(&document.id).is_none() {
            return Err(Error::Protocol("unsupported did:web form".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// Return the HTTPS DID document URL for the limited supported form.
    pub fn document_url(did: &Did) -> Result<String> {
        did_web_document_url(did)
            .ok_or_else(|| Error::Protocol("unsupported did:web form".to_owned()))
    }

    /// Validate a host-fetched HTTPS response and cache the DID document.
    pub fn insert_from_https_response(
        &mut self,
        did: &Did,
        response: DidWebDocumentResponse,
    ) -> Result<DidDocument> {
        let expected_url = Self::document_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol("did:web response URL mismatch".to_owned()));
        }
        if !is_allowed_did_web_content_type(&response.content_type) {
            return Err(Error::Protocol("unsupported did:web content type".to_owned()));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES {
            return Err(Error::Protocol("did:web document exceeds size limit".to_owned()));
        }
        let document: DidDocument = serde_json::from_slice(&response.body)?;
        if &document.id != did {
            return Err(Error::Protocol("did:web document id mismatch".to_owned()));
        }
        self.insert(document.clone())?;
        Ok(document)
    }
}

impl DidResolver for DidWebResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "web" && did_web_document_url(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol("unsupported DID method for did:web resolver".to_owned()));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:web document not found".to_owned()))
    }
}

/// Limited `did:keri` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidKeriResolver {
    documents: BTreeMap<Did, DidDocument>,
}

impl DidKeriResolver {
    /// Create an empty `did:keri` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `did:keri` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "keri" {
            return Err(Error::Protocol("did:keri resolver only accepts did:keri".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }
}

impl DidResolver for DidKeriResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "keri"
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol("unsupported DID method for did:keri resolver".to_owned()));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:keri document not found".to_owned()))
    }
}

/// Resolver for `did:key` identifiers with base58btc multicodec validation.
#[derive(Clone, Debug, Default)]
pub struct DidKeyResolver;

impl DidKeyResolver {
    /// Create a `did:key` resolver.
    pub fn new() -> Self {
        Self
    }
}

impl DidResolver for DidKeyResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "key" && did_key_material(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        let key = did_key_material(did)
            .ok_or_else(|| Error::Protocol("unsupported did:key form".to_owned()))?;
        Ok(DidDocument::new(did.clone(), format!("{}#{key}", did.as_str()), key))
    }
}

/// Resolver that tries registered adapters in order.
#[derive(Default)]
pub struct CompositeDidResolver {
    resolvers: Vec<Box<dyn DidResolver + Send + Sync>>,
}

impl CompositeDidResolver {
    /// Create an empty resolver chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a resolver adapter.
    pub fn push<R>(&mut self, resolver: R)
    where
        R: DidResolver + Send + Sync + 'static,
    {
        self.resolvers.push(Box::new(resolver));
    }
}

impl std::fmt::Debug for CompositeDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeDidResolver")
            .field("resolver_count", &self.resolvers.len())
            .finish()
    }
}

impl DidResolver for CompositeDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.resolvers.iter().any(|resolver| resolver.supports(did))
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        self.resolvers
            .iter()
            .find(|resolver| resolver.supports(did))
            .ok_or_else(|| Error::Protocol("unsupported DID method".to_owned()))?
            .resolve_did(did)
    }
}

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
/// TODO: production adapters must fetch from the configured registry network,
/// enforce response size/content-type limits, validate signed key-log receipts
/// and fail closed on stale or conflicting heads. This trait intentionally
/// captures the stable SDK API before binding to a concrete HTTP client.
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

/// Visibility scope for a DID.
///
/// Controls whether a DID is globally public, scoped to a specific peer
/// relationship (pairwise), or private to the local device/user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidVisibility {
    /// DID is globally resolvable and publicly visible.
    Public,
    /// DID is scoped to a specific peer relationship (pairwise).
    Pairwise,
    /// DID is private to the local device or user only.
    Private,
}

/// Pairwise DID binding: a unique DID derived for a specific peer relationship.
///
/// Pairwise DIDs prevent correlation across different peers. Each user derives
/// a distinct DID for each counterparty, so a compromised pairwise DID does not
/// expose the user's activity with other peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairwiseDidBinding {
    /// The pairwise DID (unique per peer relationship).
    pub pairwise_did: Did,
    /// The real/parent DID that this pairwise DID represents.
    pub parent_did: Did,
    /// The counterparty DID this pairwise binding is scoped to.
    pub peer_did: Did,
    /// Optional space or context this binding is limited to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// When this pairwise binding was created.
    pub created_at: DateTime<Utc>,
    /// When this pairwise binding expires (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Proof required before revealing a pairwise DID's parent DID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairwiseDidResolutionProof {
    pub pairwise_did: Did,
    pub requester: Did,
    pub peer_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub challenge: String,
    pub proof: String,
    pub created_at: DateTime<Utc>,
}

impl PairwiseDidBinding {
    /// Create a new pairwise DID binding.
    pub fn new(pairwise_did: Did, parent_did: Did, peer_did: Did, scope: Option<String>) -> Self {
        Self { pairwise_did, parent_did, peer_did, scope, created_at: Utc::now(), expires_at: None }
    }

    /// Set an expiration time for this pairwise binding.
    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check whether this binding has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }

    /// Derive a deterministic pairwise DID from parent, peer, and optional scope.
    ///
    /// Uses SHA-256(parent + ":" + peer + ":" + scope) to produce a `did:uuid`
    /// form that is unique per peer relationship.
    pub fn derive_pairwise_did(parent: &Did, peer: &Did, scope: Option<&str>) -> Result<Did> {
        let input = format!("{}:{}:{}", parent, peer, scope.unwrap_or(""));
        let hash = Sha256::digest(input.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        // Set version 4 (random-like, derived from SHA-256) and variant bits
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        );
        Did::new(format!("did:uuid:{uuid}"))
    }

    /// Build a deterministic proof allowing a scoped peer to resolve this binding.
    pub fn resolution_proof(
        &self,
        requester: Did,
        challenge: impl Into<String>,
    ) -> PairwiseDidResolutionProof {
        let challenge = challenge.into();
        let proof = pairwise_resolution_proof(
            &self.pairwise_did,
            &requester,
            &self.peer_did,
            self.scope.as_deref(),
            &challenge,
        );
        PairwiseDidResolutionProof {
            pairwise_did: self.pairwise_did.clone(),
            requester,
            peer_did: self.peer_did.clone(),
            scope: self.scope.clone(),
            challenge,
            proof,
            created_at: Utc::now(),
        }
    }
}

/// Compute the deterministic proof for gated pairwise DID resolution.
pub fn pairwise_resolution_proof(
    pairwise_did: &Did,
    requester: &Did,
    peer_did: &Did,
    scope: Option<&str>,
    challenge: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        pairwise_did,
        requester,
        peer_did,
        scope.unwrap_or(""),
        challenge
    );
    sha256_hex(payload.as_bytes())
}

/// Manages pairwise DID bindings for privacy-preserving identity.
#[derive(Clone, Debug, Default)]
pub struct PairwiseDidStore {
    /// Bindings indexed by pairwise DID.
    by_pairwise: BTreeMap<Did, PairwiseDidBinding>,
    /// Reverse index: parent DID → all its pairwise DIDs.
    by_parent: BTreeMap<Did, Vec<Did>>,
}

impl PairwiseDidStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pairwise DID binding.
    pub fn insert(&mut self, binding: PairwiseDidBinding) -> Result<()> {
        let pairwise = binding.pairwise_did.clone();
        let parent = binding.parent_did.clone();
        self.by_pairwise.insert(pairwise.clone(), binding);
        self.by_parent.entry(parent).or_default().push(pairwise);
        Ok(())
    }

    /// Look up the binding for a pairwise DID.
    pub fn get(&self, pairwise_did: &Did) -> Option<&PairwiseDidBinding> {
        self.by_pairwise.get(pairwise_did)
    }

    /// Resolve a pairwise DID to its parent DID.
    pub fn resolve_parent(&self, pairwise_did: &Did) -> Option<&Did> {
        self.by_pairwise.get(pairwise_did).map(|b| &b.parent_did)
    }

    /// Resolve a pairwise DID to its parent DID only after validating proof.
    pub fn resolve_parent_with_proof(
        &self,
        pairwise_did: &Did,
        proof: &PairwiseDidResolutionProof,
    ) -> Result<&Did> {
        let binding = self
            .by_pairwise
            .get(pairwise_did)
            .ok_or_else(|| Error::Protocol("pairwise DID binding not found".to_owned()))?;
        if binding.is_expired() {
            return Err(Error::Protocol("pairwise DID binding expired".to_owned()));
        }
        if &proof.pairwise_did != pairwise_did {
            return Err(Error::Protocol("pairwise DID proof target mismatch".to_owned()));
        }
        if proof.requester != binding.peer_did && proof.requester != binding.parent_did {
            return Err(Error::Protocol(
                "pairwise DID proof requester is not authorized".to_owned(),
            ));
        }
        if proof.peer_did != binding.peer_did || proof.scope != binding.scope {
            return Err(Error::Protocol("pairwise DID proof scope mismatch".to_owned()));
        }
        let expected = pairwise_resolution_proof(
            pairwise_did,
            &proof.requester,
            &binding.peer_did,
            binding.scope.as_deref(),
            &proof.challenge,
        );
        if proof.proof != expected {
            return Err(Error::Protocol("invalid pairwise DID resolution proof".to_owned()));
        }
        Ok(&binding.parent_did)
    }

    /// Check if a pairwise DID is valid (exists and not expired).
    pub fn is_valid(&self, pairwise_did: &Did) -> bool {
        self.by_pairwise.get(pairwise_did).is_some_and(|b| !b.is_expired())
    }

    /// List all pairwise DIDs for a parent DID.
    pub fn pairwise_dids_for(&self, parent: &Did) -> Vec<&PairwiseDidBinding> {
        self.by_parent
            .get(parent)
            .map(|ids| ids.iter().filter_map(|id| self.by_pairwise.get(id)).collect())
            .unwrap_or_default()
    }

    /// Remove expired bindings.
    pub fn purge_expired(&mut self) {
        let expired: Vec<Did> = self
            .by_pairwise
            .iter()
            .filter(|(_, b)| b.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(binding) = self.by_pairwise.remove(&id)
                && let Some(parent_ids) = self.by_parent.get_mut(&binding.parent_did)
            {
                parent_ids.retain(|pid| pid != &id);
            }
        }
    }
}

/// DID migration record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMigration {
    /// Old DID.
    pub from: Did,
    /// New DID.
    pub to: Did,
    /// Migration proof.
    pub proof: String,
    /// Migration time.
    pub migrated_at: DateTime<Utc>,
}

/// Handle attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestation {
    /// Issuer DID.
    pub issuer: Did,
    /// Attestation proof.
    pub proof: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Handle claim state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleClaim {
    /// Claimed handle.
    pub handle: String,
    /// Owner DID.
    pub user_id: Did,
    /// Validation challenge.
    pub challenge: String,
    /// Whether the claim is verified.
    pub verified: bool,
    /// Optional attestation.
    pub attestation: Option<HandleAttestation>,
}

/// External proof profile for handle ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleProofProfile {
    DnsTxt,
    WellKnown,
}

/// Host-fetched DNS TXT or well-known handle proof validated by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalHandleProof {
    pub profile: HandleProofProfile,
    pub handle: String,
    pub user_id: Did,
    pub challenge: String,
    pub proof: String,
}

impl ExternalHandleProof {
    pub fn validate(&self) -> Result<()> {
        let expected = handle_claim_proof(&self.handle, &self.user_id, &self.challenge);
        if self.proof.trim() == expected {
            Ok(())
        } else {
            Err(Error::Protocol("handle proof mismatch".to_owned()))
        }
    }
}

/// Identity manager.
#[derive(Clone, Debug, Default)]
pub struct IdentityManager {
    documents: BTreeMap<Did, DidDocument>,
    migrations: Vec<DidMigration>,
    handles: BTreeMap<String, HandleClaim>,
}

impl IdentityManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a DID document after validation.
    pub fn upsert_document(&mut self, document: DidDocument) -> Result<()> {
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// Resolve a DID document.
    pub fn resolve(&self, did: &Did) -> Option<&DidDocument> {
        self.documents.get(did)
    }

    /// Rotate or add a verification key.
    pub fn rotate_key(
        &mut self,
        did: &Did,
        key_id: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Result<()> {
        let document = self
            .documents
            .get_mut(did)
            .ok_or_else(|| Error::Protocol("did document not found".to_owned()))?;
        document.verification_methods.insert(key_id.into(), public_key.into());
        document.updated_at = Utc::now();
        Ok(())
    }

    /// Migrate one DID to another.
    pub fn migrate_did(&mut self, from: Did, to: Did, proof: impl Into<String>) -> DidMigration {
        let migration = DidMigration { from, to, proof: proof.into(), migrated_at: Utc::now() };
        self.migrations.push(migration.clone());
        migration
    }

    /// Bind a handle and issue a validation challenge.
    pub fn bind_handle(&mut self, handle: impl Into<String>, user_id: Did) -> HandleClaim {
        let handle = normalize_handle(&handle.into());
        let challenge = sha256_hex(format!("{handle}:{}:{}", user_id, Utc::now()).as_bytes());
        let claim = HandleClaim {
            handle: handle.clone(),
            user_id,
            challenge,
            verified: false,
            attestation: None,
        };
        self.handles.insert(handle, claim.clone());
        claim
    }

    /// Validate a handle claim proof. Expected proof is SHA-256(handle + DID + challenge).
    pub fn validate_handle_claim(&mut self, handle: &str, proof: &str) -> Result<()> {
        let handle = normalize_handle(handle);
        let claim = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| Error::Protocol("handle claim not found".to_owned()))?;
        let expected = handle_claim_proof(&claim.handle, &claim.user_id, &claim.challenge);
        if expected != proof {
            return Err(Error::Protocol("invalid handle claim proof".to_owned()));
        }
        claim.verified = true;
        Ok(())
    }

    /// Add an attestation to a verified handle.
    pub fn attest_handle(
        &mut self,
        handle: &str,
        issuer: Did,
        proof: impl Into<String>,
    ) -> Result<()> {
        let handle = normalize_handle(handle);
        let claim = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| Error::Protocol("handle claim not found".to_owned()))?;
        if !claim.verified {
            return Err(Error::Protocol("handle claim is not verified".to_owned()));
        }
        claim.attestation =
            Some(HandleAttestation { issuer, proof: proof.into(), created_at: Utc::now() });
        Ok(())
    }

    /// Get a handle claim.
    pub fn handle_claim(&self, handle: &str) -> Option<&HandleClaim> {
        self.handles.get(&normalize_handle(handle))
    }

    /// Verify a handle through bidirectional `also_known_as` linking.
    ///
    /// This checks that:
    /// 1. The DID document for `user_id` exists and lists the handle in `also_known_as`.
    /// 2. A handle claim exists linking the handle to the same `user_id`.
    /// 3. The handle claim has been verified through a proof challenge.
    ///
    /// If both conditions hold, the handle is considered bidirectionally verified:
    /// the DID document asserts the handle, and the handle claim proves the DID.
    pub fn verify_handle_bidirectional(&self, handle: &str, user_id: &Did) -> Result<()> {
        let normalized = normalize_handle(handle);
        let document = self
            .documents
            .get(user_id)
            .ok_or_else(|| Error::Protocol("DID document not found for user".to_owned()))?;

        // Check that the DID document lists the handle in also_known_as
        let handle_variants: Vec<String> = vec![normalized.clone(), format!("@{normalized}")];
        let listed_in_document = document.also_known_as.iter().any(|aka| {
            let normalized_aka = normalize_handle(aka);
            handle_variants.contains(&normalized_aka)
        });
        if !listed_in_document {
            return Err(Error::Protocol(format!(
                "handle '{}' is not listed in DID document also_known_as for {}",
                normalized, user_id
            )));
        }

        // Check that the handle claim exists and is verified
        let claim = self.handles.get(&normalized).ok_or_else(|| {
            Error::Protocol(format!("handle claim not found for '{}'", normalized))
        })?;
        if claim.user_id != *user_id {
            return Err(Error::Protocol(format!(
                "handle claim links to {} but expected {}",
                claim.user_id, user_id
            )));
        }
        if !claim.verified {
            return Err(Error::Protocol(format!(
                "handle '{}' claim for {} is not yet verified",
                normalized, user_id
            )));
        }

        Ok(())
    }

    /// Return all handles listed in a DID document's `also_known_as` that
    /// are not yet claimed in this manager.
    pub fn unclaimed_handles_for_did(&self, did: &Did) -> Vec<String> {
        let Some(document) = self.documents.get(did) else {
            return Vec::new();
        };
        document
            .also_known_as
            .iter()
            .filter(|aka| {
                let normalized = normalize_handle(aka);
                // Only return entries that look like handles (not URLs)
                !normalized.contains("://") && !normalized.is_empty()
            })
            .filter(|aka| {
                let normalized = normalize_handle(aka);
                !self.handles.contains_key(&normalized)
            })
            .cloned()
            .collect()
    }

    /// Migration records.
    pub fn migrations(&self) -> &[DidMigration] {
        &self.migrations
    }
}

/// Compute the expected proof for a handle claim.
pub fn handle_claim_proof(handle: &str, user_id: &Did, challenge: &str) -> String {
    sha256_hex(format!("{}:{}:{}", normalize_handle(handle), user_id, challenge).as_bytes())
}

/// DNS TXT name that should contain the Contrix handle proof.
pub fn handle_dns_txt_name(handle: &str) -> Result<String> {
    let (local, domain) = split_domain_handle(handle)?;
    Ok(format!("_contrix-handle.{local}.{domain}"))
}

/// HTTPS well-known URL that should return the Contrix handle proof.
pub fn handle_well_known_url(handle: &str) -> Result<String> {
    let (local, domain) = split_domain_handle(handle)?;
    Ok(format!("https://{domain}/.well-known/contrix/handle/{local}.json"))
}

fn split_domain_handle(handle: &str) -> Result<(String, String)> {
    let normalized = normalize_handle(handle);
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(Error::Protocol("handle proof requires local@domain form".to_owned()));
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || local.contains('/')
        || domain.contains('/')
        || domain.contains("..")
    {
        return Err(Error::Protocol("invalid domain handle".to_owned()));
    }
    Ok((local.to_owned(), domain.to_owned()))
}

fn normalize_handle(handle: &str) -> String {
    handle.trim().trim_start_matches('@').to_lowercase()
}

fn did_web_document_url(did: &Did) -> Option<String> {
    if did.method() != "web" {
        return None;
    }
    let method_id = did.as_str().strip_prefix("did:web:")?;
    if method_id.is_empty() || method_id.contains("//") || method_id.contains('?') {
        return None;
    }
    let parts = method_id.split(':').collect::<Vec<_>>();
    let host = parts.first()?;
    if host.is_empty() || !host.contains('.') || host.contains('/') {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return None;
    }
    if parts.len() == 1 {
        return Some(format!("https://{host}/.well-known/did.json"));
    }
    if parts[1..].iter().any(|part| part.is_empty() || part.contains('/') || part.contains("..")) {
        return None;
    }
    Some(format!("https://{host}/{}/did.json", parts[1..].join("/")))
}

fn is_allowed_did_web_content_type(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(media_type.as_str(), "application/did+json" | "application/json")
}

fn did_key_material(did: &Did) -> Option<String> {
    let method_id = did.as_str().strip_prefix("did:key:")?;
    let encoded = method_id.strip_prefix('z')?;
    let decoded = decode_base58btc(encoded)?;
    if !is_supported_did_key_multicodec(&decoded) {
        return None;
    }
    Some(method_id.to_owned())
}

fn decode_base58btc(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    let mut output = Vec::<u8>::new();
    for byte in input.bytes() {
        let mut carry = base58btc_value(byte)?;
        for item in output.iter_mut().rev() {
            let value = u32::from(*item) * 58 + carry;
            *item = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            output.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading_zeroes = input.bytes().take_while(|byte| *byte == b'1').count();
    for _ in 0..leading_zeroes {
        output.insert(0, 0);
    }
    Some(output)
}

fn base58btc_value(byte: u8) -> Option<u32> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    ALPHABET.iter().position(|candidate| *candidate == byte).map(|index| index as u32)
}

fn is_supported_did_key_multicodec(bytes: &[u8]) -> bool {
    let Some((code, offset)) = decode_multicodec_varint(bytes) else {
        return false;
    };
    let key = &bytes[offset..];
    match code {
        0xec | 0xed => key.len() == 32,           // X25519-pub / Ed25519-pub
        0xe7 | 0x1200 => key.len() == 33,         // secp256k1-pub / P-256-pub
        0x1201 => key.len() == 49,                // P-384-pub
        0x1202 => (66..=67).contains(&key.len()), // P-521-pub
        0x1205 => key.len() >= 64,                // RSA-pub
        _ => false,
    }
}

fn decode_multicodec_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn operation_payload(operation: &DidKeyLogOperation) -> String {
    match operation {
        DidKeyLogOperation::Inception { verification_keys, recovery_keys } => {
            format!(
                "inception|{}|{}",
                key_set_payload(verification_keys),
                key_set_payload(recovery_keys)
            )
        }
        DidKeyLogOperation::Rotate { verification_keys } => {
            format!("rotate|{}", key_set_payload(verification_keys))
        }
        DidKeyLogOperation::Recover { verification_keys, recovery_keys } => {
            format!(
                "recover|{}|{}",
                key_set_payload(verification_keys),
                key_set_payload(recovery_keys)
            )
        }
        DidKeyLogOperation::Deactivate => "deactivate".to_owned(),
    }
}

fn key_set_payload(keys: &BTreeMap<String, String>) -> String {
    keys.iter().map(|(id, key)| format!("{id}={key}")).collect::<Vec<_>>().join(",")
}

fn ensure_key_set(name: &str, keys: &BTreeMap<String, String>) -> Result<()> {
    if keys.is_empty() {
        return Err(Error::Protocol(format!("{name} key set is empty")));
    }
    if keys.iter().any(|(id, key)| id.trim().is_empty() || key.trim().is_empty()) {
        return Err(Error::Protocol(format!("{name} key set has an empty key")));
    }
    Ok(())
}

fn ensure_active(state: &VerifiedDidKeyLog) -> Result<()> {
    if state.deactivated {
        return Err(Error::Protocol("DID is deactivated".to_owned()));
    }
    Ok(())
}

fn verify_did_key_log_proof(entry: &DidKeyLogEntry, signer_public_key: &str) -> Result<()> {
    let expected = did_key_log_proof(
        entry.sequence,
        &entry.did,
        entry.previous_hash.as_deref(),
        &entry.operation,
        &entry.signer,
        entry.created_at,
        signer_public_key,
    );
    if entry.proof != expected {
        return Err(Error::Protocol("invalid DID key log proof".to_owned()));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn identity_resolves_validates_rotates_and_migrates_dids() {
        let alice = did("alice");
        let alice_v2 = did("alice-v2");
        let mut manager = IdentityManager::new();
        manager.upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1")).unwrap();

        assert!(manager.resolve(&alice).unwrap().validate().is_ok());
        manager.rotate_key(&alice, "key-2", "pubkey-2").unwrap();
        assert!(manager.resolve(&alice).unwrap().verification_methods.contains_key("key-2"));

        manager.migrate_did(alice, alice_v2, "proof");
        assert_eq!(manager.migrations().len(), 1);
    }

    #[test]
    fn identity_binds_validates_and_attests_handles() {
        let alice = did("alice");
        let issuer = did("issuer");
        let mut manager = IdentityManager::new();

        let claim = manager.bind_handle("@Alice", alice.clone());
        let proof = handle_claim_proof("alice", &alice, &claim.challenge);
        manager.validate_handle_claim("alice", &proof).unwrap();
        manager.attest_handle("alice", issuer, "attestation").unwrap();

        let claim = manager.handle_claim("@alice").unwrap();
        assert!(claim.verified);
        assert!(claim.attestation.is_some());
    }

    #[test]
    fn handle_external_proof_profiles_validate_dns_and_well_known_shapes() {
        let alice = did("alice");
        let challenge = "challenge-1";
        let handle = "alice@example.com";
        let proof = handle_claim_proof(handle, &alice, challenge);

        assert_eq!(handle_dns_txt_name(handle).unwrap(), "_contrix-handle.alice.example.com");
        assert_eq!(
            handle_well_known_url(handle).unwrap(),
            "https://example.com/.well-known/contrix/handle/alice.json"
        );
        ExternalHandleProof {
            profile: HandleProofProfile::DnsTxt,
            handle: handle.to_owned(),
            user_id: alice.clone(),
            challenge: challenge.to_owned(),
            proof: proof.clone(),
        }
        .validate()
        .unwrap();
        assert!(
            ExternalHandleProof {
                profile: HandleProofProfile::WellKnown,
                handle: handle.to_owned(),
                user_id: alice,
                challenge: challenge.to_owned(),
                proof: "bad-proof".to_owned(),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn did_resolver_adapters_resolve_uuid_web_key_and_keri() {
        let uuid = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
        let web = Did::new("did:web:alice.example").unwrap();
        let web_path = Did::new("did:web:example.com:users:alice").unwrap();
        let keri = Did::new("did:keri:E123456789abcdef").unwrap();
        let key = Did::new("did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP").unwrap();

        let mut uuid_resolver = DidUuidResolver::new();
        uuid_resolver.insert(DidDocument::new(uuid.clone(), "root", "uuid-key")).unwrap();

        let mut web_resolver = DidWebResolver::new();
        web_resolver.insert(DidDocument::new(web.clone(), "owner", "web-key")).unwrap();
        let mut keri_resolver = DidKeriResolver::new();
        keri_resolver.insert(DidDocument::new(keri.clone(), "inception", "keri-key")).unwrap();

        assert_eq!(
            DidWebResolver::document_url(&web).unwrap(),
            "https://alice.example/.well-known/did.json"
        );
        assert_eq!(
            DidWebResolver::document_url(&web_path).unwrap(),
            "https://example.com/users/alice/did.json"
        );
        let mut web_https_resolver = DidWebResolver::new();
        let web_body =
            serde_json::to_vec(&DidDocument::new(web.clone(), "owner", "web-key")).unwrap();
        web_https_resolver
            .insert_from_https_response(
                &web,
                DidWebDocumentResponse {
                    url: DidWebResolver::document_url(&web).unwrap(),
                    content_type: "application/did+json; charset=utf-8".to_owned(),
                    body: web_body,
                },
            )
            .unwrap();
        assert!(
            web_https_resolver
                .insert_from_https_response(
                    &web,
                    DidWebDocumentResponse {
                        url: DidWebResolver::document_url(&web).unwrap(),
                        content_type: "text/plain".to_owned(),
                        body: b"{}".to_vec(),
                    },
                )
                .is_err()
        );
        assert!(
            web_https_resolver
                .insert_from_https_response(
                    &web,
                    DidWebDocumentResponse {
                        url: DidWebResolver::document_url(&web).unwrap(),
                        content_type: "application/json".to_owned(),
                        body: vec![b' '; DID_WEB_MAX_DOCUMENT_BYTES + 1],
                    },
                )
                .is_err()
        );

        let mut resolver = CompositeDidResolver::new();
        resolver.push(uuid_resolver);
        resolver.push(web_resolver);
        resolver.push(keri_resolver);
        resolver.push(DidKeyResolver::new());

        assert_eq!(resolver.resolve_did(&uuid).unwrap().verification_methods["root"], "uuid-key");
        assert_eq!(resolver.resolve_did(&web).unwrap().verification_methods["owner"], "web-key");
        assert_eq!(
            resolver.resolve_did(&keri).unwrap().verification_methods["inception"],
            "keri-key"
        );

        let key_doc = resolver.resolve_did(&key).unwrap();
        assert_eq!(key_doc.id, key);
        assert!(
            key_doc
                .verification_methods
                .contains_key("did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP#z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP")
        );
        assert!(DidKeyResolver::new().resolve_did(&Did::new("did:key:z1111").unwrap()).is_err());
    }

    #[test]
    fn did_key_log_verifies_rotate_recover_and_deactivate_without_changing_did() {
        let alice = did("alice");
        let inception_keys = BTreeMap::from([("key-1".to_owned(), "pub-1".to_owned())]);
        let recovery_keys = BTreeMap::from([("recovery-1".to_owned(), "recover-pub-1".to_owned())]);
        let inception = DidKeyLogEntry::signed(
            0,
            alice.clone(),
            None,
            DidKeyLogOperation::Inception { verification_keys: inception_keys, recovery_keys },
            "key-1",
            "pub-1",
        );

        let rotated_keys = BTreeMap::from([("key-2".to_owned(), "pub-2".to_owned())]);
        let rotate = DidKeyLogEntry::signed(
            1,
            alice.clone(),
            Some(inception.entry_hash()),
            DidKeyLogOperation::Rotate { verification_keys: rotated_keys },
            "key-1",
            "pub-1",
        );

        let recovered_keys = BTreeMap::from([("key-3".to_owned(), "pub-3".to_owned())]);
        let new_recovery_keys =
            BTreeMap::from([("recovery-2".to_owned(), "recover-pub-2".to_owned())]);
        let recover = DidKeyLogEntry::signed(
            2,
            alice.clone(),
            Some(rotate.entry_hash()),
            DidKeyLogOperation::Recover {
                verification_keys: recovered_keys,
                recovery_keys: new_recovery_keys,
            },
            "recovery-1",
            "recover-pub-1",
        );

        let deactivate = DidKeyLogEntry::signed(
            3,
            alice.clone(),
            Some(recover.entry_hash()),
            DidKeyLogOperation::Deactivate,
            "key-3",
            "pub-3",
        );

        let state =
            verify_did_key_log(&[inception.clone(), rotate.clone(), recover.clone(), deactivate])
                .unwrap();
        assert_eq!(state.did, alice);
        assert!(state.deactivated);
        assert_eq!(state.verification_keys["key-3"], "pub-3");
        assert!(state.to_document().is_err());

        let active = verify_did_key_log(&[inception, rotate, recover]).unwrap();
        assert!(!active.deactivated);
        assert_eq!(active.to_document().unwrap().verification_methods["key-3"], "pub-3");
    }

    #[test]
    fn did_key_log_rejects_did_change_and_bad_proof() {
        let alice = did("alice");
        let bob = did("bob");
        let inception_keys = BTreeMap::from([("key-1".to_owned(), "pub-1".to_owned())]);
        let inception = DidKeyLogEntry::signed(
            0,
            alice,
            None,
            DidKeyLogOperation::Inception {
                verification_keys: inception_keys,
                recovery_keys: BTreeMap::new(),
            },
            "key-1",
            "pub-1",
        );

        let rotate = DidKeyLogEntry::signed(
            1,
            bob,
            Some(inception.entry_hash()),
            DidKeyLogOperation::Rotate {
                verification_keys: BTreeMap::from([("key-2".to_owned(), "pub-2".to_owned())]),
            },
            "key-1",
            "pub-1",
        );
        assert!(verify_did_key_log(&[inception.clone(), rotate]).is_err());

        let mut tampered = inception;
        tampered.proof = "bad-proof".to_owned();
        assert!(verify_did_key_log(&[tampered]).is_err());
    }

    #[test]
    fn did_registry_receipt_verifies_signature_binding() {
        let alice = did("alice");
        let registry = did("registry");
        let receipt = DidRegistryReceipt::signed(
            alice.clone(),
            registry,
            "sha256:abc",
            "did:web:registry.example#key-1",
            "registry-public-key",
        );

        receipt.verify("registry-public-key").unwrap();
        assert!(receipt.verify("wrong-key").is_err());

        let expected = did_registry_receipt_signature(
            &alice,
            &receipt.registry_did,
            &receipt.operation_hash,
            &receipt.verification_method,
            receipt.issued_at,
            "registry-public-key",
        );
        assert_eq!(receipt.signature, expected);
    }

    #[test]
    fn starid_registry_adapter_resolves_records_and_control_proofs() {
        let alice = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
        let registry = did("registry");
        let document = DidDocument::new(alice.clone(), "root", "alice-public-key");
        let receipt = DidRegistryReceipt::signed(
            alice.clone(),
            registry.clone(),
            "sha256:abc",
            "did:web:registry.example#key-1",
            "registry-public-key",
        );
        let record = StaridRegistryRecord {
            did: alice.clone(),
            registry_did: registry.clone(),
            document,
            key_log_head: "sha256:abc".to_owned(),
            current_control_key: "root".to_owned(),
            receipt: Some(receipt),
            resolved_at: Utc::now(),
        };

        let mut adapter = InMemoryStaridRegistryAdapter::new(registry);
        adapter.insert(record).unwrap();
        assert_eq!(adapter.resolve_did(&alice).unwrap().primary_key().unwrap().0, "root");
        assert_eq!(adapter.current_key_log_head(&alice).unwrap(), "sha256:abc");
        assert_eq!(adapter.current_control_key(&alice).unwrap(), "root");
        adapter.verify_registry_receipt(&alice, "registry-public-key").unwrap();

        let challenge = "challenge-1";
        let proof = starid_control_proof(&alice, "root", challenge, "alice-public-key");
        let verified = adapter
            .verify_control_proof(&StaridControlProofRequest {
                did: alice.clone(),
                verification_method: "root".to_owned(),
                challenge: challenge.to_owned(),
                proof,
            })
            .unwrap();
        assert_eq!(verified.did, alice);

        assert!(
            adapter
                .verify_control_proof(&StaridControlProofRequest {
                    did: verified.did,
                    verification_method: "root".to_owned(),
                    challenge: challenge.to_owned(),
                    proof: "bad".to_owned(),
                })
                .is_err()
        );
    }

    #[test]
    fn handle_bidirectional_verification_succeeds_with_also_known_as() {
        let alice = did("alice");
        let mut manager = IdentityManager::new();

        // Create DID document with also_known_as listing the handle
        let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
        doc.also_known_as = vec!["@alice".to_owned()];
        manager.upsert_document(doc).unwrap();

        // Bind and verify handle
        let claim = manager.bind_handle("@alice", alice.clone());
        let proof = handle_claim_proof("alice", &alice, &claim.challenge);
        manager.validate_handle_claim("alice", &proof).unwrap();

        // Bidirectional verification should succeed
        assert!(manager.verify_handle_bidirectional("alice", &alice).is_ok());
    }

    #[test]
    fn handle_bidirectional_verification_fails_without_also_known_as() {
        let alice = did("alice");
        let mut manager = IdentityManager::new();

        // DID document without also_known_as
        manager.upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1")).unwrap();

        let claim = manager.bind_handle("@alice", alice.clone());
        let proof = handle_claim_proof("alice", &alice, &claim.challenge);
        manager.validate_handle_claim("alice", &proof).unwrap();

        // Should fail because handle is not in also_known_as
        assert!(manager.verify_handle_bidirectional("alice", &alice).is_err());
    }

    #[test]
    fn handle_bidirectional_verification_fails_when_claim_not_verified() {
        let alice = did("alice");
        let mut manager = IdentityManager::new();

        let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
        doc.also_known_as = vec!["@alice".to_owned()];
        manager.upsert_document(doc).unwrap();

        // Bind handle but don't verify it
        manager.bind_handle("@alice", alice.clone());

        // Should fail because claim is not verified
        assert!(manager.verify_handle_bidirectional("alice", &alice).is_err());
    }

    #[test]
    fn handle_bidirectional_verification_fails_for_wrong_did() {
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = IdentityManager::new();

        let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
        doc.also_known_as = vec!["@alice".to_owned()];
        manager.upsert_document(doc).unwrap();

        let claim = manager.bind_handle("@alice", alice.clone());
        let proof = handle_claim_proof("alice", &alice, &claim.challenge);
        manager.validate_handle_claim("alice", &proof).unwrap();

        // Should fail because handle belongs to alice, not bob
        assert!(manager.verify_handle_bidirectional("alice", &bob).is_err());
    }

    #[test]
    fn unclaimed_handles_for_did_returns_unlisted_handles() {
        let alice = did("alice");
        let mut manager = IdentityManager::new();

        let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
        doc.also_known_as = vec!["@alice".to_owned(), "@alice_alt".to_owned()];
        manager.upsert_document(doc).unwrap();

        // Claim one handle
        manager.bind_handle("@alice", alice.clone());

        // Should return the unclaimed one
        let unclaimed = manager.unclaimed_handles_for_did(&alice);
        assert_eq!(unclaimed.len(), 1);
        assert_eq!(unclaimed[0], "@alice_alt");
    }

    #[test]
    fn unclaimed_handles_excludes_urls() {
        let alice = did("alice");
        let mut manager = IdentityManager::new();

        let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
        doc.also_known_as = vec!["@alice".to_owned(), "https://alice.example".to_owned()];
        manager.upsert_document(doc).unwrap();

        let unclaimed = manager.unclaimed_handles_for_did(&alice);
        assert_eq!(unclaimed.len(), 1);
        assert_eq!(unclaimed[0], "@alice");
    }

    #[test]
    fn handle_bidirectional_with_case_insensitive_matching() {
        let alice = did("alice");
        let mut manager = IdentityManager::new();

        let mut doc = DidDocument::new(alice.clone(), "key-1", "pubkey-1");
        doc.also_known_as = vec!["@Alice".to_owned()];
        manager.upsert_document(doc).unwrap();

        let claim = manager.bind_handle("@alice", alice.clone());
        let proof = handle_claim_proof("alice", &alice, &claim.challenge);
        manager.validate_handle_claim("alice", &proof).unwrap();

        // Should succeed despite case difference
        assert!(manager.verify_handle_bidirectional("@Alice", &alice).is_ok());
    }

    #[test]
    fn pairwise_did_derivation_is_deterministic_and_unique() {
        let alice = Did::new("did:web:alice.example").unwrap();
        let bob = Did::new("did:web:bob.example").unwrap();
        let charlie = Did::new("did:web:charlie.example").unwrap();

        let ab1 = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();
        let ab2 = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();
        assert_eq!(ab1, ab2, "pairwise DID derivation must be deterministic");

        let ac = PairwiseDidBinding::derive_pairwise_did(&alice, &charlie, None).unwrap();
        assert_ne!(ab1, ac, "different peers must produce different pairwise DIDs");

        let ba = PairwiseDidBinding::derive_pairwise_did(&bob, &alice, None).unwrap();
        assert_ne!(ab1, ba, "asymmetric peer pairs must produce different pairwise DIDs");
    }

    #[test]
    fn pairwise_did_with_scope_varies() {
        let alice = Did::new("did:web:alice.example").unwrap();
        let bob = Did::new("did:web:bob.example").unwrap();

        let no_scope = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();
        let with_scope =
            PairwiseDidBinding::derive_pairwise_did(&alice, &bob, Some("space:01")).unwrap();
        assert_ne!(no_scope, with_scope, "scope must change the derived DID");
    }

    #[test]
    fn pairwise_did_store_insert_resolve_and_purge() {
        let alice = Did::new("did:web:alice.example").unwrap();
        let bob = Did::new("did:web:bob.example").unwrap();
        let pairwise = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, None).unwrap();

        let binding = PairwiseDidBinding::new(pairwise.clone(), alice.clone(), bob.clone(), None);
        let mut store = PairwiseDidStore::new();
        store.insert(binding).unwrap();

        assert_eq!(store.resolve_parent(&pairwise), Some(&alice));
        assert!(store.is_valid(&pairwise));
        assert_eq!(store.pairwise_dids_for(&alice).len(), 1);

        // Expired binding is invalid
        let pairwise2 = PairwiseDidBinding::derive_pairwise_did(&alice, &bob, Some("x")).unwrap();
        let expired = PairwiseDidBinding::new(pairwise2.clone(), alice, bob, Some("x".to_owned()))
            .with_expiry("2020-01-01T00:00:00Z".parse().unwrap());
        store.insert(expired).unwrap();
        assert!(!store.is_valid(&pairwise2));

        store.purge_expired();
        assert!(store.get(&pairwise2).is_none());
        assert!(store.get(&pairwise).is_some());
    }

    #[test]
    fn pairwise_did_resolution_requires_valid_proof() {
        let alice = Did::new("did:web:alice.example").unwrap();
        let bob = Did::new("did:web:bob.example").unwrap();
        let mallory = Did::new("did:web:mallory.example").unwrap();
        let pairwise =
            PairwiseDidBinding::derive_pairwise_did(&alice, &bob, Some("space:01")).unwrap();
        let binding = PairwiseDidBinding::new(
            pairwise.clone(),
            alice.clone(),
            bob.clone(),
            Some("space:01".to_owned()),
        );
        let proof = binding.resolution_proof(bob, "challenge-1");
        let mut store = PairwiseDidStore::new();
        store.insert(binding).unwrap();

        assert_eq!(store.resolve_parent_with_proof(&pairwise, &proof).unwrap(), &alice);

        let mut bad_proof = proof.clone();
        bad_proof.requester = mallory;
        assert!(store.resolve_parent_with_proof(&pairwise, &bad_proof).is_err());

        let mut tampered = proof;
        tampered.proof = "bad".to_owned();
        assert!(store.resolve_parent_with_proof(&pairwise, &tampered).is_err());
    }

    #[test]
    fn pairwise_did_visibility_enum_roundtrips() {
        let vis = DidVisibility::Pairwise;
        let json = serde_json::to_string(&vis).unwrap();
        assert_eq!(json, "\"pairwise\"");
        let back: DidVisibility = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DidVisibility::Pairwise);
    }
}
