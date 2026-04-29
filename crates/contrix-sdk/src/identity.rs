//! DID, DID document and handle management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Did, Error, Result};

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

/// Temporary test resolver for `did:key` identifiers.
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

    /// Migration records.
    pub fn migrations(&self) -> &[DidMigration] {
        &self.migrations
    }
}

/// Compute the expected proof for a handle claim.
pub fn handle_claim_proof(handle: &str, user_id: &Did, challenge: &str) -> String {
    sha256_hex(format!("{}:{}:{}", normalize_handle(handle), user_id, challenge).as_bytes())
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

fn did_key_material(did: &Did) -> Option<String> {
    let method_id = did.as_str().strip_prefix("did:key:")?;
    if method_id.len() < 2
        || !method_id.starts_with('z')
        || !method_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
    {
        return None;
    }
    Some(method_id.to_owned())
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
    fn did_resolver_adapters_resolve_uuid_web_key_and_keri() {
        let uuid = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
        let web = Did::new("did:web:alice.example").unwrap();
        let web_path = Did::new("did:web:example.com:users:alice").unwrap();
        let keri = Did::new("did:keri:E123456789abcdef").unwrap();
        let key = Did::new("did:key:z6MkiTestKeyMateriaa").unwrap();

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
                .contains_key("did:key:z6MkiTestKeyMateriaa#z6MkiTestKeyMateriaa")
        );
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
}
