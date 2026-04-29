use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    BlobRef, Commit, CommitId, Did, Error, Event, EventId, Hash, Operation, OperationId, Result,
    SpaceId,
    auth::AuthSession,
    crypto,
    e2ee::AuditEntry,
    model::BlobMetadata,
    resolver::{SnapshotRestore, SpaceState, StateSnapshot},
};

pub trait RepoStore: Send + Sync {
    fn put_operation(&mut self, operation: Operation) -> Result<()>;
    fn put_commit(&mut self, commit: Commit) -> Result<()>;
    fn operation(&self, operation_id: &OperationId) -> Option<&Operation>;
    fn commit(&self, commit_id: &CommitId) -> Option<&Commit>;
    fn head(&self) -> Option<&Hash>;
}

pub trait RepoObjectStore: Send + Sync {
    fn store_operation(&mut self, operation: Operation) -> Result<()>;
    fn store_commit(&mut self, commit: Commit) -> Result<()>;
    fn load_operation(&self, operation_id: &OperationId) -> Option<&Operation>;
    fn load_commit(&self, commit_id: &CommitId) -> Option<&Commit>;
    fn repo_head(&self) -> Option<&Hash>;
}

impl<T> RepoObjectStore for T
where
    T: RepoStore,
{
    fn store_operation(&mut self, operation: Operation) -> Result<()> {
        self.put_operation(operation)
    }

    fn store_commit(&mut self, commit: Commit) -> Result<()> {
        self.put_commit(commit)
    }

    fn load_operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.operation(operation_id)
    }

    fn load_commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.commit(commit_id)
    }

    fn repo_head(&self) -> Option<&Hash> {
        self.head()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RepoWriteBatch {
    pub operations: Vec<Operation>,
    pub commits: Vec<Commit>,
}

impl RepoWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operations.push(operation);
        self
    }

    pub fn with_commit(mut self, commit: Commit) -> Self {
        self.commits.push(commit);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty() && self.commits.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoWriteReceipt {
    pub operations_written: usize,
    pub commits_written: usize,
    pub head: Option<Hash>,
}

pub trait TransactionalRepoStore: RepoObjectStore {
    fn write_batch(&mut self, batch: RepoWriteBatch) -> Result<RepoWriteReceipt>;
}

pub trait StateSnapshotStore: Send + Sync {
    fn put_state_snapshot(&mut self, snapshot: StateSnapshot) -> Result<()>;
    fn state_snapshot(&self, space_id: &SpaceId) -> Option<&StateSnapshot>;
    fn remove_state_snapshot(&mut self, space_id: &SpaceId) -> Result<()>;
}

pub trait EventCacheStore: Send + Sync {
    fn put_event(&mut self, event: Event) -> Result<()>;
    fn event(&self, event_id: &EventId) -> Option<&Event>;
    fn events_for_space(&self, space_id: &SpaceId) -> Vec<&Event>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredAccountData {
    pub principal_id: Did,
    pub data_type: String,
    pub content: Value,
    pub updated_at: DateTime<Utc>,
}

pub trait AccountSessionStore: Send + Sync {
    fn put_session(&mut self, session: AuthSession) -> Result<()>;
    fn session(&self, session_id: &str) -> Option<&AuthSession>;
    fn sessions_for_principal(&self, principal_id: &Did) -> Vec<&AuthSession>;
    fn revoke_session(&mut self, session_id: &str) -> Result<()>;
    fn put_account_data(&mut self, data: StoredAccountData) -> Result<()>;
    fn account_data(&self, principal_id: &Did, data_type: &str) -> Option<&StoredAccountData>;
}

pub trait BlobMetadataStore: Send + Sync {
    fn put_blob_metadata(&mut self, metadata: BlobMetadata) -> Result<()>;
    fn blob_metadata(&self, blob_ref: &BlobRef) -> Option<&BlobMetadata>;
}

pub trait AuditLogStore: Send + Sync {
    fn append_audit_entry(&mut self, entry: AuditEntry) -> Result<()>;
    fn audit_entries(&self) -> Vec<&AuditEntry>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationReplayRecord {
    pub transaction_id: String,
    pub origin: Did,
    pub destination: Did,
    pub request_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    pub seen_at: DateTime<Utc>,
}

pub trait FederationReplayStore: Send + Sync {
    fn put_federation_replay(&mut self, record: FederationReplayRecord) -> Result<()>;
    fn federation_replay(&self, transaction_id: &str) -> Option<&FederationReplayRecord>;
    fn has_federation_replay(&self, transaction_id: &str) -> bool {
        self.federation_replay(transaction_id).is_some()
    }
}

pub trait CommitProofVerifier {
    fn verify_commit(&self, commit: &Commit) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct AcceptUnsignedCommitProofs;

impl CommitProofVerifier for AcceptUnsignedCommitProofs {
    fn verify_commit(&self, _commit: &Commit) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryRepoStore {
    operations: BTreeMap<OperationId, (String, Operation)>,
    commits: BTreeMap<CommitId, (String, Commit)>,
    head: Option<Hash>,
    author_seq: BTreeMap<String, u64>,
}

impl MemoryRepoStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn operations_len(&self) -> usize {
        self.operations.len()
    }

    pub fn commits_len(&self) -> usize {
        self.commits.len()
    }

    pub fn put_commit_verified(
        &mut self,
        commit: Commit,
        verifier: &impl CommitProofVerifier,
    ) -> Result<()> {
        verifier.verify_commit(&commit)?;
        self.put_commit(commit)
    }

    pub fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.operations.values().map(|(_, operation)| operation)
    }

    pub fn commits(&self) -> impl Iterator<Item = &Commit> {
        self.commits.values().map(|(_, commit)| commit)
    }
}

impl RepoStore for MemoryRepoStore {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(operation_id = %operation.operation_id)))]
    fn put_operation(&mut self, operation: Operation) -> Result<()> {
        let digest = operation.operation_digest()?;
        match self.operations.get(&operation.operation_id) {
            Some((existing_digest, _)) if existing_digest == &digest => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(operation.operation_id.to_string())),
            None => {
                self.operations.insert(operation.operation_id.clone(), (digest, operation));
                Ok(())
            }
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(commit_id = %commit.commit_id, author = %commit.author)))]
    fn put_commit(&mut self, commit: Commit) -> Result<()> {
        let digest = commit.commit_digest()?;
        match self.commits.get(&commit.commit_id) {
            Some((existing_digest, _)) if existing_digest == &digest => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(commit.commit_id.to_string())),
            None => {
                self.validate_commit_append(&commit)?;
                self.head = Some(Hash::new(digest.clone())?);
                self.author_seq.insert(commit.author.to_string(), commit.author_seq);
                self.commits.insert(commit.commit_id.clone(), (digest, commit));
                Ok(())
            }
        }
    }

    fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.operations.get(operation_id).map(|(_, operation)| operation)
    }

    fn commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.commits.get(commit_id).map(|(_, commit)| commit)
    }

    fn head(&self) -> Option<&Hash> {
        self.head.as_ref()
    }
}

impl TransactionalRepoStore for MemoryRepoStore {
    fn write_batch(&mut self, batch: RepoWriteBatch) -> Result<RepoWriteReceipt> {
        let mut candidate = self.clone();
        for operation in batch.operations {
            RepoStore::put_operation(&mut candidate, operation)?;
        }
        for commit in batch.commits {
            RepoStore::put_commit(&mut candidate, commit)?;
        }

        let receipt = RepoWriteReceipt {
            operations_written: candidate.operations.len().saturating_sub(self.operations.len()),
            commits_written: candidate.commits.len().saturating_sub(self.commits.len()),
            head: candidate.head.clone(),
        };
        *self = candidate;
        Ok(receipt)
    }
}

impl MemoryRepoStore {
    fn validate_commit_append(&self, commit: &Commit) -> Result<()> {
        if commit.prev_commit.as_ref() != self.head.as_ref() {
            return Err(Error::Protocol(
                "commit prev_commit does not match current repo head".to_owned(),
            ));
        }

        if let Some(last_seq) = self.author_seq.get(commit.author.as_str())
            && commit.author_seq <= *last_seq
        {
            return Err(Error::Protocol(
                "commit author_seq must be monotonically increasing".to_owned(),
            ));
        }

        for operation_digest in &commit.operations {
            let found =
                self.operations.values().any(|(digest, _)| digest == operation_digest.as_str());
            if !found {
                return Err(Error::Protocol(format!(
                    "commit references unknown operation digest: {}",
                    operation_digest
                )));
            }
        }

        Ok(())
    }
}

/// Store migration descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMigration {
    /// Monotonic schema version.
    pub version: u32,
    /// SQL or backend-specific migration statements.
    pub statements: Vec<String>,
}

impl StoreMigration {
    pub fn applied_metadata(&self, applied_at: DateTime<Utc>) -> Result<StoreMigrationMetadata> {
        Ok(StoreMigrationMetadata {
            version: self.version,
            checksum: crate::canonical::canonical_sha256(self)?,
            applied_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMigrationMetadata {
    pub version: u32,
    pub checksum: String,
    pub applied_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSchemaMetadata {
    pub store_name: String,
    pub schema_version: u32,
    pub migration_profile: String,
    pub applied_migrations: Vec<StoreMigrationMetadata>,
}

/// Serializable store snapshot used for persistence and import/export.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub schema_version: u32,
    pub operations: Vec<Operation>,
    pub commits: Vec<Commit>,
    pub head: Option<Hash>,
}

/// Lightweight SQLite-compatible store facade.
///
/// The SDK keeps this implementation dependency-free. It models the SQLite
/// storage contract (schema version, migrations, indexes and snapshots) so an
/// application can back it with a real SQLite adapter without changing callers.
#[derive(Clone, Debug, Default)]
pub struct SqliteRepoStore {
    inner: MemoryRepoStore,
    schema_version: u32,
    migrations: Vec<StoreMigration>,
    migration_metadata: Vec<StoreMigrationMetadata>,
    operation_index: BTreeMap<String, OperationId>,
    commit_index: BTreeMap<String, CommitId>,
}

impl SqliteRepoStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a migration.
    pub fn apply_migration(&mut self, migration: StoreMigration) {
        self.schema_version = self.schema_version.max(migration.version);
        let metadata =
            migration.applied_metadata(Utc::now()).expect("store migration metadata serializes");
        self.migration_metadata.push(metadata);
        self.migrations.push(migration);
    }

    /// Apply a migration and reject duplicate or out-of-order versions.
    pub fn apply_migration_checked(
        &mut self,
        migration: StoreMigration,
    ) -> Result<StoreMigrationMetadata> {
        if migration.version <= self.schema_version {
            return Err(Error::Protocol(format!(
                "migration version {} is not greater than current schema version {}",
                migration.version, self.schema_version
            )));
        }
        let metadata = migration.applied_metadata(Utc::now())?;
        self.schema_version = migration.version;
        self.migration_metadata.push(metadata.clone());
        self.migrations.push(migration);
        Ok(metadata)
    }

    /// Current schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Current schema metadata suitable for durable adapters.
    pub fn schema_metadata(&self) -> StoreSchemaMetadata {
        StoreSchemaMetadata {
            store_name: "sqlite_repo_store".to_owned(),
            schema_version: self.schema_version,
            migration_profile: "cx.store.sqlite.repo.v1".to_owned(),
            applied_migrations: self.migration_metadata.clone(),
        }
    }

    /// Export a persistence snapshot.
    pub fn export_snapshot(&self) -> StoreSnapshot {
        StoreSnapshot {
            schema_version: self.schema_version,
            operations: self
                .inner
                .operations
                .values()
                .map(|(_, operation)| operation.clone())
                .collect(),
            commits: self.inner.commits.values().map(|(_, commit)| commit.clone()).collect(),
            head: self.inner.head.clone(),
        }
    }

    /// Import a persistence snapshot.
    pub fn import_snapshot(&mut self, snapshot: StoreSnapshot) -> Result<()> {
        let mut candidate = Self::new();
        candidate.schema_version = snapshot.schema_version;
        candidate.migrations = self.migrations.clone();
        candidate.migration_metadata = self.migration_metadata.clone();
        for operation in snapshot.operations {
            candidate.put_operation(operation)?;
        }
        for commit in snapshot.commits {
            candidate.put_commit(commit)?;
        }
        if let Some(snapshot_head) = snapshot.head
            && candidate.head() != Some(&snapshot_head)
        {
            return Err(Error::Protocol(
                "store snapshot head does not match imported commits".to_owned(),
            ));
        }
        *self = candidate;
        Ok(())
    }

    /// Build a store from a snapshot while rebuilding indexes and head.
    pub fn recover_from_snapshot(snapshot: StoreSnapshot) -> Result<Self> {
        let mut store = Self::new();
        store.import_snapshot(snapshot)?;
        Ok(store)
    }

    /// Lookup an operation by digest index.
    pub fn operation_by_digest(&self, digest: &str) -> Option<&Operation> {
        self.operation_index.get(digest).and_then(|operation_id| self.inner.operation(operation_id))
    }

    /// Lookup a commit by digest index.
    pub fn commit_by_digest(&self, digest: &str) -> Option<&Commit> {
        self.commit_index.get(digest).and_then(|commit_id| self.inner.commit(commit_id))
    }
}

impl RepoStore for SqliteRepoStore {
    fn put_operation(&mut self, operation: Operation) -> Result<()> {
        let digest = operation.operation_digest()?;
        let operation_id = operation.operation_id.clone();
        self.inner.put_operation(operation)?;
        self.operation_index.insert(digest, operation_id);
        Ok(())
    }

    fn put_commit(&mut self, commit: Commit) -> Result<()> {
        let digest = commit.commit_digest()?;
        let commit_id = commit.commit_id.clone();
        self.inner.put_commit(commit)?;
        self.commit_index.insert(digest, commit_id);
        Ok(())
    }

    fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.inner.operation(operation_id)
    }

    fn commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.inner.commit(commit_id)
    }

    fn head(&self) -> Option<&Hash> {
        self.inner.head()
    }
}

impl TransactionalRepoStore for SqliteRepoStore {
    fn write_batch(&mut self, batch: RepoWriteBatch) -> Result<RepoWriteReceipt> {
        let mut candidate = self.clone();
        for operation in batch.operations {
            RepoStore::put_operation(&mut candidate, operation)?;
        }
        for commit in batch.commits {
            RepoStore::put_commit(&mut candidate, commit)?;
        }

        let receipt = RepoWriteReceipt {
            operations_written: candidate
                .inner
                .operations
                .len()
                .saturating_sub(self.inner.operations.len()),
            commits_written: candidate.inner.commits.len().saturating_sub(self.inner.commits.len()),
            head: candidate.inner.head.clone(),
        };
        *self = candidate;
        Ok(receipt)
    }
}

/// IndexedDB-compatible WASM store facade with quota and background sync state.
#[derive(Clone, Debug)]
pub struct IndexedDbRepoStore {
    inner: MemoryRepoStore,
    quota_bytes: usize,
    used_bytes: usize,
    pending_sync: VecDeque<String>,
}

impl IndexedDbRepoStore {
    /// Create a store with a quota in bytes.
    pub fn new(quota_bytes: usize) -> Self {
        Self {
            inner: MemoryRepoStore::new(),
            quota_bytes,
            used_bytes: 0,
            pending_sync: VecDeque::new(),
        }
    }

    /// Remaining quota.
    pub fn remaining_quota(&self) -> usize {
        self.quota_bytes.saturating_sub(self.used_bytes)
    }

    /// Enqueue an object ID for background sync.
    pub fn enqueue_background_sync(&mut self, object_id: impl Into<String>) {
        self.pending_sync.push_back(object_id.into());
    }

    /// Pop the next background sync object.
    pub fn pop_background_sync(&mut self) -> Option<String> {
        self.pending_sync.pop_front()
    }

    fn reserve(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.remaining_quota() {
            return Err(Error::Protocol("indexeddb quota exceeded".to_owned()));
        }
        self.used_bytes += bytes;
        Ok(())
    }
}

impl RepoStore for IndexedDbRepoStore {
    fn put_operation(&mut self, operation: Operation) -> Result<()> {
        let bytes = serde_json::to_vec(&operation)?;
        self.reserve(bytes.len())?;
        self.inner.put_operation(operation)
    }

    fn put_commit(&mut self, commit: Commit) -> Result<()> {
        let bytes = serde_json::to_vec(&commit)?;
        self.reserve(bytes.len())?;
        self.inner.put_commit(commit)
    }

    fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.inner.operation(operation_id)
    }

    fn commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.inner.commit(commit_id)
    }

    fn head(&self) -> Option<&Hash> {
        self.inner.head()
    }
}

impl TransactionalRepoStore for IndexedDbRepoStore {
    fn write_batch(&mut self, batch: RepoWriteBatch) -> Result<RepoWriteReceipt> {
        let mut candidate = self.clone();
        for operation in batch.operations {
            RepoStore::put_operation(&mut candidate, operation)?;
        }
        for commit in batch.commits {
            RepoStore::put_commit(&mut candidate, commit)?;
        }

        let receipt = RepoWriteReceipt {
            operations_written: candidate
                .inner
                .operations
                .len()
                .saturating_sub(self.inner.operations.len()),
            commits_written: candidate.inner.commits.len().saturating_sub(self.inner.commits.len()),
            head: candidate.inner.head.clone(),
        };
        *self = candidate;
        Ok(receipt)
    }
}

/// Store encryption key derived from a passphrase and salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreEncryptionKey([u8; 32]);

impl StoreEncryptionKey {
    /// Derive a key using repeated SHA-256 rounds.
    pub fn derive(passphrase: &str, salt: &[u8], rounds: u32) -> Self {
        let mut digest = Sha256::new();
        digest.update(passphrase.as_bytes());
        digest.update(salt);
        let mut key: [u8; 32] = digest.finalize().into();
        for _ in 0..rounds.max(1) {
            let mut digest = Sha256::new();
            digest.update(key);
            digest.update(salt);
            key = digest.finalize().into();
        }
        Self(key)
    }

    pub fn seal(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        crypto::seal(bytes, &self.0, aad)
    }
}

/// Encrypted in-memory repo store.
#[derive(Clone, Debug)]
pub struct EncryptedMemoryRepoStore {
    inner: MemoryRepoStore,
    key: StoreEncryptionKey,
    encrypted_operations: BTreeMap<OperationId, Vec<u8>>,
    encrypted_commits: BTreeMap<CommitId, Vec<u8>>,
}

impl EncryptedMemoryRepoStore {
    /// Create an encrypted store.
    pub fn new(key: StoreEncryptionKey) -> Self {
        Self {
            inner: MemoryRepoStore::new(),
            key,
            encrypted_operations: BTreeMap::new(),
            encrypted_commits: BTreeMap::new(),
        }
    }

    /// Raw encrypted operation bytes.
    pub fn encrypted_operation_bytes(&self, operation_id: &OperationId) -> Option<&[u8]> {
        self.encrypted_operations.get(operation_id).map(Vec::as_slice)
    }

    /// Raw encrypted commit bytes.
    pub fn encrypted_commit_bytes(&self, commit_id: &CommitId) -> Option<&[u8]> {
        self.encrypted_commits.get(commit_id).map(Vec::as_slice)
    }
}

impl RepoStore for EncryptedMemoryRepoStore {
    fn put_operation(&mut self, operation: Operation) -> Result<()> {
        let bytes = serde_json::to_vec(&operation)?;
        let encrypted = self.key.seal(&bytes, operation.operation_id.as_str().as_bytes())?;
        let operation_id = operation.operation_id.clone();
        self.inner.put_operation(operation)?;
        self.encrypted_operations.entry(operation_id).or_insert(encrypted);
        Ok(())
    }

    fn put_commit(&mut self, commit: Commit) -> Result<()> {
        let bytes = serde_json::to_vec(&commit)?;
        let encrypted = self.key.seal(&bytes, commit.commit_id.as_str().as_bytes())?;
        let commit_id = commit.commit_id.clone();
        self.inner.put_commit(commit)?;
        self.encrypted_commits.entry(commit_id).or_insert(encrypted);
        Ok(())
    }

    fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.inner.operation(operation_id)
    }

    fn commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.inner.commit(commit_id)
    }

    fn head(&self) -> Option<&Hash> {
        self.inner.head()
    }
}

impl TransactionalRepoStore for EncryptedMemoryRepoStore {
    fn write_batch(&mut self, batch: RepoWriteBatch) -> Result<RepoWriteReceipt> {
        let mut candidate = self.clone();
        for operation in batch.operations {
            RepoStore::put_operation(&mut candidate, operation)?;
        }
        for commit in batch.commits {
            RepoStore::put_commit(&mut candidate, commit)?;
        }

        let receipt = RepoWriteReceipt {
            operations_written: candidate
                .inner
                .operations
                .len()
                .saturating_sub(self.inner.operations.len()),
            commits_written: candidate.inner.commits.len().saturating_sub(self.inner.commits.len()),
            head: candidate.inner.head.clone(),
        };
        *self = candidate;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryPersistenceStore {
    snapshots: BTreeMap<SpaceId, StateSnapshot>,
    events: BTreeMap<SpaceId, BTreeMap<EventId, (String, Event)>>,
    event_index: BTreeMap<EventId, SpaceId>,
    sessions: BTreeMap<String, AuthSession>,
    sessions_by_principal: BTreeMap<Did, Vec<String>>,
    account_data: BTreeMap<(Did, String), StoredAccountData>,
    blob_metadata: BTreeMap<BlobRef, (String, BlobMetadata)>,
    audit_entries: Vec<AuditEntry>,
    federation_replay: BTreeMap<String, FederationReplayRecord>,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateSnapshotStore for MemoryPersistenceStore {
    fn put_state_snapshot(&mut self, snapshot: StateSnapshot) -> Result<()> {
        snapshot.verify()?;
        self.snapshots.insert(snapshot.space_id.clone(), snapshot);
        Ok(())
    }

    fn state_snapshot(&self, space_id: &SpaceId) -> Option<&StateSnapshot> {
        self.snapshots.get(space_id)
    }

    fn remove_state_snapshot(&mut self, space_id: &SpaceId) -> Result<()> {
        self.snapshots.remove(space_id);
        Ok(())
    }
}

impl EventCacheStore for MemoryPersistenceStore {
    fn put_event(&mut self, event: Event) -> Result<()> {
        let digest = event.event_digest()?;
        if let Some(existing_space_id) = self.event_index.get(&event.event_id) {
            let existing_digest = self
                .events
                .get(existing_space_id)
                .and_then(|events| events.get(&event.event_id))
                .map(|(digest, _)| digest);
            return match existing_digest {
                Some(existing_digest) if existing_digest == &digest => Ok(()),
                _ => Err(Error::IdempotencyConflict(event.event_id.to_string())),
            };
        }

        self.event_index.insert(event.event_id.clone(), event.space_id.clone());
        self.events
            .entry(event.space_id.clone())
            .or_default()
            .insert(event.event_id.clone(), (digest, event));
        Ok(())
    }

    fn event(&self, event_id: &EventId) -> Option<&Event> {
        self.event_index.get(event_id).and_then(|space_id| {
            self.events
                .get(space_id)
                .and_then(|events| events.get(event_id))
                .map(|(_, event)| event)
        })
    }

    fn events_for_space(&self, space_id: &SpaceId) -> Vec<&Event> {
        self.events
            .get(space_id)
            .map(|events| events.values().map(|(_, event)| event).collect())
            .unwrap_or_default()
    }
}

impl AccountSessionStore for MemoryPersistenceStore {
    fn put_session(&mut self, session: AuthSession) -> Result<()> {
        if let Some(existing) = self.sessions.get(&session.session_id) {
            return if existing == &session {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(session.session_id))
            };
        }

        self.sessions_by_principal
            .entry(session.principal_id.clone())
            .or_default()
            .push(session.session_id.clone());
        self.sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    fn session(&self, session_id: &str) -> Option<&AuthSession> {
        self.sessions.get(session_id)
    }

    fn sessions_for_principal(&self, principal_id: &Did) -> Vec<&AuthSession> {
        self.sessions_by_principal
            .get(principal_id)
            .into_iter()
            .flat_map(|session_ids| session_ids.iter())
            .filter_map(|session_id| self.sessions.get(session_id))
            .collect()
    }

    fn revoke_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol(format!("session not found: {session_id}")))?;
        session.revoked = true;
        Ok(())
    }

    fn put_account_data(&mut self, data: StoredAccountData) -> Result<()> {
        self.account_data.insert((data.principal_id.clone(), data.data_type.clone()), data);
        Ok(())
    }

    fn account_data(&self, principal_id: &Did, data_type: &str) -> Option<&StoredAccountData> {
        self.account_data.get(&(principal_id.clone(), data_type.to_owned()))
    }
}

impl BlobMetadataStore for MemoryPersistenceStore {
    fn put_blob_metadata(&mut self, metadata: BlobMetadata) -> Result<()> {
        let digest = crate::canonical::canonical_sha256(&metadata)?;
        match self.blob_metadata.get(&metadata.blob_ref) {
            Some((existing_digest, _)) if existing_digest == &digest => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(metadata.blob_ref.to_string())),
            None => {
                self.blob_metadata.insert(metadata.blob_ref.clone(), (digest, metadata));
                Ok(())
            }
        }
    }

    fn blob_metadata(&self, blob_ref: &BlobRef) -> Option<&BlobMetadata> {
        self.blob_metadata.get(blob_ref).map(|(_, metadata)| metadata)
    }
}

impl AuditLogStore for MemoryPersistenceStore {
    fn append_audit_entry(&mut self, entry: AuditEntry) -> Result<()> {
        self.audit_entries.push(entry);
        Ok(())
    }

    fn audit_entries(&self) -> Vec<&AuditEntry> {
        self.audit_entries.iter().collect()
    }
}

impl FederationReplayStore for MemoryPersistenceStore {
    fn put_federation_replay(&mut self, record: FederationReplayRecord) -> Result<()> {
        match self.federation_replay.get(&record.transaction_id) {
            Some(existing) if existing == &record => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(record.transaction_id)),
            None => {
                self.federation_replay.insert(record.transaction_id.clone(), record);
                Ok(())
            }
        }
    }

    fn federation_replay(&self, transaction_id: &str) -> Option<&FederationReplayRecord> {
        self.federation_replay.get(transaction_id)
    }
}

pub fn rebuild_space_state_from_events<S>(
    store: &S,
    space_id: &SpaceId,
    space_version: impl Into<String>,
) -> Result<SpaceState>
where
    S: EventCacheStore,
{
    let events: Vec<Event> = store.events_for_space(space_id).into_iter().cloned().collect();
    let mut state = SpaceState::new(space_id.clone(), space_version.into());
    state.apply_events(&events)?;
    Ok(state)
}

pub fn restore_space_state_from_persistence<S>(
    store: &S,
    space_id: &SpaceId,
    space_version: impl Into<String>,
) -> Result<SnapshotRestore>
where
    S: EventCacheStore + StateSnapshotStore,
{
    let events: Vec<Event> = store.events_for_space(space_id).into_iter().cloned().collect();
    SpaceState::restore_snapshot_or_replay(
        store.state_snapshot(space_id).cloned(),
        space_id.clone(),
        space_version,
        &events,
    )
}

/// Small LRU cache for store objects.
#[derive(Clone, Debug)]
pub struct StoreCache<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    capacity: usize,
    entries: BTreeMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V> StoreCache<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    /// Create a cache with a fixed capacity.
    pub fn new(capacity: usize) -> Self {
        Self { capacity, entries: BTreeMap::new(), order: VecDeque::new() }
    }

    /// Insert a value.
    pub fn insert(&mut self, key: K, value: V) {
        self.entries.insert(key.clone(), value);
        self.order.retain(|existing| existing != &key);
        self.order.push_back(key);
        while self.entries.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// Get a cached value.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Current cache size.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::{
        AuditAction, BLOB_SCHEMA, BlobRef, COMMIT_SCHEMA, DeviceId, Did, EventId, Hlc, ObjectState,
        SpaceId, resolver::SnapshotRestoreSource,
    };

    fn test_commit(commit_id: &str, author_seq: u64, operations: Vec<Hash>) -> Commit {
        let mut commit = Commit::new(
            CommitId::new(commit_id).unwrap(),
            "did:web:alice.example",
            Did::new("did:web:alice.example").unwrap(),
            author_seq,
        );
        commit.operations = operations;
        commit
    }

    fn entity_event(event_id: &str, title: &str) -> Event {
        Event {
            event_id: EventId::new(event_id).unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:alice.example.com").unwrap(),
            actor_seq: 1,
            created_at: Utc::now(),
            hlc: Hlc::new("01970e589d22-00000009-11111111").unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({
                "id": "cx:entity:01JS0SNAPENTITY00000000000",
                "entity_type": "task",
                "title": title
            }),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    fn blob_metadata(blob_ref: BlobRef, size: u64) -> BlobMetadata {
        BlobMetadata {
            schema: BLOB_SCHEMA.to_owned(),
            blob_ref,
            object_type: "blob".to_owned(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            size,
            media_type: "text/plain".to_owned(),
            filename: Some("note.txt".to_owned()),
            encryption: json!({"scheme": "none"}),
            thumbnail_ref: None,
            created_by: Did::new("did:web:alice.example").unwrap(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn operation_put_is_idempotent_for_same_bytes() {
        let mut store = MemoryRepoStore::new();
        let operation = Operation::create(
            OperationId::new("cx:operation:01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );

        store.put_operation(operation.clone()).unwrap();
        store.put_operation(operation).unwrap();

        assert_eq!(store.operations_len(), 1);
    }

    #[test]
    fn operation_put_rejects_same_id_with_different_payload() {
        let mut store = MemoryRepoStore::new();
        let mut operation = Operation::create(
            OperationId::new("cx:operation:01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        store.put_operation(operation.clone()).unwrap();

        operation.payload = json!({"id":"cx:entity:02"});
        assert!(matches!(store.put_operation(operation), Err(Error::IdempotencyConflict(_))));
    }

    #[test]
    fn commit_put_updates_head_to_commit_digest() {
        let mut store = MemoryRepoStore::new();
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:01").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        };
        let expected = commit.commit_digest().unwrap();

        store.put_commit(commit).unwrap();

        assert_eq!(store.head().unwrap().as_str(), expected);
    }

    #[test]
    fn commit_put_rejects_non_head_append() {
        let mut store = MemoryRepoStore::new();
        let author = Did::new("did:web:alice.example").unwrap();
        let first = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:01").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: author.clone(),
            author_seq: 1,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        };
        store.put_commit(first).unwrap();

        let fork = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:02").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author,
            author_seq: 2,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        };

        assert!(matches!(store.put_commit(fork), Err(Error::Protocol(_))));
    }

    #[test]
    fn commit_put_rejects_unknown_operation_digest() {
        let mut store = MemoryRepoStore::new();
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:missing-op").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: None,
            operations: vec![
                Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
            ],
            created_at: Utc::now(),
            proofs: Vec::new(),
        };

        assert!(matches!(store.put_commit(commit), Err(Error::Protocol(_))));
    }

    #[test]
    fn commit_put_verified_invokes_signature_hook() {
        struct RejectingVerifier;

        impl CommitProofVerifier for RejectingVerifier {
            fn verify_commit(&self, _commit: &Commit) -> Result<()> {
                Err(Error::Protocol("bad signature".to_owned()))
            }
        }

        let mut store = MemoryRepoStore::new();
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:verified").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        };

        assert!(matches!(
            store.put_commit_verified(commit, &RejectingVerifier),
            Err(Error::Protocol(_))
        ));
        assert_eq!(store.commits_len(), 0);
    }

    #[test]
    fn memory_store_lists_operations_and_commits() {
        let mut store = MemoryRepoStore::new();
        let op = Operation::create(
            OperationId::new("cx:operation:list").unwrap(),
            SpaceId::new("cx:space:list").unwrap(),
            "task",
            serde_json::json!({"title": "listed"}),
        );
        let op_digest = Hash::new(op.operation_digest().unwrap()).unwrap();
        store.put_operation(op).unwrap();

        let mut commit = Commit::new(
            CommitId::new("cx:commit:list").unwrap(),
            "did:web:alice.example",
            Did::new("did:web:alice.example").unwrap(),
            1,
        );
        commit.operations.push(op_digest);
        store.put_commit(commit).unwrap();

        assert_eq!(store.operations().count(), 1);
        assert_eq!(store.commits().count(), 1);
    }

    #[test]
    fn migration_metadata_records_schema_version_and_checksums() {
        let mut store = SqliteRepoStore::new();
        let metadata = store
            .apply_migration_checked(StoreMigration {
                version: 1,
                statements: vec!["create table operations".to_owned()],
            })
            .unwrap();

        assert_eq!(metadata.version, 1);
        assert!(metadata.checksum.starts_with("sha256:"));
        assert_eq!(store.schema_metadata().schema_version, 1);
        assert_eq!(store.schema_metadata().applied_migrations.len(), 1);
        assert!(matches!(
            store.apply_migration_checked(StoreMigration {
                version: 1,
                statements: vec!["create table commits".to_owned()],
            }),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn transactional_batch_writes_operations_and_commits_atomically() {
        let mut store = MemoryRepoStore::new();
        let operation = Operation::create(
            OperationId::new("cx:operation:txn").unwrap(),
            SpaceId::new("cx:space:txn").unwrap(),
            "entity",
            json!({"id":"cx:entity:txn"}),
        );
        let operation_digest = Hash::new(operation.operation_digest().unwrap()).unwrap();
        let commit = test_commit("cx:commit:txn", 1, vec![operation_digest]);

        let receipt = store
            .write_batch(
                RepoWriteBatch::new().with_operation(operation.clone()).with_commit(commit.clone()),
            )
            .unwrap();

        assert_eq!(receipt.operations_written, 1);
        assert_eq!(receipt.commits_written, 1);
        assert!(store.operation(&operation.operation_id).is_some());
        assert!(store.commit(&commit.commit_id).is_some());

        let idempotent_receipt = store
            .write_batch(RepoWriteBatch::new().with_operation(operation).with_commit(commit))
            .unwrap();
        assert_eq!(idempotent_receipt.operations_written, 0);
        assert_eq!(idempotent_receipt.commits_written, 0);
    }

    #[test]
    fn transactional_batch_rolls_back_partial_operation_on_commit_failure() {
        let mut store = MemoryRepoStore::new();
        let operation = Operation::create(
            OperationId::new("cx:operation:txn-rollback").unwrap(),
            SpaceId::new("cx:space:txn").unwrap(),
            "entity",
            json!({"id":"cx:entity:txn"}),
        );
        let commit = test_commit(
            "cx:commit:txn-rollback",
            1,
            vec![
                Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
            ],
        );

        assert!(matches!(
            store.write_batch(
                RepoWriteBatch::new().with_operation(operation.clone()).with_commit(commit)
            ),
            Err(Error::Protocol(_))
        ));
        assert!(store.operation(&operation.operation_id).is_none());
        assert_eq!(store.operations_len(), 0);
        assert_eq!(store.commits_len(), 0);
    }

    #[test]
    fn snapshot_recovery_rebuilds_indexes_and_rejects_bad_head() {
        let mut store = SqliteRepoStore::new();
        let operation = Operation::create(
            OperationId::new("cx:operation:recover").unwrap(),
            SpaceId::new("cx:space:recover").unwrap(),
            "entity",
            json!({"id":"cx:entity:recover"}),
        );
        let operation_digest = operation.operation_digest().unwrap();
        let commit =
            test_commit("cx:commit:recover", 1, vec![Hash::new(operation_digest.clone()).unwrap()]);
        store
            .write_batch(
                RepoWriteBatch::new().with_operation(operation.clone()).with_commit(commit),
            )
            .unwrap();

        let snapshot = store.export_snapshot();
        let recovered = SqliteRepoStore::recover_from_snapshot(snapshot.clone()).unwrap();
        assert_eq!(
            recovered.operation_by_digest(&operation_digest).unwrap().operation_id,
            operation.operation_id
        );

        let mut bad_snapshot = snapshot;
        bad_snapshot.head = Some(
            Hash::new("sha256:2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
        );
        assert!(matches!(
            SqliteRepoStore::recover_from_snapshot(bad_snapshot),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn projection_rebuild_helpers_replay_event_cache_and_use_valid_snapshot() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let event = entity_event("cx:event:01JS0STORE0000000000000001", "Stored task");
        let mut store = MemoryPersistenceStore::new();
        store.put_event(event.clone()).unwrap();
        store.put_event(event.clone()).unwrap();

        let mut conflicting = event;
        conflicting.content = json!({
            "id": "cx:entity:01JS0SNAPENTITY00000000000",
            "entity_type": "task",
            "title": "Changed"
        });
        assert!(matches!(store.put_event(conflicting), Err(Error::IdempotencyConflict(_))));

        let state = rebuild_space_state_from_events(&store, &space_id, "1").unwrap();
        assert_eq!(state.entities.len(), 1);
        assert_eq!(
            state.entities.get("cx:entity:01JS0SNAPENTITY00000000000").unwrap().state,
            Some(ObjectState::Active)
        );

        store.put_state_snapshot(state.snapshot()).unwrap();
        let restored = restore_space_state_from_persistence(&store, &space_id, "1").unwrap();
        assert_eq!(restored.source, SnapshotRestoreSource::Snapshot);
        assert_eq!(restored.state.entities.len(), 1);
    }

    #[test]
    fn memory_persistence_store_roundtrips_auxiliary_records() {
        let mut store = MemoryPersistenceStore::new();
        let principal_id = Did::new("did:web:alice.example").unwrap();
        let device_id = DeviceId::new("dev_phone").unwrap();
        let session = AuthSession {
            session_id: "sess-1".to_owned(),
            user_id: principal_id.clone(),
            principal_id: principal_id.clone(),
            device_id,
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
            expires_at: Utc::now(),
            revoked: false,
            created_at: Utc::now(),
        };
        store.put_session(session.clone()).unwrap();
        store.put_session(session).unwrap();
        assert_eq!(store.sessions_for_principal(&principal_id).len(), 1);
        store.revoke_session("sess-1").unwrap();
        assert!(store.session("sess-1").unwrap().revoked);

        store
            .put_account_data(StoredAccountData {
                principal_id: principal_id.clone(),
                data_type: "settings".to_owned(),
                content: json!({"theme": "dark"}),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(
            store.account_data(&principal_id, "settings").unwrap().content,
            json!({"theme": "dark"})
        );

        let blob_ref =
            BlobRef::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let metadata = blob_metadata(blob_ref.clone(), 12);
        store.put_blob_metadata(metadata.clone()).unwrap();
        store.put_blob_metadata(metadata.clone()).unwrap();
        let mut conflicting_metadata = metadata;
        conflicting_metadata.size = 13;
        assert!(matches!(
            store.put_blob_metadata(conflicting_metadata),
            Err(Error::IdempotencyConflict(_))
        ));
        assert_eq!(store.blob_metadata(&blob_ref).unwrap().size, 12);

        store
            .append_audit_entry(AuditEntry {
                timestamp: Utc::now(),
                action: AuditAction::KeyBackedUp,
                actor: Some(principal_id.clone()),
                group_id: Some("group1".to_owned()),
                detail: "backup".to_owned(),
            })
            .unwrap();
        assert_eq!(store.audit_entries().len(), 1);

        let replay = FederationReplayRecord {
            transaction_id: "txn-1".to_owned(),
            origin: principal_id,
            destination: Did::new("did:web:bob.example").unwrap(),
            request_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            response_digest: None,
            seen_at: Utc::now(),
        };
        store.put_federation_replay(replay.clone()).unwrap();
        store.put_federation_replay(replay).unwrap();
        assert!(store.has_federation_replay("txn-1"));
    }

    #[test]
    fn sqlite_store_applies_migrations_indexes_and_snapshots() {
        let mut store = SqliteRepoStore::new();
        store.apply_migration(StoreMigration {
            version: 1,
            statements: vec!["create table operations".to_owned()],
        });
        let operation = Operation::create(
            OperationId::new("cx:operation:02").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        let digest = operation.operation_digest().unwrap();
        store.put_operation(operation.clone()).unwrap();

        assert_eq!(store.schema_version(), 1);
        assert_eq!(
            store.operation_by_digest(&digest).unwrap().operation_id,
            operation.operation_id
        );

        let snapshot = store.export_snapshot();
        let mut imported = SqliteRepoStore::new();
        imported.import_snapshot(snapshot).unwrap();
        assert!(imported.operation(&operation.operation_id).is_some());
    }

    #[test]
    fn indexeddb_store_enforces_quota_and_background_sync() {
        let mut store = IndexedDbRepoStore::new(4096);
        let operation = Operation::create(
            OperationId::new("cx:operation:03").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        store.put_operation(operation.clone()).unwrap();
        assert!(store.remaining_quota() < 4096);

        store.enqueue_background_sync(operation.operation_id.to_string());
        assert_eq!(store.pop_background_sync(), Some("cx:operation:03".to_owned()));
    }

    #[test]
    fn encrypted_store_keeps_ciphertext_and_plain_api() {
        let key = StoreEncryptionKey::derive("passphrase", b"salt", 4);
        let mut store = EncryptedMemoryRepoStore::new(key);
        let operation = Operation::create(
            OperationId::new("cx:operation:04").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        store.put_operation(operation.clone()).unwrap();

        let ciphertext = store.encrypted_operation_bytes(&operation.operation_id).unwrap();
        assert!(!String::from_utf8_lossy(ciphertext).contains("cx:entity:01"));
        assert!(store.operation(&operation.operation_id).is_some());
    }

    #[test]
    fn store_cache_evicts_lru_entries() {
        let mut cache = StoreCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);

        assert!(cache.get(&"a").is_none());
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.len(), 2);
    }
}
