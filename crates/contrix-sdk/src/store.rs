use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Commit, CommitId, Error, Hash, Operation, OperationId, Result, crypto};

pub trait RepoStore: Send + Sync {
    fn put_operation(&mut self, operation: Operation) -> Result<()>;
    fn put_commit(&mut self, commit: Commit) -> Result<()>;
    fn operation(&self, operation_id: &OperationId) -> Option<&Operation>;
    fn commit(&self, commit_id: &CommitId) -> Option<&Commit>;
    fn head(&self) -> Option<&Hash>;
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

#[derive(Debug, Default)]
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
#[derive(Debug, Default)]
pub struct SqliteRepoStore {
    inner: MemoryRepoStore,
    schema_version: u32,
    migrations: Vec<StoreMigration>,
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
        self.migrations.push(migration);
    }

    /// Current schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
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
        self.schema_version = snapshot.schema_version;
        for operation in snapshot.operations {
            self.put_operation(operation)?;
        }
        for commit in snapshot.commits {
            self.put_commit(commit)?;
        }
        self.inner.head = snapshot.head;
        Ok(())
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

/// IndexedDB-compatible WASM store facade with quota and background sync state.
#[derive(Debug)]
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

    fn seal(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        crypto::seal(bytes, &self.0, aad)
    }
}

/// Encrypted in-memory repo store.
#[derive(Debug)]
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
        self.encrypted_operations.insert(operation.operation_id.clone(), encrypted);
        self.inner.put_operation(operation)
    }

    fn put_commit(&mut self, commit: Commit) -> Result<()> {
        let bytes = serde_json::to_vec(&commit)?;
        let encrypted = self.key.seal(&bytes, commit.commit_id.as_str().as_bytes())?;
        self.encrypted_commits.insert(commit.commit_id.clone(), encrypted);
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
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::{COMMIT_SCHEMA, Did, SpaceId};

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
