//! Durable store contracts and conformance helpers.
//!
//! The umbrella SDK still contains higher-level runtime stores. This crate is
//! the smaller adapter contract that concrete memory, SQLite and IndexedDB
//! implementations can share without depending on client runtime modules.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use contrix_core::{
    Commit, CommitId, Error, Event, EventId, Hash, Operation, OperationId, Result, SpaceId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreBackendKind {
    Memory,
    Sqlite,
    IndexedDb,
    Distributed,
    Custom(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreCapability {
    AtomicBatch,
    SchemaMigration,
    SnapshotExport,
    EventCache,
    EncryptionAtRest,
    FailureCache,
    ConcurrentReaders,
    QuotaReporting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreBackendDescriptor {
    pub backend: StoreBackendKind,
    pub schema_version: u32,
    pub capabilities: Vec<StoreCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_object_bytes: Option<u64>,
}

impl StoreBackendDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version == 0 {
            return Err(Error::Protocol("store schema version must be non-zero".to_owned()));
        }
        if self.max_object_bytes == Some(0) {
            return Err(Error::Protocol("store object size limit must be non-zero".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreWriteReceipt {
    pub inserted: bool,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreBatchReceipt {
    pub operations_written: usize,
    pub commits_written: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<Hash>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RepoWriteBatch {
    pub operations: Vec<Operation>,
    pub commits: Vec<Commit>,
}

impl RepoWriteBatch {
    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operations.push(operation);
        self
    }

    pub fn with_commit(mut self, commit: Commit) -> Self {
        self.commits.push(commit);
        self
    }
}

pub trait RepoObjectStore {
    fn put_operation(&mut self, operation: Operation) -> Result<StoreWriteReceipt>;
    fn put_commit(&mut self, commit: Commit) -> Result<StoreWriteReceipt>;
    fn operation(&self, operation_id: &OperationId) -> Option<&Operation>;
    fn commit(&self, commit_id: &CommitId) -> Option<&Commit>;
    fn head(&self) -> Option<&Hash>;

    fn write_batch(&mut self, batch: RepoWriteBatch) -> Result<StoreBatchReceipt> {
        let mut operations_written = 0;
        let mut commits_written = 0;
        for operation in batch.operations {
            if self.put_operation(operation)?.inserted {
                operations_written += 1;
            }
        }
        for commit in batch.commits {
            if self.put_commit(commit)?.inserted {
                commits_written += 1;
            }
        }
        Ok(StoreBatchReceipt { operations_written, commits_written, head: self.head().cloned() })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventCacheRecord {
    pub event_id: EventId,
    pub space_id: SpaceId,
    pub order_key: String,
    pub event: Event,
    pub cached_at: DateTime<Utc>,
}

pub trait EventCacheStore {
    fn put_event(&mut self, record: EventCacheRecord) -> Result<()>;
    fn event(&self, event_id: &EventId) -> Option<&EventCacheRecord>;
    fn events_for_space(&self, space_id: &SpaceId) -> Vec<&EventCacheRecord>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateSnapshotRecord {
    pub space_id: SpaceId,
    pub state_hash: String,
    pub content: Value,
    pub created_at: DateTime<Utc>,
}

pub trait StateSnapshotStore {
    fn put_snapshot(&mut self, snapshot: StateSnapshotRecord) -> Result<()>;
    fn snapshot(&self, space_id: &SpaceId) -> Option<&StateSnapshotRecord>;
    fn remove_snapshot(&mut self, space_id: &SpaceId) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMigration {
    pub version: u32,
    pub name: String,
    pub checksum: String,
}

impl StoreMigration {
    pub fn new(version: u32, name: impl Into<String>, ddl: impl AsRef<[u8]>) -> Result<Self> {
        if version == 0 {
            return Err(Error::Protocol("store migration version must be non-zero".to_owned()));
        }
        let name = name.into();
        if name.trim().is_empty() {
            return Err(Error::Protocol("store migration name must not be empty".to_owned()));
        }
        Ok(Self { version, name, checksum: sha256_prefixed(ddl.as_ref()) })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMigrationRecord {
    pub migration: StoreMigration,
    pub applied_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreLockLease {
    pub holder: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl StoreLockLease {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreFailureKind {
    Network,
    QuotaExceeded,
    Busy,
    Corrupt,
    PermissionDenied,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreFailureRecord {
    pub key: String,
    pub kind: StoreFailureKind,
    pub message: String,
    pub retry_after: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreFailureCache {
    records: BTreeMap<String, StoreFailureRecord>,
}

impl StoreFailureCache {
    pub fn remember(&mut self, record: StoreFailureRecord) {
        self.records.insert(record.key.clone(), record);
    }

    pub fn active_failure(&self, key: &str, now: DateTime<Utc>) -> Option<&StoreFailureRecord> {
        self.records.get(key).filter(|record| record.retry_after > now)
    }

    pub fn prune(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| record.retry_after > now);
        before - self.records.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryRepoObjectStore {
    operations: BTreeMap<OperationId, (String, Operation)>,
    commits: BTreeMap<CommitId, (String, Commit)>,
    operation_digests: BTreeMap<String, OperationId>,
    head: Option<Hash>,
}

impl MemoryRepoObjectStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn operations_len(&self) -> usize {
        self.operations.len()
    }

    pub fn commits_len(&self) -> usize {
        self.commits.len()
    }
}

impl RepoObjectStore for MemoryRepoObjectStore {
    fn put_operation(&mut self, operation: Operation) -> Result<StoreWriteReceipt> {
        let digest = operation.operation_digest()?;
        match self.operations.get(&operation.operation_id) {
            Some((existing, _)) if existing == &digest => {
                Ok(StoreWriteReceipt { inserted: false, digest })
            }
            Some(_) => Err(Error::IdempotencyConflict(operation.operation_id.to_string())),
            None => {
                self.operation_digests.insert(digest.clone(), operation.operation_id.clone());
                self.operations.insert(operation.operation_id.clone(), (digest.clone(), operation));
                Ok(StoreWriteReceipt { inserted: true, digest })
            }
        }
    }

    fn put_commit(&mut self, commit: Commit) -> Result<StoreWriteReceipt> {
        for operation_hash in &commit.operations {
            if !self.operation_digests.contains_key(operation_hash.as_str()) {
                return Err(Error::Protocol(format!(
                    "commit references unknown operation digest '{}'",
                    operation_hash
                )));
            }
        }
        let digest = commit.commit_digest()?;
        match self.commits.get(&commit.commit_id) {
            Some((existing, _)) if existing == &digest => {
                Ok(StoreWriteReceipt { inserted: false, digest })
            }
            Some(_) => Err(Error::IdempotencyConflict(commit.commit_id.to_string())),
            None => {
                self.head = Some(Hash::new(digest.clone())?);
                self.commits.insert(commit.commit_id.clone(), (digest.clone(), commit));
                Ok(StoreWriteReceipt { inserted: true, digest })
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

#[derive(Clone, Debug, Default)]
pub struct MemoryRuntimeStore {
    repo: MemoryRepoObjectStore,
    events: BTreeMap<EventId, EventCacheRecord>,
    events_by_space: BTreeMap<SpaceId, VecDeque<EventId>>,
    snapshots: BTreeMap<SpaceId, StateSnapshotRecord>,
    migrations: Vec<StoreMigrationRecord>,
    failures: StoreFailureCache,
}

impl MemoryRuntimeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn repo(&self) -> &MemoryRepoObjectStore {
        &self.repo
    }

    pub fn failures_mut(&mut self) -> &mut StoreFailureCache {
        &mut self.failures
    }

    pub fn apply_migration(&mut self, migration: StoreMigration) -> Result<()> {
        if self.migrations.iter().any(|record| record.migration.version == migration.version) {
            return Err(Error::Protocol(format!(
                "store migration version {} already applied",
                migration.version
            )));
        }
        self.migrations.push(StoreMigrationRecord { migration, applied_at: Utc::now() });
        self.migrations.sort_by_key(|record| record.migration.version);
        Ok(())
    }

    pub fn migrations(&self) -> &[StoreMigrationRecord] {
        &self.migrations
    }
}

impl RepoObjectStore for MemoryRuntimeStore {
    fn put_operation(&mut self, operation: Operation) -> Result<StoreWriteReceipt> {
        self.repo.put_operation(operation)
    }

    fn put_commit(&mut self, commit: Commit) -> Result<StoreWriteReceipt> {
        self.repo.put_commit(commit)
    }

    fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.repo.operation(operation_id)
    }

    fn commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.repo.commit(commit_id)
    }

    fn head(&self) -> Option<&Hash> {
        self.repo.head()
    }
}

impl EventCacheStore for MemoryRuntimeStore {
    fn put_event(&mut self, record: EventCacheRecord) -> Result<()> {
        self.events_by_space
            .entry(record.space_id.clone())
            .or_default()
            .push_back(record.event_id.clone());
        self.events.insert(record.event_id.clone(), record);
        Ok(())
    }

    fn event(&self, event_id: &EventId) -> Option<&EventCacheRecord> {
        self.events.get(event_id)
    }

    fn events_for_space(&self, space_id: &SpaceId) -> Vec<&EventCacheRecord> {
        self.events_by_space
            .get(space_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|event_id| self.events.get(event_id))
            .collect()
    }
}

impl StateSnapshotStore for MemoryRuntimeStore {
    fn put_snapshot(&mut self, snapshot: StateSnapshotRecord) -> Result<()> {
        self.snapshots.insert(snapshot.space_id.clone(), snapshot);
        Ok(())
    }

    fn snapshot(&self, space_id: &SpaceId) -> Option<&StateSnapshotRecord> {
        self.snapshots.get(space_id)
    }

    fn remove_snapshot(&mut self, space_id: &SpaceId) -> Result<()> {
        self.snapshots.remove(space_id);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConformanceReport {
    pub backend: StoreBackendDescriptor,
    pub checks: BTreeMap<String, bool>,
}

impl StoreConformanceReport {
    pub fn validate(&self) -> Result<()> {
        self.backend.validate()?;
        if self.checks.values().all(|passed| *passed) {
            Ok(())
        } else {
            Err(Error::Protocol("store conformance report contains failures".to_owned()))
        }
    }
}

pub fn memory_store_conformance_report() -> Result<StoreConformanceReport> {
    let mut store = MemoryRuntimeStore::new();
    let operation = test_operation("01");
    let op_digest = Hash::new(operation.operation_digest()?)?;
    let commit = test_commit("01", vec![op_digest]);
    let batch = RepoWriteBatch::default().with_operation(operation).with_commit(commit);
    let receipt = store.write_batch(batch)?;

    let migration = StoreMigration::new(1, "initial", "create table objects")?;
    store.apply_migration(migration)?;

    let now = Utc::now();
    store.failures_mut().remember(StoreFailureRecord {
        key: "sqlite://primary".to_owned(),
        kind: StoreFailureKind::Busy,
        message: "locked".to_owned(),
        retry_after: now + Duration::seconds(5),
    });

    Ok(StoreConformanceReport {
        backend: StoreBackendDescriptor {
            backend: StoreBackendKind::Memory,
            schema_version: 1,
            capabilities: vec![
                StoreCapability::AtomicBatch,
                StoreCapability::SchemaMigration,
                StoreCapability::SnapshotExport,
                StoreCapability::EventCache,
                StoreCapability::FailureCache,
            ],
            max_object_bytes: Some(16 * 1024 * 1024),
        },
        checks: BTreeMap::from([
            ("batch_writes_objects".to_owned(), receipt.operations_written == 1),
            ("batch_updates_head".to_owned(), store.head().is_some()),
            ("migration_recorded".to_owned(), store.migrations().len() == 1),
            (
                "failure_cache_blocks_retry".to_owned(),
                store.failures.active_failure("sqlite://primary", now).is_some(),
            ),
        ]),
    })
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", base16_lower(&Sha256::digest(bytes)))
}

fn base16_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn test_operation(suffix: &str) -> Operation {
    Operation::create(
        OperationId::new(format!("cx:operation:store-{suffix}")).expect("valid operation id"),
        SpaceId::new("cx:space:store").expect("valid space id"),
        "entity",
        serde_json::json!({"id": format!("cx:entity:store-{suffix}")}),
    )
}

fn test_commit(suffix: &str, operations: Vec<Hash>) -> Commit {
    let mut commit = Commit::new(
        CommitId::new(format!("cx:commit:store-{suffix}")).expect("valid commit id"),
        "did:web:store.example",
        contrix_core::Did::new("did:web:store.example").expect("valid did"),
        1,
    );
    commit.operations = operations;
    commit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_is_idempotent_and_rejects_conflicting_operation_bytes() {
        let mut store = MemoryRuntimeStore::new();
        let operation = test_operation("same");
        assert!(store.put_operation(operation.clone()).unwrap().inserted);
        assert!(!store.put_operation(operation).unwrap().inserted);

        let mut conflict = test_operation("same");
        conflict.payload = serde_json::json!({"id": "cx:entity:changed"});
        assert!(matches!(store.put_operation(conflict), Err(Error::IdempotencyConflict(_))));
    }

    #[test]
    fn commit_references_must_exist_before_write() {
        let mut store = MemoryRuntimeStore::new();
        let operation = test_operation("commit");
        let op_digest = Hash::new(operation.operation_digest().unwrap()).unwrap();
        let commit = test_commit("commit", vec![op_digest]);
        assert!(matches!(store.put_commit(commit.clone()), Err(Error::Protocol(_))));

        store.put_operation(operation).unwrap();
        assert!(store.put_commit(commit).unwrap().inserted);
        assert!(store.head().is_some());
    }

    #[test]
    fn failure_cache_tracks_retry_window() {
        let now = Utc::now();
        let mut cache = StoreFailureCache::default();
        cache.remember(StoreFailureRecord {
            key: "indexeddb://repo".to_owned(),
            kind: StoreFailureKind::QuotaExceeded,
            message: "quota".to_owned(),
            retry_after: now + Duration::seconds(1),
        });

        assert!(cache.active_failure("indexeddb://repo", now).is_some());
        assert_eq!(cache.prune(now + Duration::seconds(2)), 1);
        assert!(cache.active_failure("indexeddb://repo", now + Duration::seconds(2)).is_none());
    }

    #[test]
    fn memory_conformance_report_validates() {
        memory_store_conformance_report().unwrap().validate().unwrap();
    }
}
