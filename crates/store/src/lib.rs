//! Durable store contracts and conformance helpers.
//!
//! The umbrella SDK still contains higher-level runtime stores. This crate is
//! the smaller adapter contract that concrete memory, SQLite and IndexedDB
//! implementations can share without depending on client runtime modules.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use contrix_core::{
    BlobRef, Commit, CommitId, Error, Event, EventId, Hash, Operation, OperationId, Result, SpaceId,
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
    CoreEventStore,
    EventCache,
    SyncToken,
    SendQueue,
    MediaCache,
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

pub const CORE_EVENT_STORE_PROFILE: &str = "cx.profile.core_event_store.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreEventSubmitStatus {
    AcceptedNew,
    AcceptedDuplicate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventSubmitReceipt {
    pub event_id: EventId,
    pub digest: Hash,
    pub status: CoreEventSubmitStatus,
    pub frontier: Vec<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventFetchRequest {
    pub event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventBatchGetRequest {
    pub event_ids: Vec<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventBackfillRequest {
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_event_id: Option<EventId>,
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CoreEventBackfillResponse {
    pub events: Vec<Event>,
    pub frontier: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_event_id: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventFrontierRequest {
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventFrontierResponse {
    pub space_id: SpaceId,
    pub frontier: Vec<EventId>,
}

pub trait EventAuthRefValidator {
    fn validate_auth_refs(&self, event: &Event, known_events: &BTreeSet<EventId>) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RequireKnownAuthRefs;

impl EventAuthRefValidator for RequireKnownAuthRefs {
    fn validate_auth_refs(&self, event: &Event, known_events: &BTreeSet<EventId>) -> Result<()> {
        for auth_ref in &event.auth_refs {
            if !known_events.contains(auth_ref) {
                return Err(Error::Protocol(format!("missing auth dependency: {auth_ref}")));
            }
        }
        Ok(())
    }
}

pub trait CoreEventStore {
    fn submit_event(&mut self, event: Event) -> Result<CoreEventSubmitReceipt>;
    fn fetch_event(&self, request: &CoreEventFetchRequest) -> Option<&Event>;
    fn batch_get_events(&self, request: &CoreEventBatchGetRequest) -> Vec<&Event>;
    fn backfill_events(
        &self,
        request: &CoreEventBackfillRequest,
    ) -> Result<CoreEventBackfillResponse>;
    fn event_frontier(&self, request: &CoreEventFrontierRequest) -> CoreEventFrontierResponse;

    /// Submit a batch of events and return a per-item outcome.
    ///
    /// Unlike calling `submit_event` in a loop and `?`-ing the first
    /// error (which collapses success / duplicate / rejected into one
    /// failure), this method records every event's outcome and returns
    /// the full vector. Callers can then surface partial-success
    /// responses to the wire.
    fn submit_events_batched(&mut self, events: Vec<Event>) -> Vec<EventBatchResult> {
        events
            .into_iter()
            .map(|event| {
                let event_id = event.event_id.clone();
                match self.submit_event(event) {
                    Ok(receipt) => EventBatchResult::Accepted {
                        event_id,
                        status: receipt.status,
                        digest: receipt.digest,
                        frontier: receipt.frontier,
                    },
                    Err(err) => EventBatchResult::Rejected {
                        event_id,
                        error_code: classify_submit_error(&err),
                        reason: err.to_string(),
                    },
                }
            })
            .collect()
    }
}

/// Per-item outcome for a batched `cx.events.submit` call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EventBatchResult {
    Accepted {
        event_id: EventId,
        status: CoreEventSubmitStatus,
        digest: Hash,
        frontier: Vec<EventId>,
    },
    Rejected {
        event_id: EventId,
        /// Machine-readable error code from the spec registry
        /// (`error-code-registry.json`). See
        /// [`contrix_core::error::KNOWN_ERROR_CODES`].
        error_code: String,
        /// Human-readable reason.
        reason: String,
    },
}

impl EventBatchResult {
    /// Whether this item was accepted (new or duplicate).
    pub fn is_accepted(&self) -> bool {
        matches!(self, EventBatchResult::Accepted { .. })
    }
}

fn classify_submit_error(err: &Error) -> String {
    match err {
        Error::IdempotencyConflict(_) => "idempotency_conflict".to_owned(),
        Error::NonCanonicalNumber => "canonical_json_violation".to_owned(),
        Error::CanonicalJson(_) => "canonical_json_violation".to_owned(),
        Error::InvalidId(_) => "invalid_id".to_owned(),
        Error::Crypto(_) => "crypto_error".to_owned(),
        Error::Protocol(reason) => {
            // Derive an error code from the reason prefix where possible
            // (e.g. `digest_mismatch:` => `digest_mismatch`).
            reason
                .split_once(':')
                .map(|(code, _)| code.trim().to_owned())
                .unwrap_or_else(|| "protocol_error".to_owned())
        }
        _ => "protocol_error".to_owned(),
    }
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
pub struct PersistentSyncToken {
    pub stream: String,
    pub token: String,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl PersistentSyncToken {
    pub fn validate(&self) -> Result<()> {
        if self.stream.trim().is_empty() || self.token.trim().is_empty() {
            return Err(Error::Protocol("sync token requires stream and token".to_owned()));
        }
        Ok(())
    }
}

pub trait SyncTokenStore {
    fn put_sync_token(&mut self, token: PersistentSyncToken) -> Result<()>;
    fn sync_token(&self, stream: &str) -> Option<&PersistentSyncToken>;
    fn remove_sync_token(&mut self, stream: &str) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueStatus {
    Queued,
    Sending,
    Sent,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendQueueRecord {
    pub transaction_id: String,
    pub space_id: SpaceId,
    pub event_kind: String,
    pub content: Value,
    pub status: SendQueueStatus,
    #[serde(default)]
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SendQueueRecord {
    pub fn validate(&self) -> Result<()> {
        if self.transaction_id.trim().is_empty() {
            return Err(Error::Protocol("send queue transaction id must not be empty".to_owned()));
        }
        if self.event_kind.trim().is_empty() {
            return Err(Error::Protocol("send queue event kind must not be empty".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("send queue content must be a JSON object".to_owned()));
        }
        Ok(())
    }

    pub fn is_ready_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.status, SendQueueStatus::Queued | SendQueueStatus::Failed)
            && self.next_attempt_at.is_none_or(|retry_at| retry_at <= now)
    }
}

pub trait SendQueueStore {
    fn put_send_queue_record(&mut self, record: SendQueueRecord) -> Result<()>;
    fn send_queue_record(&self, transaction_id: &str) -> Option<&SendQueueRecord>;
    fn ready_send_queue_records(&self, now: DateTime<Utc>, limit: usize) -> Vec<&SendQueueRecord>;
    fn mark_send_queue_status(
        &mut self,
        transaction_id: &str,
        status: SendQueueStatus,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaCacheRecord {
    pub blob_ref: BlobRef,
    pub content_type: String,
    pub size: u64,
    pub sha256: Hash,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_uri: Option<String>,
    pub last_accessed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl MediaCacheRecord {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() {
            return Err(Error::Protocol("media cache content type must not be empty".to_owned()));
        }
        if self.size == 0 {
            return Err(Error::Protocol("media cache size must be non-zero".to_owned()));
        }
        Ok(())
    }
}

pub trait MediaCacheStore {
    fn put_media_cache_record(&mut self, record: MediaCacheRecord) -> Result<()>;
    fn media_cache_record(&self, blob_ref: &BlobRef) -> Option<&MediaCacheRecord>;
    fn prune_media_cache(&mut self, now: DateTime<Utc>, max_total_bytes: u64) -> Result<usize>;
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
    event_digests: BTreeMap<EventId, Hash>,
    events_by_space: BTreeMap<SpaceId, VecDeque<EventId>>,
    frontiers_by_space: BTreeMap<SpaceId, BTreeSet<EventId>>,
    actor_sequences: BTreeMap<(SpaceId, contrix_core::Did), u64>,
    snapshots: BTreeMap<SpaceId, StateSnapshotRecord>,
    sync_tokens: BTreeMap<String, PersistentSyncToken>,
    send_queue: BTreeMap<String, SendQueueRecord>,
    media_cache: BTreeMap<BlobRef, MediaCacheRecord>,
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
        let digest = Hash::new(record.event.event_digest()?)?;
        match self.event_digests.get(&record.event_id) {
            Some(existing) if existing == &digest => return Ok(()),
            Some(_) => return Err(Error::IdempotencyConflict(record.event_id.to_string())),
            None => {}
        }
        self.events_by_space
            .entry(record.space_id.clone())
            .or_default()
            .push_back(record.event_id.clone());
        self.event_digests.insert(record.event_id.clone(), digest);
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

impl MemoryRuntimeStore {
    pub fn submit_event_with_auth_validator<V>(
        &mut self,
        event: Event,
        auth_validator: &V,
    ) -> Result<CoreEventSubmitReceipt>
    where
        V: EventAuthRefValidator + ?Sized,
    {
        validate_event_for_core_store(&event)?;
        let digest = Hash::new(event.event_digest()?)?;
        if let Some(existing_digest) = self.event_digests.get(&event.event_id) {
            if existing_digest == &digest {
                return Ok(CoreEventSubmitReceipt {
                    event_id: event.event_id.clone(),
                    digest,
                    status: CoreEventSubmitStatus::AcceptedDuplicate,
                    frontier: self.frontier_for_space(&event.space_id),
                });
            }
            return Err(Error::IdempotencyConflict(event.event_id.to_string()));
        }

        for prev_ref in &event.prev_refs {
            if !self.events.contains_key(prev_ref) {
                return Err(Error::Protocol(format!("missing causal dependency: {prev_ref}")));
            }
        }
        let known_events = self.events.keys().cloned().collect::<BTreeSet<_>>();
        auth_validator.validate_auth_refs(&event, &known_events)?;

        let actor_key = (event.space_id.clone(), event.actor_id.clone());
        if let Some(last_seq) = self.actor_sequences.get(&actor_key)
            && event.actor_seq <= *last_seq
        {
            return Err(Error::Protocol(format!(
                "actor_seq {} is not greater than last accepted {} for {}",
                event.actor_seq, last_seq, event.actor_id
            )));
        }

        let event_id = event.event_id.clone();
        let space_id = event.space_id.clone();
        let order_key = event.hlc.to_string();
        let actor_seq = event.actor_seq;
        let actor_id = event.actor_id.clone();
        let prev_refs = event.prev_refs.clone();
        self.put_event(EventCacheRecord {
            event_id: event_id.clone(),
            space_id: space_id.clone(),
            order_key,
            event,
            cached_at: Utc::now(),
        })?;
        self.actor_sequences.insert((space_id.clone(), actor_id), actor_seq);
        self.update_core_event_frontier(&space_id, &event_id, &prev_refs);
        Ok(CoreEventSubmitReceipt {
            event_id,
            digest,
            status: CoreEventSubmitStatus::AcceptedNew,
            frontier: self.frontier_for_space(&space_id),
        })
    }

    fn update_core_event_frontier(
        &mut self,
        space_id: &SpaceId,
        event_id: &EventId,
        prev_refs: &[EventId],
    ) {
        let frontier = self.frontiers_by_space.entry(space_id.clone()).or_default();
        for prev_ref in prev_refs {
            frontier.remove(prev_ref);
        }
        frontier.insert(event_id.clone());
    }

    fn frontier_for_space(&self, space_id: &SpaceId) -> Vec<EventId> {
        self.frontiers_by_space
            .get(space_id)
            .map(|frontier| frontier.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl CoreEventStore for MemoryRuntimeStore {
    fn submit_event(&mut self, event: Event) -> Result<CoreEventSubmitReceipt> {
        self.submit_event_with_auth_validator(event, &RequireKnownAuthRefs)
    }

    fn fetch_event(&self, request: &CoreEventFetchRequest) -> Option<&Event> {
        self.events.get(&request.event_id).map(|record| &record.event)
    }

    fn batch_get_events(&self, request: &CoreEventBatchGetRequest) -> Vec<&Event> {
        request
            .event_ids
            .iter()
            .filter_map(|event_id| self.events.get(event_id).map(|record| &record.event))
            .collect()
    }

    fn backfill_events(
        &self,
        request: &CoreEventBackfillRequest,
    ) -> Result<CoreEventBackfillResponse> {
        if request.limit == 0 {
            return Err(Error::Protocol("core event backfill limit must be non-zero".to_owned()));
        }
        let mut started = request.from_event_id.is_none();
        let mut events = Vec::new();
        let mut next_event_id = None;
        for record in self.events_for_space(&request.space_id) {
            if !started {
                started = request.from_event_id.as_ref() == Some(&record.event_id);
                continue;
            }
            if events.len() == request.limit {
                next_event_id = Some(record.event_id.clone());
                break;
            }
            events.push(record.event.clone());
        }
        Ok(CoreEventBackfillResponse {
            events,
            frontier: self.frontier_for_space(&request.space_id),
            next_event_id,
        })
    }

    fn event_frontier(&self, request: &CoreEventFrontierRequest) -> CoreEventFrontierResponse {
        CoreEventFrontierResponse {
            space_id: request.space_id.clone(),
            frontier: self.frontier_for_space(&request.space_id),
        }
    }
}

fn validate_event_for_core_store(event: &Event) -> Result<()> {
    if !event.content.is_object() {
        return Err(Error::Protocol("event content must be a JSON object".to_owned()));
    }
    if event.critical_extensions.iter().any(|extension| !extension.fail_closed) {
        return Err(Error::Protocol(
            "event critical extensions must declare fail_closed=true".to_owned(),
        ));
    }
    if !event.proofs.is_empty() {
        event.validate_proof_bindings()?;
    }
    Ok(())
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

impl SyncTokenStore for MemoryRuntimeStore {
    fn put_sync_token(&mut self, token: PersistentSyncToken) -> Result<()> {
        token.validate()?;
        self.sync_tokens.insert(token.stream.clone(), token);
        Ok(())
    }

    fn sync_token(&self, stream: &str) -> Option<&PersistentSyncToken> {
        self.sync_tokens.get(stream)
    }

    fn remove_sync_token(&mut self, stream: &str) -> Result<()> {
        self.sync_tokens.remove(stream);
        Ok(())
    }
}

impl SendQueueStore for MemoryRuntimeStore {
    fn put_send_queue_record(&mut self, record: SendQueueRecord) -> Result<()> {
        record.validate()?;
        match self.send_queue.get(&record.transaction_id) {
            Some(existing) if existing.content != record.content => {
                Err(Error::IdempotencyConflict(record.transaction_id))
            }
            _ => {
                self.send_queue.insert(record.transaction_id.clone(), record);
                Ok(())
            }
        }
    }

    fn send_queue_record(&self, transaction_id: &str) -> Option<&SendQueueRecord> {
        self.send_queue.get(transaction_id)
    }

    fn ready_send_queue_records(&self, now: DateTime<Utc>, limit: usize) -> Vec<&SendQueueRecord> {
        self.send_queue
            .values()
            .filter(|record| record.is_ready_at(now))
            .filter(|record| {
                record.dependencies.iter().all(|dependency| {
                    self.send_queue
                        .get(dependency)
                        .is_some_and(|dependency| dependency.status == SendQueueStatus::Sent)
                })
            })
            .take(limit)
            .collect()
    }

    fn mark_send_queue_status(
        &mut self,
        transaction_id: &str,
        status: SendQueueStatus,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let Some(record) = self.send_queue.get_mut(transaction_id) else {
            return Err(Error::Protocol(format!(
                "send queue transaction not found: {transaction_id}"
            )));
        };
        record.status = status;
        record.next_attempt_at = next_attempt_at;
        record.updated_at = Utc::now();
        Ok(())
    }
}

impl MediaCacheStore for MemoryRuntimeStore {
    fn put_media_cache_record(&mut self, record: MediaCacheRecord) -> Result<()> {
        record.validate()?;
        self.media_cache.insert(record.blob_ref.clone(), record);
        Ok(())
    }

    fn media_cache_record(&self, blob_ref: &BlobRef) -> Option<&MediaCacheRecord> {
        self.media_cache.get(blob_ref)
    }

    fn prune_media_cache(&mut self, now: DateTime<Utc>, max_total_bytes: u64) -> Result<usize> {
        let before = self.media_cache.len();
        self.media_cache.retain(|_, record| record.expires_at.is_none_or(|expires| expires > now));

        let mut total: u64 = self.media_cache.values().map(|record| record.size).sum();
        if total > max_total_bytes {
            let mut by_access = self
                .media_cache
                .values()
                .map(|record| (record.last_accessed_at, record.blob_ref.clone(), record.size))
                .collect::<Vec<_>>();
            by_access.sort_by_key(|(last_accessed_at, _, _)| *last_accessed_at);
            for (_, blob_ref, size) in by_access {
                if total <= max_total_bytes {
                    break;
                }
                if self.media_cache.remove(&blob_ref).is_some() {
                    total = total.saturating_sub(size);
                }
            }
        }

        Ok(before - self.media_cache.len())
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
    store.put_sync_token(PersistentSyncToken {
        stream: "client".to_owned(),
        token: "s1".to_owned(),
        updated_at: now,
        expires_at: None,
    })?;
    store.put_send_queue_record(SendQueueRecord {
        transaction_id: "txn1".to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-a6edb4a304bf").expect("valid space id"),
        event_kind: "cx.message.text".to_owned(),
        content: serde_json::json!({"body": "hello"}),
        status: SendQueueStatus::Queued,
        attempts: 0,
        next_attempt_at: None,
        dependencies: Vec::new(),
        created_at: now,
        updated_at: now,
    })?;
    store.put_media_cache_record(MediaCacheRecord {
        blob_ref: BlobRef::from_bytes(b"media"),
        content_type: "text/plain".to_owned(),
        size: 5,
        sha256: Hash::new(sha256_prefixed(b"media"))?,
        encrypted: false,
        local_uri: Some("memory://media".to_owned()),
        last_accessed_at: now,
        expires_at: Some(now + Duration::seconds(60)),
    })?;
    let event = Event::new(
        "cx.message.create",
        SpaceId::new("cx:space:01904100-0000-7000-8000-a6edb4a304bf").expect("valid space id"),
        contrix_core::Did::new("did:web:store.example").expect("valid did"),
        1,
        contrix_core::Hlc::new("01970e589d21-00000001-a13f9c2e").expect("valid hlc"),
        serde_json::json!({"body": "hello"}),
    )?;
    let core_event_receipt = store.submit_event(event)?;

    Ok(StoreConformanceReport {
        backend: StoreBackendDescriptor {
            backend: StoreBackendKind::Memory,
            schema_version: 1,
            capabilities: vec![
                StoreCapability::AtomicBatch,
                StoreCapability::SchemaMigration,
                StoreCapability::SnapshotExport,
                StoreCapability::CoreEventStore,
                StoreCapability::EventCache,
                StoreCapability::SyncToken,
                StoreCapability::SendQueue,
                StoreCapability::MediaCache,
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
            ("sync_token_persisted".to_owned(), store.sync_token("client").is_some()),
            ("send_queue_ready".to_owned(), store.ready_send_queue_records(now, 10).len() == 1),
            (
                "media_cache_persisted".to_owned(),
                store.media_cache_record(&BlobRef::from_bytes(b"media")).is_some(),
            ),
            (
                "core_event_submit_updates_frontier".to_owned(),
                core_event_receipt.frontier.len() == 1,
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

/// Pack an ad-hoc test suffix into a canonical lowercase UUIDv7 envelope so
/// the strict typed-id validators accept it. Keeps the suffix uniqueness via
/// sha256 truncation while still passing the wire-format gate.
fn fixture_uuid7(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(seed.as_bytes());
    let mut tail = String::with_capacity(12);
    for b in digest.iter().take(6) {
        use std::fmt::Write as _;
        let _ = write!(&mut tail, "{:02x}", b);
    }
    format!("01904100-0000-7000-8000-{tail}")
}

fn test_operation(suffix: &str) -> Operation {
    Operation::create(
        OperationId::new(format!("cx:operation:{}", fixture_uuid7(&format!("op:{suffix}"))))
            .expect("valid operation id"),
        SpaceId::new("cx:space:01904100-0000-7000-8000-a6edb4a304bf").expect("valid space id"),
        "entity",
        serde_json::json!({
            "id": format!("cx:entity:{}", fixture_uuid7(&format!("entity:{suffix}"))),
        }),
    )
}

fn test_commit(suffix: &str, operations: Vec<Hash>) -> Commit {
    let mut commit = Commit::new(
        CommitId::new(format!("cx:commit:{}", fixture_uuid7(&format!("commit:{suffix}"))))
            .expect("valid commit id"),
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
    use contrix_core::{Did, Hlc};
    use serde_json::json;

    fn event(actor_seq: u64, body: &str) -> Event {
        Event::new(
            "cx.message.create",
            SpaceId::new("cx:space:01904100-0000-7000-8000-a6edb4a304bf").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            actor_seq,
            Hlc::new(format!("01970e589d21-{actor_seq:08x}-a13f9c2e")).unwrap(),
            json!({ "body": body }),
        )
        .unwrap()
    }

    #[test]
    fn memory_store_is_idempotent_and_rejects_conflicting_operation_bytes() {
        let mut store = MemoryRuntimeStore::new();
        let operation = test_operation("same");
        assert!(store.put_operation(operation.clone()).unwrap().inserted);
        assert!(!store.put_operation(operation).unwrap().inserted);

        let mut conflict = test_operation("same");
        conflict.payload = serde_json::json!({"id": "cx:entity:01904100-0000-7000-8000-3169112b9122"});
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
    fn runtime_store_persists_sync_tokens_send_queue_and_media_cache() {
        let now = Utc::now();
        let mut store = MemoryRuntimeStore::new();
        store
            .put_sync_token(PersistentSyncToken {
                stream: "sliding".to_owned(),
                token: "tok1".to_owned(),
                updated_at: now,
                expires_at: None,
            })
            .unwrap();
        assert_eq!(store.sync_token("sliding").unwrap().token, "tok1");

        store
            .put_send_queue_record(SendQueueRecord {
                transaction_id: "txn1".to_owned(),
                space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-a6edb4a304bf").unwrap(),
                event_kind: "cx.message.text".to_owned(),
                content: serde_json::json!({"body": "hello"}),
                status: SendQueueStatus::Queued,
                attempts: 0,
                next_attempt_at: None,
                dependencies: Vec::new(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();
        assert_eq!(store.ready_send_queue_records(now, 10).len(), 1);
        store.mark_send_queue_status("txn1", SendQueueStatus::Sent, None).unwrap();
        assert_eq!(store.send_queue_record("txn1").unwrap().status, SendQueueStatus::Sent);

        let blob_ref = BlobRef::from_bytes(b"cached");
        store
            .put_media_cache_record(MediaCacheRecord {
                blob_ref: blob_ref.clone(),
                content_type: "image/png".to_owned(),
                size: 128,
                sha256: Hash::new(sha256_prefixed(b"cached")).unwrap(),
                encrypted: true,
                local_uri: Some("memory://cached".to_owned()),
                last_accessed_at: now,
                expires_at: Some(now + Duration::seconds(1)),
            })
            .unwrap();
        assert_eq!(store.media_cache_record(&blob_ref).unwrap().size, 128);
        assert_eq!(store.prune_media_cache(now + Duration::seconds(2), 1024).unwrap(), 1);
        assert!(store.media_cache_record(&blob_ref).is_none());
    }

    #[test]
    fn core_event_store_accepts_duplicates_and_rejects_conflicts() {
        let mut store = MemoryRuntimeStore::new();
        let first = event(1, "one");
        let receipt = store.submit_event(first.clone()).unwrap();
        assert_eq!(receipt.status, CoreEventSubmitStatus::AcceptedNew);
        let duplicate = store.submit_event(first.clone()).unwrap();
        assert_eq!(duplicate.status, CoreEventSubmitStatus::AcceptedDuplicate);

        let mut conflict = first;
        conflict.content = json!({"body": "changed"});
        assert!(matches!(store.submit_event(conflict), Err(Error::IdempotencyConflict(_))));
    }

    #[test]
    fn core_event_store_validates_actor_seq_prev_refs_and_auth_refs() {
        let mut store = MemoryRuntimeStore::new();
        let first = event(1, "one");
        let first_id = first.event_id.clone();
        store.submit_event(first).unwrap();

        let stale_seq = event(1, "stale");
        assert!(matches!(store.submit_event(stale_seq), Err(Error::Protocol(_))));

        let mut second = event(2, "two");
        second.prev_refs.push(first_id.clone());
        second.auth_refs.push(first_id);
        second.refresh_event_id().unwrap();
        let second_id = second.event_id.clone();
        store.submit_event(second).unwrap();

        let fetched = store.fetch_event(&CoreEventFetchRequest { event_id: second_id });
        assert!(fetched.is_some());
        assert_eq!(
            store
                .event_frontier(&CoreEventFrontierRequest {
                    space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-a6edb4a304bf").unwrap()
                })
                .frontier
                .len(),
            1
        );

        let mut missing_prev = event(3, "missing");
        missing_prev.prev_refs.push(EventId::new("cx:event:01904100-0000-7000-8000-30f4e405b35e").unwrap());
        missing_prev.refresh_event_id().unwrap();
        assert!(matches!(store.submit_event(missing_prev), Err(Error::Protocol(_))));

        let mut missing_auth = event(3, "missing-auth");
        missing_auth.auth_refs.push(EventId::new("cx:event:01904100-0000-7000-8000-a135895eea64").unwrap());
        missing_auth.refresh_event_id().unwrap();
        assert!(matches!(store.submit_event(missing_auth), Err(Error::Protocol(_))));
    }

    #[test]
    fn memory_conformance_report_validates() {
        memory_store_conformance_report().unwrap().validate().unwrap();
    }
}
