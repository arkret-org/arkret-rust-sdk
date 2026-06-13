//! Federation discovery, replay/fork quarantine, and content-digest
//! helpers.
//!
//! The protocol federation surface is the registered `ck.peer.*`
//! operation family (`/_cokret/peer/*`) with Event proofs / HTTP
//! message signatures via the `cokret-signatures` pipeline. A former
//! SDK-local "federation transaction/request" layer (concatenation
//! SHA-256 pseudo-signatures, free-form `txn_*` ids, unregistered
//! `/_cokret/federation/*` paths) was removed as non-spec — do not
//! reintroduce it.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
pub use cokret_core::federation::{
    FederationBackfillAuthorization, FederationQuarantineKind, FederationQuarantineRecord,
    FederationReplayDecision, FederationReplayRecord, FederationTransactionEnvelope,
    HttpMessageSignature, ServiceEndpointDescriptor, VerifyActorChallenge,
    VerifyActorChallengeSignature, WellKnownCokretServer,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Did, Error, Hash, RealmId, Result};

/// Server discovery info.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub domain: String,
    pub base_url: String,
    pub versions: Vec<String>,
    pub capabilities: BTreeSet<String>,
}

/// Sovereign deployment configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignDeployment {
    pub domain: String,
    pub allow_federation: bool,
    pub allowed_domains: BTreeSet<String>,
    pub policy: BTreeMap<String, String>,
}

pub trait FederationReplayStore {
    fn replay_record(&self, transaction_id: &str) -> Option<&FederationReplayRecord>;
    fn remember_replay_record(&mut self, record: FederationReplayRecord);
}

/// Federation manager.
#[derive(Clone, Debug, Default)]
pub struct FederationManager {
    servers: BTreeMap<String, ServerInfo>,
    events: BTreeMap<RealmId, Vec<Value>>,
    deployment: Option<SovereignDeployment>,
    replay: BTreeMap<String, FederationReplayRecord>,
}

impl FederationManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register server discovery information.
    pub fn register_server(&mut self, info: ServerInfo) {
        self.servers.insert(info.domain.clone(), info);
    }

    /// Resolve server `.well-known` style information.
    pub fn discover_server(&self, domain: &str) -> Option<&ServerInfo> {
        self.servers.get(domain)
    }

    /// Negotiate the first locally supported version also supported by the server.
    pub fn negotiate_version(&self, domain: &str, local_versions: &[String]) -> Option<String> {
        let server = self.servers.get(domain)?;
        local_versions
            .iter()
            .find(|version| server.versions.contains(*version))
            .cloned()
    }

    /// Query discovered capabilities.
    pub fn server_supports(&self, domain: &str, capability: &str) -> bool {
        self.servers
            .get(domain)
            .map(|server| server.capabilities.contains(capability))
            .unwrap_or(false)
    }

    /// Forward a federation event into local Realm state.
    pub fn forward_event(&mut self, realm_id: RealmId, event: Value) {
        self.events.entry(realm_id).or_default().push(event);
    }

    /// Query known state/events for a Realm.
    pub fn query_state(&self, realm_id: &RealmId) -> Vec<&Value> {
        self.events
            .get(realm_id)
            .map(|events| events.iter().collect())
            .unwrap_or_default()
    }

    /// Backfill events from a starting offset.
    pub fn backfill(&self, realm_id: &RealmId, from: usize, limit: usize) -> Vec<&Value> {
        self.events
            .get(realm_id)
            .map(|events| events.iter().skip(from).take(limit).collect())
            .unwrap_or_default()
    }

    /// Set sovereign deployment config.
    pub fn set_deployment(&mut self, deployment: SovereignDeployment) {
        self.deployment = Some(deployment);
    }

    /// Check whether federation with a domain is allowed.
    pub fn federation_allowed(&self, domain: &str) -> bool {
        self.deployment
            .as_ref()
            .map(|deployment| {
                deployment.allow_federation && deployment.allowed_domains.contains(domain)
            })
            .unwrap_or(true)
    }

    /// Export deployment config.
    pub fn export_deployment(&self) -> Result<String> {
        serde_json::to_string(&self.deployment).map_err(Into::into)
    }

    /// Import deployment config.
    pub fn import_deployment(&mut self, json: &str) -> Result<()> {
        self.deployment = serde_json::from_str(json)?;
        Ok(())
    }

    /// Check and remember federation transaction replay state.
    pub fn check_transaction_replay(
        &mut self,
        transaction_id: impl Into<String>,
        content_digest: Hash,
        now: DateTime<Utc>,
    ) -> FederationReplayDecision {
        check_replay(self, transaction_id.into(), content_digest, now)
    }
}

impl FederationReplayStore for FederationManager {
    fn replay_record(&self, transaction_id: &str) -> Option<&FederationReplayRecord> {
        self.replay.get(transaction_id)
    }

    fn remember_replay_record(&mut self, record: FederationReplayRecord) {
        self.replay.insert(record.transaction_id.clone(), record);
    }
}

/// Build a Cokret wire-form digest (`sha256:<hex>`) over `bytes`.
///
/// 复用 `core::canonical::sha256_digest` 这一**唯一**摘要 helper(见
/// `core/src/canonical.rs` 文档约束),不再在 federation 侧自行 `Sha256::new()`,
/// 保证与 soland / yougen / floria 产出的摘要串字节一致。
pub fn content_digest_sha256(bytes: &[u8]) -> String {
    cokret_core::canonical::sha256_digest(bytes)
}

/// Build the value of the RFC 9530 `Content-Digest` header
/// (`sha-256=:<base64>:`).
///
/// RFC 9530 用 **base64-standard**(带 padding)包裹原始 32 字节 digest,与
/// Cokret wire-form 的 `sha256:<hex>` 是两种编码;此处复用
/// `core::canonical::sha256_hex` 取裸 hex 后转 base64-standard。
pub fn rfc9530_content_digest_sha256(bytes: &[u8]) -> String {
    let raw = sha256_raw(bytes);
    format!("sha-256=:{}:", cokret_core::base64_standard_encode(raw))
}

/// Verify an RFC 9530 `Content-Digest` header against the body bytes.
///
/// Accepts a single dictionary entry of the form `sha-256=:<base64>:`.
/// Returns `Ok(())` when the digest matches, otherwise an
/// `Error::Protocol` carrying `digest_mismatch`.
pub fn verify_rfc9530_content_digest(header_value: &str, bytes: &[u8]) -> Result<()> {
    let trimmed = header_value.trim();
    let body = trimmed
        .strip_prefix("sha-256=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| {
            Error::Protocol(format!(
                "digest_mismatch: unsupported Content-Digest format: {trimmed}"
            ))
        })?;
    let provided = cokret_core::base64_standard_decode(body).map_err(|err| {
        Error::Protocol(format!(
            "digest_mismatch: bad base64 in Content-Digest: {err}"
        ))
    })?;
    if sha256_raw(bytes) == provided.as_slice() {
        Ok(())
    } else {
        Err(Error::Protocol(
            "digest_mismatch: Content-Digest does not match body".to_owned(),
        ))
    }
}

/// Raw 32-byte SHA-256 digest. RFC 9530 needs the raw bytes (not the
/// `sha256:<hex>` wire string), so this derives them from the canonical
/// hex helper to keep a single hashing path.
fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn did_document_service_endpoint_matches(
    did_document: &Value,
    service_did: &Did,
    service_type: &str,
    endpoint: &str,
) -> bool {
    did_document.get("id").and_then(Value::as_str) == Some(service_did.as_str())
        && did_document
            .get("service")
            .map(|services| match services {
                Value::Array(values) => values
                    .iter()
                    .any(|service| service_endpoint_matches(service, service_type, endpoint)),
                Value::Object(_) => service_endpoint_matches(services, service_type, endpoint),
                _ => false,
            })
            .unwrap_or(false)
}

pub fn check_replay<S>(
    store: &mut S,
    transaction_id: String,
    content_digest: Hash,
    now: DateTime<Utc>,
) -> FederationReplayDecision
where
    S: FederationReplayStore,
{
    if let Some(record) = store.replay_record(&transaction_id) {
        return if record.content_digest == content_digest {
            FederationReplayDecision::AcceptedDuplicate
        } else {
            FederationReplayDecision::QuarantinedConflict
        };
    }

    store.remember_replay_record(FederationReplayRecord {
        transaction_id,
        content_digest,
        first_seen_at: now,
    });
    FederationReplayDecision::AcceptedNew
}

pub fn duplicate_transaction_quarantine(
    transaction_id: impl Into<String>,
    expected_digest: Hash,
    observed_digest: Hash,
) -> FederationQuarantineRecord {
    FederationQuarantineRecord {
        kind: FederationQuarantineKind::DuplicateTransactionConflict,
        object_id: transaction_id.into(),
        expected_digest: Some(expected_digest),
        observed_digest: Some(observed_digest),
        reason: "idempotent transaction id was reused with different bytes".to_owned(),
    }
}

pub fn fork_quarantine_record(
    kind: FederationQuarantineKind,
    object_id: impl Into<String>,
    expected_ref: impl Into<String>,
    observed_ref: impl Into<String>,
) -> Result<FederationQuarantineRecord> {
    if !matches!(
        kind,
        FederationQuarantineKind::CommitFork | FederationQuarantineKind::OperationFork
    ) {
        return Err(Error::Protocol(
            "fork quarantine requires commit or operation kind".to_owned(),
        ));
    }

    Ok(FederationQuarantineRecord {
        kind,
        object_id: object_id.into(),
        expected_digest: None,
        observed_digest: None,
        reason: format!(
            "same logical object observed with conflicting refs: expected {}, observed {}",
            expected_ref.into(),
            observed_ref.into()
        ),
    })
}

/// Per-`(actor, actor_seq)` ledger of accepted event IDs used to detect
/// commit forks during federation pull/push (federation.md §replay).
///
/// When a peer replays the same `actor_seq` with a different `event_id`,
/// that's a CommitFork — the second event MUST be quarantined and the
/// originating actor MUST be flagged for cross-instance investigation.
#[derive(Clone, Debug, Default)]
pub struct ActorSeqLedger {
    seen: BTreeMap<(Did, u64), crate::EventId>,
}

impl ActorSeqLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an `(actor, actor_seq, event_id)` triple. Returns:
    ///
    /// - `Ok(None)` for first-seen or idempotent duplicates;
    /// - `Ok(Some(record))` when the same `actor_seq` is replayed with a different `event_id` (the
    ///   caller MUST refuse to apply the new event and SHOULD persist the returned
    ///   `FederationQuarantineRecord`);
    /// - `Err` is reserved for future structural validation; currently never returned.
    pub fn observe(
        &mut self,
        actor_id: Did,
        actor_seq: u64,
        event_id: crate::EventId,
    ) -> Result<Option<FederationQuarantineRecord>> {
        let key = (actor_id, actor_seq);
        if let Some(prev) = self.seen.get(&key) {
            if prev == &event_id {
                return Ok(None);
            }
            let record = fork_quarantine_record(
                FederationQuarantineKind::CommitFork,
                format!("{}#{}", key.0.as_str(), actor_seq),
                prev.as_str(),
                event_id.as_str(),
            )?;
            return Ok(Some(record));
        }
        self.seen.insert(key, event_id);
        Ok(None)
    }
}

fn service_endpoint_matches(service: &Value, service_type: &str, endpoint: &str) -> bool {
    service.get("type").and_then(Value::as_str) == Some(service_type)
        && match service.get("serviceEndpoint") {
            Some(Value::String(value)) => value == endpoint,
            Some(Value::Array(values)) => {
                values.iter().any(|value| value.as_str() == Some(endpoint))
            }
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn federation_discovers_versions_and_capabilities() {
        let mut manager = FederationManager::new();
        manager.register_server(ServerInfo {
            domain: "b.example".to_owned(),
            base_url: "https://b.example".to_owned(),
            versions: vec!["1.0".to_owned(), "1.1".to_owned()],
            capabilities: BTreeSet::from(["backfill".to_owned(), "state".to_owned()]),
        });

        assert!(manager.discover_server("b.example").is_some());
        assert_eq!(
            manager.negotiate_version("b.example", &["2.0".to_owned(), "1.1".to_owned()]),
            Some("1.1".to_owned())
        );
        assert!(manager.server_supports("b.example", "backfill"));
    }

    #[test]
    fn federation_forwards_queries_and_backfills_events() {
        let mut manager = FederationManager::new();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        manager.forward_event(realm_id.clone(), json!({"event": 1}));
        manager.forward_event(realm_id.clone(), json!({"event": 2}));

        assert_eq!(manager.query_state(&realm_id).len(), 2);
        assert_eq!(
            manager.backfill(&realm_id, 1, 10),
            vec![&json!({"event": 2})]
        );
    }

    #[test]
    fn federation_imports_exports_sovereign_deployment_policy() {
        let mut manager = FederationManager::new();
        manager.set_deployment(SovereignDeployment {
            domain: "a.example".to_owned(),
            allow_federation: true,
            allowed_domains: BTreeSet::from(["b.example".to_owned()]),
            policy: BTreeMap::from([("retention".to_owned(), "30d".to_owned())]),
        });

        assert!(manager.federation_allowed("b.example"));
        assert!(!manager.federation_allowed("c.example"));
        let exported = manager.export_deployment().unwrap();
        let mut imported = FederationManager::new();
        imported.import_deployment(&exported).unwrap();
        assert!(imported.federation_allowed("b.example"));
    }

    #[test]
    fn rfc9530_content_digest_round_trips_and_reuses_core_helper() {
        let body = br#"{"ok":true}"#;
        // Wire-form digest reuses the single core helper.
        assert_eq!(
            content_digest_sha256(body),
            cokret_core::canonical::sha256_digest(body)
        );
        // RFC 9530 header verifies against the same body and rejects tamper.
        let header = rfc9530_content_digest_sha256(body);
        assert!(header.starts_with("sha-256=:") && header.ends_with(':'));
        verify_rfc9530_content_digest(&header, body).unwrap();
        assert!(verify_rfc9530_content_digest(&header, b"different").is_err());
    }

    #[test]
    fn did_document_service_endpoint_verifies_origin_binding() {
        let did = Did::new("did:web:a.example").unwrap();
        let document = json!({
            "id": did.as_str(),
            "service": [{
                "id": "did:web:a.example#cokret-federation",
                "type": "CokretFederation",
                "serviceEndpoint": "https://a.example/_cokret/peer/events"
            }]
        });

        assert!(did_document_service_endpoint_matches(
            &document,
            &did,
            "CokretFederation",
            "https://a.example/_cokret/peer/events"
        ));
        assert!(!did_document_service_endpoint_matches(
            &document,
            &Did::new("did:web:b.example").unwrap(),
            "CokretFederation",
            "https://a.example/_cokret/peer/events"
        ));
    }

    #[test]
    fn replay_and_fork_conflicts_are_quarantined() {
        let now = Utc::now();
        let mut manager = FederationManager::new();
        let first_digest =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let second_digest =
            Hash::new("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();

        assert_eq!(
            manager.check_transaction_replay("txn-1", first_digest.clone(), now),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(
            manager.check_transaction_replay("txn-1", first_digest.clone(), now),
            FederationReplayDecision::AcceptedDuplicate
        );
        assert_eq!(
            manager.check_transaction_replay("txn-1", second_digest.clone(), now),
            FederationReplayDecision::QuarantinedConflict
        );

        let record = duplicate_transaction_quarantine("txn-1", first_digest, second_digest);
        assert_eq!(
            record.kind,
            FederationQuarantineKind::DuplicateTransactionConflict
        );
        let fork = fork_quarantine_record(
            FederationQuarantineKind::OperationFork,
            "ck:operation:01904100-0000-7000-8000-b24c1b0f1a32",
            "sha256:first",
            "sha256:second",
        )
        .unwrap();
        assert_eq!(fork.kind, FederationQuarantineKind::OperationFork);
    }

    #[test]
    fn backfill_authorization_fails_closed() {
        let authorization = FederationBackfillAuthorization {
            requester_service_did: Did::new("did:web:b.example").unwrap(),
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            history_visible: true,
            service_delegated: false,
            plaintext_visible_to_service: true,
        };
        assert!(authorization.allows_pull());

        let blocked = FederationBackfillAuthorization {
            plaintext_visible_to_service: false,
            ..authorization
        };
        assert!(!blocked.allows_pull());
    }
}
