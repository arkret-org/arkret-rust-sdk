//! Federation transactions, discovery and sovereign deployment helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{Did, Error, Result, SpaceId};

/// Trust anchor for a federated domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// Domain name.
    pub domain: String,
    /// Verification key material.
    pub public_key: String,
}

/// Signed federation transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationTransaction {
    pub transaction_id: String,
    pub origin: String,
    pub destination: String,
    pub events: Vec<Value>,
    pub signature: String,
}

/// Signed cross-domain request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationRequest {
    pub request_id: String,
    pub origin: String,
    pub destination: String,
    pub path: String,
    pub payload: Value,
    pub signature: String,
}

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

/// `.well-known/contrix/server` discovery record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownContrixServer {
    pub service_did: Did,
    pub base_url: String,
    pub protocol_versions: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<ServiceEndpointDescriptor>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpointDescriptor {
    pub service_type: String,
    pub service_endpoint: String,
    #[serde(default)]
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignatureInput {
    pub method: String,
    pub target_uri: String,
    pub authority: String,
    pub content_digest: String,
    pub origin_service_did: Did,
    pub destination_service_did: Did,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignature {
    pub key_id: String,
    pub alg: String,
    pub signed_fields: Vec<String>,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationTransactionEnvelope<T = Value> {
    pub transaction_id: String,
    pub origin_service_did: Did,
    pub destination_service_did: Did,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub content_digest: String,
    pub payload: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<HttpMessageSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationReplayRecord {
    pub transaction_id: String,
    pub content_digest: String,
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationReplayDecision {
    AcceptedNew,
    AcceptedDuplicate,
    QuarantinedConflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationQuarantineKind {
    DuplicateTransactionConflict,
    CommitFork,
    OperationFork,
    BadDigest,
    StaleCursor,
    UnauthorizedPull,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationQuarantineRecord {
    pub kind: FederationQuarantineKind,
    pub object_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_digest: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationBackfillAuthorization {
    pub requester_service_did: Did,
    pub space_id: SpaceId,
    pub history_visible: bool,
    pub service_delegated: bool,
    pub plaintext_visible_to_service: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyActorChallenge {
    pub actor_id: Did,
    pub origin_service_did: Did,
    pub destination_service_did: Did,
    pub challenge: String,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyActorChallengeSignature {
    pub key_id: String,
    pub signature: String,
}

pub trait FederationReplayStore {
    fn replay_record(&self, transaction_id: &str) -> Option<&FederationReplayRecord>;
    fn remember_replay_record(&mut self, record: FederationReplayRecord);
}

/// Federation manager.
#[derive(Clone, Debug, Default)]
pub struct FederationManager {
    trust_anchors: BTreeMap<String, TrustAnchor>,
    servers: BTreeMap<String, ServerInfo>,
    events: BTreeMap<SpaceId, Vec<Value>>,
    deployment: Option<SovereignDeployment>,
    replay: BTreeMap<String, FederationReplayRecord>,
}

impl FederationManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a trust anchor.
    pub fn add_trust_anchor(&mut self, anchor: TrustAnchor) {
        self.trust_anchors.insert(anchor.domain.clone(), anchor);
    }

    /// Create and sign a transaction.
    pub fn create_transaction(
        &self,
        origin: impl Into<String>,
        destination: impl Into<String>,
        events: Vec<Value>,
        signing_key: &str,
    ) -> FederationTransaction {
        let transaction_id = format!("txn_{}", Ulid::new());
        let origin = origin.into();
        let destination = destination.into();
        let signature = federation_signature(
            &transaction_id,
            &origin,
            &destination,
            &serde_json::to_string(&events).unwrap_or_default(),
            signing_key,
        );
        FederationTransaction { transaction_id, origin, destination, events, signature }
    }

    /// Verify a transaction using the origin trust anchor.
    pub fn verify_transaction(&self, transaction: &FederationTransaction) -> bool {
        self.trust_anchors
            .get(&transaction.origin)
            .map(|anchor| {
                transaction.signature
                    == federation_signature(
                        &transaction.transaction_id,
                        &transaction.origin,
                        &transaction.destination,
                        &serde_json::to_string(&transaction.events).unwrap_or_default(),
                        &anchor.public_key,
                    )
            })
            .unwrap_or(false)
    }

    /// Create a signed cross-domain request.
    pub fn create_request(
        &self,
        origin: impl Into<String>,
        destination: impl Into<String>,
        path: impl Into<String>,
        payload: Value,
        signing_key: &str,
    ) -> FederationRequest {
        let request_id = format!("req_{}", Ulid::new());
        let origin = origin.into();
        let destination = destination.into();
        let path = path.into();
        let signature = federation_signature(
            &request_id,
            &origin,
            &destination,
            &format!("{path}:{}", serde_json::to_string(&payload).unwrap_or_default()),
            signing_key,
        );
        FederationRequest { request_id, origin, destination, path, payload, signature }
    }

    /// Verify a signed cross-domain request using the origin trust anchor.
    pub fn verify_request(&self, request: &FederationRequest) -> bool {
        self.trust_anchors
            .get(&request.origin)
            .map(|anchor| {
                request.signature
                    == federation_signature(
                        &request.request_id,
                        &request.origin,
                        &request.destination,
                        &format!(
                            "{}:{}",
                            request.path,
                            serde_json::to_string(&request.payload).unwrap_or_default()
                        ),
                        &anchor.public_key,
                    )
            })
            .unwrap_or(false)
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
        local_versions.iter().find(|version| server.versions.contains(*version)).cloned()
    }

    /// Query discovered capabilities.
    pub fn server_supports(&self, domain: &str, capability: &str) -> bool {
        self.servers
            .get(domain)
            .map(|server| server.capabilities.contains(capability))
            .unwrap_or(false)
    }

    /// Forward a federation event into local space state.
    pub fn forward_event(&mut self, space_id: SpaceId, event: Value) {
        self.events.entry(space_id).or_default().push(event);
    }

    /// Query known state/events for a space.
    pub fn query_state(&self, space_id: &SpaceId) -> Vec<&Value> {
        self.events.get(space_id).map(|events| events.iter().collect()).unwrap_or_default()
    }

    /// Backfill events from a starting offset.
    pub fn backfill(&self, space_id: &SpaceId, from: usize, limit: usize) -> Vec<&Value> {
        self.events
            .get(space_id)
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
        content_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> FederationReplayDecision {
        check_replay(self, transaction_id.into(), content_digest.into(), now)
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

impl<T> FederationTransactionEnvelope<T>
where
    T: Serialize,
{
    pub fn new(
        transaction_id: impl Into<String>,
        origin_service_did: Did,
        destination_service_did: Did,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        payload: T,
    ) -> Result<Self> {
        let content_digest = content_digest_sha256(&serde_json::to_vec(&payload)?);
        Ok(Self {
            transaction_id: transaction_id.into(),
            origin_service_did,
            destination_service_did,
            issued_at,
            expires_at,
            content_digest,
            payload,
            signature: None,
        })
    }

    pub fn with_signature(mut self, signature: HttpMessageSignature) -> Self {
        self.signature = Some(signature);
        self
    }
}

impl FederationBackfillAuthorization {
    pub fn allows_pull(&self) -> bool {
        self.history_visible && (self.service_delegated || self.plaintext_visible_to_service)
    }
}

pub fn content_digest_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

pub fn http_message_signature_base(input: &HttpMessageSignatureInput) -> String {
    format!(
        "method:{}\ntarget-uri:{}\nauthority:{}\ncontent-digest:{}\norigin-service-did:{}\ndestination-service-did:{}\ncreated:{}\nexpires:{}",
        input.method.to_ascii_uppercase(),
        input.target_uri,
        input.authority,
        input.content_digest,
        input.origin_service_did,
        input.destination_service_did,
        input.created_at.to_rfc3339(),
        input.expires_at.to_rfc3339()
    )
}

pub fn sign_http_message(
    input: &HttpMessageSignatureInput,
    key_id: impl Into<String>,
    signing_key: &str,
) -> HttpMessageSignature {
    HttpMessageSignature {
        key_id: key_id.into(),
        alg: "cx-sha256-test".to_owned(),
        signed_fields: vec![
            "method".to_owned(),
            "target-uri".to_owned(),
            "authority".to_owned(),
            "content-digest".to_owned(),
            "origin-service-did".to_owned(),
            "destination-service-did".to_owned(),
            "created".to_owned(),
            "expires".to_owned(),
        ],
        signature: signature_digest(&http_message_signature_base(input), signing_key),
    }
}

pub fn verify_http_message_signature(
    input: &HttpMessageSignatureInput,
    signature: &HttpMessageSignature,
    verification_key: &str,
    now: DateTime<Utc>,
) -> bool {
    if now < input.created_at || now > input.expires_at {
        return false;
    }
    signature.alg == "cx-sha256-test"
        && signature.signature
            == signature_digest(&http_message_signature_base(input), verification_key)
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
    content_digest: String,
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
    expected_digest: impl Into<String>,
    observed_digest: impl Into<String>,
) -> FederationQuarantineRecord {
    FederationQuarantineRecord {
        kind: FederationQuarantineKind::DuplicateTransactionConflict,
        object_id: transaction_id.into(),
        expected_digest: Some(expected_digest.into()),
        observed_digest: Some(observed_digest.into()),
        reason: "idempotent transaction id was reused with different bytes".to_owned(),
    }
}

pub fn fork_quarantine_record(
    kind: FederationQuarantineKind,
    object_id: impl Into<String>,
    expected_digest: impl Into<String>,
    observed_digest: impl Into<String>,
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
        expected_digest: Some(expected_digest.into()),
        observed_digest: Some(observed_digest.into()),
        reason: "same logical object observed with conflicting digest".to_owned(),
    })
}

pub fn verify_actor_challenge_payload(challenge: &VerifyActorChallenge) -> String {
    format!(
        "verify-actor|actor:{}|origin:{}|destination:{}|challenge:{}|purpose:{}|expires:{}|payload-hash:{}",
        challenge.actor_id,
        challenge.origin_service_did,
        challenge.destination_service_did,
        challenge.challenge,
        challenge.purpose,
        challenge.expires_at.to_rfc3339(),
        challenge.payload_hash.as_deref().unwrap_or("")
    )
}

pub fn sign_verify_actor_challenge(
    challenge: &VerifyActorChallenge,
    key_id: impl Into<String>,
    signing_key: &str,
) -> VerifyActorChallengeSignature {
    VerifyActorChallengeSignature {
        key_id: key_id.into(),
        signature: signature_digest(&verify_actor_challenge_payload(challenge), signing_key),
    }
}

pub fn verify_actor_challenge_signature(
    challenge: &VerifyActorChallenge,
    signature: &VerifyActorChallengeSignature,
    verification_key: &str,
    now: DateTime<Utc>,
) -> bool {
    now <= challenge.expires_at
        && signature.signature
            == signature_digest(&verify_actor_challenge_payload(challenge), verification_key)
}

fn federation_signature(
    id: &str,
    origin: &str,
    destination: &str,
    payload: &str,
    key: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(origin.as_bytes());
    hasher.update(destination.as_bytes());
    hasher.update(payload.as_bytes());
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn signature_digest(payload: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
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
    fn federation_signs_and_verifies_transactions_and_requests() {
        let mut manager = FederationManager::new();
        manager.add_trust_anchor(TrustAnchor {
            domain: "a.example".to_owned(),
            public_key: "shared-key".to_owned(),
        });

        let transaction = manager.create_transaction(
            "a.example",
            "b.example",
            vec![json!({"event":"one"})],
            "shared-key",
        );
        assert!(manager.verify_transaction(&transaction));

        let request = manager.create_request(
            "a.example",
            "b.example",
            "/_contrix/federation/state",
            json!({"space":"cx:space:01"}),
            "shared-key",
        );
        assert_eq!(request.origin, "a.example");
        assert!(manager.verify_request(&request));
    }

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
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        manager.forward_event(space_id.clone(), json!({"event": 1}));
        manager.forward_event(space_id.clone(), json!({"event": 2}));

        assert_eq!(manager.query_state(&space_id).len(), 2);
        assert_eq!(manager.backfill(&space_id, 1, 10), vec![&json!({"event": 2})]);
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
    fn http_message_signature_binds_service_dids_digest_and_time() {
        let now = Utc::now();
        let input = HttpMessageSignatureInput {
            method: "post".to_owned(),
            target_uri: "https://b.example/api/v1/federation/push-operations".to_owned(),
            authority: "b.example".to_owned(),
            content_digest: content_digest_sha256(br#"{"ok":true}"#),
            origin_service_did: Did::new("did:web:a.example").unwrap(),
            destination_service_did: Did::new("did:web:b.example").unwrap(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        };

        let signature = sign_http_message(&input, "did:web:a.example#svc", "shared-key");
        assert!(verify_http_message_signature(&input, &signature, "shared-key", now));

        let mut tampered = input.clone();
        tampered.destination_service_did = Did::new("did:web:evil.example").unwrap();
        assert!(!verify_http_message_signature(&tampered, &signature, "shared-key", now));
        assert!(!verify_http_message_signature(
            &input,
            &signature,
            "shared-key",
            now + chrono::Duration::minutes(6)
        ));
    }

    #[test]
    fn did_document_service_endpoint_verifies_origin_binding() {
        let did = Did::new("did:web:a.example").unwrap();
        let document = json!({
            "id": did.as_str(),
            "service": [{
                "id": "did:web:a.example#contrix-federation",
                "type": "ContrixFederation",
                "serviceEndpoint": "https://a.example/api/v1/federation"
            }]
        });

        assert!(did_document_service_endpoint_matches(
            &document,
            &did,
            "ContrixFederation",
            "https://a.example/api/v1/federation"
        ));
        assert!(!did_document_service_endpoint_matches(
            &document,
            &Did::new("did:web:b.example").unwrap(),
            "ContrixFederation",
            "https://a.example/api/v1/federation"
        ));
    }

    #[test]
    fn replay_and_fork_conflicts_are_quarantined() {
        let now = Utc::now();
        let mut manager = FederationManager::new();

        assert_eq!(
            manager.check_transaction_replay("txn-1", "sha256:first", now),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(
            manager.check_transaction_replay("txn-1", "sha256:first", now),
            FederationReplayDecision::AcceptedDuplicate
        );
        assert_eq!(
            manager.check_transaction_replay("txn-1", "sha256:second", now),
            FederationReplayDecision::QuarantinedConflict
        );

        let record = duplicate_transaction_quarantine("txn-1", "sha256:first", "sha256:second");
        assert_eq!(record.kind, FederationQuarantineKind::DuplicateTransactionConflict);
        let fork = fork_quarantine_record(
            FederationQuarantineKind::OperationFork,
            "cx:operation:1",
            "sha256:first",
            "sha256:second",
        )
        .unwrap();
        assert_eq!(fork.kind, FederationQuarantineKind::OperationFork);
    }

    #[test]
    fn backfill_and_verify_actor_helpers_fail_closed() {
        let authorization = FederationBackfillAuthorization {
            requester_service_did: Did::new("did:web:b.example").unwrap(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
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

        let now = Utc::now();
        let challenge = VerifyActorChallenge {
            actor_id: Did::new("did:web:actor.example").unwrap(),
            origin_service_did: Did::new("did:web:a.example").unwrap(),
            destination_service_did: Did::new("did:web:b.example").unwrap(),
            challenge: "chal_123".to_owned(),
            purpose: "federation.verify_actor".to_owned(),
            expires_at: now + chrono::Duration::minutes(5),
            payload_hash: Some(content_digest_sha256(b"actor-proof")),
        };
        let signature =
            sign_verify_actor_challenge(&challenge, "did:web:actor.example#key", "actor-key");
        assert!(verify_actor_challenge_signature(&challenge, &signature, "actor-key", now));

        let mut tampered = challenge;
        tampered.challenge = "public-oracle-probe".to_owned();
        assert!(!verify_actor_challenge_signature(&tampered, &signature, "actor-key", now));
    }
}
