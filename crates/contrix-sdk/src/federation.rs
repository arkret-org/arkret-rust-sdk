//! Federation transactions, discovery and sovereign deployment helpers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{Result, SpaceId};

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

/// Federation manager.
#[derive(Clone, Debug, Default)]
pub struct FederationManager {
    trust_anchors: BTreeMap<String, TrustAnchor>,
    servers: BTreeMap<String, ServerInfo>,
    events: BTreeMap<SpaceId, Vec<Value>>,
    deployment: Option<SovereignDeployment>,
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
}
