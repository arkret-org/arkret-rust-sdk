//! Contrix federation API models.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_core::{
    Did, Error, FederationTransactionRequest, Hash, Operation, OperationId, Result, SpaceId,
    canonical,
};
use contrix_signatures::HttpMessageSignature;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod protocol {
    pub use contrix_core::{
        FederationPullOperationsResponse, FederationPushOperationsRequest,
        FederationPushOperationsResponse, FederationSpaceMembersResponse,
        FederationTransactionRequest, FederationTransactionResponse, FederationVerifyActorRequest,
        FederationVerifyActorResponse,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FederationMethod {
    Get,
    Post,
    Put,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationEndpoint {
    pub operation_id: &'static str,
    pub method: FederationMethod,
    pub path: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
}

pub const FEDERATION_ENDPOINTS: &[FederationEndpoint] = &[
    FederationEndpoint {
        operation_id: "cx.federation.discovery",
        method: FederationMethod::Get,
        path: "/.well-known/contrix/server",
        request_schema: "FederationDiscoveryRequest",
        response_schema: "WellKnownContrixServer",
    },
    FederationEndpoint {
        operation_id: "cx.federation.transaction",
        method: FederationMethod::Put,
        path: "/api/v1/federation/transactions/{txn_id}",
        request_schema: "FederationTransactionRequest",
        response_schema: "FederationTransactionResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.push_operations",
        method: FederationMethod::Post,
        path: "/api/v1/federation/push-operations",
        request_schema: "FederationPushOperationsRequest",
        response_schema: "FederationPushOperationsResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.pull_operations",
        method: FederationMethod::Get,
        path: "/api/v1/federation/pull-operations",
        request_schema: "FederationPullOperationsQuery",
        response_schema: "FederationPullOperationsResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.space_members",
        method: FederationMethod::Get,
        path: "/api/v1/federation/space-members",
        request_schema: "FederationSpaceMembersQuery",
        response_schema: "FederationSpaceMembersResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.verify_actor",
        method: FederationMethod::Post,
        path: "/api/v1/federation/verify-actor",
        request_schema: "FederationVerifyActorRequest",
        response_schema: "FederationVerifyActorResponse",
    },
];

pub fn federation_endpoints() -> &'static [FederationEndpoint] {
    FEDERATION_ENDPOINTS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownContrixServer {
    pub service_did: Did,
    pub base_url: String,
    pub protocol_versions: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationTransactionEnvelope<T = FederationTransactionRequest> {
    pub transaction_id: String,
    pub origin: Did,
    pub destination: Did,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub content_digest: Hash,
    pub payload: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<HttpMessageSignature>,
}

impl<T> FederationTransactionEnvelope<T>
where
    T: Serialize,
{
    pub fn new(
        transaction_id: impl Into<String>,
        origin: Did,
        destination: Did,
        expires_at: DateTime<Utc>,
        payload: T,
    ) -> Result<Self> {
        let content_digest = Hash::new(canonical::canonical_sha256(&payload)?)?;
        Ok(Self {
            transaction_id: transaction_id.into(),
            origin,
            destination,
            issued_at: Utc::now(),
            expires_at,
            content_digest,
            payload,
            signature: None,
        })
    }

    pub fn validate_digest(&self) -> Result<()> {
        let expected = Hash::new(canonical::canonical_sha256(&self.payload)?)?;
        if expected == self.content_digest {
            Ok(())
        } else {
            Err(Error::Protocol("federation envelope content digest mismatch".to_owned()))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationReplayRecord {
    pub transaction_id: String,
    pub content_digest: Hash,
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationReplayDecision {
    AcceptedNew,
    AcceptedDuplicate,
    QuarantinedConflict,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryFederationReplayStore {
    records: BTreeMap<String, FederationReplayRecord>,
}

impl MemoryFederationReplayStore {
    pub fn remember(
        &mut self,
        transaction_id: impl Into<String>,
        content_digest: Hash,
    ) -> FederationReplayDecision {
        let transaction_id = transaction_id.into();
        match self.records.get(&transaction_id) {
            Some(record) if record.content_digest == content_digest => {
                FederationReplayDecision::AcceptedDuplicate
            }
            Some(_) => FederationReplayDecision::QuarantinedConflict,
            None => {
                self.records.insert(
                    transaction_id.clone(),
                    FederationReplayRecord {
                        transaction_id,
                        content_digest,
                        first_seen_at: Utc::now(),
                    },
                );
                FederationReplayDecision::AcceptedNew
            }
        }
    }
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
    BadSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationQuarantineRecord {
    pub kind: FederationQuarantineKind,
    pub object_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_digest: Option<Hash>,
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

impl FederationBackfillAuthorization {
    pub fn is_authorized(&self) -> bool {
        self.history_visible && self.service_delegated && self.plaintext_visible_to_service
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationDeltaBatch {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<OperationId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn federation_endpoint_catalog_covers_core_flows() {
        let operations = federation_endpoints()
            .iter()
            .map(|endpoint| endpoint.operation_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(operations.contains("cx.federation.discovery"));
        assert!(operations.contains("cx.federation.transaction"));
        assert!(!operations.contains("cx.federation.backfill"));
        assert!(operations.contains("cx.federation.verify_actor"));
    }

    #[test]
    fn transaction_envelope_validates_digest() {
        let payload = FederationTransactionRequest {
            origin: did("a"),
            destination: did("b"),
            service_binding_ref: "svc".to_owned(),
            operations: Vec::new(),
            receipts: Vec::new(),
            frontier: None,
        };
        let mut envelope = FederationTransactionEnvelope::new(
            "txn_1",
            did("a"),
            did("b"),
            Utc::now() + Duration::minutes(5),
            payload,
        )
        .unwrap();
        envelope.validate_digest().unwrap();
        envelope.payload.frontier = Some("tamper".to_owned());
        assert!(envelope.validate_digest().is_err());
    }

    #[test]
    fn replay_store_accepts_duplicates_and_quarantines_conflicts() {
        let digest =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let other =
            Hash::new("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let mut store = MemoryFederationReplayStore::default();
        assert_eq!(store.remember("txn", digest.clone()), FederationReplayDecision::AcceptedNew);
        assert_eq!(store.remember("txn", digest), FederationReplayDecision::AcceptedDuplicate);
        assert_eq!(store.remember("txn", other), FederationReplayDecision::QuarantinedConflict);
    }

    #[test]
    fn backfill_authorization_requires_all_visibility_flags() {
        let auth = FederationBackfillAuthorization {
            requester_service_did: did("a"),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            history_visible: true,
            service_delegated: true,
            plaintext_visible_to_service: false,
        };
        assert!(!auth.is_authorized());
    }

    #[test]
    fn delta_batch_serializes_operations_surface() {
        let batch = FederationDeltaBatch {
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            operations: Vec::new(),
            accepted: Vec::new(),
            rejected: vec![json!({"reason": "bad_signature"})],
        };
        assert_eq!(serde_json::to_value(batch).unwrap()["rejected"][0]["reason"], "bad_signature");
    }
}
