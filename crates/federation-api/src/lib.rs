//! Contrix federation API models.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_core::{
    BlobRef, Did, Error, EventId, FederationTransactionRequest, Hash, Operation, OperationId,
    Result, SpaceId, canonical,
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
        operation_id: "cx.federation.backfill",
        method: FederationMethod::Get,
        path: "/api/v1/federation/backfill",
        request_schema: "FederationBackfillQuery",
        response_schema: "FederationBackfillResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.event_auth",
        method: FederationMethod::Get,
        path: "/api/v1/federation/event-auth",
        request_schema: "FederationEventAuthQuery",
        response_schema: "FederationEventAuthResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.query_profile",
        method: FederationMethod::Get,
        path: "/api/v1/federation/profile",
        request_schema: "FederationProfileQuery",
        response_schema: "FederationProfileResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.query_keys",
        method: FederationMethod::Post,
        path: "/api/v1/federation/keys/query",
        request_schema: "FederationKeyQuery",
        response_schema: "FederationKeyResponse",
    },
    FederationEndpoint {
        operation_id: "cx.federation.media",
        method: FederationMethod::Get,
        path: "/api/v1/federation/media/{blob_ref}",
        request_schema: "FederationMediaRequest",
        response_schema: "FederationMediaResponse",
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationBackfillQuery {
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_event_id: Option<EventId>,
    pub limit: u32,
    pub authorization: FederationBackfillAuthorization,
}

impl FederationBackfillQuery {
    pub fn validate(&self) -> Result<()> {
        if self.limit == 0 {
            return Err(Error::Protocol("federation backfill limit must be non-zero".to_owned()));
        }
        if !self.authorization.is_authorized() {
            return Err(Error::Protocol("federation backfill is not authorized".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationBackfillResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_events: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationEventAuthQuery {
    pub space_id: SpaceId,
    pub event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationEventAuthResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_chain: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_hash: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationProfileQuery {
    pub user_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationProfileResponse {
    pub user_id: Did,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationKeyQuery {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<Did>,
}

impl FederationKeyQuery {
    pub fn validate(&self) -> Result<()> {
        if self.services.is_empty() && self.users.is_empty() {
            Err(Error::Protocol("federation key query requires service or user ids".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationKeyResponse {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<Did, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<Did, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMediaRequest {
    pub blob_ref: BlobRef,
    #[serde(default)]
    pub allow_remote_thumbnail: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMediaResponse {
    pub blob_ref: BlobRef,
    pub content_type: String,
    pub size: u64,
    pub sha256: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

impl FederationMediaResponse {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() || self.size == 0 {
            Err(Error::Protocol(
                "federation media response requires content type and size".to_owned(),
            ))
        } else {
            Ok(())
        }
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
        assert!(operations.contains("cx.federation.backfill"));
        assert!(operations.contains("cx.federation.event_auth"));
        assert!(operations.contains("cx.federation.query_keys"));
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
    fn federation_backfill_keys_and_media_contracts_validate_fail_closed() {
        let authorized = FederationBackfillAuthorization {
            requester_service_did: did("a"),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            history_visible: true,
            service_delegated: true,
            plaintext_visible_to_service: true,
        };
        FederationBackfillQuery {
            space_id: authorized.space_id.clone(),
            from_event_id: Some(EventId::new("cx:event:1").unwrap()),
            limit: 10,
            authorization: authorized,
        }
        .validate()
        .unwrap();

        assert!(matches!(
            FederationKeyQuery { services: Vec::new(), users: Vec::new() }.validate(),
            Err(Error::Protocol(_))
        ));
        FederationKeyQuery { services: vec![did("server")], users: Vec::new() }.validate().unwrap();

        FederationMediaResponse {
            blob_ref: BlobRef::from_bytes(b"media"),
            content_type: "image/png".to_owned(),
            size: 42,
            sha256: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            redirect_url: None,
        }
        .validate()
        .unwrap();
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
