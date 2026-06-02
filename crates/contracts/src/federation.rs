//! Contrix federation wire contracts and shared helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_core::{
    BlobRef, Did, Error, EventId, FederationTransactionReqBody, Hash, Operation, OperationId,
    Result, SpaceId, TypedTrustDomainId, canonical,
};
pub use contrix_signatures::HttpMessageSignature;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod protocol {
    pub use contrix_core::{
        FederationPullOperationsResBody, FederationPushOperationsReqBody,
        FederationPushOperationsResBody, FederationSpaceMembersResBody,
        FederationTransactionReqBody, FederationTransactionResBody, FederationVerifyActorReqBody,
        FederationVerifyActorResBody,
    };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownContrixServer {
    pub service_did: Did,
    pub base_url: String,
    pub protocol_versions: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<ServiceEndpointDescriptor>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
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
    /// Optional federation trust-domain transcript fields. When present they
    /// MUST be included in the canonical HTTP message signature base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_trust_domain: Option<TypedTrustDomainId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_trust_domain: Option<TypedTrustDomainId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationTransactionEnvelope<T = FederationTransactionReqBody> {
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

    pub fn with_signature(mut self, signature: HttpMessageSignature) -> Self {
        self.signature = Some(signature);
        self
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

    /// SDK compatibility helper for callers that model read access as either
    /// explicit delegation or plaintext service visibility.
    pub fn allows_pull(&self) -> bool {
        self.history_visible && (self.service_delegated || self.plaintext_visible_to_service)
    }
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
    pub payload_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyActorChallengeSignature {
    pub key_id: String,
    pub signature: String,
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
pub struct FederationBackfillResBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_events: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationEventAuthQuery {
    pub space_id: SpaceId,
    pub event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationEventAuthResBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_chain: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationProfileQuery {
    pub user_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationProfileResBody {
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
pub struct FederationKeyResBody {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<Did, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<Did, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMediaReqBody {
    pub blob_ref: BlobRef,
    #[serde(default)]
    pub allow_remote_thumbnail: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMediaResBody {
    pub blob_ref: BlobRef,
    pub content_type: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub content_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

impl FederationMediaResBody {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() || self.size_bytes == 0 {
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
    fn transaction_envelope_validates_digest() {
        let payload = FederationTransactionReqBody {
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
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
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
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            history_visible: true,
            service_delegated: true,
            plaintext_visible_to_service: true,
        };
        FederationBackfillQuery {
            space_id: authorized.space_id.clone(),
            from_event_id: Some(
                EventId::new("cx:event:01904100-0000-7000-8000-0b94566027c1").unwrap(),
            ),
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

        FederationMediaResBody {
            blob_ref: BlobRef::from_bytes(b"media"),
            content_type: "image/png".to_owned(),
            size_bytes: 42,
            content_digest: Hash::new(
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
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            operations: Vec::new(),
            accepted: Vec::new(),
            rejected: vec![json!({"reason": "bad_signature"})],
        };
        assert_eq!(serde_json::to_value(batch).unwrap()["rejected"][0]["reason"], "bad_signature");
    }
}
