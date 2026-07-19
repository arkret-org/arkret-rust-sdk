//! Arkret federation wire contracts and shared helpers.
//!
//! The pure federation frame shapes migrated to
//! `arkret-models-collaboration` (`federation::frames`, re-exported
//! below). This module keeps the transaction envelope (which embeds the
//! core HTTP transaction body and RFC 9421 signature envelope), the
//! in-memory replay-protection store (server runtime, destined for
//! `arkret-server`), and the delta batch aggregate over core HTTP body
//! DTOs.

use std::collections::BTreeMap;

pub use arkret_models_collaboration::federation::frames::{
    FederationBackfillAuthorization, FederationBackfillOutcome, FederationBackfillQuery,
    FederationEventAuthOutcome, FederationEventAuthQuery, FederationMediaOutcome,
    FederationMediaRequestBody, FederationQuarantineKind, FederationQuarantineRecord,
    FederationReplayDecision, FederationReplayRecord, HttpMessageSignatureInput,
    ServiceEndpointDescriptor, VerifyActorChallenge, VerifyActorChallengeSignature,
    WellKnownArkretServer,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use crate::HttpMessageSignature;
use crate::identifiers::Did;
use crate::{
    Error, EventsSubmitRejectedItem, FederationTransactionRequestBody, Hash, Operation,
    OperationId, RealmId, Result, canonical,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationTransactionEnvelope<T = FederationTransactionRequestBody> {
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
            Err(Error::Protocol(
                "federation envelope content digest mismatch".to_owned(),
            ))
        }
    }
}

pub const DEFAULT_FEDERATION_REPLAY_TTL_SECS: i64 = 10 * 60;
pub const DEFAULT_FEDERATION_REPLAY_CAPACITY: usize = 4096;

#[derive(Clone, Debug)]
pub struct MemoryFederationReplayStore {
    records: BTreeMap<String, FederationReplayRecord>,
    ttl: chrono::Duration,
    capacity: usize,
}

impl MemoryFederationReplayStore {
    pub fn with_limits(ttl: chrono::Duration, capacity: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            ttl,
            capacity: capacity.max(1),
        }
    }

    pub fn remember(
        &mut self,
        transaction_id: impl Into<String>,
        content_digest: Hash,
    ) -> FederationReplayDecision {
        self.remember_at(transaction_id, content_digest, Utc::now())
    }

    pub fn remember_at(
        &mut self,
        transaction_id: impl Into<String>,
        content_digest: Hash,
        now: DateTime<Utc>,
    ) -> FederationReplayDecision {
        self.evict_expired(now);
        let transaction_id = transaction_id.into();
        match self.records.get(&transaction_id) {
            Some(record) if record.content_digest == content_digest => {
                FederationReplayDecision::AcceptedDuplicate
            }
            Some(_) => FederationReplayDecision::QuarantinedConflict,
            None => {
                self.evict_to_capacity();
                self.records.insert(
                    transaction_id.clone(),
                    FederationReplayRecord {
                        transaction_id,
                        content_digest,
                        first_seen_at: now,
                    },
                );
                FederationReplayDecision::AcceptedNew
            }
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn evict_expired(&mut self, now: DateTime<Utc>) {
        let ttl = self.ttl;
        self.records
            .retain(|_, record| now.signed_duration_since(record.first_seen_at) <= ttl);
    }

    fn evict_to_capacity(&mut self) {
        while self.records.len() >= self.capacity {
            let Some(oldest_transaction_id) = self
                .records
                .values()
                .min_by_key(|record| record.first_seen_at)
                .map(|record| record.transaction_id.clone())
            else {
                return;
            };
            self.records.remove(&oldest_transaction_id);
        }
    }
}

impl Default for MemoryFederationReplayStore {
    fn default() -> Self {
        Self::with_limits(
            chrono::Duration::seconds(DEFAULT_FEDERATION_REPLAY_TTL_SECS),
            DEFAULT_FEDERATION_REPLAY_CAPACITY,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationDeltaBatch {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<OperationId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<EventsSubmitRejectedItem>,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn transaction_envelope_validates_digest() {
        let payload = FederationTransactionRequestBody {
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
        assert_eq!(
            store.remember("txn", digest.clone()),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(
            store.remember("txn", digest),
            FederationReplayDecision::AcceptedDuplicate
        );
        assert_eq!(
            store.remember("txn", other),
            FederationReplayDecision::QuarantinedConflict
        );
    }

    #[test]
    fn replay_store_evicts_expired_records_by_first_seen_at() {
        let digest =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let other =
            Hash::new("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let now = Utc::now();
        let mut store = MemoryFederationReplayStore::with_limits(Duration::seconds(5), 8);

        assert_eq!(
            store.remember_at("txn", digest, now),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(
            store.remember_at("txn", other, now + Duration::seconds(6)),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn replay_store_evicts_oldest_record_when_capacity_is_full() {
        let digest =
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let now = Utc::now();
        let mut store = MemoryFederationReplayStore::with_limits(Duration::minutes(5), 2);

        assert_eq!(
            store.remember_at("txn_1", digest.clone(), now),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(
            store.remember_at("txn_2", digest.clone(), now + Duration::seconds(1)),
            FederationReplayDecision::AcceptedNew
        );
        assert_eq!(
            store.remember_at("txn_3", digest, now + Duration::seconds(2)),
            FederationReplayDecision::AcceptedNew
        );

        assert_eq!(store.len(), 2);
        assert!(!store.records.contains_key("txn_1"));
        assert!(store.records.contains_key("txn_2"));
        assert!(store.records.contains_key("txn_3"));
    }

    #[test]
    fn delta_batch_serializes_operations_surface() {
        let batch = FederationDeltaBatch {
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            operations: Vec::new(),
            accepted: Vec::new(),
            rejected: vec![EventsSubmitRejectedItem {
                id: "ak:operation:01904100-0000-7000-8000-000000000001".to_owned(),
                reason_code: "bad_signature".to_owned(),
                detail: None,
            }],
        };
        assert_eq!(
            serde_json::to_value(batch).unwrap()["rejected"][0]["reason_code"],
            "bad_signature"
        );
    }
}
