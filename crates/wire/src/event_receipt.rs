//! Event batch receipt and event proof wire counterparts.
//!
//! Counterparts for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`
//! and `event-envelope.schema.json#/$defs/event_proof`. These shapes are
//! payload-agnostic proof-binding containers: they reference events only by
//! identifier and canonical digest.

use arkret_identifiers::{Did, EventId, Hash, RealmId, ReceiptId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::primitives::Proof;
use crate::wire_strings::NonEmptyString;
use crate::{SchemaId, canonical};

/// Counterpart for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventBatchReceiptScope {
    DeviceReanchor(DeviceReanchorReceiptScope),
    Ordinary(EventBatchOrdinaryReceiptScope),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchOrdinaryReceiptScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_digest: Option<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceReanchorReceiptScopeKind {
    #[serde(rename = "device_reanchor_unit")]
    DeviceReanchorUnit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorReceiptScope {
    pub kind: DeviceReanchorReceiptScopeKind,
    pub principal_id: Did,
    pub realm_id: RealmId,
    pub did_version_id: NonEmptyString,
    pub registry_head: Hash,
    pub reanchor_digest: Hash,
    pub replacement_authorize_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptFrontier {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceipt {
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub issuer: Did,
    pub scope: EventBatchReceiptScope,
    pub frontier: EventBatchReceiptFrontier,
    pub events: Vec<EventBatchReceiptEvent>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventBatchReceiptEvent {
    Digest(Hash),
    Item(EventBatchReceiptItem),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptItem {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub kind: NonEmptyString,
}

impl EventBatchReceiptEvent {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }
}

impl EventBatchReceipt {
    pub const SCHEMA: &'static str = SchemaId::EVENT_BATCH_RECEIPT_V1;
    /// Sort and deduplicate the receipt's set projection before signing it.
    pub fn canonicalize_events(&mut self) -> Result<()> {
        let mut keyed = self
            .events
            .drain(..)
            .map(|event| Ok((event.canonical_json_bytes()?, event)))
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        keyed.dedup_by(|left, right| left.0 == right.0);
        self.events = keyed.into_iter().map(|(_, event)| event).collect();
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != "ak.schema.event_batch_receipt.v1" {
            return Err(Error::Protocol(
                "event batch receipt schema must be ak.schema.event_batch_receipt.v1".to_owned(),
            ));
        }
        if self.events.is_empty() || self.proofs.is_empty() {
            return Err(Error::Protocol(
                "event batch receipt requires events and proofs".to_owned(),
            ));
        }
        let canonical_events = self
            .events
            .iter()
            .map(EventBatchReceiptEvent::canonical_json_bytes)
            .collect::<Result<Vec<_>>>()?;
        if canonical_events.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Protocol(
                "event batch receipt events must be canonical sorted and duplicate-free".to_owned(),
            ));
        }
        if self.frontier.actor_seq.is_none()
            && self.frontier.event_id.is_none()
            && self.frontier.event_digest.is_none()
            && self.frontier.hlc.is_none()
        {
            return Err(Error::Protocol(
                "event batch receipt frontier must not be empty".to_owned(),
            ));
        }
        match &self.scope {
            EventBatchReceiptScope::Ordinary(scope) => {
                if scope.actor_id.is_none()
                    && scope.realm_id.is_none()
                    && scope.query_digest.is_none()
                {
                    return Err(Error::Protocol(
                        "event batch receipt ordinary scope must not be empty".to_owned(),
                    ));
                }
            }
            EventBatchReceiptScope::DeviceReanchor(scope) => {
                if self.events.len() != 2
                    || self
                        .events
                        .iter()
                        .any(|event| !matches!(event, EventBatchReceiptEvent::Item(_)))
                {
                    return Err(Error::Protocol(
                        "device reanchor receipt must contain exactly two typed event items"
                            .to_owned(),
                    ));
                }
                let reanchor = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == "ak.device.reanchor" =>
                    {
                        Some(item)
                    }
                    _ => None,
                });
                let authorize = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == "ak.device.authorize" =>
                    {
                        Some(item)
                    }
                    _ => None,
                });
                if reanchor.map(|item| &item.event_digest) != Some(&scope.reanchor_digest)
                    || authorize.map(|item| &item.event_digest)
                        != Some(&scope.replacement_authorize_digest)
                {
                    return Err(Error::Protocol(
                        "device reanchor receipt event binding mismatch".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// `event-envelope.schema.json#/$defs/event_proof` is modelled by
// [`crate::primitives::Proof`]. A second, incompatible `EventProof` struct used
// to live here with `verification_method: Did`, which rejected every legal wire
// value (the schema pattern requires a `#fragment`). It had zero constructors
// and zero readers across all repositories, so it was removed rather than
// migrated; `EventProofAudience` below is still used by
// `arkret_models_integration::artifacts_applet`.

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventProofAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[cfg(test)]
mod event_batch_receipt_tests {
    use super::*;
    use crate::DidUrl;

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn item(id: &str, digest: Hash, kind: &str) -> EventBatchReceiptEvent {
        EventBatchReceiptEvent::Item(EventBatchReceiptItem {
            event_id: EventId::new(id).unwrap(),
            event_digest: digest,
            kind: NonEmptyString::new(kind).unwrap(),
        })
    }

    #[test]
    fn bare_event_id_is_not_a_receipt_event() {
        let encoded = "\"ak:event:0196419b-0000-8000-8000-000000000001\"";
        assert!(serde_json::from_str::<EventBatchReceiptEvent>(encoded).is_err());
    }

    #[test]
    fn reanchor_binding_is_by_kind_after_canonical_sort() {
        let reanchor_digest = hash(0xbb);
        let authorize_digest = hash(0xaa);
        let mut receipt = EventBatchReceipt {
            schema: "ak.schema.event_batch_receipt.v1".to_owned(),
            receipt_id: ReceiptId::new("ak:receipt:0196419b-0000-7000-8000-000000000003").unwrap(),
            issuer: Did::new("did:web:service.example").unwrap(),
            scope: EventBatchReceiptScope::DeviceReanchor(DeviceReanchorReceiptScope {
                kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
                principal_id: Did::new("did:web:alice.example").unwrap(),
                realm_id: RealmId::new("ak:realm:0196419b-0000-8000-8000-000000000001").unwrap(),
                did_version_id: NonEmptyString::new("1-fixture").unwrap(),
                registry_head: hash(0xcc),
                reanchor_digest: reanchor_digest.clone(),
                replacement_authorize_digest: authorize_digest.clone(),
            }),
            frontier: EventBatchReceiptFrontier {
                actor_seq: Some(2),
                event_id: None,
                event_digest: None,
                hlc: None,
            },
            events: vec![
                item(
                    "ak:event:0196419b-0000-8000-8000-000000000001",
                    reanchor_digest,
                    "ak.device.reanchor",
                ),
                item(
                    "ak:event:0196419b-0000-8000-8000-000000000002",
                    authorize_digest,
                    "ak.device.authorize",
                ),
            ],
            created_at: Utc::now(),
            proofs: vec![Proof {
                kind: "DataIntegrityProof".to_owned(),
                verification_method: DidUrl::new("did:web:service.example#key-1").unwrap(),
                event_digest: hash(0xdd),
                created_at: Utc::now(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "AAAA..BBBB".to_owned(),
            }],
        };

        receipt.canonicalize_events().unwrap();
        assert!(matches!(
            &receipt.events[0],
            EventBatchReceiptEvent::Item(item)
                if item.kind.as_str() == "ak.device.authorize"
        ));
        receipt.validate().unwrap();
        receipt.events.reverse();
        let error = receipt.validate().unwrap_err();
        assert!(error.to_string().contains("canonical sorted"));
    }
}
