//! Event batch receipt and event proof wire counterparts.
//!
//! Counterparts for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`
//! and `event-envelope.schema.json#/$defs/event_proof`. These shapes are
//! payload-agnostic proof-binding containers: they reference events only by
//! identifier and canonical digest.

use arkret_identifiers::{DidCoreId, EventId, Hash, RealmId, ReceiptId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, WireError};
use crate::event_envelope::PrincipalAuthorityKey;
use crate::primitives::{PayloadProof, UnsignedPayloadProof};
use crate::wire_strings::NonEmptyString;
use crate::{ProofContextId, SchemaId, canonical};

/// Counterpart for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventBatchReceiptScope {
    PcrGenesis(PcrGenesisReceiptScope),
    DeviceReanchor(DeviceReanchorReceiptScope),
    Ordinary(EventBatchOrdinaryReceiptScope),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcrGenesisReceiptScopeKind {
    #[serde(rename = "pcr_genesis_unit")]
    PcrGenesisUnit,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisReceiptScope {
    pub kind: PcrGenesisReceiptScopeKind,
    pub principal_id: DidCoreId,
    pub realm_id: RealmId,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    pub registration_evidence_digest: Hash,
    pub accepted_device_id: crate::DeviceId,
    pub device_key_digest: Hash,
    pub hpke_key_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub audience: DidCoreId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchOrdinaryReceiptScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_digest: Option<Hash>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceReanchorReceiptScopeKind {
    #[serde(rename = "device_reanchor_unit")]
    DeviceReanchorUnit,
}

/// Counterpart for `event-batch-receipt.schema.json#/$defs/device_reanchor_scope`.
///
/// Authority is selected by the public principal pair plus the PCR-local
/// device generation CAS. Every field here MUST equal the covered
/// `ak.device.reanchor` payload.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorReceiptScope {
    pub kind: DeviceReanchorReceiptScopeKind,
    pub principal_id: DidCoreId,
    pub principal_server_id: DidCoreId,
    pub realm_id: RealmId,
    pub previous_device_generation: u64,
    pub new_device_generation: u64,
}

impl DeviceReanchorReceiptScope {
    /// Verify the scope's own authority selection before any event binding.
    ///
    /// The instance digest must recompute, the instance must reverse-bind
    /// `principal_id` and `realm_id`, and the generations must be an immediate
    /// monotonic successor pair. A same-core instance selecting a different
    /// Principal Server, PCR Realm or genesis receipt is a different PCR.
    pub fn validate_authority(&self) -> Result<()> {
        PrincipalAuthorityKey {
            principal_id: self.principal_id.clone(),
            principal_server_id: self.principal_server_id.clone(),
        }
        .validate()?;
        if self.previous_device_generation == 0
            || self.new_device_generation != self.previous_device_generation.saturating_add(1)
        {
            return Err(WireError::Protocol(
                "device reanchor receipt scope generations must be positive immediate successors"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceipt {
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub issuer: DidCoreId,
    pub scope: EventBatchReceiptScope,
    pub events: Vec<EventBatchReceiptEvent>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<PayloadProof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventBatchReceiptEvent {
    Digest(Hash),
    Item(EventBatchReceiptItem),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptItem {
    pub event_id: EventId,
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

    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("EventBatchReceipt serializes as an object")
            .remove("proofs");
        Ok(Hash::new(canonical::canonical_sha256(&value)?)?)
    }

    pub fn proof_signing_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest || proof.created_at != self.created_at {
            return Err(WireError::Protocol(
                "event batch receipt proof digest or created_at mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::from_iter([
            (
                "context".to_owned(),
                serde_json::Value::String(ProofContextId::RECEIPT_PROOF_V1.to_owned()),
            ),
            (
                "payload_digest".to_owned(),
                serde_json::to_value(&payload_digest)?,
            ),
            ("issuer".to_owned(), serde_json::to_value(&self.issuer)?),
            (
                "verification_method".to_owned(),
                serde_json::to_value(&proof.verification_method)?,
            ),
            (
                "created_at".to_owned(),
                serde_json::Value::String(canonical::format_timestamp_canonical(proof.created_at)),
            ),
        ]);
        if let Some(domain) = &proof.domain {
            binding.insert(
                "domain".to_owned(),
                serde_json::Value::String(domain.clone()),
            );
        }
        if let Some(audience) = &proof.audience {
            binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(
            &serde_json::Value::Object(binding),
        )?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        self.proof_signing_bytes(&proof.unsigned())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::EVENT_BATCH_RECEIPT_V1 {
            return Err(WireError::Protocol(
                "event batch receipt schema must be ak.schema.event_batch_receipt.v1".to_owned(),
            ));
        }
        if self.events.is_empty() || self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "event batch receipt requires events and proofs".to_owned(),
            ));
        }
        for proof in &self.proofs {
            self.proof_binding_bytes(proof)?;
        }
        let canonical_events = self
            .events
            .iter()
            .map(EventBatchReceiptEvent::canonical_json_bytes)
            .collect::<Result<Vec<_>>>()?;
        if canonical_events.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(WireError::Protocol(
                "event batch receipt events must be canonical sorted and duplicate-free".to_owned(),
            ));
        }
        match &self.scope {
            EventBatchReceiptScope::Ordinary(scope) => {
                if scope.actor_id.is_none()
                    && scope.realm_id.is_none()
                    && scope.query_digest.is_none()
                {
                    return Err(WireError::Protocol(
                        "event batch receipt ordinary scope must not be empty".to_owned(),
                    ));
                }
            }
            EventBatchReceiptScope::DeviceReanchor(scope) => {
                scope.validate_authority()?;
                if self.events.len() != 2
                    || self
                        .events
                        .iter()
                        .any(|event| !matches!(event, EventBatchReceiptEvent::Item(_)))
                {
                    return Err(WireError::Protocol(
                        "device reanchor receipt must contain exactly two typed event items"
                            .to_owned(),
                    ));
                }
                let reanchor = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == crate::event_kind_str::DEVICE_REANCHOR =>
                    {
                        Some(item)
                    }
                    _ => None,
                });
                let authorize = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == crate::event_kind_str::DEVICE_AUTHORIZE =>
                    {
                        Some(item)
                    }
                    _ => None,
                });
                if reanchor.is_none() || authorize.is_none() {
                    return Err(WireError::Protocol(
                        "device reanchor receipt event kinds mismatch".to_owned(),
                    ));
                }
            }
            EventBatchReceiptScope::PcrGenesis(_scope) => {
                if self.events.len() != 2
                    || self
                        .events
                        .iter()
                        .any(|event| !matches!(event, EventBatchReceiptEvent::Item(_)))
                {
                    return Err(WireError::Protocol(
                        "PCR genesis receipt must contain exactly two typed event items".to_owned(),
                    ));
                }
                let create = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == crate::event_kind_str::REALM_CREATE =>
                    {
                        Some(item)
                    }
                    _ => None,
                });
                let authorize = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == crate::event_kind_str::DEVICE_AUTHORIZE =>
                    {
                        Some(item)
                    }
                    _ => None,
                });
                if create.is_none() || authorize.is_none() {
                    return Err(WireError::Protocol(
                        "PCR genesis receipt event kinds mismatch".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn pcr_genesis_scope(&self) -> Result<&PcrGenesisReceiptScope> {
        self.validate()?;
        match &self.scope {
            EventBatchReceiptScope::PcrGenesis(scope) => Ok(scope),
            _ => Err(WireError::Protocol(
                "event batch receipt scope is not pcr_genesis_unit".to_owned(),
            )),
        }
    }
}

// `event-envelope.schema.json#/$defs/event_proof` is modelled by
// [`crate::primitives::ProducerEventProof`]. A second, incompatible `EventProof` struct used
// to live here with `verification_method: DidCoreId`, which rejected every legal wire
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

    fn fixture_authority() -> PrincipalAuthorityKey {
        PrincipalAuthorityKey::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        )
    }

    fn item(digest: Hash, kind: &str) -> EventBatchReceiptEvent {
        EventBatchReceiptEvent::Item(EventBatchReceiptItem {
            event_id: EventId::from_event_digest(&digest).unwrap(),
            kind: NonEmptyString::new(kind).unwrap(),
        })
    }

    #[test]
    fn bare_event_id_is_not_a_receipt_event() {
        let encoded = "\"ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-\"";
        assert!(serde_json::from_str::<EventBatchReceiptEvent>(encoded).is_err());
    }

    #[test]
    fn reanchor_binding_is_by_kind_after_canonical_sort() {
        let reanchor_digest = hash(0xbb);
        let authorize_digest = hash(0xaa);
        let mut receipt = EventBatchReceipt {
            schema: "ak.schema.event_batch_receipt.v1".to_owned(),
            receipt_id: ReceiptId::new("ak:receipt:0196419b-0000-7000-8000-000000000003").unwrap(),
            issuer: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            scope: EventBatchReceiptScope::DeviceReanchor(DeviceReanchorReceiptScope {
                kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
                principal_id: fixture_authority().principal_id,
                principal_server_id: fixture_authority().principal_server_id,
                realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                    .unwrap(),
                previous_device_generation: 1,
                new_device_generation: 2,
            }),
            events: vec![
                item(reanchor_digest, "ak.device.reanchor"),
                item(authorize_digest, "ak.device.authorize"),
            ],
            created_at: Utc::now(),
            proofs: Vec::new(),
        };

        receipt.canonicalize_events().unwrap();
        let unsigned_proof = UnsignedPayloadProof {
            kind: crate::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:service.example#key-1").unwrap(),
            payload_digest: receipt.payload_digest().unwrap(),
            created_at: receipt.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
        };
        let signing_bytes = receipt.proof_signing_bytes(&unsigned_proof).unwrap();
        assert!(unsigned_proof.clone().finalize("").is_err());
        let proof = unsigned_proof.finalize("AAAA..BBBB").unwrap();
        assert_eq!(receipt.proof_binding_bytes(&proof).unwrap(), signing_bytes);
        receipt.proofs.push(proof);
        assert!(matches!(
            &receipt.events[0],
            EventBatchReceiptEvent::Item(item)
                if item.kind.as_str() == "ak.device.authorize"
        ));
        receipt.validate().unwrap();
        receipt.events.reverse();
        let reversed_digest = receipt.payload_digest().unwrap();
        receipt.proofs[0].payload_digest = reversed_digest;
        let error = receipt.validate().unwrap_err();
        assert!(error.to_string().contains("canonical sorted"));
    }

    #[test]
    fn receipt_proof_binding_is_stable_across_canonical_timestamp_roundtrip() {
        let created_at = DateTime::parse_from_rfc3339("2026-08-12T08:18:26.601188800Z")
            .unwrap()
            .with_timezone(&Utc);
        let event_digest = hash(0xaa);
        let mut receipt = EventBatchReceipt {
            schema: EventBatchReceipt::SCHEMA.to_owned(),
            receipt_id: ReceiptId::new("ak:receipt:0196419b-0000-7000-8000-000000000004").unwrap(),
            issuer: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            scope: EventBatchReceiptScope::DeviceReanchor(DeviceReanchorReceiptScope {
                kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
                principal_id: fixture_authority().principal_id,
                principal_server_id: fixture_authority().principal_server_id,
                realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                    .unwrap(),
                previous_device_generation: 1,
                new_device_generation: 2,
            }),
            events: vec![
                item(event_digest, "ak.device.reanchor"),
                item(hash(0xbb), "ak.device.authorize"),
            ],
            created_at,
            proofs: Vec::new(),
        };
        let proof = UnsignedPayloadProof {
            kind: crate::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:service.example#notary-key").unwrap(),
            payload_digest: receipt.payload_digest().unwrap(),
            created_at: receipt.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
        }
        .finalize("AAAA..BBBB")
        .unwrap();
        receipt.proofs.push(proof.clone());
        let before = receipt.proof_binding_bytes(&proof).unwrap();
        let roundtripped: EventBatchReceipt =
            serde_json::from_value(serde_json::to_value(&receipt).unwrap()).unwrap();
        let after = roundtripped
            .proof_binding_bytes(&roundtripped.proofs[0])
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn reanchor_scope_rejects_non_successor_generations() {
        let authority = fixture_authority();
        let scope = DeviceReanchorReceiptScope {
            kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
            principal_id: authority.principal_id,
            principal_server_id: authority.principal_server_id,
            realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                .unwrap(),
            previous_device_generation: 1,
            new_device_generation: 3,
        };
        let error = scope.validate_authority().unwrap_err();
        assert!(error.to_string().contains("immediate successors"));
    }

    #[test]
    fn reanchor_scope_serializes_the_single_flat_authority_pair() {
        let scope = DeviceReanchorReceiptScope {
            kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
            principal_id: fixture_authority().principal_id,
            principal_server_id: fixture_authority().principal_server_id,
            realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                .unwrap(),
            previous_device_generation: 1,
            new_device_generation: 2,
        };
        let value = serde_json::to_value(scope).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "kind",
                "new_device_generation",
                "previous_device_generation",
                "principal_id",
                "principal_server_id",
                "realm_id",
            ])
        );
        assert!(!object.contains_key("authority"));
    }
}
