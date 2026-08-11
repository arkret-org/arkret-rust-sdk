//! Event batch receipt and event proof wire counterparts.
//!
//! Counterparts for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`
//! and `event-envelope.schema.json#/$defs/event_proof`. These shapes are
//! payload-agnostic proof-binding containers: they reference events only by
//! identifier and canonical digest.

use arkret_identifiers::{DidCoreId, EventId, Hash, RealmId, ReceiptId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event_envelope::PrincipalAuthorityInstance;
use crate::primitives::PayloadProof;
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
    pub create_digest: Hash,
    pub founding_authorize_digest: Hash,
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
/// Authority is selected by the exact [`PrincipalAuthorityInstance`] plus the
/// PCR-local device generation CAS. The base re-anchor branch carries no DID
/// version or registry head, and neither may be synthesized from a generation
/// ref. Every field here MUST equal the covered `ak.device.reanchor` payload.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorReceiptScope {
    pub kind: DeviceReanchorReceiptScopeKind,
    pub principal_id: DidCoreId,
    pub realm_id: RealmId,
    pub authority_instance: PrincipalAuthorityInstance,
    pub previous_device_generation: u64,
    pub new_device_generation: u64,
    pub reanchor_digest: Hash,
    pub replacement_authorize_digest: Hash,
}

impl DeviceReanchorReceiptScope {
    /// Verify the scope's own authority selection before any event binding.
    ///
    /// The instance digest must recompute, the instance must reverse-bind
    /// `principal_id` and `realm_id`, and the generations must be an immediate
    /// monotonic successor pair. A same-core instance selecting a different
    /// Principal Server, PCR Realm or genesis receipt is a different PCR.
    pub fn validate_authority(&self) -> Result<()> {
        self.authority_instance.validate()?;
        if self.authority_instance.principal_id != self.principal_id
            || self.authority_instance.pcr_realm_id != self.realm_id
        {
            return Err(Error::Protocol(
                "device reanchor receipt scope authority_instance does not reverse-bind its principal and realm"
                    .to_owned(),
            ));
        }
        if self.previous_device_generation == 0
            || self.new_device_generation != self.previous_device_generation.saturating_add(1)
        {
            return Err(Error::Protocol(
                "device reanchor receipt scope generations must be positive immediate successors"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Compare the scope against the covered `ak.device.reanchor` payload
    /// selection. Callers pass the payload's own authority fields; any
    /// difference is a substitution and MUST fail closed.
    pub fn matches_payload_authority(
        &self,
        payload_authority_instance: &PrincipalAuthorityInstance,
        payload_previous_device_generation: u64,
        payload_new_device_generation: u64,
    ) -> Result<()> {
        self.validate_authority()?;
        if &self.authority_instance != payload_authority_instance
            || self.previous_device_generation != payload_previous_device_generation
            || self.new_device_generation != payload_new_device_generation
        {
            return Err(Error::Protocol(
                "device reanchor receipt scope does not match the covered payload authority"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceipt {
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub issuer: DidCoreId,
    pub scope: EventBatchReceiptScope,
    pub frontier: EventBatchReceiptFrontier,
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

    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("EventBatchReceipt serializes as an object")
            .remove("proofs");
        Ok(Hash::new(canonical::canonical_sha256(&value)?)?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest || proof.created_at != self.created_at {
            return Err(Error::Protocol(
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
                serde_json::to_value(proof.created_at)?,
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
        for proof in &self.proofs {
            self.proof_binding_bytes(proof)?;
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
                scope.validate_authority()?;
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
            EventBatchReceiptScope::PcrGenesis(scope) => {
                if self.events.len() != 2
                    || self
                        .events
                        .iter()
                        .any(|event| !matches!(event, EventBatchReceiptEvent::Item(_)))
                {
                    return Err(Error::Protocol(
                        "PCR genesis receipt must contain exactly two typed event items".to_owned(),
                    ));
                }
                let create = self.events.iter().find_map(|event| match event {
                    EventBatchReceiptEvent::Item(item)
                        if item.kind.as_str() == "ak.realm.create" =>
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
                if create.map(|item| &item.event_digest) != Some(&scope.create_digest)
                    || authorize.map(|item| &item.event_digest)
                        != Some(&scope.founding_authorize_digest)
                {
                    return Err(Error::Protocol(
                        "PCR genesis receipt event binding mismatch".to_owned(),
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
            _ => Err(Error::Protocol(
                "event batch receipt scope is not pcr_genesis_unit".to_owned(),
            )),
        }
    }
}

// `event-envelope.schema.json#/$defs/event_proof` is modelled by
// [`crate::primitives::Proof`]. A second, incompatible `EventProof` struct used
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

    fn fixture_authority_instance() -> PrincipalAuthorityInstance {
        PrincipalAuthorityInstance::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            hash(0xcc),
        )
        .unwrap()
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
                principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                    .unwrap(),
                authority_instance: fixture_authority_instance(),
                previous_device_generation: 1,
                new_device_generation: 2,
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
                    "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    reanchor_digest,
                    "ak.device.reanchor",
                ),
                item(
                    "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
                    authorize_digest,
                    "ak.device.authorize",
                ),
            ],
            created_at: Utc::now(),
            proofs: Vec::new(),
        };

        receipt.canonicalize_events().unwrap();
        receipt.proofs.push(PayloadProof {
            kind: crate::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:service.example#key-1").unwrap(),
            payload_digest: receipt.payload_digest().unwrap(),
            created_at: receipt.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "AAAA..BBBB".to_owned(),
        });
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
    fn reanchor_scope_rejects_same_core_authority_substitution() {
        let authority = fixture_authority_instance();
        let scope = DeviceReanchorReceiptScope {
            kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
            principal_id: authority.principal_id.clone(),
            realm_id: authority.pcr_realm_id.clone(),
            authority_instance: authority.clone(),
            previous_device_generation: 1,
            new_device_generation: 2,
            reanchor_digest: hash(0xbb),
            replacement_authorize_digest: hash(0xaa),
        };
        scope.validate_authority().unwrap();
        scope
            .matches_payload_authority(&authority, 1, 2)
            .expect("identical selection must match");

        // Same principal core, different Principal Server: a different PCR.
        let substituted = PrincipalAuthorityInstance::new(
            authority.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-ps.example").unwrap(),
            authority.pcr_realm_id.clone(),
            authority.principal_genesis_receipt_digest.clone(),
        )
        .unwrap();
        let error = scope
            .matches_payload_authority(&substituted, 1, 2)
            .unwrap_err();
        assert!(error.to_string().contains("covered payload authority"));

        let error = scope
            .matches_payload_authority(&authority, 1, 3)
            .unwrap_err();
        assert!(error.to_string().contains("covered payload authority"));
    }

    #[test]
    fn reanchor_scope_rejects_non_successor_generations() {
        let authority = fixture_authority_instance();
        let scope = DeviceReanchorReceiptScope {
            kind: DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
            principal_id: authority.principal_id.clone(),
            realm_id: authority.pcr_realm_id.clone(),
            authority_instance: authority,
            previous_device_generation: 1,
            new_device_generation: 3,
            reanchor_digest: hash(0xbb),
            replacement_authorize_digest: hash(0xaa),
        };
        let error = scope.validate_authority().unwrap_err();
        assert!(error.to_string().contains("immediate successors"));
    }
}
