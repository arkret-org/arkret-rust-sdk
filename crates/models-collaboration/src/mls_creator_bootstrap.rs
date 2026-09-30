//! Client-local creator intent constrained by the normative bootstrap registry.
//! This record is never a wire request or a shared current-state value.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ActorId, DeviceId, DidUrl, Event, EventId, EventKind, MlsGroupId, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::authority_commit::SelfAuthoritySubmitRequest;
use crate::events_payloads::MlsGenesisBindingProposalCarrier;
use crate::internal_prelude::{Result, WireError};

crate::string_marker!(MlsCreatorBootstrapOperation, MlsGenesis, "mls_genesis");

/// The whole closed creation intent. Hosts atomically persist it before any
/// create submission or selector-dependent MLS randomness, and retain it
/// unchanged after Realm acceptance. The signer is not part of its logical key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapIntent {
    owner_actor_id: ActorId,
    effective_scope: ScopeRef,
    operation: MlsCreatorBootstrapOperation,
    creator_device_id: DeviceId,
    creator_signer_method: DidUrl,
    mls_group_id: MlsGroupId,
    proposed_group_genesis_binding: MlsGenesisBindingProposalCarrier,
    signed_scope_create_unit: SelfAuthoritySubmitRequest,
    scope_create_event_id: EventId,
}

impl MlsCreatorBootstrapIntent {
    pub fn new(
        owner_actor_id: ActorId,
        effective_scope: ScopeRef,
        creator_device_id: DeviceId,
        creator_signer_method: DidUrl,
        proposed_group_genesis_binding: MlsGovernanceBindingPayload,
        signed_scope_create_unit: SelfAuthoritySubmitRequest,
    ) -> Result<Self> {
        let create = scope_create_event(&signed_scope_create_unit)?;
        let value = Self {
            owner_actor_id: owner_actor_id.clone(),
            effective_scope: effective_scope.clone(),
            operation: MlsCreatorBootstrapOperation::MlsGenesis,
            creator_device_id,
            creator_signer_method,
            mls_group_id: effective_scope.canonical_mls_group_id()?,
            proposed_group_genesis_binding: MlsGenesisBindingProposalCarrier::new(
                owner_actor_id,
                effective_scope,
                proposed_group_genesis_binding,
            ),
            scope_create_event_id: create.event_id.clone(),
            signed_scope_create_unit,
        };
        value.validate()?;
        Ok(value)
    }

    /// Check local consistency, not producer signatures or current authority.
    /// Evidence verification and the durable CAS remain mandatory host duties.
    pub fn validate(&self) -> Result<()> {
        self.signed_scope_create_unit.validate()?;
        let create = scope_create_event(&self.signed_scope_create_unit)?;
        let proof = create.producer_proof.as_ref().ok_or_else(|| {
            WireError::Protocol("creator intent requires the exact signed create unit".into())
        })?;
        if proof.verification_method != self.creator_signer_method
            || create.human_device_producer()?.is_some_and(|producer| {
                producer.device_id != self.creator_device_id
                    || self
                        .owner_actor_id
                        .as_account_id()
                        .is_some_and(|owner| owner != &producer.account_id)
            })
        {
            return Err(WireError::Protocol(
                "creator intent changed its authoring device or signer".into(),
            ));
        }
        let proposal = &self.proposed_group_genesis_binding;
        let binding = proposal.proposed_group_genesis_binding();
        binding.validate()?;
        if create.actor_id != self.owner_actor_id
            || create.event_id != self.scope_create_event_id
            || proposal.sender_actor_id() != &self.owner_actor_id
            || proposal.target_scope() != &self.effective_scope
            || proposal.event_kind() != &EventKind::MlsGenesis
            || proposal.proposal_kind() != MlsGenesisBindingProposalCarrier::PROPOSAL_KIND
            || binding.effective_scope() != &self.effective_scope
            || binding.base_group_state_ref().is_some()
            || binding.previous_epoch() != 0
            || binding.next_epoch() != 0
            || binding.key_access_revision() != 0
            || binding.mls_group_id()? != self.mls_group_id
        {
            return Err(WireError::Protocol(
                "creator intent changed its closed proposal or create identity".into(),
            ));
        }
        match &self.effective_scope {
            ScopeRef::Realm { realm_id }
                if create.kind == EventKind::RealmCreate
                    && &create.realm_id == realm_id
                    && *realm_id == arkret_wire::RealmId::from_event_id(&create.event_id) => {}
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } if create.kind == EventKind::CircleCreate
                && &create.realm_id == realm_id
                && *circle_id == arkret_wire::CircleId::from_event_id(&create.event_id) => {}
            _ => return Err(WireError::Protocol(
                "creator intent requires its own exact Realm or Circle create; Sidecar is excluded"
                    .into(),
            )),
        }
        Ok(())
    }

    pub fn owner_actor_id(&self) -> &ActorId {
        &self.owner_actor_id
    }
    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }
    pub fn creator_device_id(&self) -> &DeviceId {
        &self.creator_device_id
    }
    pub fn creator_signer_method(&self) -> &DidUrl {
        &self.creator_signer_method
    }
    pub fn mls_group_id(&self) -> &MlsGroupId {
        &self.mls_group_id
    }
    pub fn proposal(&self) -> &MlsGenesisBindingProposalCarrier {
        &self.proposed_group_genesis_binding
    }
    pub fn signed_scope_create_unit(&self) -> &SelfAuthoritySubmitRequest {
        &self.signed_scope_create_unit
    }
    pub fn scope_create_event_id(&self) -> &EventId {
        &self.scope_create_event_id
    }
}

fn scope_create_event(request: &SelfAuthoritySubmitRequest) -> Result<&Event> {
    match request {
        SelfAuthoritySubmitRequest::Event(submission) => Ok(&submission.event),
        SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit) => unit
            .events
            .first()
            .map(|submission| &submission.event)
            .ok_or_else(|| WireError::Protocol("creator intent has no signed create unit".into())),
        SelfAuthoritySubmitRequest::DirectConversationFounding(unit) => Ok(&unit.events[0].event),
        _ => Err(WireError::Protocol(
            "creator intent is not a scope creation unit".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, DidCoreId, Hash, ProducerEventProof};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    const DEVICE: &str = "ak:device:0198ff00-0000-7000-8000-000000000001";

    fn intent(circle: bool) -> MlsCreatorBootstrapIntent {
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let parent =
            arkret_wire::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let timestamp = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let mut create = arkret_wire::test_support::raw_event_for_actor_at(
            if circle {
                "ak.circle.create"
            } else {
                "ak.realm.create"
            },
            if circle {
                ScopeRef::Realm {
                    realm_id: parent.clone(),
                }
            } else {
                ScopeRef::RealmGenesis
            },
            actor.clone(),
            json!({}),
            timestamp,
        )
        .unwrap();
        let method = DidUrl::new(format!("did:web:alice.example#{DEVICE}")).unwrap();
        let digest = Hash::new(
            create
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        // This fixture checks durable DTO bindings, not signature verification.
        create.producer_proof = Some(ProducerEventProof {
            kind: "detached_jws".into(),
            verification_method: method.clone(),
            event_digest: digest.clone(),
            created_at: timestamp,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
        });
        let scope = if circle {
            ScopeRef::Circle {
                realm_id: parent,
                circle_id: arkret_wire::CircleId::from_event_id(&create.event_id),
            }
        } else {
            ScopeRef::Realm {
                realm_id: create.realm_id.clone(),
            }
        };
        MlsCreatorBootstrapIntent::new(
            actor,
            scope.clone(),
            DeviceId::new(DEVICE).unwrap(),
            method,
            MlsGovernanceBindingPayload::new(scope, None, 0, 0, 0).unwrap(),
            SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(create)),
        )
        .unwrap()
    }

    #[test]
    fn realm_and_circle_intents_retain_exact_create_bytes_and_derived_group() {
        for circle in [false, true] {
            let original = intent(circle);
            let bytes = arkret_canonical::canonical_json_bytes(&original).unwrap();
            let restored: MlsCreatorBootstrapIntent = serde_json::from_slice(&bytes).unwrap();
            restored.validate().unwrap();
            assert_eq!(original, restored);
            assert_eq!(
                restored.mls_group_id(),
                &restored.effective_scope().canonical_mls_group_id().unwrap()
            );
        }
    }

    #[test]
    fn creator_intent_rejects_foreign_station_device_signer_and_create_identity() {
        let original = intent(false);
        let mut altered = original.clone();
        altered.owner_actor_id = ActorId::account(AccountId::new(
            original
                .owner_actor_id
                .as_account_id()
                .unwrap()
                .principal_id
                .clone(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        assert!(altered.validate().is_err());
        altered = original.clone();
        altered.creator_device_id =
            DeviceId::new("ak:device:0198ff00-0000-7000-8000-000000000002").unwrap();
        assert!(altered.validate().is_err());
        altered = original.clone();
        altered.creator_signer_method = DidUrl::new("did:web:other.example#key").unwrap();
        assert!(altered.validate().is_err());
        altered = original.clone();
        altered.scope_create_event_id = intent(true).scope_create_event_id;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn intent_cannot_borrow_another_scope_or_serialize_an_open_or_partial_record() {
        let original = intent(false);
        let mut altered = original.clone();
        altered.effective_scope = intent(true).effective_scope;
        assert!(altered.validate().is_err());
        let value = serde_json::to_value(original).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut partial = value.clone();
            partial.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<MlsCreatorBootstrapIntent>(partial).is_err(),
                "missing {field}"
            );
        }
        let mut open = value;
        open["proof_outcome"] = json!({});
        assert!(serde_json::from_value::<MlsCreatorBootstrapIntent>(open).is_err());
    }

    #[test]
    fn deserialized_intent_cannot_rebind_genesis_coordinates_or_its_derived_group() {
        let original = intent(false);
        for field in ["previous_epoch", "next_epoch", "key_access_revision"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value["proposed_group_genesis_binding"]["proposed_group_genesis_binding"][field] =
                json!(1);
            let altered: MlsCreatorBootstrapIntent = serde_json::from_value(value).unwrap();
            assert!(altered.validate().is_err(), "changed {field}");
        }
        let mut altered = original;
        altered.mls_group_id = intent(true).mls_group_id;
        assert!(altered.validate().is_err());
    }
}
