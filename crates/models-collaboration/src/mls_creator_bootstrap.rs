//! Client-local creator intent constrained by the normative bootstrap registry.
//! This record is never a wire request or a shared current-state value.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ActorId, DeviceId, DidUrl, Event, EventId, EventKind, MlsGroupId, ScopeRef};
use serde::{Deserialize, Serialize};

use crate::authority_commit::SelfAuthoritySubmitRequest;
use crate::events_payloads::MlsGenesisBindingProposalCarrier;
use crate::internal_prelude::{Result, WireError};
use crate::sync_frames::account_subscribe::RealmDetailBaseline;
use crate::sync_frames::current_results::AccountCurrentResult;

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
    creator_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
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
        let endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: creator_device_id.clone(),
        };
        Self::new_with_endpoint(
            owner_actor_id,
            effective_scope,
            creator_device_id,
            creator_signer_method,
            endpoint,
            proposed_group_genesis_binding,
            signed_scope_create_unit,
        )
    }

    /// Preserve the explicit endpoint slot for human, Agent or service authoring.
    /// The authoring device remains immutable vault metadata, not the Actor class.
    pub fn new_with_endpoint(
        owner_actor_id: ActorId,
        effective_scope: ScopeRef,
        creator_device_id: DeviceId,
        creator_signer_method: DidUrl,
        creator_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
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
            creator_endpoint,
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
        let device_producer = create.human_device_producer()?;
        let endpoint_matches = match &self.creator_endpoint {
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => {
                device_id == &self.creator_device_id && device_producer.is_some()
            }
            arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => verification_method == &self.creator_signer_method && device_producer.is_none(),
        };
        if proof.verification_method != self.creator_signer_method
            || !endpoint_matches
            || device_producer.is_some_and(|producer| {
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
    pub fn creator_endpoint(&self) -> &arkret_wire::MlsWelcomeRecipientEndpoint {
        &self.creator_endpoint
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

/// A complete authorized current cut retained with pinned creator evidence.
/// These existing carriers provide coverage and current values together;
/// neither a missing projection nor an empty incomplete result proves absence.
/// Signature, authority-chain and source authentication remain host duties.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapCurrentCut {
    baseline: RealmDetailBaseline,
    current: AccountCurrentResult,
}

impl MlsCreatorBootstrapCurrentCut {
    pub fn new(baseline: RealmDetailBaseline, current: AccountCurrentResult) -> Self {
        Self { baseline, current }
    }

    /// Check byte-local coverage and exact-scope absence against the independently
    /// verified authority coordinates of this cut. This is not authentication.
    pub fn validate_absence_binding(
        &self,
        scope: &ScopeRef,
        governance_generation: u64,
        realm_head: &arkret_wire::CommitStreamHead,
    ) -> Result<()> {
        use arkret_wire::{CommitStreamRef, CurrentSelector};

        let stream = match scope {
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. } => {
                CommitStreamRef::from_scope(scope, None)?
            }
            _ => {
                return Err(WireError::Protocol(
                    "creator current cut requires a Realm or Circle scope".into(),
                ));
            }
        };
        self.baseline.validate()?;
        self.current.validate()?;
        let coverage = &self.baseline.coverage;
        if !self.baseline.complete
            || !coverage.complete_for_authorized_streams
            || coverage.realm_id != *stream.realm_id()
            || self.current.realm_id != coverage.realm_id
            || self.current.governance_generation != governance_generation
            || realm_head.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: coverage.realm_id.clone(),
                })
            || !coverage.stream_heads.contains(realm_head)
            || !coverage
                .stream_heads
                .iter()
                .any(|head| head.stream_ref == stream)
            || coverage.stream_heads.len() != self.current.stream_heads.len()
            || coverage.stream_heads.iter().any(|head| {
                head.stream_ref.realm_id() != &coverage.realm_id
                    || !self.current.stream_heads.contains(head)
            })
            || self
                .current
                .entry(&CurrentSelector::MlsGroup {
                    scope_ref: scope.clone(),
                })
                .is_some()
        {
            return Err(WireError::Protocol(
                "creator current cut does not bind complete exact-scope Genesis absence".into(),
            ));
        }
        Ok(())
    }

    pub fn baseline(&self) -> &RealmDetailBaseline {
        &self.baseline
    }

    pub fn current(&self) -> &AccountCurrentResult {
        &self.current
    }
}

/// Exact accepted creation and its authority-root resolution retained by the
/// transaction. Shape checks cannot replace producer/Commit/route verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapAcceptedCreate {
    accepted_event: Event,
    covering_commit: arkret_wire::RealmCommit,
    digest_suite: arkret_canonical::DigestSuite,
    accepted_bytes_digest: arkret_wire::Hash,
    authority_root: arkret_wire::RealmAuthorityBundle,
}

/// Durable prefix of the normative creator transaction. Unsupported later
/// states are deliberately not deserializable until their recovery units are
/// implemented. Hosts authenticate evidence before committing a transition;
/// the checks here bind the saved bytes, not their signatures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsCreatorBootstrapRecord {
    GenesisIntentPersisted {
        intent: MlsCreatorBootstrapIntent,
    },
    RealmAccepted {
        intent: MlsCreatorBootstrapIntent,
        accepted_create: Box<MlsCreatorBootstrapAcceptedCreate>,
        genesis_absence: Box<arkret_wire::RealmStateSnapshot>,
    },
}

impl MlsCreatorBootstrapRecord {
    pub fn new(intent: MlsCreatorBootstrapIntent) -> Result<Self> {
        intent.validate()?;
        Ok(Self::GenesisIntentPersisted { intent })
    }

    pub fn intent(&self) -> &MlsCreatorBootstrapIntent {
        match self {
            Self::GenesisIntentPersisted { intent } | Self::RealmAccepted { intent, .. } => intent,
        }
    }

    pub fn state(&self) -> arkret_wire::MlsCreatorBootstrapState {
        match self {
            Self::GenesisIntentPersisted { .. } => {
                arkret_wire::MlsCreatorBootstrapState::GenesisIntentPersisted
            }
            Self::RealmAccepted { .. } => arkret_wire::MlsCreatorBootstrapState::RealmAccepted,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.intent().validate()?;
        if let Self::RealmAccepted {
            intent,
            accepted_create,
            genesis_absence,
        } = self
        {
            accepted_create.validate_binding(intent)?;
            validate_creator_genesis_absence_snapshot(intent, accepted_create, genesis_absence)?;
        }
        Ok(())
    }

    /// Advance exactly the registered acceptance arrow. Once accepted, retain
    /// the original cut; an idempotent replay cannot replace it with a new one.
    pub fn accept_realm(
        &mut self,
        accepted_create: MlsCreatorBootstrapAcceptedCreate,
        genesis_absence: arkret_wire::RealmStateSnapshot,
    ) -> Result<()> {
        let next = Self::RealmAccepted {
            intent: self.intent().clone(),
            accepted_create: Box::new(accepted_create),
            genesis_absence: Box::new(genesis_absence),
        };
        next.validate()?;
        if *self == next {
            return Ok(());
        }
        let arrow =
            arkret_wire::MlsCreatorBootstrapTransition::GenesisIntentPersistedToRealmAccepted;
        if Some(self.state()) != arrow.from_state() || next.state() != arrow.to_state() {
            return Err(WireError::Protocol(
                "creator acceptance cannot replace an immutable durable cut".into(),
            ));
        }
        *self = next;
        Ok(())
    }
}

/// Bind an independently authenticated complete snapshot to exact Genesis
/// absence. A signed current snapshot is an existing complete current carrier;
/// no fabricated Account baseline or empty projection is used as evidence.
pub fn validate_creator_genesis_absence_snapshot(
    intent: &MlsCreatorBootstrapIntent,
    accepted: &MlsCreatorBootstrapAcceptedCreate,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> Result<()> {
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentResult};
    let stream = CommitStreamRef::from_scope(intent.effective_scope(), None)?;
    let root = accepted.authority_root();
    let create = accepted.covering_commit();
    let scope_head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream);
    let create_head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == create.stream_ref);
    let distinct: std::collections::BTreeSet<_> = snapshot
        .visible_stream_heads
        .iter()
        .map(|head| &head.stream_ref)
        .collect();
    if snapshot.realm_id != root.realm_id
        || snapshot.governance_generation != root.current_generation
        || distinct.len() != snapshot.visible_stream_heads.len()
        || snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref.realm_id() != &root.realm_id)
        || scope_head.is_none()
        || create_head.is_none_or(|head| {
            head.stream_position < create.stream_position
                || (head.stream_position == create.stream_position
                    && head.commit_id != create.commit_id)
        })
        || !snapshot
            .visible_stream_heads
            .contains(&root.realm_stream_head)
        || snapshot.current_state_entries.iter().any(|entry| {
            let selector = match entry {
                TypedCurrentResult::Value { selector, .. } => selector,
            };
            selector
                == &CurrentSelector::MlsGroup {
                    scope_ref: intent.effective_scope().clone(),
                }
        })
    {
        return Err(WireError::Protocol("creator snapshot does not prove complete exact-scope Genesis absence at the accepted authority cut".into()));
    }
    Ok(())
}

impl MlsCreatorBootstrapAcceptedCreate {
    pub fn new(
        intent: &MlsCreatorBootstrapIntent,
        accepted_event: Event,
        covering_commit: arkret_wire::RealmCommit,
        digest_suite: arkret_canonical::DigestSuite,
        authority_root: arkret_wire::RealmAuthorityBundle,
    ) -> Result<Self> {
        let bytes = arkret_canonical::canonical_json_bytes(&accepted_event)?;
        let value = Self {
            accepted_event,
            covering_commit,
            digest_suite,
            accepted_bytes_digest: arkret_wire::Hash::new(arkret_canonical::canonical::digest(
                digest_suite,
                &bytes,
            ))?,
            authority_root,
        };
        value.validate_binding(intent)?;
        Ok(value)
    }

    /// Require the unchanged signed creation, covering independent-stream
    /// Commit and the exact authority root. The host verifies all signatures
    /// and complete accepted history before advancing the transaction.
    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        intent.validate()?;
        self.covering_commit.validate_shape()?;
        self.authority_root.validate_shape()?;
        self.accepted_event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        self.accepted_event
            .validate_proof_bindings_with_digest_suite(self.digest_suite)?;
        self.authority_root
            .genesis_event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)?;
        let original = scope_create_event(intent.signed_scope_create_unit())?;
        let expected_stream = arkret_wire::CommitStreamRef::from_scope(
            &original.scope_ref,
            Some(original.realm_id.clone()),
        )?;
        let bytes = arkret_canonical::canonical_json_bytes(&self.accepted_event)?;
        if &self.accepted_event != original
            || self.accepted_bytes_digest.as_str()
                != arkret_canonical::canonical::digest(self.digest_suite, &bytes)
            || self.covering_commit.event_ref != original.event_id
            || self.covering_commit.realm_id != original.realm_id
            || self.covering_commit.stream_ref != expected_stream
            || self.authority_root.realm_id != original.realm_id
            || self.covering_commit.governance_generation > self.authority_root.current_generation
            || (original.kind == EventKind::RealmCreate
                && (self.authority_root.genesis_event != self.accepted_event
                    || self.authority_root.genesis_commit != self.covering_commit))
        {
            return Err(WireError::Protocol(
                "accepted creator evidence changed the exact creation, digest, stream, or root"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn accepted_event(&self) -> &Event {
        &self.accepted_event
    }

    pub fn covering_commit(&self) -> &arkret_wire::RealmCommit {
        &self.covering_commit
    }

    pub fn digest_suite(&self) -> arkret_canonical::DigestSuite {
        self.digest_suite
    }

    pub fn accepted_bytes_digest(&self) -> &arkret_wire::Hash {
        &self.accepted_bytes_digest
    }

    pub fn authority_root(&self) -> &arkret_wire::RealmAuthorityBundle {
        &self.authority_root
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

    fn fixture_intent(circle: bool) -> MlsCreatorBootstrapIntent {
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let parent = if circle {
            scope_create_event(fixture_intent(false).signed_scope_create_unit())
                .unwrap()
                .realm_id
                .clone()
        } else {
            arkret_wire::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap()
        };
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
            let original = fixture_intent(circle);
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
        let original = fixture_intent(false);
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
        altered.scope_create_event_id = fixture_intent(true).scope_create_event_id;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn intent_cannot_borrow_another_scope_or_serialize_an_open_or_partial_record() {
        let original = fixture_intent(false);
        let mut altered = original.clone();
        altered.effective_scope = fixture_intent(true).effective_scope;
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
        let original = fixture_intent(false);
        for field in ["previous_epoch", "next_epoch", "key_access_revision"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value["proposed_group_genesis_binding"]["proposed_group_genesis_binding"][field] =
                json!(1);
            let altered: MlsCreatorBootstrapIntent = serde_json::from_value(value).unwrap();
            assert!(altered.validate().is_err(), "changed {field}");
        }
        let mut altered = original;
        altered.mls_group_id = fixture_intent(true).mls_group_id;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn human_creator_cannot_replace_the_device_proof_with_a_generic_account_key() {
        let mut altered = fixture_intent(false);
        let method = DidUrl::new("did:web:alice.example#key").unwrap();
        altered.creator_signer_method = method.clone();
        let SelfAuthoritySubmitRequest::Event(event) = &mut altered.signed_scope_create_unit else {
            panic!("fixture must be an Event");
        };
        event
            .event
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method = method;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn runtime_endpoint_does_not_classify_an_agent_account_as_a_human_device() {
        let mut original = fixture_intent(false);
        let method = DidUrl::new("did:web:alice.example#agent-key").unwrap();
        let SelfAuthoritySubmitRequest::Event(event) = &mut original.signed_scope_create_unit
        else {
            panic!("fixture must be an Event");
        };
        event
            .event
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method = method.clone();
        let endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: method.clone(),
        };
        let mut runtime = MlsCreatorBootstrapIntent::new_with_endpoint(
            original.owner_actor_id.clone(),
            original.effective_scope.clone(),
            original.creator_device_id.clone(),
            method,
            endpoint,
            original.proposal().proposed_group_genesis_binding().clone(),
            original.signed_scope_create_unit.clone(),
        )
        .unwrap();
        runtime.validate().unwrap();
        runtime.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: runtime.creator_device_id.clone(),
        };
        assert!(runtime.validate().is_err());
        let mut device = fixture_intent(false);
        device.creator_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: device.creator_signer_method.clone(),
        };
        assert!(device.validate().is_err());
    }

    fn current_cut(
        circle: bool,
    ) -> (
        ScopeRef,
        arkret_wire::CommitStreamHead,
        MlsCreatorBootstrapCurrentCut,
    ) {
        use arkret_wire::{CommitStreamHead, CommitStreamRef, RealmCommitId};

        use crate::sync_frames::current_results::AccountCurrentCoverage;

        let scope = fixture_intent(circle).effective_scope;
        let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
        let realm_id = stream.realm_id().clone();
        let realm_head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: 7,
            commit_id: RealmCommitId::new(
                "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            )
            .unwrap(),
        };
        let mut heads = vec![realm_head.clone()];
        if circle {
            heads.push(CommitStreamHead {
                stream_ref: stream,
                stream_position: 2,
                commit_id: RealmCommitId::new(
                    "ak:realm_commit:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            });
        }
        let cut = MlsCreatorBootstrapCurrentCut::new(
            RealmDetailBaseline {
                snapshot_cursor: "ak:cursor:creator_cut".into(),
                cut_revision: 11,
                coverage: AccountCurrentCoverage {
                    realm_id: realm_id.clone(),
                    stream_heads: heads.clone(),
                    complete_for_authorized_streams: true,
                },
                complete: true,
            },
            AccountCurrentResult {
                realm_id,
                governance_generation: 3,
                stream_heads: heads,
                entries: vec![],
            },
        );
        (scope, realm_head, cut)
    }

    #[test]
    fn complete_realm_and_circle_cuts_preserve_independent_heads_across_reload() {
        for circle in [false, true] {
            let (scope, head, cut) = current_cut(circle);
            let bytes = arkret_canonical::canonical_json_bytes(&cut).unwrap();
            let mut restored: MlsCreatorBootstrapCurrentCut =
                serde_json::from_slice(&bytes).unwrap();
            restored.current.stream_heads.reverse();
            restored.validate_absence_binding(&scope, 3, &head).unwrap();
        }
    }

    #[test]
    fn empty_incomplete_or_uncovered_cuts_never_prove_genesis_absence() {
        let (scope, head, cut) = current_cut(true);
        let mut altered = cut.clone();
        altered.baseline.complete = false;
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        altered.baseline.coverage.complete_for_authorized_streams = false;
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        altered.baseline.coverage.stream_heads.pop();
        altered.current.stream_heads.pop();
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut;
        altered.baseline.coverage.stream_heads.clear();
        altered.current.stream_heads.clear();
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
    }

    #[test]
    fn creator_cut_cannot_mix_generations_heads_realms_or_duplicate_coverage() {
        let (scope, head, cut) = current_cut(true);
        assert!(cut.validate_absence_binding(&scope, 4, &head).is_err());
        let mut altered = cut.clone();
        altered.current.stream_heads[1].stream_position += 1;
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        altered.baseline.coverage.stream_heads.push(head.clone());
        altered.current.stream_heads.push(head.clone());
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        altered = cut.clone();
        let mut other = current_cut(false).1;
        other.stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        };
        altered.baseline.coverage.stream_heads.push(other.clone());
        altered.current.stream_heads.push(other);
        assert!(altered.validate_absence_binding(&scope, 3, &head).is_err());
        let mut advanced_head = head;
        advanced_head.stream_position += 1;
        assert!(
            cut.validate_absence_binding(&scope, 3, &advanced_head)
                .is_err()
        );
    }

    #[test]
    fn an_exact_scope_mls_current_entry_is_a_winner_even_if_its_value_is_empty() {
        let (scope, head, mut cut) = current_cut(true);
        let entry = arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::MlsGroup {
                scope_ref: scope.clone(),
            },
            source_stream_ref: cut.current.stream_heads[1].stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: cut.current.stream_heads[1].commit_id.clone(),
                stream_position: 2,
            },
            value: json!({}),
        };
        cut.current.entries.push(entry);
        assert!(cut.validate_absence_binding(&scope, 3, &head).is_err());
    }

    fn accepted_create(
        circle: bool,
    ) -> (MlsCreatorBootstrapIntent, MlsCreatorBootstrapAcceptedCreate) {
        use arkret_wire::{
            Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedObjectSignature,
            DetachedSignatureAlgorithm, DetachedSignatureContext, RealmAuthorityBundle,
            RealmAuthorityCurrentAssertion, RealmCommit, RealmCommitAuthorityRef, RealmCommitId,
        };

        let intent = fixture_intent(circle);
        let root_event = scope_create_event(fixture_intent(false).signed_scope_create_unit())
            .unwrap()
            .clone();
        let realm_id = root_event.realm_id.clone();
        let service = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let timestamp = root_event.created_at;
        // These detached signatures exercise shape bindings only. No test
        // claims independently verified acceptance from this synthetic bundle.
        let signature = |context| DetachedObjectSignature {
            context,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:web:station.example#key").unwrap(),
            signed_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            created_at: timestamp,
            sig: Base64UrlString::new("AA").unwrap(),
        };
        let root_commit = RealmCommit {
            commit_id: RealmCommitId::new(
                "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            )
            .unwrap(),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: root_event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                root_event.event_id.clone(),
            ),
            committed_at: timestamp,
            signature: signature(DetachedSignatureContext::RealmCommit),
        };
        let head = CommitStreamHead {
            stream_ref: root_commit.stream_ref.clone(),
            stream_position: 0,
            commit_id: root_commit.commit_id.clone(),
        };
        let root = RealmAuthorityBundle {
            realm_id: realm_id.clone(),
            genesis_event: root_event,
            genesis_commit: root_commit.clone(),
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: service.clone(),
            current_route_record: json!({}),
            realm_stream_head: head.clone(),
            bundle_issued_at: timestamp,
            current_assertion: RealmAuthorityCurrentAssertion {
                realm_id,
                current_generation: 0,
                current_service_id: service,
                last_handoff_ref: None,
                realm_stream_head: head,
                nonce: Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
                expires_at: timestamp + chrono::TimeDelta::minutes(5),
                signature: signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
            },
        };
        let event = scope_create_event(intent.signed_scope_create_unit())
            .unwrap()
            .clone();
        let mut commit = root_commit;
        if circle {
            commit.previous_commit_ref = Some(commit.commit_id.clone());
            commit.commit_id =
                RealmCommitId::new("ak:realm_commit:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap();
            commit.stream_position = 1;
            commit.event_ref = event.event_id.clone();
        }
        let accepted = MlsCreatorBootstrapAcceptedCreate::new(
            &intent,
            event,
            commit,
            arkret_canonical::DigestSuite::Sha256,
            root,
        )
        .unwrap();
        (intent, accepted)
    }

    fn absence_snapshot(
        accepted: &MlsCreatorBootstrapAcceptedCreate,
    ) -> arkret_wire::RealmStateSnapshot {
        let root = accepted.authority_root();
        let head = root.realm_stream_head.clone();
        let mut signature = root.current_assertion.signature.clone();
        signature.context = arkret_wire::DetachedSignatureContext::RealmSnapshot;
        // Structural fixture only; the host must authenticate this carrier.
        arkret_wire::RealmStateSnapshot {
            snapshot_id: arkret_wire::RealmSnapshotId::from_digest([3; 32]),
            realm_id: root.realm_id.clone(),
            governance_generation: root.current_generation,
            visible_stream_heads: vec![head.clone()],
            current_state_entries: vec![],
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: head.stream_ref,
                    oldest_position: 0,
                }],
            },
            created_at: root.bundle_issued_at,
            signature,
        }
    }

    #[test]
    fn creator_record_acceptance_roundtrips_without_replacing_its_cut() {
        let (intent, accepted) = accepted_create(false);
        let snapshot = absence_snapshot(&accepted);
        let mut record = MlsCreatorBootstrapRecord::new(intent).unwrap();
        record
            .accept_realm(accepted.clone(), snapshot.clone())
            .unwrap();
        record
            .accept_realm(accepted.clone(), snapshot.clone())
            .unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        let restored: MlsCreatorBootstrapRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, record);
        restored.validate().unwrap();
        let mut changed = snapshot;
        changed.created_at += chrono::TimeDelta::seconds(1);
        assert!(record.accept_realm(accepted, changed).is_err());
        assert_eq!(record, restored);
    }

    #[test]
    fn creator_record_unknown_or_incomplete_acceptance_keeps_intent_unchanged() {
        let (intent, accepted) = accepted_create(false);
        let snapshot = absence_snapshot(&accepted);
        let original = MlsCreatorBootstrapRecord::new(intent).unwrap();
        let mut missing = snapshot.clone();
        missing.visible_stream_heads.clear();
        let mut stale = snapshot.clone();
        stale.governance_generation += 1;
        let mut duplicate = snapshot.clone();
        duplicate
            .visible_stream_heads
            .push(duplicate.visible_stream_heads[0].clone());
        for invalid in [missing, stale, duplicate] {
            let mut record = original.clone();
            assert!(record.accept_realm(accepted.clone(), invalid).is_err());
            assert_eq!(record, original);
        }
        let mut changed = serde_json::to_value(&original).unwrap();
        changed["state"] = serde_json::json!("ready");
        assert!(serde_json::from_value::<MlsCreatorBootstrapRecord>(changed).is_err());
    }

    #[test]
    fn creator_circle_absence_cannot_borrow_its_parent_realm_head() {
        let (intent, accepted) = accepted_create(true);
        let parent_only = absence_snapshot(&accepted);
        assert!(
            validate_creator_genesis_absence_snapshot(&intent, &accepted, &parent_only).is_err()
        );
    }

    #[test]
    fn accepted_creation_keeps_its_exact_signed_event_and_parent_authorization_stream() {
        for circle in [false, true] {
            let (intent, accepted) = accepted_create(circle);
            let bytes = arkret_canonical::canonical_json_bytes(&accepted).unwrap();
            let restored: MlsCreatorBootstrapAcceptedCreate =
                serde_json::from_slice(&bytes).unwrap();
            restored.validate_binding(&intent).unwrap();
            assert_eq!(accepted, restored);
            if circle {
                assert_ne!(
                    restored.covering_commit.stream_ref,
                    arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None)
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn accepted_creation_cannot_rebind_proof_commit_scope_or_digest_suite() {
        let (intent, accepted) = accepted_create(true);
        assert!(
            MlsCreatorBootstrapAcceptedCreate::new(
                &intent,
                accepted.accepted_event.clone(),
                accepted.covering_commit.clone(),
                arkret_canonical::DigestSuite::Blake3,
                accepted.authority_root.clone()
            )
            .is_err()
        );
        let mut altered = accepted.clone();
        altered
            .accepted_event
            .producer_proof
            .as_mut()
            .unwrap()
            .jws
            .push('x');
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted.clone();
        altered.covering_commit.stream_ref =
            arkret_wire::CommitStreamRef::from_scope(intent.effective_scope(), None).unwrap();
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted.clone();
        altered.digest_suite = arkret_canonical::DigestSuite::Blake3;
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted.clone();
        altered.covering_commit.event_ref = fixture_intent(false).scope_create_event_id;
        assert!(altered.validate_binding(&intent).is_err());
        altered = accepted;
        altered.covering_commit.governance_generation = 1;
        assert!(altered.validate_binding(&intent).is_err());
    }
}
