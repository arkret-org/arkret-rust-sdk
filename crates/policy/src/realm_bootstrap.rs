//! Ordinary Realm bootstrap batch validation and Realm authority root.
//!
//! `ak.realm.create` is not an independently committable Event.  The wire
//! unit is the ordered batch `create -> closed followups`.  Keeping that shape
//! here prevents clients and servers from growing separate kind allowlists or
//! interpreting genesis authority differently.
//!
//! Genesis authority is not a per-person grant.  `ak.realm.create` registers a
//! singleton `ak.component.realm.authority_root.v1` cell whose current
//! controller holds effective `ak.realm.owner`
//! (`models/realm-and-space.md` section 2.5).

use arkret_event_draft::{EventIntent, EventPayloadExt, EventSpec, TypedEventDraft};
use arkret_models_collaboration::events_payloads::{
    RealmAuthorityResetPayload, RealmCreatePayload, RealmOwnerTransferPayload, RealmProfile,
    RealmPurpose,
};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_wire::{
    ActorId, AuthorizationRef, CellRef, Event, EventId, EventKind, PredicateOp,
    REALM_AUTHORITY_ROOT_CELL, RealmId, Result, ScopeRef, WireError, event_spec,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Closed set of initial Realm facets that may follow the create Event.
pub fn is_realm_bootstrap_followup_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::RealmProfile
            | EventKind::MemberState
            | EventKind::RealmHistoryAccess
            | EventKind::RealmPolicyBundle
            | EventKind::RealmDiscovery
            | EventKind::RealmJoinRule
            | EventKind::RealmPlaintextVisibleServices
            | EventKind::RealmAlias
    )
}

/// Canonical value of the Realm authority-root cell.
///
/// Field order follows the registered `value_projection` in
/// `contract-registry.json`; the JCS bytes of this struct are a `state_root`
/// leaf preimage, so the order is wire-significant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityRootValue {
    pub controller_actor_id: ActorId,
    pub controller_epoch: u64,
    pub authority_generation: u64,
}

impl RealmAuthorityRootValue {
    /// Derive the genesis value from an accepted `ak.realm.create` payload.
    pub fn genesis(controller_actor_id: ActorId) -> Self {
        Self {
            controller_actor_id,
            controller_epoch: 0,
            authority_generation: 0,
        }
    }

    /// True when this value is a well-formed genesis root for `created_by`.
    pub fn is_genesis_for(&self, created_by: &ActorId) -> bool {
        &self.controller_actor_id == created_by
            && self.controller_epoch == 0
            && self.authority_generation == 0
    }
}

/// Draft a Realm authority-root write with its mandatory root authorization.
///
/// This returns an [`EventIntent`], not an authored Event: the actor-chain
/// position and HLC belong to whoever submits it, and inventing placeholders
/// here is what used to hand callers an `event_id` that authoring would move.
fn build_realm_authority_intent<K: EventSpec>(
    scope_ref: ScopeRef,
    actor_id: ActorId,
    created_at: DateTime<Utc>,
    payload: K::Payload,
) -> Result<EventIntent> {
    TypedEventDraft::<K>::new(scope_ref, actor_id, payload)
        .map_err(|error| WireError::Protocol(error.to_string()))?
        .with_authorization_ref(
            AuthorizationRef::new(REALM_AUTHORITY_ROOT_CELL)
                .expect("realm authority-root constant must be a valid authorization reference"),
        )
        .into_intent(created_at)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

/// Build an unsigned `ak.realm.owner.transfer` Event with the mandatory root
/// authorization reference.
pub fn build_realm_owner_transfer_intent(
    scope_ref: ScopeRef,
    actor_id: ActorId,
    created_at: DateTime<Utc>,
    payload: RealmOwnerTransferPayload,
) -> Result<EventIntent> {
    if scope_ref.realm_id() != &payload.realm_id
        || !payload
            .expected_state_digest
            .as_str()
            .starts_with("sha256:")
    {
        return Err(WireError::Protocol(
            "schema_violation: invalid Realm owner transfer payload".to_owned(),
        ));
    }
    let proof = serde_json::to_value(&payload.successor_acceptance)?;
    if match proof {
        serde_json::Value::String(value) => value.is_empty(),
        serde_json::Value::Object(value) => value.is_empty(),
        _ => true,
    } {
        return Err(WireError::Protocol(
            "schema_violation: successor_acceptance must be non-empty".to_owned(),
        ));
    }
    build_realm_authority_intent::<event_spec::RealmOwnerTransfer>(
        scope_ref, actor_id, created_at, payload,
    )
}

/// Build an unsigned destructive `ak.realm.authority.reset` Event.
pub fn build_realm_authority_reset_intent(
    scope_ref: ScopeRef,
    actor_id: ActorId,
    created_at: DateTime<Utc>,
    payload: RealmAuthorityResetPayload,
) -> Result<EventIntent> {
    if scope_ref.realm_id() != &payload.realm_id
        || payload.destructive_confirmation != arkret_wire::event_kind_str::REALM_AUTHORITY_RESET
        || !payload
            .expected_state_digest
            .as_str()
            .starts_with("sha256:")
    {
        return Err(WireError::Protocol(
            "schema_violation: invalid Realm authority reset payload".to_owned(),
        ));
    }
    build_realm_authority_intent::<event_spec::RealmAuthorityReset>(
        scope_ref, actor_id, created_at, payload,
    )
}

/// How an Event proves it speaks for the Realm authority root.
///
/// The two forms are not interchangeable: a staged proof exists only while the
/// genesis batch is being evaluated and no accepted Seal covers the cell yet,
/// and an accepted-Seal proof is the only form that survives outside that unit.
/// Accepting either one in the other's context would let a genesis-window
/// credential be replayed for the lifetime of the Realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmAuthorityRootProof {
    /// Valid only inside the atomic genesis unit, bound to the same batch's
    /// `ak.realm.create` Event.
    StagedGenesis { create_event_id: EventId },
    /// Inclusion proof of the registered cell under an accepted Seal.
    AcceptedSeal,
}

impl RealmAuthorityRootProof {
    /// The `authorization_ref` an Event carries for either proof form.
    ///
    /// The wire ref is the same closed constant in both cases; which proof the
    /// reducer resolves is decided by admission context, exactly like the rest
    /// of the bootstrap follow-up whitelist.
    pub const fn authorization_ref(&self) -> &'static str {
        REALM_AUTHORITY_ROOT_CELL
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmBootstrapValidationError {
    NotOrdinaryRealmBootstrap,
    RealmAuthorityRootMissing,
    RealmAuthorityRootConflict,
    OutOfOrderBootstrap,
    EffectsPayloadMismatch,
    PlaneCrossWrite,
}

impl RealmBootstrapValidationError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::NotOrdinaryRealmBootstrap => "not_ordinary_realm_bootstrap",
            Self::RealmAuthorityRootMissing => "realm_authority_root_missing",
            Self::RealmAuthorityRootConflict => "realm_authority_root_conflict",
            Self::OutOfOrderBootstrap => "out_of_order_bootstrap",
            Self::EffectsPayloadMismatch => "effects_payload_mismatch",
            Self::PlaneCrossWrite => "plane_cross_write",
        }
    }
}

impl std::fmt::Display for RealmBootstrapValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for RealmBootstrapValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRealmBootstrap {
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub authority_root: RealmAuthorityRootValue,
}

/// Validate the complete ordinary (non-PCR) Realm genesis transaction.
///
/// Envelope schema/proof validation remains the caller's responsibility. This
/// function owns the cross-Event shape and the genesis authority-root
/// invariants.
pub fn validate_realm_bootstrap_unit(
    events: &[Event],
) -> std::result::Result<ValidatedRealmBootstrap, RealmBootstrapValidationError> {
    let Some(create) = events.first() else {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    };
    if create.kind != EventKind::RealmCreate {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    // PCR bootstrap is a distinct, exactly-two-Event protocol unit.
    if events
        .get(1)
        .is_some_and(|event| event.kind == EventKind::DeviceAuthorize)
    {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    let actor_id = &create.actor_id;
    let realm_id = create.realm_id.as_str();
    let object = create
        .payload
        .get("object")
        .and_then(serde_json::Value::as_object)
        .ok_or(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap)?;
    let authority_root = genesis_authority_root(object, actor_id)?;
    let direct_conversation = object
        .get("schema_refs")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|profiles| {
            profiles.iter().any(|profile| {
                profile.as_str() == Some(arkret_wire::ProfileId::DIRECT_CONVERSATION_REALM_V1)
            })
        });
    if direct_conversation {
        let exact: [&Event; 4] = events
            .iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| RealmBootstrapValidationError::OutOfOrderBootstrap)?;
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingPlan::from_events(exact)
            .map_err(|_| RealmBootstrapValidationError::OutOfOrderBootstrap)?;
        let direct_roles = create
            .refs
            .iter()
            .filter(|reference| {
                reference.critical
                    && matches!(
                        reference.role.as_str(),
                        "direct_conversation_basis" | "direct_conversation_agent_provision"
                    )
            })
            .collect::<Vec<_>>();
        if direct_roles.len() != 1 {
            return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
        }
        return Ok(ValidatedRealmBootstrap {
            realm_id: create.realm_id.clone(),
            actor_id: create.actor_id.clone(),
            authority_root,
        });
    }
    let payload: RealmCreatePayload = create
        .typed_payload::<event_spec::RealmCreate>()
        .map_err(|_| RealmBootstrapValidationError::NotOrdinaryRealmBootstrap)?;
    if payload.object.purpose != RealmPurpose::Collaboration {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    let mut previous_slot = 0_usize;
    let mut present = std::collections::HashSet::new();
    for followup in &events[1..] {
        if &followup.actor_id != actor_id
            || followup.realm_id.as_str() != realm_id
            || !is_realm_bootstrap_followup_kind(&followup.kind)
        {
            return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
        }
        let slot = match &followup.kind {
            EventKind::RealmProfile => 1,
            EventKind::RealmPolicyBundle => 2,
            EventKind::RealmJoinRule => 3,
            EventKind::RealmHistoryAccess => 4,
            EventKind::RealmDiscovery => 5,
            EventKind::RealmAlias => 6,
            EventKind::RealmPlaintextVisibleServices => 7,
            EventKind::MemberState => 8,
            _ => return Err(RealmBootstrapValidationError::OutOfOrderBootstrap),
        };
        if slot <= previous_slot || !present.insert(followup.kind.clone()) {
            return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
        }
        previous_slot = slot;
        match &followup.kind {
            EventKind::RealmProfile => {
                let profile: RealmProfile = followup
                    .typed_payload::<event_spec::RealmProfile>()
                    .map_err(|_| RealmBootstrapValidationError::EffectsPayloadMismatch)?;
                profile
                    .to_value()
                    .map_err(|_| RealmBootstrapValidationError::EffectsPayloadMismatch)?;
            }
            EventKind::MemberState => {
                let payload: MembershipPayload = followup
                    .typed_payload::<event_spec::MemberState>()
                    .map_err(|_| RealmBootstrapValidationError::EffectsPayloadMismatch)?;
                if &payload.member_id != actor_id
                    || payload.membership != MembershipPayloadState::Join
                    || payload.realm_id.as_ref().map(RealmId::as_str) != Some(realm_id)
                {
                    return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
                }
                let actor_key = actor_id
                    .canonical_key()
                    .map_err(|_| RealmBootstrapValidationError::OutOfOrderBootstrap)?;
                let creator_subject = arkret_wire::composite_subject(&[actor_key])
                    .map_err(|_| RealmBootstrapValidationError::OutOfOrderBootstrap)?;
                let creator_cell = CellRef::new(format!(
                    "ak:cell:ak.component.member.state.v1:{creator_subject}"
                ))
                .map_err(|_| RealmBootstrapValidationError::OutOfOrderBootstrap)?;
                let genesis_head_eq_registered = arkret_schema::realm_bootstrap_slot_for_condition(
                    arkret_schema::RealmBootstrapProfile::OrdinaryCollaboration,
                    arkret_schema::RealmBootstrapCondition::SubjectIsGenesisActorAndMembershipIsJoin,
                )
                .is_some_and(|slot| {
                    slot.head_eq == Some(arkret_schema::RealmBootstrapHeadEq::Null)
                });
                if !genesis_head_eq_registered
                    || followup.preconditions.len() != 1
                    || followup.preconditions[0].cell_id != creator_cell
                    || followup.preconditions[0].predicate.op != PredicateOp::HeadEq
                    || followup.preconditions[0].predicate.value != Some(serde_json::Value::Null)
                {
                    return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
                }
            }
            _ => {}
        }
        // Every member of the closed bootstrap follow-up set is an active
        // reducer input. Validate its complete `cell_writes[]` contract. The
        // event-kind registry explicitly forbids the flattened
        // single-target aliases, so consulting descriptor.lattice here would
        // skip every migrated contract and turn bootstrap validation into a
        // no-op.
        arkret_schema::validate_registered_cell_writes_in_context(
            followup,
            arkret_schema::EventCellContractContext::OrdinaryRealmBootstrap,
            payload.object.digest_algorithm,
        )
        .map_err(|error| match error.reason_code() {
            "plane_cross_write" => RealmBootstrapValidationError::PlaneCrossWrite,
            _ => RealmBootstrapValidationError::EffectsPayloadMismatch,
        })?;
    }
    for required in [
        EventKind::RealmProfile,
        EventKind::RealmPolicyBundle,
        EventKind::RealmJoinRule,
        EventKind::RealmHistoryAccess,
        EventKind::RealmDiscovery,
        EventKind::MemberState,
    ] {
        if !present.contains(&required) {
            return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
        }
    }
    Ok(ValidatedRealmBootstrap {
        realm_id: create.realm_id.clone(),
        actor_id: create.actor_id.clone(),
        authority_root,
    })
}

/// Derive and check the registered authority-root value of a create payload.
fn genesis_authority_root(
    _object: &serde_json::Map<String, serde_json::Value>,
    actor_id: &ActorId,
) -> std::result::Result<RealmAuthorityRootValue, RealmBootstrapValidationError> {
    actor_id
        .validate()
        .map_err(|_| RealmBootstrapValidationError::RealmAuthorityRootConflict)?;
    Ok(RealmAuthorityRootValue::genesis(actor_id.clone()))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, DidCoreId, Hlc, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AS_LTHQu5UtXbAIUOgUFzEY5nFJzI1cgPvxODB_NnHSR";
    const ACTOR: &str = "ak:did_core:webvh:z6mkfixture";
    const STATION: &str = "ak:did_core:webvh:z6mkfixtureps";

    fn actor() -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(ACTOR).unwrap(),
            DidCoreId::new(STATION).unwrap(),
        ))
    }

    fn created_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-26T10:30:00.000Z")
            .expect("a canonical test timestamp")
            .with_timezone(&Utc)
    }

    fn event(kind: EventKind, payload: serde_json::Value) -> Event {
        arkret_wire::test_support::raw_event_at(
            kind.to_string(),
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).unwrap(),
            },
            DidCoreId::new(ACTOR).unwrap(),
            DidCoreId::new(STATION).unwrap(),
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            payload,
            Utc::now(),
        )
        .unwrap()
    }

    fn create() -> Event {
        event(
            EventKind::RealmCreate,
            json!({"object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1"],
                "reducer_profile": "ak.reducer.core.v1",
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "encryption_profile": "mls_rfc9420",
                "notary": {
                    "kind": "single_signer",
                    "signer": {
                        "actor_id": actor(),
                        "verification_method": "did:webvh:z6mkfixture:founder.example#key-1",
                        "key_kind": "ed25519_raw32",
                        "jose_algorithm": "Ed25519",
                        "frozen_public_key_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "frozen_public_key_digest": "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
                    }
                }
            }}),
        )
    }

    fn complete_unit() -> Vec<Event> {
        let mut events = vec![
            create(),
            event(
                EventKind::RealmProfile,
                json!({"schema": "ak.schema.realm_profile.v1", "title": "Realm"}),
            ),
            event(
                EventKind::RealmPolicyBundle,
                json!({"policy_revision": 1, "content_scheme": "mls_exporter_aead_v1"}),
            ),
            event(EventKind::RealmJoinRule, json!({"value": "invite"})),
            event(
                EventKind::RealmHistoryAccess,
                json!({"from": null, "to": "since_join"}),
            ),
            event(EventKind::RealmDiscovery, json!({"value": "invite_only"})),
            event(
                EventKind::MemberState,
                json!({
                    "realm_id": REALM,
                    "member_id": actor(),
                    "membership": "join"
                }),
            ),
        ];
        let actor_key = actor().canonical_key().unwrap();
        let creator_subject = arkret_wire::composite_subject(&[actor_key]).unwrap();
        events.last_mut().unwrap().preconditions = vec![arkret_wire::Precondition {
            cell_id: CellRef::new(format!(
                "ak:cell:ak.component.member.state.v1:{creator_subject}"
            ))
            .unwrap(),
            predicate: arkret_wire::Predicate {
                op: PredicateOp::HeadEq,
                value: Some(serde_json::Value::Null),
                values: None,
                predicate_id: None,
            },
        }];
        events
    }

    #[test]
    fn accepts_create_with_registered_authority_root_and_followup() {
        let events = complete_unit();
        let result = validate_realm_bootstrap_unit(&events);
        let bootstrap = result.expect("bootstrap accepted");
        assert!(bootstrap.authority_root.is_genesis_for(&actor()));
    }

    #[test]
    fn rejects_bootstrap_followup_routed_with_data_plane_basis() {
        let mut events = complete_unit();
        let followup = events.get_mut(1).unwrap();
        followup.seal_ref =
            Some(arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap());
        assert_eq!(
            validate_realm_bootstrap_unit(&events),
            Err(RealmBootstrapValidationError::PlaneCrossWrite)
        );
    }

    #[test]
    fn rejects_creator_member_with_wrong_subject() {
        let mut events = complete_unit();
        // A well-formed `did_core_id` that is simply a different actor. A bare
        // DID would fail the typed payload parse first and never reach the
        // subject comparison this test exists to pin.
        events.last_mut().unwrap().payload.insert(
            "member_id".to_owned(),
            json!(ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:other.example").unwrap(),
                DidCoreId::new(STATION).unwrap(),
            ))),
        );
        assert_eq!(
            validate_realm_bootstrap_unit(&events),
            Err(RealmBootstrapValidationError::OutOfOrderBootstrap)
        );
    }

    #[test]
    fn rejects_creator_member_that_claims_an_existing_join_head() {
        let mut events = complete_unit();
        events.last_mut().unwrap().preconditions[0].predicate.value = Some(json!("join"));
        assert_eq!(
            validate_realm_bootstrap_unit(&events),
            Err(RealmBootstrapValidationError::OutOfOrderBootstrap)
        );
    }

    #[test]
    fn rejects_direct_conversation_as_ordinary_bootstrap() {
        let mut events = complete_unit();
        events[0]
            .payload
            .get_mut("object")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert("purpose".to_owned(), json!("direct_conversation"));
        assert_eq!(
            validate_realm_bootstrap_unit(&events),
            Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap)
        );
    }

    #[test]
    fn genesis_root_value_is_controller_epoch_and_generation_zero() {
        let value = RealmAuthorityRootValue::genesis(actor());
        assert_eq!(value.controller_epoch, 0);
        assert_eq!(value.authority_generation, 0);
        assert!(!value.is_genesis_for(&ActorId::service(
            DidCoreId::new("ak:did_core:web:other.example").unwrap()
        )));
    }

    #[test]
    fn authority_transition_builders_stamp_the_root_authorization() {
        let scope = ScopeRef::Realm {
            realm_id: RealmId::new(REALM).unwrap(),
        };
        let actor = actor();
        let expected = format!("sha256:{}", "1".repeat(64));
        let successor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:successor.example").unwrap(),
            DidCoreId::new(STATION).unwrap(),
        ));
        let transfer: RealmOwnerTransferPayload = serde_json::from_value(json!({
            "realm_id": REALM,
            "expected_state_digest": expected,
            "patch": {"controller_actor_id": successor},
            "successor_acceptance": "detached-successor-proof"
        }))
        .unwrap();
        let intent =
            build_realm_owner_transfer_intent(scope.clone(), actor.clone(), created_at(), transfer)
                .unwrap();
        assert_eq!(intent.kind(), &EventKind::RealmOwnerTransfer);
        assert_eq!(
            intent.authorization_ref().map(AuthorizationRef::as_str),
            Some(REALM_AUTHORITY_ROOT_CELL)
        );

        let reset: RealmAuthorityResetPayload = serde_json::from_value(json!({
            "realm_id": REALM,
            "expected_state_digest": format!("sha256:{}", "2".repeat(64)),
            "destructive_confirmation": EventKind::RealmAuthorityReset
        }))
        .unwrap();
        let intent = build_realm_authority_reset_intent(scope, actor, created_at(), reset).unwrap();
        assert_eq!(intent.kind(), &EventKind::RealmAuthorityReset);
        assert_eq!(
            intent.authorization_ref().map(AuthorizationRef::as_str),
            Some(REALM_AUTHORITY_ROOT_CELL)
        );
    }

    #[test]
    fn reset_builder_rejects_missing_destructive_confirmation() {
        let payload: RealmAuthorityResetPayload = serde_json::from_value(json!({
            "realm_id": REALM,
            "expected_state_digest": format!("sha256:{}", "4".repeat(64)),
            "destructive_confirmation": "RESET"
        }))
        .unwrap();
        assert!(
            build_realm_authority_reset_intent(
                ScopeRef::Realm {
                    realm_id: RealmId::new(REALM).unwrap()
                },
                actor(),
                created_at(),
                payload,
            )
            .is_err()
        );
    }
}
