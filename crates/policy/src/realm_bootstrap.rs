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

use arkret_wire::{Did, Error, Event, EventId, EventKind, Hash, REALM_AUTHORITY_ROOT_CELL, Result};
use serde::{Deserialize, Serialize};

/// Closed set of initial Realm facets that may follow the create Event.
pub fn is_realm_bootstrap_followup_kind(kind: &str) -> bool {
    matches!(
        kind,
        EventKind::MEMBER_STATE
            | EventKind::REALM_HISTORY_VISIBILITY
            | EventKind::REALM_HISTORY_SHARING_POLICY
            | EventKind::REALM_POLICY_BUNDLE
            | EventKind::REALM_DISCOVERY
            | EventKind::REALM_JOIN_RULE
            | EventKind::REALM_DELIVERY_BINDING_POLICY
            | EventKind::REALM_PLAINTEXT_VISIBLE_SERVICES
            | EventKind::REALM_ALIAS
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
    pub controller_id: Did,
    pub controller_epoch: u64,
    pub authority_generation: u64,
    pub capability_action_registry_digest: Hash,
}

impl RealmAuthorityRootValue {
    /// Derive the genesis value from an accepted `ak.realm.create` payload.
    ///
    /// Both inputs come from the signed payload: the receiver copies the
    /// author's registry digest verbatim instead of substituting its own
    /// embedded snapshot, because the digest is a `state_root` leaf input and
    /// inferring it would fork genesis state across software versions.
    pub fn genesis(controller_id: Did, capability_action_registry_digest: Hash) -> Self {
        Self {
            controller_id,
            controller_epoch: 0,
            authority_generation: 0,
            capability_action_registry_digest,
        }
    }

    /// True when this value is a well-formed genesis root for `created_by`.
    pub fn is_genesis_for(&self, created_by: &str) -> bool {
        self.controller_id.as_str() == created_by
            && self.controller_epoch == 0
            && self.authority_generation == 0
    }
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

/// Build the `authorization_ref` value for a staged genesis-batch root proof.
///
/// The create Event id is not carried in the ref itself; it is the batch
/// predecessor the Event must descend from. Returning it here keeps callers
/// from inventing their own binding.
pub fn staged_root_authorization(create: &Event) -> Result<RealmAuthorityRootProof> {
    if create.kind.as_str() != EventKind::REALM_CREATE {
        return Err(Error::Protocol(
            "staged Realm authority-root proof must bind an ak.realm.create Event".to_owned(),
        ));
    }
    Ok(RealmAuthorityRootProof::StagedGenesis {
        create_event_id: create.event_id.clone(),
    })
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
    pub realm_id: String,
    pub actor_id: String,
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
    if create.kind.as_str() != EventKind::REALM_CREATE {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    // PCR bootstrap is a distinct, exactly-two-Event protocol unit.
    if events
        .get(1)
        .is_some_and(|event| event.kind.as_str() == EventKind::DEVICE_AUTHORIZE)
    {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    let actor_id = create.actor_id.as_str();
    let realm_id = create.realm_id.as_str();
    let object = create
        .payload
        .get("object")
        .and_then(serde_json::Value::as_object)
        .ok_or(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap)?;
    if object.get("created_by").and_then(serde_json::Value::as_str) != Some(actor_id) {
        return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
    }
    let authority_root = genesis_authority_root(object, actor_id)?;

    for followup in &events[1..] {
        if followup.actor_id.as_str() != actor_id
            || followup.realm_id.as_str() != realm_id
            || !is_realm_bootstrap_followup_kind(followup.kind.as_str())
        {
            return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
        }
        let descriptor = followup.kind.descriptor();
        if descriptor.is_some_and(|descriptor| {
            descriptor.reducer_input && descriptor.lattice == Some("cas_register")
        }) {
            arkret_schema::validate_registered_cell_writes_in_context(
                followup,
                arkret_schema::EventCellContractContext::OrdinaryRealmBootstrap,
            )
            .map_err(|error| match error.reason_code() {
                "plane_cross_write" => RealmBootstrapValidationError::PlaneCrossWrite,
                _ => RealmBootstrapValidationError::EffectsPayloadMismatch,
            })?;
        }
    }
    Ok(ValidatedRealmBootstrap {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
        authority_root,
    })
}

/// Derive and check the registered authority-root value of a create payload.
fn genesis_authority_root(
    object: &serde_json::Map<String, serde_json::Value>,
    actor_id: &str,
) -> std::result::Result<RealmAuthorityRootValue, RealmBootstrapValidationError> {
    let digest = object
        .get("capability_action_registry_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(RealmBootstrapValidationError::RealmAuthorityRootMissing)?;
    let digest = Hash::new(digest.to_owned())
        .map_err(|_| RealmBootstrapValidationError::RealmAuthorityRootConflict)?;
    let controller_id = Did::new(actor_id)
        .map_err(|_| RealmBootstrapValidationError::RealmAuthorityRootConflict)?;
    Ok(RealmAuthorityRootValue::genesis(controller_id, digest))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Hlc, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:01964120-0000-7000-8000-000000000000";
    const ACTOR: &str = "did:web:founder.example";
    const DIGEST: &str = "sha256:9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a";

    fn event(kind: &str, payload: serde_json::Value) -> Event {
        Event::new_at(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).unwrap(),
            },
            Did::new(ACTOR).unwrap(),
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            payload,
            chrono::Utc::now(),
        )
        .unwrap()
    }

    fn create() -> Event {
        event(
            EventKind::REALM_CREATE,
            json!({"object": {
                "created_by": ACTOR,
                "capability_action_registry_digest": DIGEST
            }}),
        )
    }

    fn history_sharing_followup() -> Event {
        // The producer no longer states its writes: this kind's registry
        // contract projects the set onto
        // ak:cell:ak.component.realm.history_sharing_policy.v1:null from the
        // payload alone, which is exactly what
        // validate_realm_bootstrap_unit re-derives for cas_register follow-ups.
        event(
            EventKind::REALM_HISTORY_SHARING_POLICY,
            json!({"value": {"version": 1}}),
        )
    }

    #[test]
    fn accepts_create_with_registered_authority_root_and_followup() {
        let events = vec![create(), history_sharing_followup()];
        let result = validate_realm_bootstrap_unit(&events);
        let bootstrap = result.expect("bootstrap accepted");
        assert!(bootstrap.authority_root.is_genesis_for(ACTOR));
        assert_eq!(
            bootstrap
                .authority_root
                .capability_action_registry_digest
                .as_str(),
            DIGEST
        );
    }

    #[test]
    fn rejects_create_without_registry_basis() {
        let mut create = create();
        create
            .payload
            .get_mut("object")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("capability_action_registry_digest");
        assert_eq!(
            validate_realm_bootstrap_unit(&[create]),
            Err(RealmBootstrapValidationError::RealmAuthorityRootMissing)
        );
    }

    #[test]
    fn rejects_create_with_malformed_registry_basis() {
        let mut create = create();
        create
            .payload
            .get_mut("object")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "capability_action_registry_digest".to_owned(),
                json!("not-a-digest"),
            );
        assert_eq!(
            validate_realm_bootstrap_unit(&[create]),
            Err(RealmBootstrapValidationError::RealmAuthorityRootConflict)
        );
    }

    #[test]
    fn rejects_legacy_founding_grant_slot() {
        // The old genesis shape put a self ak.capability.grant right after
        // create. It is not a bootstrap follow-up kind, so it now fails as an
        // out-of-order unit rather than being recognised as an authority root.
        let legacy = event(
            EventKind::CAPABILITY_GRANT,
            json!({"grant_id": "ak:grant:01964120-0000-7000-8000-000000000001"}),
        );
        assert_eq!(
            validate_realm_bootstrap_unit(&[create(), legacy]),
            Err(RealmBootstrapValidationError::OutOfOrderBootstrap)
        );
    }

    #[test]
    fn genesis_root_value_is_controller_epoch_and_generation_zero() {
        let value = RealmAuthorityRootValue::genesis(
            Did::new(ACTOR).unwrap(),
            Hash::new(DIGEST.to_owned()).unwrap(),
        );
        assert_eq!(value.controller_epoch, 0);
        assert_eq!(value.authority_generation, 0);
        assert!(!value.is_genesis_for("did:web:other.example"));
    }

    #[test]
    fn staged_root_authorization_binds_the_create_event() {
        let create = create();
        let proof = staged_root_authorization(&create).unwrap();
        assert_eq!(
            proof,
            RealmAuthorityRootProof::StagedGenesis {
                create_event_id: create.event_id.clone()
            }
        );
        assert_eq!(proof.authorization_ref(), REALM_AUTHORITY_ROOT_CELL);
        assert!(staged_root_authorization(&history_sharing_followup()).is_err());
    }
}
