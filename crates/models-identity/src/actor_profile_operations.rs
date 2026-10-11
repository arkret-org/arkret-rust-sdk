//! Authorized shared-Realm projection of another principal's global Actor Profile.
//!
//! A global profile Event lives in its owner's Principal Control Realm, so a
//! co-member cannot reach it through an ordinary Realm-scoped read and must not
//! reach it through a cross-principal actor selector. This operation is the only
//! outward carrier for that PCR-resident fact.

use arkret_wire::{
    AccountId, AccountStatusRecordId, ActorId, ActorStatus, Event, RealmCommit, RealmId,
};
use serde::{Deserialize, Serialize};

use crate::actor_profile::ActorProfile;

/// Upper bound on actors resolvable in one request.
pub const ACTOR_PROFILE_RESOLVE_MAX_ACTORS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ActorProfileResolveRequest {
    /// Shared Collaboration Realm establishing the relationship.
    ///
    /// A Principal Control Realm must not be used: PCR co-membership is the
    /// owner's own devices, which would make this a self-read wearing an
    /// outward shape.
    pub realm_id: RealmId,
    pub actor_ids: Vec<ActorId>,
}

impl ActorProfileResolveRequest {
    pub fn new(realm_id: RealmId, actor_ids: Vec<ActorId>) -> Self {
        Self {
            realm_id,
            actor_ids,
        }
    }

    /// Reject the locally decidable selector shapes before a round trip.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.actor_ids.is_empty() {
            return Err(arkret_wire::WireError::Protocol(
                "actor profile resolve requires at least one actor".to_owned(),
            ));
        }
        if self.actor_ids.len() > ACTOR_PROFILE_RESOLVE_MAX_ACTORS {
            return Err(arkret_wire::WireError::Protocol(format!(
                "actor profile resolve exceeds {ACTOR_PROFILE_RESOLVE_MAX_ACTORS} actors"
            )));
        }
        let mut sorted = self.actor_ids.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != self.actor_ids.len() {
            return Err(arkret_wire::WireError::Protocol(
                "actor profile resolve actor_ids must be unique".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One actor's current global profile, the exact accepted Event sourcing it
/// and that Event's covering RealmCommit in the owner's PCR stream.
///
/// The Event and Commit are provenance for the authenticated Station
/// projection. They do not prove complete causal history or grant
/// authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolvedActorProfile {
    pub actor_id: ActorId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub actor_profile: ActorProfile,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile_commit: RealmCommit,
    /// Present only when the Station holds a verified AccountStatusRecord for
    /// this exact account; absence means unknown, never `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_status: Option<AccountStatusProjection>,
}

/// `actor-profile-operations.schema.json#/$defs/account_status_projection`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusProjection {
    pub account_id: AccountId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub status: ActorStatus,
    pub status_seq: u64,
    pub account_status_record_id: AccountStatusRecordId,
}

/// Per-actor failure reason.
///
/// Deliberately single-valued: unknown actor, actor without an accepted
/// profile, non-member actor and unauthorized caller are indistinguishable, so
/// the operation cannot probe membership or account existence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ActorProfileResolveFailureReason {
    ProfileUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ActorProfileResolveFailure {
    pub actor_id: ActorId,
    pub reason: ActorProfileResolveFailureReason,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ActorProfileResolveOutcome {
    pub profiles: Vec<ResolvedActorProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<ActorProfileResolveFailure>>,
}

impl ActorProfileResolveOutcome {
    /// Every requested actor must appear exactly once across `profiles` and
    /// `failures`, so a caller cannot distinguish an omitted actor from a
    /// withheld one.
    pub fn validate_covers(&self, requested: &[ActorId]) -> arkret_wire::Result<()> {
        let mut seen: Vec<&ActorId> = self
            .profiles
            .iter()
            .map(|row| &row.actor_id)
            .chain(self.failures.iter().flatten().map(|row| &row.actor_id))
            .collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return Err(arkret_wire::WireError::Protocol(
                "actor profile resolve outcome reports an actor twice".to_owned(),
            ));
        }
        let mut expected: Vec<&ActorId> = requested.iter().collect();
        expected.sort();
        if seen != expected {
            return Err(arkret_wire::WireError::Protocol(
                "actor profile resolve outcome does not account for every requested actor"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}
