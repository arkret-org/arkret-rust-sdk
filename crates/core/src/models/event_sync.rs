//! Event frontier, submission, subscription, and snapshot wire models.
//!
//! The frontier / submit DTOs (`FrontierPeerRole`, the
//! `EventsFrontier*` family, `FederationServiceBindingRef`,
//! `EventsSubmitFederationRequestBody`) migrated to
//! `arkret-models-collaboration` (`event_sync`, re-exported below). The
//! `federation_minimal` reducer-profile digest constant/fn stay here because
//! they resolve against `arkret_policy::generated::profiles` — a higher layer
//! than the collaboration data crate, which may not depend on it.

pub use arkret_models_collaboration::event_sync::*;

pub const FEDERATION_MINIMAL_PROFILE_ID: &str = "ak.profile.federation_minimal.v1";
pub const FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST: &str =
    arkret_policy::generated::profiles::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST;

pub fn federation_minimal_reducer_profile_digest() -> &'static str {
    FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Did, EventId, Hash};

    #[test]
    fn federation_minimal_reducer_profile_digest_is_well_formed() {
        assert_eq!(
            FEDERATION_MINIMAL_PROFILE_ID,
            "ak.profile.federation_minimal.v1"
        );
        assert_eq!(
            federation_minimal_reducer_profile_digest(),
            FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST
        );
        assert_eq!(
            arkret_policy::generated::profiles::reducer_profile_digest(
                FEDERATION_MINIMAL_PROFILE_ID
            ),
            Some(FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST)
        );
        assert_eq!(
            Hash::new(FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST)
                .unwrap()
                .as_str(),
            FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST
        );
    }

    #[test]
    fn actor_frontier_distinguishes_empty_and_non_empty_histories() {
        let actor_id = Did::new("did:web:alice.example").unwrap();
        ActorFrontierView {
            actor_id: actor_id.clone(),
            actor_seq: 0,
            event_id: None,
        }
        .validate()
        .unwrap();
        ActorFrontierView {
            actor_id: actor_id.clone(),
            actor_seq: 1,
            event_id: Some(EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap()),
        }
        .validate()
        .unwrap();

        assert!(
            ActorFrontierView {
                actor_id,
                actor_seq: 1,
                event_id: None,
            }
            .validate()
            .is_err()
        );
    }
}
