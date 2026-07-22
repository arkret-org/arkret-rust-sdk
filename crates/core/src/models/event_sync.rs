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
    use crate::canonical::DigestSuite;
    use crate::{Did, EventId, Hash, RealmId};

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
    fn realm_actor_frontier_distinguishes_empty_and_seq_zero_histories() {
        let actor_id = Did::new("did:web:alice.example").unwrap();
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        RealmActorFrontierView::new(
            realm_id.clone(),
            actor_id.clone(),
            0,
            Vec::new(),
            DigestSuite::Sha256,
        )
        .unwrap();
        RealmActorFrontierView::new(
            realm_id.clone(),
            actor_id.clone(),
            1,
            vec![EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap()],
            DigestSuite::Sha256,
        )
        .unwrap();

        assert!(
            RealmActorFrontierView::new(realm_id, actor_id, 1, Vec::new(), DigestSuite::Sha256,)
                .is_err()
        );
    }

    #[test]
    fn realm_actor_frontier_digest_matches_the_spec_vector() {
        let frontier = RealmActorFrontierView::new(
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            43,
            vec![
                EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap(),
                EventId::new("ak:event:01904100-0000-7000-8000-000000000002").unwrap(),
            ],
            DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(
            frontier.frontier_digest.as_str(),
            "sha256:4f928af58951a0a04f532b272fe6c45b371d33e932d0a15a8df84725a5efe1cf"
        );
    }
}
