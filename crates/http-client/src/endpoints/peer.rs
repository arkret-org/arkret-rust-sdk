//! Typed service-authenticated peer query endpoints.

use arkret_models_crypto::keys::{PeerKeysQueryOutcome, PeerKeysQueryRequestBody};
use arkret_wire::PATH_PEER_KEYS_QUERY;

use crate::{Client, Result};

impl Client {
    /// Read one destination Station's device directory and published prekey
    /// bundles on behalf of a local account (`device-lifecycle.md` §8.2.1).
    ///
    /// The requesting Station authenticates itself; it never forwards the
    /// client's SessionGrant or DPoP proof. Rows come back with the origin's own
    /// attestation, and a fetch that fails is a `device_directory_unavailable`
    /// failure row rather than an omitted row or an empty device set.
    pub async fn peer_keys_query(
        &self,
        request: &PeerKeysQueryRequestBody,
    ) -> Result<PeerKeysQueryOutcome> {
        request.validate()?;
        request.destination_station_id()?;
        let outcome: PeerKeysQueryOutcome = self.post(PATH_PEER_KEYS_QUERY, request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }
}

impl Client {
    /// Service-authenticated self-only Watch query to the verified governor.
    /// The caller supplies its fresh nonce-bound governing generation.
    pub async fn peer_strand_watch_current(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        expected_governance_generation: u64,
    ) -> Result<arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome>
    {
        use arkret_models_collaboration::strand_watch_operations::{
            PEER_STRAND_WATCH_CURRENT_PATH, StrandWatchCurrentOutcome,
        };
        request.validate()?;
        let outcome: StrandWatchCurrentOutcome =
            self.post(PEER_STRAND_WATCH_CURRENT_PATH, request).await?;
        outcome
            .validate_for_generation(request, expected_governance_generation)
            .map_err(|error| crate::Error::Protocol(error.to_owned()))?;
        Ok(outcome)
    }
}
