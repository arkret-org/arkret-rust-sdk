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
