//! Typed service-authenticated peer query endpoints.

use arkret_models_collaboration::http_bodies::{
    PeerEventsResolveOutcome, PeerEventsResolveRequestBody, PeerEventsSiblingPositionsOutcome,
    PeerEventsSiblingPositionsRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_models_crypto::keys::{PeerKeysQueryOutcome, PeerKeysQueryRequestBody};
use arkret_wire::{
    DeviceRevocationGateCheckOutcome, DeviceRevocationGateCheckRequestBody,
    PATH_PEER_DEVICE_REVOCATIONS_CHECK, PATH_PEER_KEYS_QUERY, PATH_PEER_PRINCIPAL_GENESIS,
};
use reqwest::Method;

use crate::{Client, Error, Result};

impl Client {
    /// Resolve an exact retained Event selector set from an authenticated peer.
    /// The formal operation uses QUERY with a canonical JSON body.
    pub async fn peer_events_resolve(
        &self,
        request: &PeerEventsResolveRequestBody,
    ) -> Result<PeerEventsResolveOutcome> {
        request.validate()?;
        let method = Method::from_bytes(b"QUERY")
            .map_err(|error| Error::Protocol(format!("invalid QUERY method: {error}")))?;
        let builder = self.request(method, "/_arkret/peer/events/resolve")?;
        let builder = self.canonical_json_body(builder, request)?;
        let outcome: PeerEventsResolveOutcome = self.send_json(builder).await?;
        outcome.validate_for_request(request)?;
        if !outcome.missing_event_ids.is_empty() || !outcome.missing_event_digests.is_empty() {
            return Err(Error::Protocol(
                "peer Event resolution is incomplete".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Challenge a peer for its complete canonical sibling set at exact
    /// adjudicated `(actor_id, actor_seq)` positions.
    ///
    /// This is the only sibling-position disclosure face for the second phase
    /// of clearing confirmed fork evidence (`sync/federation.md` section
    /// 4.5.3). It is bounded by the request, so it never degrades into an
    /// actor-wide scan; a position the responder does not adjudicate comes back
    /// in the single indistinguishable undisclosed bucket, which is a
    /// fail-closed answer rather than an error.
    pub async fn peer_events_sibling_positions(
        &self,
        request: &PeerEventsSiblingPositionsRequestBody,
    ) -> Result<PeerEventsSiblingPositionsOutcome> {
        request.validate()?;
        let method = Method::from_bytes(b"QUERY")
            .map_err(|error| Error::Protocol(format!("invalid QUERY method: {error}")))?;
        let builder = self.request(method, "/_arkret/peer/events/sibling-positions")?;
        let builder = self.canonical_json_body(builder, request)?;
        let outcome: PeerEventsSiblingPositionsOutcome = self.send_json(builder).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

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

    /// Atomically linearize an immutable issuance intent against the origin
    /// Station's durable device-revocation log.
    pub async fn peer_device_revocations_check(
        &self,
        request: &DeviceRevocationGateCheckRequestBody,
    ) -> Result<DeviceRevocationGateCheckOutcome> {
        request.validate()?;
        let outcome: DeviceRevocationGateCheckOutcome = self
            .post_protocol_replay_safe(PATH_PEER_DEVICE_REVOCATIONS_CHECK, request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Relay the exact client-signed PCR genesis unit. The service-to-service
    /// signature authenticates transport only and never replaces either
    /// client proof in the unit.
    pub async fn peer_principal_genesis_submit(
        &self,
        request: &PcrGenesisSubmitRequestBody,
    ) -> Result<PcrGenesisSubmitOutcome> {
        request.validate()?;
        let outcome: PcrGenesisSubmitOutcome = self
            .post_protocol_replay_safe(PATH_PEER_PRINCIPAL_GENESIS, request)
            .await?;
        outcome.validate_against(request)?;
        Ok(outcome)
    }
}
