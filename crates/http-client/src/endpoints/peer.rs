//! Typed service-authenticated peer query endpoints.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusResolveOutcome, AccountStatusResolveRequestBody,
};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependencyResolveOutcome, PeerGovernanceDependencyResolveRequest,
};
use arkret_models_collaboration::http_bodies::{
    PeerEventsResolveOutcome, PeerEventsResolveRequestBody, PeerSealResolveRequestBody,
    SealResolveOutcome,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsGroupStateMaterialRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_models_crypto::{MlsGovernanceProofBundle, MlsGovernanceProofRequestBody};
use arkret_models_identity::{
    ServiceResolutionPublishOutcome, ServiceResolutionPublishRequest,
    ServiceResolutionResolveOutcome, ServiceResolutionResolveRequest,
};
use arkret_wire::{
    DeviceRevocationGateCheckOutcome, DeviceRevocationGateCheckRequestBody,
    PATH_PEER_ACCOUNT_STATUS_RESOLVE, PATH_PEER_DEVICE_REVOCATIONS_CHECK,
    PATH_PEER_MLS_GROUP_STATE_MATERIAL, PATH_PEER_PRINCIPAL_GENESIS,
};
use reqwest::Method;

use crate::{Client, ClientRequestOptions, Error, Result};

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

    /// Resolve an exact retained Seal selector set from an authenticated peer.
    /// The formal operation uses QUERY with a canonical JSON body.
    pub async fn peer_seals_resolve(
        &self,
        request: &PeerSealResolveRequestBody,
    ) -> Result<SealResolveOutcome> {
        request.validate()?;
        let method = Method::from_bytes(b"QUERY")
            .map_err(|error| Error::Protocol(format!("invalid QUERY method: {error}")))?;
        let builder = self.request(method, "/_arkret/peer/seals/resolve")?;
        let builder = self.canonical_json_body(builder, request)?;
        let outcome: SealResolveOutcome = self.send_json(builder).await?;
        outcome.validate_for_peer_request(request)?;
        if !outcome.missing_seal_refs.is_empty() {
            return Err(Error::Protocol(
                "peer Seal resolution is incomplete".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Atomically linearize an immutable issuance intent against the origin
    /// Principal Server's durable device-revocation log.
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

    pub async fn peer_service_resolution_publish(
        &self,
        request: &ServiceResolutionPublishRequest,
    ) -> Result<ServiceResolutionPublishOutcome> {
        request.validate()?;
        let options =
            ClientRequestOptions::new().idempotency_key(request.request_id.as_str().to_owned());
        let outcome: ServiceResolutionPublishOutcome = self
            .post_with_options(
                "/_arkret/peer/service-resolution/publish",
                request,
                &options,
            )
            .await?;
        if outcome.ack.ack.request_id != request.request_id
            || outcome.ack.ack.realm_id != request.realm_id
            || outcome.ack.ack.request_digest != request.canonical_digest()?
        {
            return Err(Error::Protocol(
                "service resolution publish ack request binding mismatch".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn peer_service_resolution_resolve(
        &self,
        request: &ServiceResolutionResolveRequest,
    ) -> Result<ServiceResolutionResolveOutcome> {
        request.validate_bounds()?;
        let method = Method::from_bytes(b"QUERY")
            .map_err(|error| Error::Protocol(format!("invalid QUERY method: {error}")))?;
        let builder = self.request(method, "/_arkret/peer/service-resolution/resolve")?;
        let builder = self.canonical_json_body(builder, request)?;
        let outcome: ServiceResolutionResolveOutcome = self.send_json(builder).await?;
        outcome.validate_chain(request)?;
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

    /// Read a bounded contiguous range from the Account Authority issuer ledger.
    pub async fn peer_account_status_resolve(
        &self,
        request: &AccountStatusResolveRequestBody,
    ) -> Result<AccountStatusResolveOutcome> {
        request.validate()?;
        let outcome: AccountStatusResolveOutcome =
            self.post(PATH_PEER_ACCOUNT_STATUS_RESOLVE, request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/peer/mls/group-state-material`
    /// (`ak.peer.mls.read.group_state_material`). This validates selectors,
    /// content-addressed refs, raw-byte digests, and response bounds. Callers
    /// then pass the decoded bytes to `arkret_mls::validate_public_group_state`.
    pub async fn peer_mls_group_state_material(
        &self,
        request: &MlsGroupStateMaterialRequestBody,
    ) -> Result<MlsGroupStateMaterialOutcome> {
        request.validate()?;
        let outcome: MlsGroupStateMaterialOutcome = self
            .post(PATH_PEER_MLS_GROUP_STATE_MATERIAL, request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Fetch one complete near-current MLS group-security-frontier proof from
    /// an authenticated federation peer.
    pub async fn peer_mls_governance_proof(
        &self,
        request: &MlsGovernanceProofRequestBody,
    ) -> Result<MlsGovernanceProofBundle> {
        request.validate()?;
        let outcome: MlsGovernanceProofBundle = self
            .post("/_arkret/peer/seals/mls-governance-proof", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Resolve one exact governance dependency selector set from a peer.
    /// Missing selectors are a hard failure for replay consumers.
    pub async fn peer_governance_dependencies_resolve(
        &self,
        request: &PeerGovernanceDependencyResolveRequest,
    ) -> Result<GovernanceDependencyResolveOutcome> {
        request.validate()?;
        let outcome: GovernanceDependencyResolveOutcome = self
            .post("/_arkret/peer/seals/governance-dependencies", request)
            .await?;
        outcome.validate_for_peer_request(request)?;
        if !outcome.missing_selectors.is_empty() {
            return Err(Error::Protocol(
                "peer governance dependency resolution is incomplete".to_owned(),
            ));
        }
        Ok(outcome)
    }
}
