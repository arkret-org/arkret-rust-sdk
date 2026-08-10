//! Typed service-authenticated peer query endpoints.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusAuthoringBasisOutcome, AccountStatusAuthoringBasisRequestBody,
};
use arkret_models_collaboration::direct_conversation_repair::{
    DirectConversationRepairEnqueueOutcome, DirectConversationRepairRelayRequest,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsGroupStateMaterialRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_models_identity::{
    ServiceResolutionPublishOutcome, ServiceResolutionPublishRequest,
    ServiceResolutionResolveOutcome, ServiceResolutionResolveRequest,
};
use arkret_wire::{
    PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS, PATH_PEER_DIRECT_CONVERSATIONS_REPAIR_RELAY,
    PATH_PEER_MLS_GROUP_STATE_MATERIAL, PATH_PEER_PRINCIPAL_GENESIS,
};
use reqwest::Method;

use crate::{Client, ClientRequestOptions, Error, Result};

impl Client {
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

    /// Relay one exact requester-authorized repair trigger. The idempotency
    /// header is forced to the body request id; service HTTP-signature setup
    /// remains the caller's transport responsibility.
    pub async fn peer_direct_conversation_repair_relay(
        &self,
        request: &DirectConversationRepairRelayRequest,
    ) -> Result<DirectConversationRepairEnqueueOutcome> {
        request.validate_shape()?;
        let options =
            ClientRequestOptions::new().idempotency_key(request.request_id.as_str().to_owned());
        let outcome: DirectConversationRepairEnqueueOutcome = self
            .post_with_options(
                PATH_PEER_DIRECT_CONVERSATIONS_REPAIR_RELAY,
                request,
                &options,
            )
            .await?;
        outcome.validate_shape()?;
        if outcome.request_id != request.request_id {
            return Err(Error::Protocol(
                "repair relay outcome request_id mismatch".to_owned(),
            ));
        }
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

    /// `POST /_arkret/peer/account-status/authoring-basis`
    /// (`ak.peer.account_status.read.authoring_basis`).
    pub async fn peer_account_status_authoring_basis(
        &self,
        request: &AccountStatusAuthoringBasisRequestBody,
    ) -> Result<AccountStatusAuthoringBasisOutcome> {
        request.validate()?;
        let outcome: AccountStatusAuthoringBasisOutcome = self
            .post(PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS, request)
            .await?;
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
}
