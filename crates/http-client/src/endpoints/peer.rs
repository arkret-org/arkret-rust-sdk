//! Typed service-authenticated peer query endpoints.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusAuthoringBasisOutcome, AccountStatusAuthoringBasisRequestBody,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsGroupStateMaterialRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_wire::{
    PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS, PATH_PEER_MLS_GROUP_STATE_MATERIAL,
    PATH_PEER_PRINCIPAL_GENESIS,
};

use crate::{Client, Result};

impl Client {
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
