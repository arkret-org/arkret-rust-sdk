//! Typed MLS historical authority operations.

use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialRequestBody, MlsGroupStateMaterialResponseBody,
    MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_models_collaboration::mls_roster_authority::{
    MlsAttestAddRequestBody, MlsAttestAddResponseBody, MlsMemberRosterAuthorityReadRequestBody,
    MlsRosterAuthorityReadRequestBody, MlsRosterAuthorityReadResponseBody,
};
use arkret_wire::{
    PATH_PEER_MLS_ATTEST_ADD, PATH_PEER_MLS_GROUP_STATE_MATERIAL, PATH_PEER_MLS_ROSTER_AUTHORITY,
    PATH_SELF_MLS_GROUP_STATE_MATERIAL, PATH_SELF_MLS_ROSTER_AUTHORITY,
};

use crate::{Client, Result};

impl Client {
    /// Fetch accepted Genesis public material as an authorized member through
    /// the caller's Account Station. The peer route is Station-only.
    pub async fn self_mls_group_state_material(
        &self,
        request: &MlsMemberGroupStateMaterialReadRequestBody,
    ) -> Result<MlsGroupStateMaterialResponseBody> {
        request.validate()?;
        let outcome: MlsGroupStateMaterialResponseBody = self
            .post(PATH_SELF_MLS_GROUP_STATE_MATERIAL, request)
            .await?;
        outcome.validate_for_request(&request.as_peer_request())?;
        Ok(outcome)
    }

    /// Fetch exact public GroupInfo/tree bytes for one accepted MLS Genesis.
    pub async fn peer_mls_group_state_material(
        &self,
        request: &MlsGroupStateMaterialRequestBody,
    ) -> Result<MlsGroupStateMaterialResponseBody> {
        request.validate()?;
        let outcome: MlsGroupStateMaterialResponseBody = self
            .post(PATH_PEER_MLS_GROUP_STATE_MATERIAL, request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Submit a recipient Station's signed Add authority after its existing
    /// committed-replication claim check.
    pub async fn peer_mls_attest_add(
        &self,
        request: &MlsAttestAddRequestBody,
    ) -> Result<MlsAttestAddResponseBody> {
        request.validate_claim_binding()?;
        self.post(PATH_PEER_MLS_ATTEST_ADD, request).await
    }

    /// Fetch one signed page from the current governance Station.
    pub async fn peer_mls_roster_authority(
        &self,
        request: &MlsRosterAuthorityReadRequestBody,
    ) -> Result<MlsRosterAuthorityReadResponseBody> {
        request.validate()?;
        self.post(PATH_PEER_MLS_ROSTER_AUTHORITY, request).await
    }

    /// Fetch one signed page through the caller's Account Station.
    pub async fn self_mls_roster_authority(
        &self,
        request: &MlsMemberRosterAuthorityReadRequestBody,
    ) -> Result<
        arkret_models_collaboration::mls_roster_authority::MlsSelfRosterAuthorityReadResponseBody,
    > {
        request.validate()?;
        self.post(PATH_SELF_MLS_ROSTER_AUTHORITY, request).await
    }
}
