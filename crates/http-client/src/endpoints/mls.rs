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

use crate::{Client, Result, reject_path_segment};

impl Client {
    /// Observe a prepared episode's narrow cleanup result. The host verifies
    /// both signatures, native qualification and first acceptance separately.
    /// Operation: `ak.self.mls.command.reconcile_recovery_scope.v1`.
    pub async fn self_mls_reconcile_recovery_scope(
        &self,
        request: &arkret_models_crypto::ContentRecoveryScopeCleanupRequestBody,
    ) -> Result<arkret_models_crypto::ContentRecoveryScopeCleanupSelfResponseBody> {
        request.validate()?;
        let result: arkret_models_crypto::ContentRecoveryScopeCleanupSelfResponseBody = self
            .post(arkret_wire::PATH_SELF_MLS_RECOVERY_SCOPE_CLEANUP, request)
            .await?;
        result.validate_for_request(request)?;
        Ok(result)
    }

    /// Registered Station-to-governor command. Decoding its result does not
    /// prove native retention, migration rights or a durable endpoint fence.
    /// Operation: `ak.peer.mls.command.reconcile_recovery_scope.v1`.
    pub async fn peer_mls_reconcile_recovery_scope(
        &self,
        request: &arkret_models_collaboration::content_history::ContentRecoveryScopeCleanupSource,
    ) -> Result<arkret_models_crypto::ContentRecoveryScopeCleanupResponseBody> {
        request.validate_shape()?;
        let result: arkret_models_crypto::ContentRecoveryScopeCleanupResponseBody = self
            .post(arkret_wire::PATH_PEER_MLS_RECOVERY_SCOPE_CLEANUP, request)
            .await?;
        result.validate_for_source(&request.attestation)?;
        Ok(result)
    }

    /// Observe inventory preparation for an already accepted native replacement.
    /// Callers bind the result to their qualified episode before using its private Blob.
    pub async fn self_mls_content_recovery(
        &self,
        authorization_event_ref: &arkret_wire::EventId,
    ) -> Result<arkret_models_crypto::ContentRecoveryPreparation> {
        reject_path_segment(authorization_event_ref.as_str())?;
        let outcome: arkret_models_crypto::ContentRecoveryPreparation = self
            .get(&format!(
                "/_arkret/self/mls/content-recoveries/{authorization_event_ref}"
            ))
            .await?;
        outcome.validate_for_authorization(authorization_event_ref)?;
        Ok(outcome)
    }

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
