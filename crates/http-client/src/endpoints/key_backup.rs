//! Encrypted key-backup endpoint methods.

use arkret_models_crypto::{
    KeyBackup, KeyBackupsListQuery, KeysBackupsDeleteChallenge, KeysBackupsDeleteRequestBody,
    KeysBackupsIssueDeleteChallengeRequestBody, KeysBackupsIssueUnlockChallengeRequestBody,
    KeysBackupsPage, KeysBackupsReplaceResponseBody, KeysBackupsUnlockChallenge,
    KeysBackupsUnlockRequestBody,
};
use arkret_wire::BackupId;

use crate::{Client, Result, reject_path_segment};

impl Client {
    fn require_backup_manager_transport(&self) -> Result<()> {
        if self.service_signature_identity.is_none()
            || self.auth.is_some()
            || self.managed_device_signature_identity.is_some()
        {
            return Err(crate::Error::Protocol(
                "native archive reads require the actual manager Service signature transport"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Manager-only archive DTOs. The caller validates full immutable sources
    /// and the all-page manifest; this raw response is not a verified capability.
    pub async fn realm_actor_backup_archive_inventory(
        &self,
        query: &arkret_models_crypto::RealmActorArchiveInventoryQuery,
    ) -> Result<arkret_models_integration::RealmActorArchiveInventoryPage> {
        self.require_backup_manager_transport()?;
        let pairs = arkret_models_crypto::KeysBackupsListParameters::Manager(query.clone())
            .to_query_pairs()?;
        let value: arkret_models_integration::RealmActorArchiveInventoryPage = self
            .send_json(
                self.request(reqwest::Method::GET, "/_arkret/self/keys/backups")?
                    .query(&pairs),
            )
            .await?;
        if value.realm_actor_id != query.realm_actor_id
            || value.entries.len() > 200
            || value.has_more != value.next_cursor.is_some()
            || arkret_canonical::canonical_json_bytes(&value)?.len() > 4_194_304
        {
            return Err(crate::Error::Protocol(
                "archive inventory response changed its actor or page boundary".into(),
            ));
        }
        Ok(value)
    }

    pub async fn issue_realm_actor_archive_unlock_challenge(
        &self,
        backup_id: &BackupId,
        request: &arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody,
    ) -> Result<arkret_models_crypto::RealmActorBackupUnlockChallenge> {
        self.require_backup_manager_transport()?;
        request.validate()?;
        if request.kind
            != arkret_models_crypto::RealmActorBackupUnlockChallengeKind::RealmActorManager
        {
            return Err(crate::Error::Protocol(
                "manager cannot borrow a Device head intent".into(),
            ));
        }
        let value: arkret_models_crypto::RealmActorBackupUnlockChallenge = self
            .post(
                &format!("/_arkret/self/keys/backups/{backup_id}/unlock-challenge"),
                request,
            )
            .await?;
        value.validate_for_native_request(request, backup_id)?;
        Ok(value)
    }

    pub async fn unlock_realm_actor_archive_backup(
        &self,
        proof: &arkret_models_crypto::RealmActorManagerKeyBackupUnlockProof,
    ) -> Result<arkret_models_integration::RealmActorArchiveUnlockResponseBody> {
        self.require_backup_manager_transport()?;
        proof.validate()?;
        let request = arkret_models_crypto::KeysBackupsUnlockOperationRequestBody {
            proof: arkret_models_crypto::KeyBackupUnlockProofBody::Manager(proof.clone()),
        };
        let value: arkret_models_integration::RealmActorArchiveUnlockResponseBody = self
            .post(
                &format!("/_arkret/self/keys/backups/{}/unlock", proof.backup_id),
                &request,
            )
            .await?;
        if value.backup.backup_id != proof.backup_id
            || value.native_source.admission.envelope_digest != proof.envelope_digest
        {
            return Err(crate::Error::Protocol(
                "archive unlock returned another immutable packet".into(),
            ));
        }
        Ok(value)
    }

    pub async fn publish_recovery_policy(
        &self,
        request: &arkret_identity::VerifiedSubmission<arkret_wire::EventAdmissionSubmission>,
    ) -> Result<arkret_models_crypto::RecoveryPolicyPublishResponseBody> {
        arkret_models_crypto::RecoveryPolicyPublishRequestBody::new(request.wire().clone())?;
        self.post("/_arkret/root/identity/recovery-policy", request)
            .await
    }

    pub async fn create_recovery_session(
        &self,
        request: &arkret_models_crypto::RecoverySessionCreateRequestBody,
    ) -> Result<arkret_models_crypto::RecoverySession> {
        self.post("/_arkret/root/identity/recovery-sessions", request)
            .await
    }

    pub async fn submit_recovery_proof(
        &self,
        session_id: &str,
        request: &arkret_models_crypto::RecoverySessionProofSubmitRequestBody,
    ) -> Result<arkret_models_crypto::RecoverySessionProofSubmitResponseBody> {
        reject_path_segment(session_id)?;
        request.proof.validate_shape()?;
        self.post(
            &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
            request,
        )
        .await
    }

    pub async fn put_key_backup(
        &self,
        backup_id: &BackupId,
        record: &KeyBackup,
        idempotency_key: &str,
    ) -> Result<KeysBackupsReplaceResponseBody> {
        reject_path_segment(backup_id.as_str())?;
        record.validate()?;
        if &record.backup_id != backup_id {
            return Err(crate::Error::Protocol(
                "key backup path/body backup_id mismatch".to_owned(),
            ));
        }
        self.put_with_options(
            &format!("/_arkret/self/keys/backups/{}", backup_id.as_str()),
            record,
            &crate::ClientRequestOptions::new().idempotency_key(idempotency_key),
        )
        .await
    }

    pub async fn issue_key_backup_unlock_challenge(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsIssueUnlockChallengeRequestBody,
    ) -> Result<KeysBackupsUnlockChallenge> {
        reject_path_segment(backup_id.as_str())?;
        request.validate()?;
        let challenge: KeysBackupsUnlockChallenge = self
            .post(
                &format!(
                    "/_arkret/self/keys/backups/{}/unlock-challenge",
                    backup_id.as_str()
                ),
                request,
            )
            .await?;
        challenge.validate_for_request(request, backup_id)?;
        Ok(challenge)
    }

    pub async fn unlock_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsUnlockRequestBody,
    ) -> Result<KeyBackup> {
        reject_path_segment(backup_id.as_str())?;
        request.proof.validate()?;
        self.post(
            &format!("/_arkret/self/keys/backups/{}/unlock", backup_id.as_str()),
            request,
        )
        .await
    }

    pub async fn list_key_backups(&self, query: &KeyBackupsListQuery) -> Result<KeysBackupsPage> {
        let builder = self
            .request(reqwest::Method::GET, "/_arkret/self/keys/backups")?
            .query(query);
        self.send_json(builder).await
    }

    pub async fn issue_key_backup_delete_challenge(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsIssueDeleteChallengeRequestBody,
    ) -> Result<KeysBackupsDeleteChallenge> {
        reject_path_segment(backup_id.as_str())?;
        self.post(
            &format!(
                "/_arkret/self/keys/backups/{}/delete-challenge",
                backup_id.as_str()
            ),
            request,
        )
        .await
    }

    pub async fn delete_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsDeleteRequestBody,
    ) -> Result<()> {
        reject_path_segment(backup_id.as_str())?;
        request.validate()?;
        let builder = self.canonical_json_body(
            self.request(
                reqwest::Method::DELETE,
                &format!("/_arkret/self/keys/backups/{}", backup_id.as_str()),
            )?,
            request,
        )?;
        let response = self.send_response(builder).await?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(crate::Error::Protocol(
                "backup delete success must use its registered HTTP 200 status".into(),
            ));
        }
        if !crate::client_internals::read_body_limited(response, 1024)
            .await?
            .is_empty()
        {
            return Err(crate::Error::Protocol(
                "backup delete success must have no entity body".into(),
            ));
        }
        Ok(())
    }
}
