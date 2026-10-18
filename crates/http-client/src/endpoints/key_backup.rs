//! Encrypted key-backup endpoint methods.

use arkret_models_crypto::{
    KeyBackup, KeyBackupsListQuery, KeysBackupsDeleteChallenge, KeysBackupsDeleteOutcome,
    KeysBackupsDeleteRequestBody, KeysBackupsIssueDeleteChallengeRequestBody,
    KeysBackupsIssueUnlockChallengeRequestBody, KeysBackupsList, KeysBackupsReplaceOutcome,
    KeysBackupsUnlockChallenge, KeysBackupsUnlockRequestBody,
};
use arkret_wire::BackupId;

use crate::{Client, Result, reject_path_segment};

impl Client {
    pub async fn publish_recovery_policy(
        &self,
        request: &arkret_identity::VerifiedSubmission<arkret_wire::EventAdmissionSubmission>,
    ) -> Result<arkret_models_crypto::RecoveryPolicyPublishOutcome> {
        arkret_models_crypto::RecoveryPolicyPublishRequest::new(request.wire().clone())?;
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
    ) -> Result<arkret_models_crypto::RecoverySessionProofSubmitOutcome> {
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
    ) -> Result<KeysBackupsReplaceOutcome> {
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
        self.post(
            &format!(
                "/_arkret/self/keys/backups/{}/unlock-challenge",
                backup_id.as_str()
            ),
            request,
        )
        .await
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

    pub async fn list_key_backups(&self, query: &KeyBackupsListQuery) -> Result<KeysBackupsList> {
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
    ) -> Result<KeysBackupsDeleteOutcome> {
        reject_path_segment(backup_id.as_str())?;
        self.delete_with_body(
            &format!("/_arkret/self/keys/backups/{}", backup_id.as_str()),
            request,
        )
        .await
    }
}
