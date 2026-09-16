//! Convenience wrapper for encrypted key-backup operations.

use arkret_models_crypto::{
    KeyBackup, KeyBackupsListQuery, KeysBackupsDeleteChallenge, KeysBackupsDeleteOutcome,
    KeysBackupsDeleteRequestBody, KeysBackupsIssueDeleteChallengeRequestBody, KeysBackupsList,
    KeysBackupsReplaceOutcome, KeysBackupsUnlockRequestBody,
};
use arkret_wire::BackupId;

use crate::{Client, Result};

#[derive(Clone, Debug)]
pub struct KeyBackupClient {
    client: Client,
}

impl KeyBackupClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn put_key_backup(&self, record: &KeyBackup) -> Result<KeysBackupsReplaceOutcome> {
        let digest = arkret_canonical::canonical_sha256(record)?;
        let idempotency_key = format!("arkret-key-backup-{}", digest.trim_start_matches("sha256:"));
        self.client
            .put_key_backup(&record.backup_id, record, &idempotency_key)
            .await
    }

    pub async fn unlock_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsUnlockRequestBody,
    ) -> Result<KeyBackup> {
        let record = self.client.unlock_key_backup(backup_id, request).await?;
        record.validate()?;
        Ok(record)
    }

    pub async fn list_key_backups(&self, query: &KeyBackupsListQuery) -> Result<KeysBackupsList> {
        self.client.list_key_backups(query).await
    }

    pub async fn issue_delete_challenge(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsIssueDeleteChallengeRequestBody,
    ) -> Result<KeysBackupsDeleteChallenge> {
        self.client
            .issue_key_backup_delete_challenge(backup_id, request)
            .await
    }

    pub async fn delete_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsDeleteRequestBody,
    ) -> Result<KeysBackupsDeleteOutcome> {
        self.client.delete_key_backup(backup_id, request).await
    }
}
