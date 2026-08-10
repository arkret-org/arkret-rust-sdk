use arkret_models_crypto::{
    MlsCommitEnvelope, MlsCommitSource, MlsEndpointIdentity, MlsWelcomeEnvelope,
};
use arkret_wire::{DeviceId, DidCoreId};
use serde::{Deserialize, Serialize};

use crate::group::ArkretMlsGroup;
use crate::{MlsError as Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsDeviceWorkflowAction {
    PublishKeyPackage,
    RevokeKeyPackage,
    ConsumeWelcome,
    ApplyCommit,
    RequestEpochRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsDeviceWorkflowStep {
    pub action: MlsDeviceWorkflowAction,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub group_id: Option<String>,
    pub from_epoch: Option<u64>,
    pub to_epoch: Option<u64>,
}

pub fn late_device_join_steps(welcome: &MlsWelcomeEnvelope) -> Result<Vec<MlsDeviceWorkflowStep>> {
    let MlsEndpointIdentity::HumanDevice {
        principal_id,
        device_id,
    } = &welcome.recipient
    else {
        return Err(Error::Protocol(
            "device recovery workflow cannot consume a Native Agent Welcome".to_owned(),
        ));
    };
    Ok(vec![MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::ConsumeWelcome,
        principal_id: principal_id.clone(),
        device_id: device_id.clone(),
        group_id: Some(welcome.group_id.clone()),
        from_epoch: None,
        to_epoch: Some(welcome.epoch),
    }])
}

pub fn epoch_recovery_step(
    principal_id: DidCoreId,
    device_id: DeviceId,
    group_id: impl Into<String>,
    from_epoch: u64,
    to_epoch: u64,
) -> MlsDeviceWorkflowStep {
    MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::RequestEpochRecovery,
        principal_id,
        device_id,
        group_id: Some(group_id.into()),
        from_epoch: Some(from_epoch),
        to_epoch: Some(to_epoch),
    }
}

/// Request for epoch recovery sent to a group member that has the missing commits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecoveryRequestBody {
    /// Group that needs recovery.
    pub group_id: String,
    /// Device requesting recovery.
    pub requesting_principal: DidCoreId,
    pub requesting_device: DeviceId,
    /// The epoch the device is currently at.
    pub local_epoch: u64,
    /// The epoch the device needs to reach.
    pub target_epoch: u64,
}

/// Response containing the commits needed for epoch recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecoveryOutcome {
    /// Group that was recovered.
    pub group_id: String,
    /// The commits from `local_epoch + 1` through `target_epoch`.
    pub commits: Vec<MlsCommitEnvelope>,
    /// Optional updated ratchet tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// Epoch the responder is at.
    pub responder_epoch: u64,
}

impl EpochRecoveryRequestBody {
    /// Create a new epoch recovery request.
    pub fn new(
        group_id: impl Into<String>,
        requesting_principal: DidCoreId,
        requesting_device: DeviceId,
        local_epoch: u64,
        target_epoch: u64,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            requesting_principal,
            requesting_device,
            local_epoch,
            target_epoch,
        }
    }

    /// Validate the request is well-formed.
    pub fn validate(&self) -> Result<()> {
        if self.group_id.is_empty() {
            return Err(Error::Protocol(
                "epoch recovery group_id is empty".to_owned(),
            ));
        }
        if self.local_epoch >= self.target_epoch {
            return Err(Error::Protocol(
                "epoch recovery local_epoch must be less than target_epoch".to_owned(),
            ));
        }
        Ok(())
    }
}

impl EpochRecoveryOutcome {
    /// Apply all commits in this recovery response to a group.
    pub fn apply_to_group(&self, group: &mut ArkretMlsGroup) -> Result<u64> {
        group.apply_commits(&self.commits)
    }

    /// Validate that the response covers the requested epoch range.
    pub fn validate_range(&self, request: &EpochRecoveryRequestBody) -> Result<()> {
        if self.group_id != request.group_id {
            return Err(Error::Protocol(
                "epoch recovery response group_id mismatch".to_owned(),
            ));
        }
        for commit in &self.commits {
            if commit.epoch <= request.local_epoch || commit.epoch > request.target_epoch {
                return Err(Error::Protocol(format!(
                    "epoch recovery commit epoch {} is outside requested range ({}, {}]",
                    commit.epoch, request.local_epoch, request.target_epoch
                )));
            }
        }
        Ok(())
    }
}

/// Build an epoch recovery response from a group that has the needed commits.
pub fn build_epoch_recovery_response(
    group: &ArkretMlsGroup,
    store: &impl MlsCommitSource,
    request: &EpochRecoveryRequestBody,
) -> Result<EpochRecoveryOutcome> {
    request.validate()?;

    let commits = store.commits_for_group(&request.group_id);
    let recovery_commits: Vec<MlsCommitEnvelope> = commits
        .into_iter()
        .filter(|commit| commit.epoch > request.local_epoch && commit.epoch <= request.target_epoch)
        .cloned()
        .collect();

    if recovery_commits.is_empty() {
        return Err(Error::Protocol(
            "no commits available for epoch recovery".to_owned(),
        ));
    }

    Ok(EpochRecoveryOutcome {
        group_id: request.group_id.clone(),
        commits: recovery_commits,
        ratchet_tree: Some(group.ratchet_tree()?),
        responder_epoch: group.epoch(),
    })
}
