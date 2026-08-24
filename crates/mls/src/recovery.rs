use arkret_models_crypto::{MlsEndpointIdentity, MlsWelcomeEnvelope};
use arkret_wire::{DeviceId, DidCoreId};
use serde::{Deserialize, Serialize};

use crate::{MlsError as Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsDeviceWorkflowAction {
    PublishKeyPackage,
    RevokeKeyPackage,
    ConsumeWelcome,
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
            "device recovery workflow requires a human-device Welcome".to_owned(),
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
