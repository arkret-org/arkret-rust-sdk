//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/applet-managed-authority-registry.json;
//! sha256=edc2650fc7ed9fe61ce93adea9793e87caaa4d201556c610f6ac26f43ad06f60 Input: registry/
//! contract-registry.json; sha256=1bde71b428c1fcbf12de2072f155a3a0191e1d6bacec46b421c85bf2e07938c5
//! Entries: managed_device_operations=26

use super::{CapabilityActionId, ServiceOperationId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedDeviceControl {
    OwnExactPreviouslyDeliveredItemsAck,
    OwnExactKeypackageRevoke,
    OwnScopeBoundKeypackageUpload,
    OwnExactDurableWelcomeReceiptConsume,
    OwnExactDeviceAuthorizationOrNativeBackupCurrentMaterialRead,
    NativeRootBackup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedDeviceScopeRule {
    AllActions(&'static [CapabilityActionId]),
    AllActionsAndControl {
        actions: &'static [CapabilityActionId],
        control: ManagedDeviceControl,
    },
    SubmittedBusinessActions,
    DeviceControl(ManagedDeviceControl),
}

/// Transport inventory only; every business gate remains mandatory.
pub const fn applet_managed_device_scope_rule(
    operation: ServiceOperationId,
) -> Option<ManagedDeviceScopeRule> {
    Some(match operation {
        ServiceOperationId::SelfBlobCommandPresignV1 => ManagedDeviceScopeRule::AllActions(&[
            CapabilityActionId::SelfBlobCommandPresignV1,
            CapabilityActionId::ObjectReadContent,
        ]),
        ServiceOperationId::SelfBlobResourceGetV1 => ManagedDeviceScopeRule::AllActions(&[
            CapabilityActionId::SelfBlobResourceGetV1,
            CapabilityActionId::ObjectReadContent,
        ]),
        ServiceOperationId::SelfBlobResourceHeadV1 => ManagedDeviceScopeRule::AllActions(&[
            CapabilityActionId::SelfBlobResourceHeadV1,
            CapabilityActionId::ObjectReadContent,
        ]),
        ServiceOperationId::SelfBlobUploadCreateV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::SelfBlobUploadCreateV1])
        }
        ServiceOperationId::SelfDeviceMessagesCommandAckV1 => {
            ManagedDeviceScopeRule::DeviceControl(
                ManagedDeviceControl::OwnExactPreviouslyDeliveredItemsAck,
            )
        }
        ServiceOperationId::SelfDeviceMessagesReadListV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfKeysKeypackagesCommandClaimV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1 => {
            ManagedDeviceScopeRule::DeviceControl(
                ManagedDeviceControl::OwnExactDurableWelcomeReceiptConsume,
            )
        }
        ServiceOperationId::SelfKeysKeypackagesCommandRevokeV1 => {
            ManagedDeviceScopeRule::DeviceControl(ManagedDeviceControl::OwnExactKeypackageRevoke)
        }
        ServiceOperationId::SelfKeysKeypackagesReadClaimV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfKeysKeypackagesUploadCreateV1 => {
            ManagedDeviceScopeRule::DeviceControl(
                ManagedDeviceControl::OwnScopeBoundKeypackageUpload,
            )
        }
        ServiceOperationId::SelfMlsReadGroupStateMaterialV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfMlsReadRosterAuthorityV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfSignerKeysReadResolveV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCurrentStateReadExactV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCommittedEventResourceGetV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCommittedEventReadScanV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfCommittedEventStreamSubscribeV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfRealmStateSnapshotReadByRefV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1 => {
            ManagedDeviceScopeRule::AllActions(&[CapabilityActionId::EventRead])
        }
        ServiceOperationId::SelfEventsCommandSubmitV1 => {
            ManagedDeviceScopeRule::SubmittedBusinessActions
        }
        ServiceOperationId::SelfRealmActorReadMaterialV1 => ManagedDeviceScopeRule::DeviceControl(
            ManagedDeviceControl::OwnExactDeviceAuthorizationOrNativeBackupCurrentMaterialRead,
        ),
        ServiceOperationId::SelfKeysBackupsResourceReplaceV1 => {
            ManagedDeviceScopeRule::AllActionsAndControl {
                actions: &[CapabilityActionId::SelfKeysBackupsResourceReplaceV1],
                control: ManagedDeviceControl::NativeRootBackup,
            }
        }
        ServiceOperationId::SelfKeysBackupsReadListV1 => {
            ManagedDeviceScopeRule::AllActionsAndControl {
                actions: &[CapabilityActionId::SelfKeysBackupsReadListV1],
                control: ManagedDeviceControl::NativeRootBackup,
            }
        }
        ServiceOperationId::SelfKeysBackupsCommandIssueUnlockChallengeV1 => {
            ManagedDeviceScopeRule::AllActionsAndControl {
                actions: &[CapabilityActionId::SelfKeysBackupsCommandIssueUnlockChallengeV1],
                control: ManagedDeviceControl::NativeRootBackup,
            }
        }
        ServiceOperationId::SelfKeysBackupsCommandUnlockV1 => {
            ManagedDeviceScopeRule::AllActionsAndControl {
                actions: &[CapabilityActionId::SelfKeysBackupsCommandUnlockV1],
                control: ManagedDeviceControl::NativeRootBackup,
            }
        }
        _ => return None,
    })
}
