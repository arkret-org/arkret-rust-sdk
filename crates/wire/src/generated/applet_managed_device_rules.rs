//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/applet-managed-authority-registry.json;
//! sha256=a596ae7994158e3e446ac7f41bdb70743b021854c79cd9efd632ac7fbd8aca67 Input: registry/
//! contract-registry.json; sha256=4603ea9c66ada9ca9e09db7ccce8dfd3b0ba0675ac2f67bdeaba66402115762c
//! Entries: managed_device_operations=22

use super::{CapabilityActionId, ServiceOperationId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedDeviceControl {
    OwnExactPreviouslyDeliveredItemsAck,
    OwnExactKeypackageRevoke,
    OwnScopeBoundKeypackageUpload,
    OwnExactDurableWelcomeReceiptConsume,
    OwnExactDeviceAuthorizationMaterialRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedDeviceScopeRule {
    AllActions(&'static [CapabilityActionId]),
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
            ManagedDeviceControl::OwnExactDeviceAuthorizationMaterialRead,
        ),
        _ => return None,
    })
}
