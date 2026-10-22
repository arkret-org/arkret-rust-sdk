//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/applet-managed-authority-registry.json; version=2026-10-21.4;
//! sha256=3b2d94cbfdf28df731075275467b57d71030fceebdfba60a482c617b571f9e27 Input: registry/
//! contract-registry.json; version=2026-10-22.9;
//! sha256=1dd5f15c1e88e2d4b5a7d8a3f7d2ce055aadf1c02197f433788c3177c7277991
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
        ServiceOperationId::SelfCurrentResultsReadExactV1 => {
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
