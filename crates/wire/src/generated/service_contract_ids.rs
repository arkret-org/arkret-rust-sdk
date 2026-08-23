//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/contract-registry.json; version=2026-08-24.1;
//! sha256=3c298254a6adf516a7994b6955bcda8ddb79addb024f607d5075df3512e85586
//! Entries: service_contracts=2

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ServiceContractId {
    IntegrationManifestV1,
    PushBridgeV1,
}

impl ServiceContractId {
    pub const ALL: &'static [Self] = &[Self::IntegrationManifestV1, Self::PushBridgeV1];

    pub const INTEGRATION_MANIFEST_V1: &'static str = "ak.integration.manifest.v1";
    pub const PUSH_BRIDGE_V1: &'static str = "ak.push.bridge.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntegrationManifestV1 => Self::INTEGRATION_MANIFEST_V1,
            Self::PushBridgeV1 => Self::PUSH_BRIDGE_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::INTEGRATION_MANIFEST_V1 => Some(Self::IntegrationManifestV1),
            Self::PUSH_BRIDGE_V1 => Some(Self::PushBridgeV1),
            _ => None,
        }
    }
}
