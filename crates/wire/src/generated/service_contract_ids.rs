//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-13.2;
//! sha256=15da88f059b5b3ecccfef43168be7cff75c945e764430624a9c227134a2fda52
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
