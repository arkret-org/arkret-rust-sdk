//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-29.2;
//! sha256=2a63871bfd54b91d7107bab7a92b096d60e5ee0b8c63bdf32bca92f9667f751c
//! Entries: service_contracts=5

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ServiceContractId {
    ActorPrivateEffectsV1,
    ContactAdmissionV1,
    IntegrationManifestV1,
    PushBridgeV1,
    RealmGovernanceStationHandoffV1,
}

impl ServiceContractId {
    pub const ALL: &'static [Self] = &[
        Self::ActorPrivateEffectsV1,
        Self::ContactAdmissionV1,
        Self::IntegrationManifestV1,
        Self::PushBridgeV1,
        Self::RealmGovernanceStationHandoffV1,
    ];

    pub const ACTOR_PRIVATE_EFFECTS_V1: &'static str = "ak.actor_private.effects.v1";
    pub const CONTACT_ADMISSION_V1: &'static str = "ak.contact.admission.v1";
    pub const INTEGRATION_MANIFEST_V1: &'static str = "ak.integration.manifest.v1";
    pub const PUSH_BRIDGE_V1: &'static str = "ak.push.bridge.v1";
    pub const REALM_GOVERNANCE_STATION_HANDOFF_V1: &'static str =
        "ak.realm.governance_station_handoff.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActorPrivateEffectsV1 => Self::ACTOR_PRIVATE_EFFECTS_V1,
            Self::ContactAdmissionV1 => Self::CONTACT_ADMISSION_V1,
            Self::IntegrationManifestV1 => Self::INTEGRATION_MANIFEST_V1,
            Self::PushBridgeV1 => Self::PUSH_BRIDGE_V1,
            Self::RealmGovernanceStationHandoffV1 => Self::REALM_GOVERNANCE_STATION_HANDOFF_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::ACTOR_PRIVATE_EFFECTS_V1 => Some(Self::ActorPrivateEffectsV1),
            Self::CONTACT_ADMISSION_V1 => Some(Self::ContactAdmissionV1),
            Self::INTEGRATION_MANIFEST_V1 => Some(Self::IntegrationManifestV1),
            Self::PUSH_BRIDGE_V1 => Some(Self::PushBridgeV1),
            Self::REALM_GOVERNANCE_STATION_HANDOFF_V1 => {
                Some(Self::RealmGovernanceStationHandoffV1)
            }
            _ => None,
        }
    }
}
