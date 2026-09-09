//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-10.2;
//! sha256=b9d3f35e7fcc1a7076cf4e544a4591fa037da4c1ff15e3bb62d6ba90a6c3ee78
//! Entries: sole_recovery_families=7

use arkret_wire::CellFamilyId;

pub const SOLE_RECOVERY_FAMILIES: &[&str] = &[
    CellFamilyId::FORK_RESOLUTION_V1,
    CellFamilyId::IDENTITY_RESOLUTION_V1,
    CellFamilyId::INVITE_LIVE_TARGET_V1,
    CellFamilyId::MLS_EPOCH_V1,
    CellFamilyId::REALM_AUTHORITY_ROOT_V1,
    CellFamilyId::REALM_ORGANIZATION_RECOVERY_KEY_V1,
    CellFamilyId::REALM_REDUCER_PROFILE_V1,
];
