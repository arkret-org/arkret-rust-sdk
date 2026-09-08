//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-08.9;
//! sha256=4171e60e73740e69dbd12c11b6845134e9b18598fa99fbb52f8b76641d98648c
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
