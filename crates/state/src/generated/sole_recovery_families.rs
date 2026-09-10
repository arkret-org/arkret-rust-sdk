//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-11.1;
//! sha256=9c8b1279062921ba19f67e5adaf6b9f54cc00122d3a5e3cf5a0a5551bcde5b67
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
