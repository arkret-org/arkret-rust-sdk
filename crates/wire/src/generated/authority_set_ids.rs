//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/authority-set-policy-registry.json; version=2026-09-08.1;
//! sha256=f62f00479445688aa4c3aad1b898a06b36a342900f7a9c8d17b626bc6271c71e
//! Entries: authority_sets=3

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthoritySetId {
    RealmAdmissionV1,
    RecoveryAccountAuthorityV1,
    RecoveryIdentityReanchorV1,
}

impl AuthoritySetId {
    pub const ALL: &'static [Self] = &[
        Self::RealmAdmissionV1,
        Self::RecoveryAccountAuthorityV1,
        Self::RecoveryIdentityReanchorV1,
    ];

    pub const REALM_ADMISSION_V1: &'static str = "ak.authority_set.realm_admission.v1";
    pub const RECOVERY_ACCOUNT_AUTHORITY_V1: &'static str =
        "ak.authority_set.recovery_account_authority.v1";
    pub const RECOVERY_IDENTITY_REANCHOR_V1: &'static str =
        "ak.authority_set.recovery_identity_reanchor.v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealmAdmissionV1 => Self::REALM_ADMISSION_V1,
            Self::RecoveryAccountAuthorityV1 => Self::RECOVERY_ACCOUNT_AUTHORITY_V1,
            Self::RecoveryIdentityReanchorV1 => Self::RECOVERY_IDENTITY_REANCHOR_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::REALM_ADMISSION_V1 => Some(Self::RealmAdmissionV1),
            Self::RECOVERY_ACCOUNT_AUTHORITY_V1 => Some(Self::RecoveryAccountAuthorityV1),
            Self::RECOVERY_IDENTITY_REANCHOR_V1 => Some(Self::RecoveryIdentityReanchorV1),
            _ => None,
        }
    }
}
