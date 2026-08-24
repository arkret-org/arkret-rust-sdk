//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/track-name-registry.json; version=2026-08-25.2;
//! sha256=d3ddb62a7f2f4ae4636bc2c19f913b0c73861cfd6169a80fb478bbb664dc5564 Input: registry/
//! binding-kind-registry.json; version=2026-08-25.2;
//! sha256=b9e2b1f830d2a232453cc79623dc3dc62d12512df045e82589ce1d170547d184 Input: registry/
//! authority-set-policy-registry.json; version=2026-08-23.1;
//! sha256=cc421f88133d643d2c52757597cf49340d6ad4510e9ea8c2a487ca8001ae7236 Entries: track_names=2,
//! binding_kinds=3, authority_policy_kinds=3, authority_source_kinds=2

use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackName {
    Discussion,
    Synthesis,
}

impl TrackName {
    pub const ALL: &'static [Self] = &[Self::Discussion, Self::Synthesis];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discussion => "discussion",
            Self::Synthesis => "synthesis",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "discussion" => Some(Self::Discussion),
            "synthesis" => Some(Self::Synthesis),
            _ => None,
        }
    }
}

impl std::fmt::Display for TrackName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingKind {
    HttpJson,
    Tus,
    Websocket,
}

impl BindingKind {
    pub const ALL: &'static [Self] = &[Self::HttpJson, Self::Tus, Self::Websocket];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpJson => "http_json",
            Self::Tus => "tus",
            Self::Websocket => "websocket",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "http_json" => Some(Self::HttpJson),
            "tus" => Some(Self::Tus),
            "websocket" => Some(Self::Websocket),
            _ => None,
        }
    }
}

impl std::fmt::Display for BindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySetPolicyKind {
    AccountAuthority,
    PrincipalControl,
    RealmAdmission,
}

impl AuthoritySetPolicyKind {
    pub const ALL: &'static [Self] = &[
        Self::AccountAuthority,
        Self::PrincipalControl,
        Self::RealmAdmission,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountAuthority => "account_authority",
            Self::PrincipalControl => "principal_control",
            Self::RealmAdmission => "realm_admission",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "account_authority" => Some(Self::AccountAuthority),
            "principal_control" => Some(Self::PrincipalControl),
            "realm_admission" => Some(Self::RealmAdmission),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthoritySetPolicyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySetSourceKind {
    RealmControl,
    RecoveryPolicy,
}

impl AuthoritySetSourceKind {
    pub const ALL: &'static [Self] = &[Self::RealmControl, Self::RecoveryPolicy];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealmControl => "realm_control",
            Self::RecoveryPolicy => "recovery_policy",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "realm_control" => Some(Self::RealmControl),
            "recovery_policy" => Some(Self::RecoveryPolicy),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthoritySetSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str((*self).as_str())
    }
}
