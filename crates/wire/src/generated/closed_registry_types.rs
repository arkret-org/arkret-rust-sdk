//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/track-name-registry.json; version=2026-08-06.3;
//! sha256=5323f3554fdf8142d4ade3e969e945a9760a6dc8c120fc46e7310e553adafebc Input: registry/
//! binding-kind-registry.json; version=2026-08-06.3;
//! sha256=46fc2e41fe600bf18c8d4f184319eaad6527500ce1c4d4a8c72d77a3a19a5578 Input: registry/
//! authority-set-policy-registry.json; version=2026-07-29;
//! sha256=dc07cbcb760b98bbefbeb59a101a76b7ca05d5f9a9e2d8f025096c1234f2e004 Entries: track_names=2,
//! binding_kinds=3, authority_policy_kinds=2, authority_source_kinds=4

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
    PrincipalControl,
    RealmAdmission,
}

impl AuthoritySetPolicyKind {
    pub const ALL: &'static [Self] = &[Self::PrincipalControl, Self::RealmAdmission];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalControl => "principal_control",
            Self::RealmAdmission => "realm_admission",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
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
    CrossSigningPublish,
    DidDocument,
    RealmControl,
    RecoveryPolicy,
}

impl AuthoritySetSourceKind {
    pub const ALL: &'static [Self] = &[
        Self::CrossSigningPublish,
        Self::DidDocument,
        Self::RealmControl,
        Self::RecoveryPolicy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CrossSigningPublish => "cross_signing_publish",
            Self::DidDocument => "did_document",
            Self::RealmControl => "realm_control",
            Self::RecoveryPolicy => "recovery_policy",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "cross_signing_publish" => Some(Self::CrossSigningPublish),
            "did_document" => Some(Self::DidDocument),
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
