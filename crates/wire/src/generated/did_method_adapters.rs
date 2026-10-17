//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-10-17;
//! sha256=d922a3ce35503bb5134aa98b8fd1fa57a4aafb6c8b4ca475692ab145df06fa62 Entries: registered=3

/// Method-history evidence kinds, keyed the way the registry keys them.
///
/// `adapter_version` is not a wire member: review 2026-09-02-1951 A8 deleted
/// it from every method-history evidence carrier because the registry already
/// fixes one adapter version per evidence kind. Producers and verifiers each
/// recompute it from `evidence_kind` through this table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidMethodEvidenceKind {
    DidKeyExpansion,
    DidWebDocument,
    WebvhLog,
}

impl DidMethodEvidenceKind {
    pub const ALL: &'static [Self] = &[Self::DidKeyExpansion, Self::DidWebDocument, Self::WebvhLog];

    pub const DID_KEY_EXPANSION: &'static str = "did_key_expansion";
    pub const DID_WEB_DOCUMENT: &'static str = "did_web_document";
    pub const WEBVH_LOG: &'static str = "webvh_log";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DidKeyExpansion => Self::DID_KEY_EXPANSION,
            Self::DidWebDocument => Self::DID_WEB_DOCUMENT,
            Self::WebvhLog => Self::WEBVH_LOG,
        }
    }

    /// The registry's adapter version for this evidence kind.
    pub const fn adapter_version(self) -> &'static str {
        match self {
            Self::DidKeyExpansion => "did:key:1",
            Self::DidWebDocument => "did:web:1",
            Self::WebvhLog => "did:webvh:1.0",
        }
    }

    /// The DID method this adapter admits.
    pub const fn method(self) -> &'static str {
        match self {
            Self::DidKeyExpansion => "did:key",
            Self::DidWebDocument => "did:web",
            Self::WebvhLog => "did:webvh",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            Self::DID_KEY_EXPANSION => Some(Self::DidKeyExpansion),
            Self::DID_WEB_DOCUMENT => Some(Self::DidWebDocument),
            Self::WEBVH_LOG => Some(Self::WebvhLog),
            _ => None,
        }
    }
}
