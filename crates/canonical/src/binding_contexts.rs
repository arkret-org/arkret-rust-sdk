//! Canonical domain-separation prefixes for signed protocol transcripts.

// Device-authorization possession domains are not restated here: they are
// registered proof contexts, so their only source is the generated
// `ProofContextId` surface in `arkret-wire`, which this crate sits below. A
// hand-copied literal would be a second, unchecked spelling of a registry
// value.
pub const IDENTITY_LINK_PREFIX: &[u8] =
    crate::generated::binding_prefixes::DomainPrefix::AK_IDENTITY_LINK_V1;
