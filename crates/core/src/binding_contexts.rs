//! Canonical domain-separation prefixes for signed protocol transcripts.

pub const CROSS_SIGNING_BIND_PREFIX: &[u8] = b"ak.cross-signing-bind-v1\n";
pub const CROSS_SIGNING_RESET_PREFIX: &[u8] = b"ak.cross-signing-reset-v1\n";
pub const CROSS_SIGNING_RESET_UNLOCK_BINDING_PREFIX: &[u8] =
    b"ak.cross-signing-reset-unlock-binding-v1\n";
pub const DEVICE_TRUST_BIND_PREFIX: &[u8] = b"ak.device-trust-bind-v1\n";
pub const DEVICE_AUTHORIZE_POSSESSION_PREFIX: &[u8] = b"ak.device-authorize-possession-v1\n";
pub const IDENTITY_LINK_PREFIX: &[u8] = b"ak.identity-link-v1\n";
