//! Canonical domain-separation prefixes for signed protocol transcripts.

pub const CROSS_SIGNING_BIND_PREFIX: &[u8] = b"ck-cross-signing-bind-v1\n";
pub const CROSS_SIGNING_RESET_PREFIX: &[u8] = b"ck-cross-signing-reset-v1\n";
pub const CROSS_SIGNING_RESET_UNLOCK_BINDING_PREFIX: &[u8] =
    b"ck-cross-signing-reset-unlock-binding-v1\n";
pub const DEVICE_TRUST_BIND_PREFIX: &[u8] = b"ck-device-trust-bind-v1\n";
pub const DEVICE_AUTHORIZE_POSSESSION_PREFIX: &[u8] = b"ck-device-authorize-possession-v1\n";
pub const IDENTITY_LINK_PREFIX: &[u8] = b"ck-identity-link-v1\n";
