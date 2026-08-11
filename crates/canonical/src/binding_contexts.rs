//! Canonical domain-separation prefixes for signed protocol transcripts.

pub const DEVICE_TRUST_BIND_PREFIX: &[u8] = b"ak.device-trust-bind-v1\n";
pub const DEVICE_AUTHORIZE_POSSESSION_PREFIX: &[u8] = b"ak.device-authorize-possession-proof-v1\n";
pub const DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PREFIX: &[u8] =
    b"ak.device-authorize-recovery-possession-proof-v1\n";
pub const IDENTITY_LINK_PREFIX: &[u8] = b"ak.identity-link-v1\n";
