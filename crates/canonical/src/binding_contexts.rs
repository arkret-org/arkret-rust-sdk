//! Canonical domain-separation prefixes for signed protocol transcripts.

pub const DEVICE_AUTHORIZE_POSSESSION_PREFIX: &[u8] = b"ak.device_authorize_possession_proof.v1\n";
pub const DEVICE_AUTHORIZE_RECOVERY_POSSESSION_PREFIX: &[u8] =
    b"ak.device_authorize_recovery_possession_proof.v1\n";
pub const IDENTITY_LINK_PREFIX: &[u8] = b"ak.identity-link-v1\n";
