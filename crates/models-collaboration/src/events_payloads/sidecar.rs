//! Sidecar Event payloads.

use serde::{Deserialize, Serialize};

/// The only active v1 Sidecar encryption profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SidecarEncryptionProfile {
    #[serde(rename = "mls_rfc9420")]
    MlsRfc9420,
}

/// Counterpart for `event-payload.schema.json#/$defs/sidecar_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarCreatePayload {
    pub encryption_profile: SidecarEncryptionProfile,
}
