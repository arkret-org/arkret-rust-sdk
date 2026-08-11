//! Actor-profile event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileCreatePayload {
    pub object: ActorProfile,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileUpdatePayload {
    pub target_ref: ActorProfileId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl ActorProfileUpdatePayload {
    pub fn validate_for_account_self_service(&self) -> Result<()> {
        self.patch.validate()?;
        for (path, _) in self.patch.iter() {
            if !account_profile_patch_path_allowed(path.as_str()) {
                return Err(Error::Protocol(format!(
                    "account profile update patch path `{path}` is not writable"
                )));
            }
        }
        Ok(())
    }
}

fn account_profile_patch_path_allowed(path: &str) -> bool {
    if matches!(path, "display_name" | "avatar_blob_ref") {
        return true;
    }
    let Some(key) = path.strip_prefix("profile_fields.") else {
        return false;
    };
    let mut bytes = key.bytes();
    key.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
