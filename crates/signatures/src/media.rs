use arkret_models_collaboration::objects::media::CallMediaParticipantBinding;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::Result;

pub const PARTICIPANT_BINDING_LABEL: &str = "ak.media.participant_binding.v1";

#[derive(Serialize)]
struct ParticipantBindingSigningFields<'a> {
    actor_id: &'a arkret_wire::Did,
    call_id: &'a arkret_wire::CallId,
    device_id: &'a arkret_wire::DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    focus_id: &'a str,
    participant_identity: &'a str,
    realm_id: &'a arkret_wire::RealmId,
}

/// Build the canonical transcript covered by a media participant binding signature.
pub fn participant_binding_signing_input(binding: &CallMediaParticipantBinding) -> Result<Vec<u8>> {
    let fields = ParticipantBindingSigningFields {
        actor_id: &binding.actor_id,
        call_id: &binding.call_id,
        device_id: &binding.device_id,
        expires_at: binding.expires_at,
        focus_id: &binding.focus_id,
        participant_identity: &binding.participant_identity,
        realm_id: &binding.realm_id,
    };
    let mut input = Vec::new();
    input.extend_from_slice(PARTICIPANT_BINDING_LABEL.as_bytes());
    input.push(0);
    input.extend_from_slice(&arkret_canonical::canonical::canonical_json_bytes(&fields)?);
    Ok(input)
}
