use arkret_wire::{AuthoredEvent, Base64UrlString, Event, EventId, EventKind, Hash};
use serde::{Deserialize, Serialize};

/// Canonical service-prepared Event digest payload plus its suite-bearing digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PreparedEventDraft {
    pub unsigned_event_bytes: Base64UrlString,
    pub event_digest: Hash,
}

impl PreparedEventDraft {
    pub fn unsigned_event(&self) -> arkret_wire::Result<AuthoredEvent> {
        let bytes = arkret_canonical::base64url_decode(self.unsigned_event_bytes.as_str())?;
        let digest_suite = self.event_digest.digest_suite().map_err(|error| {
            arkret_wire::WireError::Protocol(format!("prepared Event digest is invalid: {error}"))
        })?;
        let event = Event::from_digest_payload_bytes(&bytes, digest_suite)?;
        if Hash::new(event.event_digest_with_digest_suite(digest_suite)?)? != self.event_digest {
            return Err(arkret_wire::WireError::Protocol(
                "prepared Event digest does not match unsigned_event_bytes".to_owned(),
            ));
        }
        AuthoredEvent::from_verified_with_digest_suite(event, digest_suite)
    }

    pub fn event_id(&self) -> arkret_wire::Result<EventId> {
        Ok(self.unsigned_event()?.event_id().clone())
    }

    pub fn kind(&self) -> arkret_wire::Result<EventKind> {
        Ok(self.unsigned_event()?.event().kind.clone())
    }
}
