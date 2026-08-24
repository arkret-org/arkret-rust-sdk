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

    pub fn unsigned_event_for_kind(
        &self,
        expected_kind: &str,
    ) -> arkret_wire::Result<AuthoredEvent> {
        let event = self.unsigned_event()?;
        if event.event().kind.as_str() != expected_kind {
            return Err(arkret_wire::WireError::Protocol(format!(
                "prepared Event kind must be {expected_kind}"
            )));
        }
        Ok(event)
    }

    pub fn kind(&self) -> arkret_wire::Result<EventKind> {
        Ok(self.unsigned_event()?.event().kind.clone())
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::{DidCoreId, Hlc, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    fn draft(kind: &str) -> PreparedEventDraft {
        let mut event = arkret_wire::test_support::raw_event_at(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm")
                    .unwrap(),
            },
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"fixture": true}),
            "2026-08-24T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
            .unwrap();
        PreparedEventDraft {
            unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
                arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap(),
            ))
            .unwrap(),
            event_digest: Hash::new(
                event
                    .event_digest_with_digest_suite(DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn operation_specific_kind_is_checked_from_exact_unsigned_bytes() {
        let draft = draft("ak.contact.request");
        draft.unsigned_event_for_kind("ak.contact.request").unwrap();
        let error = draft
            .unsigned_event_for_kind("ak.contact.accept")
            .unwrap_err();
        assert!(error.to_string().contains("prepared Event kind must be"));
    }
}
