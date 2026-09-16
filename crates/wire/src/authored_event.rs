//! Producer-side boundary for an Event whose content-bound identity is final.

use std::ops::Deref;

use arkret_canonical::DigestSuite;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Event, EventId, ProducerEventProof, Result, WireError};

/// An Event whose `event_id` has been derived from exactly its producer-signed
/// content. There is intentionally no `DerefMut`: changing producer fields
/// requires leaving this wrapper and finalizing again.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthoredEvent {
    event: Event,
    digest_suite: DigestSuite,
}

impl AuthoredEvent {
    pub fn finalize_with_digest_suite(mut event: Event, digest_suite: DigestSuite) -> Result<Self> {
        if !event.proofs.is_empty() {
            return Err(WireError::Protocol(
                "proofs must be attached after Event authoring is finalized".to_owned(),
            ));
        }
        event.refresh_content_bound_identity_with_digest_suite(digest_suite)?;
        Ok(Self {
            event,
            digest_suite,
        })
    }

    pub fn from_verified_with_digest_suite(
        event: Event,
        digest_suite: DigestSuite,
    ) -> Result<Self> {
        event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
        Ok(Self {
            event,
            digest_suite,
        })
    }

    pub fn digest_suite(&self) -> DigestSuite {
        self.digest_suite
    }

    pub fn event_id(&self) -> &EventId {
        &self.event.event_id
    }

    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn into_event(self) -> Event {
        self.event
    }

    pub fn attach_proof(&mut self, proof: ProducerEventProof) {
        self.event.proofs.clear();
        self.event.proofs.push(proof);
    }

    pub fn clear_proofs(&mut self) {
        self.event.proofs.clear();
    }

    pub fn verify_identity(&self) -> Result<()> {
        self.event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)
    }
}

impl Deref for AuthoredEvent {
    type Target = Event;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

impl AsRef<Event> for AuthoredEvent {
    fn as_ref(&self) -> &Event {
        &self.event
    }
}

impl From<AuthoredEvent> for Event {
    fn from(value: AuthoredEvent) -> Self {
        value.event
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredEventRecordRef<'a> {
    digest_suite: DigestSuite,
    event: &'a Event,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredEventRecord {
    digest_suite: DigestSuite,
    event: Event,
}

impl Serialize for AuthoredEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        AuthoredEventRecordRef {
            digest_suite: self.digest_suite,
            event: &self.event,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuthoredEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let record = AuthoredEventRecord::deserialize(deserializer)?;
        Self::from_verified_with_digest_suite(record.event, record.digest_suite)
            .map_err(serde::de::Error::custom)
    }
}
