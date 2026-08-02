//! Validated, immutable Event submission states.
//!
//! [`arkret_wire::Event`] is the common wire envelope and intentionally uses
//! optional fields so it can deserialize every protocol plane. Producers must
//! not treat that representation as proof that an Event is ready to publish.
//! The types in this module consume and validate an Event, then expose it only
//! immutably so the CBA shape cannot be invalidated before submission.

use arkret_wire::Event;

use crate::{Result, SchemaError, validate_event_for_submit};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedEventPlane {
    Data,
    Control,
    NonReducer,
}

macro_rules! prepared_event_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(Event);

        impl $name {
            #[must_use]
            pub fn event(&self) -> &Event {
                &self.0
            }

            #[must_use]
            pub fn into_event(self) -> Event {
                self.0
            }
        }

        impl AsRef<Event> for $name {
            fn as_ref(&self) -> &Event {
                self.event()
            }
        }
    };
}

prepared_event_newtype!(PreparedDataEvent);
prepared_event_newtype!(PreparedControlMove);
prepared_event_newtype!(PreparedNonReducerEvent);

impl TryFrom<Event> for PreparedDataEvent {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if !event.kind.is_reducer_input()
            || event.seal_ref.is_none()
            || event.auth_context.is_none()
            || event.seal_basis.is_some()
            || !event.preconditions.is_empty()
        {
            return Err(SchemaError::Protocol(
                "prepared DataEvent requires seal_ref + auth_context and forbids seal_basis + preconditions"
                    .to_owned(),
            ));
        }
        Ok(Self(event))
    }
}

impl TryFrom<Event> for PreparedControlMove {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if !event.kind.is_reducer_input()
            || event.seal_ref.is_some()
            || event.auth_context.is_some()
            || event.seal_basis.is_none()
        {
            return Err(SchemaError::Protocol(
                "prepared Control Move requires seal_basis and forbids seal_ref + auth_context"
                    .to_owned(),
            ));
        }
        Ok(Self(event))
    }
}

impl TryFrom<Event> for PreparedNonReducerEvent {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if event.kind.is_reducer_input()
            || event.seal_ref.is_some()
            || event.auth_context.is_some()
            || event.seal_basis.is_some()
            || !event.preconditions.is_empty()
        {
            return Err(SchemaError::Protocol(
                "prepared non-reducer Event forbids all CBA reducer fields".to_owned(),
            ));
        }
        Ok(Self(event))
    }
}

/// A schema-validated Event in one of the ordinary (non-anchor) submission
/// planes. Anchor units remain an explicit ordered-batch protocol and cannot
/// be inferred from an Event with missing CBA fields.
#[derive(Clone, Debug, PartialEq)]
pub enum PreparedStandardEvent {
    Data(PreparedDataEvent),
    Control(PreparedControlMove),
    NonReducer(PreparedNonReducerEvent),
}

impl PreparedStandardEvent {
    #[must_use]
    pub const fn plane(&self) -> PreparedEventPlane {
        match self {
            Self::Data(_) => PreparedEventPlane::Data,
            Self::Control(_) => PreparedEventPlane::Control,
            Self::NonReducer(_) => PreparedEventPlane::NonReducer,
        }
    }

    #[must_use]
    pub fn event(&self) -> &Event {
        match self {
            Self::Data(event) => event.event(),
            Self::Control(event) => event.event(),
            Self::NonReducer(event) => event.event(),
        }
    }

    #[must_use]
    pub fn into_event(self) -> Event {
        match self {
            Self::Data(event) => event.into_event(),
            Self::Control(event) => event.into_event(),
            Self::NonReducer(event) => event.into_event(),
        }
    }
}

impl TryFrom<Event> for PreparedStandardEvent {
    type Error = SchemaError;

    fn try_from(event: Event) -> Result<Self> {
        validate_event_for_submit(&event)?;
        if event.kind.is_reducer_input() {
            if event.seal_ref.is_some() {
                Ok(Self::Data(PreparedDataEvent(event)))
            } else {
                Ok(Self::Control(PreparedControlMove(event)))
            }
        } else {
            Ok(Self::NonReducer(PreparedNonReducerEvent(event)))
        }
    }
}

impl From<PreparedDataEvent> for PreparedStandardEvent {
    fn from(event: PreparedDataEvent) -> Self {
        Self::Data(event)
    }
}

impl From<PreparedControlMove> for PreparedStandardEvent {
    fn from(event: PreparedControlMove) -> Self {
        Self::Control(event)
    }
}

impl From<PreparedNonReducerEvent> for PreparedStandardEvent {
    fn from(event: PreparedNonReducerEvent) -> Self {
        Self::NonReducer(event)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AuthContext, Did, DidUrl, Event, Hash, Hlc, Proof, RealmId, ScopeRef, SealId,
    };
    use serde_json::json;

    use super::*;

    fn message_event() -> Event {
        let actor = Did::new("did:webvh:z6mkfixture:agent.example").unwrap();
        let mut event = Event::new(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            },
            actor.clone(),
            0,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000001",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        )
        .unwrap();
        event.seal_ref = Some(SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap());
        event.auth_context = Some(AuthContext {
            did: actor,
            key_id: "agent-device".to_owned(),
            key_epoch: 0,
            credential_epoch: None,
        });
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:agent.example#agent-device")
                .unwrap(),
            alg: "EdDSA".to_owned(),
            event_digest: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header.payload.signature".to_owned(),
        });
        event
    }

    #[test]
    fn prepared_data_event_accepts_only_complete_data_plane_shape() {
        let prepared = PreparedDataEvent::try_from(message_event()).expect("prepared DataEvent");
        assert_eq!(prepared.event().kind.as_str(), "ak.message.create");
    }

    #[test]
    fn prepared_data_event_rejects_missing_mandatory_basis() {
        let mut event = message_event();
        event.seal_ref = None;
        event.auth_context = None;

        assert!(PreparedDataEvent::try_from(event).is_err());
    }

    #[test]
    fn standard_event_classification_preserves_the_validated_plane() {
        let prepared = PreparedStandardEvent::try_from(message_event()).expect("prepared Event");
        assert_eq!(prepared.plane(), PreparedEventPlane::Data);
    }
}
